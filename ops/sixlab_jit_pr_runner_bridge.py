#!/usr/bin/env python3
"""Collect and map a vendored B correlation into R1 shadow observations.

The production bridge executes only the exact bytes reviewed in SIXLAB PR
#1201.  It supplies an empty-by-default Node environment, so neither callers
nor an ambient shell can inject Node loaders, module paths, or inspectors.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
import hashlib
import json
import os
import re
import select
import selectors
import signal
import stat
import subprocess
import time

import sixlab_jit_shadow_controller as shadow


CORRELATION_SCHEMA = "sixlab-jit-pr-runner-correlation-v2"
BRIDGE_SCHEMA = "sixlab-jit-open-pr-cycle-v1"
SOURCE_REPOSITORY = "Steven-ZYH/sixlab"
SOURCE_PULL_REQUEST = 1201
SOURCE_HEAD = "1efdfd2d754822d29d4f0a4f93b48117a663116f"
CANONICAL_MANIFEST_SHA256 = "9595d39c7ff80dce09cd33cf328efb0cf90d6709f14b32e51371df6e882ebc9e"
CANONICAL_VALIDATOR_SHA256 = "70a8cdb5fea2d0a5a04fb896336041dce80dd8cdf51663115bc96d65114e3e31"
CANONICAL_CONTRACT_SHA256 = "57a0fd3d88a344bab7b6174742b3a1b10f02f0fd16e582bff1fba99bd2d83d61"
CANONICAL_COLLECTOR_SHA256 = "c3611524baf3e535ad4815898fa1c6cc791f777815e121674af280e3838cf021"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
VENDOR_ROOT = PROJECT_ROOT / "vendor" / "sixlab-pr1201"
VENDOR_FILES = {
    ".claude/ci-runner-automation-contract.v1.json": CANONICAL_CONTRACT_SHA256,
    ".github/workflows/test-backend.yml": "233f8ecfa172361bc54d3c8c87ff0df5d0bf1d961fc23e54f6547631d2595ec8",
    ".github/workflows/test.yml": "aee582274151a53c4b9ca27eee068f37fcc38b8dc460d1b09ad523daa644bd4a",
    ".github/workflows/pr-peer-review-gate.yml": "7fed9a4e58a1d4c0cc665be804ac5071d3384ea02da08b3b9e36662b7c5ce7fc",
    "scripts/ci/collect-pr-runner-correlation.mjs": CANONICAL_COLLECTOR_SHA256,
    "scripts/ci/collect-pr-runner-correlation.test.mjs": "ba774eda78b020edf5a9189863f1f0529cc1cf80838a07b88178f9fe670b763f",
    "scripts/ci/pr-runner-contract.mjs": CANONICAL_VALIDATOR_SHA256,
}
# Installation is a separate, root-administered activation step.  In
# particular, this is not derived from PATH, a user configuration directory,
# or a developer's Homebrew installation.
NODE_TRUST_MANIFEST = Path("/etc/opcb/sixlab-jit-node-trust-v2.json")
NODE_TRUST_SCHEMA = "opcb-sixlab-jit-node-trust-v2"
# This is deliberately an installation location, not a location underneath
# this checkout.  A root-administered installer may copy the reviewed source
# vendor here, but the bridge never executes the checkout copy in production.
INSTALLED_VENDOR_ROOT = Path("/var/lib/opcb/sixlab-jit/vendor/sixlab-pr1201")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
COLLECTOR_TIMEOUT_SECONDS = 120.0
COLLECTOR_STDOUT_LIMIT_BYTES = 8 * 1024 * 1024
COLLECTOR_STDERR_LIMIT_BYTES = 256 * 1024
VALIDATOR_TIMEOUT_SECONDS = 15.0
VALIDATOR_INPUT_LIMIT_BYTES = 8 * 1024 * 1024
VALIDATOR_STDOUT_LIMIT_BYTES = 8 * 1024 * 1024
VALIDATOR_STDERR_LIMIT_BYTES = 256 * 1024
PROCESS_REAP_TIMEOUT_SECONDS = 1.0
PROCESS_IO_CHUNK_BYTES = 64 * 1024
PROCESS_EXIT_POLL_SECONDS = 0.05


class BridgeError(RuntimeError):
    pass


class _LeaderExitWatch:
    """Observe leader exit without reaping it, preserving its PID/PGID."""

    def __init__(self, pid: int) -> None:
        self._pidfd: int | None = None
        self._pidfd_selector: selectors.BaseSelector | None = None
        self._kqueue: Any = None
        try:
            if hasattr(os, "pidfd_open"):
                self._pidfd = os.pidfd_open(pid)
                self._pidfd_selector = selectors.DefaultSelector()
                self._pidfd_selector.register(self._pidfd, selectors.EVENT_READ)
            elif hasattr(select, "kqueue"):
                self._kqueue = select.kqueue()
                event = select.kevent(
                    pid,
                    filter=select.KQ_FILTER_PROC,
                    flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE,
                    fflags=select.KQ_NOTE_EXIT,
                )
                self._kqueue.control([event], 0, 0)
            else:
                raise BridgeError("bounded subprocess exit observation is unsupported")
        except Exception:
            self.close()
            raise

    def has_exited(self) -> bool:
        if self._pidfd is not None:
            assert self._pidfd_selector is not None
            return bool(self._pidfd_selector.select(0))
        assert self._kqueue is not None
        return bool(self._kqueue.control(None, 1, 0))

    def close(self) -> None:
        if self._pidfd_selector is not None:
            self._pidfd_selector.close()
            self._pidfd_selector = None
        if self._pidfd is not None:
            os.close(self._pidfd)
            self._pidfd = None
        if self._kqueue is not None:
            self._kqueue.close()
            self._kqueue = None


class _VerifiedFile:
    """A root-owned regular file whose identity and bytes were checked."""

    def __init__(
        self, path: Path, device: int, inode: int, mode: int, uid: int,
        digest: str, contents: bytes | None = None, immutable: bool = False,
    ) -> None:
        self.path = path
        self.device = device
        self.inode = inode
        self.mode = mode
        self.uid = uid
        self.digest = digest
        self.contents = contents
        self.immutable = immutable


class _InstalledVendor:
    """The fixed installed B bundle used for one production cycle."""

    def __init__(self, root: Path, files: dict[str, _VerifiedFile]) -> None:
        self.root = root
        self.files = files

    def executable_path(self, relative: str) -> Path:
        verified = self.files[relative]
        # The parent hierarchy is root-owned and non-writable, so an
        # unprivileged caller cannot race this check with the exec below.  The
        # identity comparison additionally makes a privileged/path drift fail
        # closed before either collector or validator starts.
        _same_verified_file(verified, f"installed SIXLAB file {relative}")
        return verified.path


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _record(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise BridgeError(f"{label} fields are not canonical")
    return value


def _regular_bytes(path: Path, label: str) -> bytes:
    """Read a non-symlink regular source file for fixture/install validation.

    This deliberately does *not* establish a production trust boundary.  See
    ``_verified_root_owned_file`` for the installation-time execution path.
    """
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError as error:
        raise BridgeError(f"{label} is unreadable") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or not raw:
        raise BridgeError(f"{label} must be a regular non-symlink file")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise BridgeError(f"{label} has unsafe write permissions")
    return raw


def _vendored_b() -> dict[str, Path]:
    """Return checked checkout vendor files for tests and installation only.

    No production entry point calls this function.  A working tree is mutable
    by its checkout owner even if the individual bytes happened to match at
    validation time.
    """
    root = VENDOR_ROOT
    manifest = root / "provenance.json"
    manifest_raw = _regular_bytes(manifest, "vendored SIXLAB provenance manifest")
    if _digest(manifest_raw) != CANONICAL_MANIFEST_SHA256:
        raise BridgeError("vendored SIXLAB provenance manifest digest drifted")
    try:
        parsed = json.loads(manifest_raw)
    except json.JSONDecodeError as error:
        raise BridgeError("vendored SIXLAB provenance manifest is invalid JSON") from error
    if parsed != {
        "schema": "opcb-projectmanager-vendored-sixlab-pr1201-v1",
        "source": {"repository": SOURCE_REPOSITORY, "pullRequest": SOURCE_PULL_REQUEST, "head": SOURCE_HEAD},
        "files": VENDOR_FILES,
    }:
        raise BridgeError("vendored SIXLAB provenance manifest is not the reviewed source")
    files: dict[str, Path] = {}
    for relative, expected_digest in VENDOR_FILES.items():
        path = root / relative
        raw = _regular_bytes(path, f"vendored SIXLAB file {relative}")
        if _digest(raw) != expected_digest:
            raise BridgeError(f"vendored SIXLAB file digest drifted: {relative}")
        files[relative] = path
    return files


def _fixture_pinned_validator() -> Path:
    """Return the checkout validator only for non-admitting fixture tests."""
    return _vendored_b()["scripts/ci/pr-runner-contract.mjs"]


def _close_stream(stream: Any, selector: selectors.BaseSelector | None = None) -> None:
    if stream is None:
        return
    if selector is not None:
        try:
            selector.unregister(stream)
        except (KeyError, ValueError):
            pass
    try:
        stream.close()
    except OSError:
        pass


def _terminate_process_group(process: subprocess.Popen[bytes], label: str) -> None:
    """Kill the isolated child group and reap its leader within a fixed bound."""
    # There is no graceful grace period after the operation deadline: the
    # collector may hold a credential and a descendant may retain a pipe.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        # macOS may report EPERM when only an unreaped orphan remains.  The
        # leader is still our direct child and must never survive cleanup.
        if process.poll() is None:
            process.kill()
    try:
        process.wait(timeout=PROCESS_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise BridgeError(f"{label} cleanup timed out") from error


def _run_bounded_process(
    command: list[str], *, input_bytes: bytes | None, env: dict[str, str],
    timeout_seconds: float, stdout_limit_bytes: int, stderr_limit_bytes: int,
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    """Run one isolated process with a hard deadline and bounded pipe reads."""
    if timeout_seconds <= 0 or stdout_limit_bytes < 0 or stderr_limit_bytes < 0:
        raise BridgeError(f"{label} process limits are invalid")
    deadline = time.monotonic() + timeout_seconds
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
        bufsize=0,
    )
    exit_watch: _LeaderExitWatch | None = None
    selector: selectors.BaseSelector | None = None
    stdout = bytearray()
    stderr = bytearray()
    cleanup_started = False
    try:
        try:
            exit_watch = _LeaderExitWatch(process.pid)
            selector = selectors.DefaultSelector()
        except BridgeError:
            raise
        except Exception as error:
            raise BridgeError(f"{label} process setup failed") from error
        assert process.stdout is not None and process.stderr is not None
        for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        if process.stdin is not None:
            if input_bytes:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                _close_stream(process.stdin)

        input_offset = 0
        leader_exited = False
        while not leader_exited or selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BridgeError(f"{label} timed out")
            if not leader_exited and exit_watch.has_exited():
                # Observe exit without waitpid first.  The unreaped leader keeps
                # its PID/PGID stable while every remaining group member is
                # killed; only then may the leader be reaped.
                cleanup_started = True
                _terminate_process_group(process, label)
                leader_exited = True
                continue
            events = selector.select(min(remaining, PROCESS_EXIT_POLL_SECONDS))
            for key, _ in events:
                stream = key.fileobj
                name = key.data
                if name == "stdin":
                    assert process.stdin is not None and input_bytes is not None
                    try:
                        written = os.write(process.stdin.fileno(), input_bytes[input_offset:])
                    except BrokenPipeError:
                        written = 0
                        input_offset = len(input_bytes)
                    else:
                        input_offset += written
                    if input_offset == len(input_bytes):
                        _close_stream(process.stdin, selector)
                    continue

                target = stdout if name == "stdout" else stderr
                limit = stdout_limit_bytes if name == "stdout" else stderr_limit_bytes
                allowance = limit - len(target)
                try:
                    chunk = os.read(stream.fileno(), min(PROCESS_IO_CHUNK_BYTES, allowance + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    _close_stream(stream, selector)
                    continue
                if len(chunk) > allowance:
                    raise BridgeError(f"{label} {name} exceeds byte limit")
                target.extend(chunk)

        assert process.returncode is not None
        return subprocess.CompletedProcess(command, process.returncode, bytes(stdout), bytes(stderr))
    finally:
        if selector is not None:
            selector.close()
        if exit_watch is not None:
            exit_watch.close()
        _close_stream(process.stdin)
        _close_stream(process.stdout)
        _close_stream(process.stderr)
        if not cleanup_started:
            _terminate_process_group(process, label)


def _canonical_validation(
    correlation: object, validator: Path, node: Path, *, expected_validator: Path | None = None,
) -> dict[str, Any]:
    """Run B's fixed validator and retain only its contract-derived output."""
    pinned_validator = expected_validator or _fixture_pinned_validator()
    if validator != pinned_validator:
        raise BridgeError("canonical SIXLAB validator path is invalid")
    validator = pinned_validator
    try:
        source = json.dumps(correlation, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise BridgeError("correlation cannot be encoded for canonical validation") from error
    if len(source) > VALIDATOR_INPUT_LIMIT_BYTES:
        raise BridgeError("canonical SIXLAB validator input exceeds byte limit")
    completed = _run_bounded_process(
        [str(node), str(validator), "--validate-snapshot-stdin"],
        input_bytes=source,
        # Validator input is untrusted correlation JSON.  It has no need for a
        # credential, PATH, Node flags/module paths, proxy, or CA settings.
        env={},
        timeout_seconds=VALIDATOR_TIMEOUT_SECONDS,
        stdout_limit_bytes=VALIDATOR_STDOUT_LIMIT_BYTES,
        stderr_limit_bytes=VALIDATOR_STDERR_LIMIT_BYTES,
        label="canonical SIXLAB validator",
    )
    if completed.returncode != 0:
        raise BridgeError("canonical SIXLAB contract rejected correlation")
    try:
        result = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BridgeError("canonical SIXLAB validator returned invalid JSON") from error
    _record(result, {"schemaVersion", "repository", "openPullRequests", "selectedRuns"}, "canonical SIXLAB validation")
    if result["schemaVersion"] != 2 or result["repository"] != shadow.EXPECTED_REPOSITORY:
        raise BridgeError("canonical SIXLAB validation identity is invalid")
    if not isinstance(result["openPullRequests"], list) or not result["openPullRequests"]:
        raise BridgeError("canonical SIXLAB validation open PR inventory is invalid")
    if not isinstance(result["selectedRuns"], list) or not result["selectedRuns"]:
        raise BridgeError("canonical SIXLAB validation workflow inventory is invalid")
    return result


def _safe_root_metadata(metadata: os.stat_result, label: str, *, immutable: bool = False) -> None:
    if metadata.st_uid != 0:
        raise BridgeError(f"{label} is not root-owned")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise BridgeError(f"{label} has unsafe write permissions")
    if immutable and metadata.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
        raise BridgeError(f"{label} is not immutable")


def _root_owned_safe_path(path: Path, label: str) -> None:
    """Require an absolute root-owned non-symlink path and every parent."""
    if not path.is_absolute():
        raise BridgeError(f"{label} must be an absolute path")
    current = path
    while True:
        try:
            metadata = current.lstat()
        except OSError as error:
            raise BridgeError(f"{label} is unreadable") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise BridgeError(f"{label} must not traverse a symlink")
        _safe_root_metadata(metadata, label)
        if current == current.parent:
            return
        current = current.parent


def _verified_root_owned_file(
    path: Path, label: str, expected_digest: str | None, *, immutable: bool = False,
) -> _VerifiedFile:
    """Open and verify a root-installed immutable regular file without links.

    ``O_NOFOLLOW`` and the lstat/fstat identity check reject a replacement that
    happens between pathname resolution and reading.  The entire parent chain
    is separately root-owned and not group/other writable; therefore the
    subsequent subprocess path cannot be replaced by the checkout owner.
    """
    _root_owned_safe_path(path, label)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BridgeError(f"{label} is unreadable") from error
    try:
        opened = os.fstat(descriptor)
        listed = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(listed.st_mode)
            or opened.st_dev != listed.st_dev
            or opened.st_ino != listed.st_ino
        ):
            raise BridgeError(f"{label} changed while it was verified")
        _safe_root_metadata(opened, label, immutable=immutable)
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    digest = _digest(raw)
    if not raw or (expected_digest is not None and digest != expected_digest):
        raise BridgeError(f"{label} digest drifted")
    return _VerifiedFile(
        path=path,
        device=opened.st_dev,
        inode=opened.st_ino,
        mode=stat.S_IMODE(opened.st_mode),
        uid=opened.st_uid,
        digest=digest,
        contents=raw,
        immutable=immutable,
    )


def _same_verified_file(verified: _VerifiedFile, label: str) -> None:
    """Reject post-validation inode, ownership, mode, link, or byte drift."""
    _root_owned_safe_path(verified.path, label)
    current = _verified_root_owned_file(
        verified.path, label, verified.digest, immutable=verified.immutable,
    )
    if (
        current.device != verified.device
        or current.inode != verified.inode
        or current.mode != verified.mode
        or current.uid != verified.uid
    ):
        raise BridgeError(f"{label} identity drifted after verification")


def _trusted_runtime() -> tuple[_VerifiedFile, _InstalledVendor]:
    """Load the root-administered Node and installed B bundle for production."""
    manifest = NODE_TRUST_MANIFEST
    verified_manifest = _verified_root_owned_file(
        manifest, "Node trust manifest", None, immutable=True,
    )
    assert verified_manifest.contents is not None
    manifest_raw = verified_manifest.contents
    try:
        parsed = json.loads(manifest_raw)
    except json.JSONDecodeError as error:
        raise BridgeError("Node trust manifest is invalid JSON") from error
    if (not isinstance(parsed, dict) or set(parsed) != {"schema", "node", "vendor"}
            or parsed.get("schema") != NODE_TRUST_SCHEMA
            or not isinstance(parsed.get("node"), dict)
            or set(parsed["node"]) != {"path", "sha256"}
            or not isinstance(parsed.get("vendor"), dict)
            or set(parsed["vendor"]) != {"root", "provenance_sha256", "files"}):
        raise BridgeError("Node trust manifest fields are not canonical")
    node_path = parsed["node"]["path"]
    expected_digest = parsed["node"]["sha256"]
    if (not isinstance(node_path, str) or not node_path.startswith("/")
            or not isinstance(expected_digest, str) or not _SHA256.fullmatch(expected_digest)):
        raise BridgeError("Node trust manifest binding is invalid")
    node = _verified_root_owned_file(Path(node_path), "trusted Node executable", expected_digest)
    if not (node.mode & stat.S_IXUSR):
        raise BridgeError("trusted Node executable binding is invalid")
    vendor = parsed["vendor"]
    if (
        vendor.get("root") != str(INSTALLED_VENDOR_ROOT)
        or vendor.get("provenance_sha256") != CANONICAL_MANIFEST_SHA256
        or vendor.get("files") != VENDOR_FILES
    ):
        raise BridgeError("Node trust manifest installed vendor binding is invalid")
    _root_owned_safe_path(INSTALLED_VENDOR_ROOT, "installed SIXLAB vendor root")
    if not stat.S_ISDIR(INSTALLED_VENDOR_ROOT.lstat().st_mode):
        raise BridgeError("installed SIXLAB vendor root is not a directory")
    files = {
        "provenance.json": _verified_root_owned_file(
            INSTALLED_VENDOR_ROOT / "provenance.json",
            "installed SIXLAB provenance manifest", CANONICAL_MANIFEST_SHA256, immutable=True,
        ),
    }
    for relative, expected in VENDOR_FILES.items():
        files[relative] = _verified_root_owned_file(
            INSTALLED_VENDOR_ROOT / relative,
            f"installed SIXLAB file {relative}", expected, immutable=True,
        )
    return node, _InstalledVendor(root=INSTALLED_VENDOR_ROOT, files=files)


def _trusted_node() -> Path:
    """Compatibility helper for tests; production uses ``_trusted_runtime``."""
    return _trusted_runtime()[0].path


def _test_node(test_node: Path | None) -> Path:
    """Verify an explicit test-only Node override for fixture validation.

    This never reaches ``build_cycle`` and returns a non-admitting fixture, so
    it cannot become an installation shortcut or a production trust root.
    """
    if test_node is None or not test_node.is_absolute():
        raise BridgeError("test fixture requires an explicit absolute test-only Node executable")
    try:
        metadata = test_node.lstat()
    except OSError as error:
        raise BridgeError("test-only Node executable is unreadable") from error
    if test_node.is_symlink() or not stat.S_ISREG(metadata.st_mode) or not (metadata.st_mode & stat.S_IXUSR):
        raise BridgeError("test-only Node executable is invalid")
    return test_node


def _collector_environment() -> dict[str, str]:
    """Pass only the short-lived GitHub read token to the collector."""
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise BridgeError("canonical SIXLAB live collector requires GITHUB_TOKEN")
    return {"GITHUB_TOKEN": token}


def _collect_live_correlation(node: Path, installed_vendor: _InstalledVendor | None = None) -> object:
    """Run B's read-only GitHub collector; caller data cannot replace this.

    ``installed_vendor`` is mandatory for production.  The fallback exists
    solely for the non-admitting test seam below, and is deliberately unable
    to reach ``build_cycle``.
    """
    collector = (
        installed_vendor.executable_path("scripts/ci/collect-pr-runner-correlation.mjs")
        if installed_vendor is not None
        else _vendored_b()["scripts/ci/collect-pr-runner-correlation.mjs"]
    )
    completed = _run_bounded_process(
        [str(node), str(collector), "--stdout"],
        input_bytes=None,
        env=_collector_environment(),
        timeout_seconds=COLLECTOR_TIMEOUT_SECONDS,
        stdout_limit_bytes=COLLECTOR_STDOUT_LIMIT_BYTES,
        stderr_limit_bytes=COLLECTOR_STDERR_LIMIT_BYTES,
        label="canonical SIXLAB live collector",
    )
    if completed.returncode != 0:
        raise BridgeError("canonical SIXLAB live collector failed")
    try:
        correlation = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BridgeError("canonical SIXLAB live collector returned invalid JSON") from error
    _record(correlation, {"schema", "observedAt", "repository", "openPullRequests", "runs"}, "live correlation")
    return correlation


def _build_from_validated_correlation(
    correlation: object,
    selections: object,
    evidence_by_pull: object,
    canonical_validator: Path,
    node: Path,
    *,
    installed_vendor: _InstalledVendor | None = None,
) -> dict[str, Any]:
    """Build R1 observations after the SIXLAB validator accepts correlation.

    ``selections`` maps every open PR number to one exact workflow name. Each
    evidence row supplies ProjectManager-only head observations and host/receipt
    evidence; the GitHub correlation remains the sole source for PR/run/job
    identity. This private helper only serves the trusted collector entrypoint
    and non-admitting fixture validation.
    """
    validator = (
        installed_vendor.executable_path("scripts/ci/pr-runner-contract.mjs")
        if installed_vendor is not None else canonical_validator
    )
    if validator != canonical_validator:
        raise BridgeError("installed SIXLAB validator path drifted")
    validated = _canonical_validation(
        correlation, validator, node, expected_validator=canonical_validator,
    )
    source = _record(correlation, {"schema", "observedAt", "repository", "openPullRequests", "runs"}, "correlation")
    if source["schema"] != CORRELATION_SCHEMA or source["repository"] != shadow.EXPECTED_REPOSITORY:
        raise BridgeError("correlation schema or repository is invalid")
    if not isinstance(selections, dict) or not isinstance(evidence_by_pull, dict):
        raise BridgeError("bridge selections or evidence are invalid")
    pulls: dict[int, dict[str, Any]] = {}
    for index, raw in enumerate(validated["openPullRequests"]):
        pull = _record(raw, {"number", "state", "draft", "baseRef", "headSha"}, f"openPullRequests[{index}]")
        number = pull["number"]
        if type(number) is not int or number <= 0 or number in pulls:
            raise BridgeError("open PR numbers are invalid")
        if pull["state"] != "open" or pull["draft"] is not False or pull["baseRef"] != shadow.EXPECTED_BASE:
            raise BridgeError("open PR is not ready for the main JIT lane")
        shadow._sha(pull["headSha"], f"openPullRequests[{index}].headSha")
        pulls[number] = pull
    if set(selections) != set(pulls) or set(evidence_by_pull) != set(pulls):
        raise BridgeError("every open PR requires one explicit selection and one evidence row")

    canonical_runs: dict[tuple[int, str], dict[str, Any]] = {}
    for index, raw in enumerate(validated["selectedRuns"]):
        row = _record(raw, {"pullRequestNumber", "workflow", "workflowSourcePath", "workflowApiId", "requiredContext", "runId", "attempt", "jobFamily", "headSha", "exactLabels"}, f"canonical selectedRuns[{index}]")
        key = (row["pullRequestNumber"], row["workflow"])
        if (type(row["pullRequestNumber"]) is not int or row["pullRequestNumber"] not in pulls
                or not isinstance(row["workflow"], str) or not row["workflow"]
                or not isinstance(row["workflowSourcePath"], str) or not row["workflowSourcePath"]
                or not isinstance(row["workflowApiId"], str) or not row["workflowApiId"]
                or key in canonical_runs or row["headSha"] != pulls[row["pullRequestNumber"]]["headSha"]
                or not isinstance(row["exactLabels"], list) or not row["exactLabels"]):
            raise BridgeError("canonical SIXLAB workflow binding is invalid")
        canonical_runs[key] = row
    if set(number for number, _ in canonical_runs) != set(pulls):
        raise BridgeError("canonical SIXLAB validation omitted an open PR")

    selected_runs: list[tuple[int, dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    for number, pull in pulls.items():
        workflow = selections[number]
        if not isinstance(workflow, str) or not workflow:
            raise BridgeError("selected workflow is invalid")
        canonical = canonical_runs.get((number, workflow))
        if canonical is None:
            raise BridgeError("selected workflow is not allowed")
        matches = [row for row in source["runs"] if isinstance(row, dict) and row.get("pullRequestNumber") == number and row.get("workflow") == workflow and row.get("run", {}).get("id") == canonical["runId"]]
        if len(matches) != 1:
            raise BridgeError("selected workflow does not have one exact current PR run")
        row = _record(matches[0], {"pullRequestNumber", "workflow", "run", "jobs"}, "selected run")
        run = _record(row["run"], {"id", "headSha", "attempt", "latestAttempt", "status"}, "selected run.run")
        if run["headSha"] != pull["headSha"] or run["attempt"] != run["latestAttempt"]:
            raise BridgeError("selected run head or attempt drifted")
        if not isinstance(row["jobs"], list) or not row["jobs"]:
            raise BridgeError("selected run jobs are invalid")
        evidence = _record(evidence_by_pull[number], {"headObservations", "host", "allocation", "receipt"}, "ProjectManager evidence")
        expected_jobs: dict[str, int] = {}
        for expected_index, raw_expected in enumerate(canonical["exactLabels"]):
            expected = _record(raw_expected, {"jobId", "instances", "label"}, f"canonical exactLabels[{expected_index}]")
            if (not isinstance(expected["jobId"], str) or not expected["jobId"]
                    or type(expected["instances"]) is not int or expected["instances"] <= 0
                    or expected["jobId"] in expected_jobs
                    or expected["label"] != shadow.exact_label(pull["headSha"], expected["jobId"])):
                raise BridgeError("canonical SIXLAB job map is invalid")
            expected_jobs[expected["jobId"]] = expected["instances"]
        observed_jobs: dict[str, int] = {}
        for index, raw in enumerate(row["jobs"]):
            job = _record(raw, {"id", "runId", "runAttempt", "name", "family", "status", "conclusion", "labels", "runnerId", "runnerName", "createdAt"}, f"selected jobs[{index}]")
            if job["runId"] != run["id"] or job["runAttempt"] != run["attempt"]:
                raise BridgeError("selected job run binding drifted")
            name = job["name"]
            family = job["family"]
            base_name = re.sub(r" \([^)]*\)$", "", name) if isinstance(name, str) else ""
            if base_name not in expected_jobs or family != base_name:
                raise BridgeError("selected job is undeclared or crosses workflow family")
            if job["labels"] != [shadow.exact_label(pull["headSha"], family)]:
                raise BridgeError("selected job exact label binding drifted")
            observed_jobs[base_name] = observed_jobs.get(base_name, 0) + 1
        if observed_jobs != expected_jobs:
            raise BridgeError("selected workflow job instances are incomplete or duplicated")
        selected_runs.append((number, pull, row, evidence))

    run_inventory = sorted(run["id"] for _, _, row, _ in selected_runs for run in [row["run"]])
    if len(set(run_inventory)) != len(run_inventory):
        raise BridgeError("selected run inventory is duplicated")
    snapshots = []
    for number, pull, row, evidence in selected_runs:
        run = row["run"]
        jobs = []
        for index, raw in enumerate(row["jobs"]):
            job = _record(raw, {"id", "runId", "runAttempt", "name", "family", "status", "conclusion", "labels", "runnerId", "runnerName", "createdAt"}, f"selected jobs[{index}]")
            if job["runId"] != run["id"] or job["runAttempt"] != run["attempt"]:
                raise BridgeError("selected job run binding drifted")
            jobs.append({
                "id": job["id"], "run_id": job["runId"], "run_attempt": job["runAttempt"],
                "name": job["name"], "family": job["family"], "status": job["status"],
                "conclusion": job["conclusion"], "labels": job["labels"],
                "runner_id": job["runnerId"], "runner_name": job["runnerName"],
                "created_at": job["createdAt"],
            })
        snapshots.append({
            "schema": shadow.SCHEMA,
            "observed_at": source["observedAt"],
            "pull": {"number": number, "state": pull["state"], "draft": pull["draft"], "base_ref": pull["baseRef"], "head_sha": pull["headSha"]},
            "head_observations": evidence["headObservations"],
            "run_inventory": run_inventory,
            "run": {"id": run["id"], "attempt": run["attempt"], "head_sha": run["headSha"], "status": run["status"]},
            "jobs": jobs,
            "host": evidence["host"],
            "allocation": evidence["allocation"],
            "receipt": evidence["receipt"],
        })
    return {"schema": BRIDGE_SCHEMA, "observed_at": source["observedAt"], "open_pull_numbers": sorted(pulls), "snapshots": snapshots}


def build_cycle(selections: object, evidence_by_pull: object) -> dict[str, Any]:
    """Build a schedulable cycle from B's freshly collected live inventory."""
    # The installed manifest binds the Node executable and the *installed*
    # immutable B source.  The checkout vendor never crosses this boundary.
    verified_node, installed_vendor = _trusted_runtime()
    _same_verified_file(verified_node, "trusted Node executable")
    node = verified_node.path
    correlation = _collect_live_correlation(node, installed_vendor)
    _same_verified_file(verified_node, "trusted Node executable")
    return _build_from_validated_correlation(
        correlation, selections, evidence_by_pull,
        installed_vendor.executable_path("scripts/ci/pr-runner-contract.mjs"), node,
        installed_vendor=installed_vendor,
    )


def validate_test_fixture(
    correlation: object,
    selections: object,
    evidence_by_pull: object,
    *,
    test_node: Path | None,
) -> dict[str, Any]:
    """Validate a fixture without returning a cycle that scheduling can consume."""
    _build_from_validated_correlation(
        correlation, selections, evidence_by_pull, _fixture_pinned_validator(), _test_node(test_node),
    )
    return {
        "schema": "sixlab-jit-bridge-test-fixture-v1",
        "status": "CHECK-INCOMPLETE",
        "token_allowed": False,
        "live_mutation_allowed": False,
        "next_action": "test-fixture-cannot-enter-scheduler-or-actuator",
    }
