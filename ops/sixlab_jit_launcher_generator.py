#!/usr/bin/env python3
"""Render a reviewed exact-PR/head/attempt/slot launcher candidate locally only."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any


TEMPLATE_NAME = "pr1173-one-job-launcher-fcca0r1.sh"
TEMPLATE_SHA256 = "84d2019e978ca54212cacbd2c1cbd5e279ff7bdee14880d9ead5edff0423f826"
SOURCE_PULL_NUMBER = 1173
SOURCE_HEAD = "fcca0a92d8882f01b8e203f6ed661358882c5339"
SOURCE_ATTEMPT = 1
SOURCE_PREFIX = "fcca0r1"
SOURCE_LAUNCHER_PREFIX = "fcca0-r1-usproxy5-scopefd1-exitmemv5"
SOURCE_SLOT = "07"
SOURCE_FAMILY = "spa-checks"
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SLOT_FAMILIES = {
    "01": "spa-detect",
    "02": "backend-detect",
    "03": "spa-tests",
    "04": "spa-tests",
    "05": "backend-tests",
    "06": "backend-unit",
    "07": "spa-checks",
}


class GeneratorError(RuntimeError):
    pass


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _template() -> Path:
    return Path(__file__).resolve().parent / "templates" / TEMPLATE_NAME


def _read_template() -> str:
    path = _template()
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise GeneratorError("launcher template is missing") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise GeneratorError("launcher template must be a regular non-symlink file")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise GeneratorError("launcher template must not be group- or world-writable")
    raw = path.read_bytes()
    if _digest(raw) != TEMPLATE_SHA256:
        raise GeneratorError("launcher template digest drifted")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise GeneratorError("launcher template is not UTF-8") from error
    source_bindings = (
        f"readonly PULL_NUMBER='{SOURCE_PULL_NUMBER}'",
        f"readonly EXPECTED_HEAD='{SOURCE_HEAD}'",
        f"readonly ATTEMPT='{SOURCE_ATTEMPT}'",
        f"readonly PREFIX='{SOURCE_PREFIX}'",
        f"readonly LAUNCHER_PREFIX='{SOURCE_LAUNCHER_PREFIX}'",
        f"readonly ALLOWED_SLOT='{SOURCE_SLOT}'",
        f"readonly ALLOWED_FAMILY='{SOURCE_FAMILY}'",
    )
    if any(text.count(binding) != 1 for binding in source_bindings):
        raise GeneratorError("launcher template source binding drifted")
    required = (
        "set -Eeuo pipefail",
        "umask 077",
        "flock -n 9",
        "--ephemeral --disableupdate --no-default-labels --unattended",
        "--run) [[ $# == 2 ]]",
        'systemd-run --user --scope --quiet --unit="$scope_unit" --property=Delegate=yes',
        "IFS= read -r token",
        "--proxy-canary) [[ $# == 1 ]]",
        '[[ "${1:-}" == "$ALLOWED_SLOT" ]]',
        'printf \'sixlab-pr-job-%s-%s\' "$EXPECTED_HEAD" "$ALLOWED_FAMILY"',
        "load5 above 1.5",
        "disk gate below 32 GiB",
        "memory plus swap below 4 GiB",
        "readonly UPSTREAM_PROXY_HOST='47.88.16.146'",
        "readonly UPSTREAM_PROXY_PORT='8443'",
        "local relay private-target rejection failed",
        "direct external HTTPS unexpectedly reachable",
        'HTTP_PROXY="$PROXY_URL" HTTPS_PROXY="$PROXY_URL"',
        'iptables -w -A "$chain" -m comment --comment "$comment" -j DROP',
        "P2-R2E US proxy canary PASS",
        "P2-R2E proxy canary teardown verification failed",
        "P2-R2E launcher teardown verification failed",
        "trap 'cleanup_canary 143' TERM",
        "trap 'cleanup 143' TERM",
        'trap "cleanup_inner 143" TERM',
        "DNS_LISTEN_PORT = 15353",
        "def dns_query_allowed(packet):",
        'REDIRECT --to-ports "$LOCAL_DNS_PORT"',
        "allowlist DNS relay accepted forbidden query",
        "priority filter + 10",
        "receipt path already exists; archive explicitly before run",
        "os.O_WRONLY | os.O_CREAT | os.O_EXCL",
        "exclusive receipt creation failed",
        "evidence path already exists; archive explicitly before run",
        "sixlab-jit-launcher-evidence-v5",
        "sixlab-jit-scope-memory-evidence-v5",
        "SIXLAB_SCOPE_MEMORY_COLLECTOR_BEGIN",
        "RUNNER_MANUALLY_TRAP_SIG=1 ./run.sh",
        '--unit="$scope_unit"',
        "scope memory evidence unavailable or stale",
        "runner_listener_not_observed",
        "expected_runner_identity",
        "copied Runner.Listener identity invalid",
        "stop_dedicated_runtime()",
        "egress fence retained: dedicated runtime remains",
        'pkill -KILL -u "$USER_ID"',
        "class BoundedThreadingMixIn(socketserver.ThreadingMixIn):",
        "class DNSUDPServer(BoundedThreadingMixIn, socketserver.UDPServer):",
        "class DNSTCPServer(BoundedThreadingMixIn, socketserver.TCPServer):",
        "CLIENT_GATE = threading.BoundedSemaphore(MAX_CLIENTS)",
        "status=70",
        "dedicated process exists before job admission",
        "dedicated process exists before token exposure",
        "getent, pkill or timeout missing for canary",
        "getent pkill timeout",
        "proxy canary iptables enumeration failed",
        "proxy canary nftables enumeration failed",
        "iptables enumeration failed",
        "nftables enumeration failed",
    )
    if any(item not in text for item in required):
        raise GeneratorError("launcher template safety contract drifted")
    if any(option in text for option in ("--pipe", "--pty", "--wait", "--no-block")):
        raise GeneratorError("launcher template combines scope mode with incompatible systemd-run stdio or wait options")
    if text.count("systemd-run --user --scope") != 1 or text.count("IFS= read -r token") != 1:
        raise GeneratorError("launcher template scope or single-read stdin contract drifted")
    if "amazonaws.com" in text or "blob.core.windows.net" in text:
        raise GeneratorError("launcher template contains a tenant-controlled cloud suffix")
    if any(forbidden in text for forbidden in ("--stage-token", "--stage-existing-token", "token_path", "token_file", "registration-token", ".token")):
        raise GeneratorError("launcher template persists or reuses a registration token")
    if (
        "ip daddr { 183.60.83.19, 183.60.82.98 } udp dport 53 accept" in text
        or "ip daddr { 183.60.83.19, 183.60.82.98 } tcp dport 53 accept" in text
        or '-d "$resolver" -p udp --dport 53' in text
        or '-d "$resolver" -p tcp --dport 53' in text
    ):
        raise GeneratorError("launcher template exposes direct recursive DNS")
    return text


def render(
    pull_number: int, expected_head: str, attempt: int, slot: str,
) -> tuple[str, dict[str, Any]]:
    if type(pull_number) is not int or pull_number <= 0:
        raise GeneratorError("pull number must be a positive integer")
    if SHA_PATTERN.fullmatch(expected_head) is None:
        raise GeneratorError("expected head must be lowercase 40-hex")
    if type(attempt) is not int or not 1 <= attempt <= 99:
        raise GeneratorError("attempt must be between 1 and 99")
    if slot not in SLOT_FAMILIES:
        raise GeneratorError("slot is not allowed")
    family = SLOT_FAMILIES[slot]
    prefix = f"{expected_head[:5]}r{attempt}"
    launcher_prefix = f"{expected_head[:5]}-r{attempt}-usproxy5-scopefd1-exitmemv5"
    text = _read_template()
    replacements = (
        (f"readonly PULL_NUMBER='{SOURCE_PULL_NUMBER}'", f"readonly PULL_NUMBER='{pull_number}'"),
        (f"readonly EXPECTED_HEAD='{SOURCE_HEAD}'", f"readonly EXPECTED_HEAD='{expected_head}'"),
        (f"readonly ATTEMPT='{SOURCE_ATTEMPT}'", f"readonly ATTEMPT='{attempt}'"),
        (f"readonly PREFIX='{SOURCE_PREFIX}'", f"readonly PREFIX='{prefix}'"),
        (
            f"readonly LAUNCHER_PREFIX='{SOURCE_LAUNCHER_PREFIX}'",
            f"readonly LAUNCHER_PREFIX='{launcher_prefix}'",
        ),
        (f"readonly ALLOWED_SLOT='{SOURCE_SLOT}'", f"readonly ALLOWED_SLOT='{slot}'"),
        (f"readonly ALLOWED_FAMILY='{SOURCE_FAMILY}'", f"readonly ALLOWED_FAMILY='{family}'"),
    )
    rendered = text
    for source, target in replacements:
        rendered = rendered.replace(source, target)
    if any(rendered.count(target) != 1 for _, target in replacements):
        raise GeneratorError("rendered exact binding count is invalid")
    expected_self = (
        'readonly SELF="$ROOT/bin/pr${PULL_NUMBER}-one-job-launcher-'
        '${LAUNCHER_PREFIX}-slot${ALLOWED_SLOT}-${ALLOWED_FAMILY}.sh"'
    )
    if expected_self not in rendered:
        raise GeneratorError("rendered self path is invalid")
    output_name = (
        f"pr{pull_number}-one-job-launcher-{launcher_prefix}-"
        f"slot{slot}-{family}.sh"
    )
    manifest_name = output_name[:-3] + ".manifest.json"
    raw = rendered.encode("utf-8")
    manifest = {
        "schema": "sixlab-jit-launcher-candidate-v1",
        "repository": "Steven-ZYH/sixlab",
        "pull_number": pull_number,
        "expected_head": expected_head,
        "attempt": attempt,
        "slot": slot,
        "family": family,
        "exact_label": f"sixlab-pr-job-{expected_head}-{family}",
        "prefix": prefix,
        "launcher_prefix": launcher_prefix,
        "egress_profile": "us-proxy-v5",
        "supersedes_egress_profile": "us-proxy-v4",
        "upstream_proxy": "47.88.16.146:8443",
        "output_name": output_name,
        "manifest_name": manifest_name,
        "source_template": TEMPLATE_NAME,
        "source_sha256": TEMPLATE_SHA256,
        "rendered_sha256": _digest(raw),
        "capability_scope": "single-slot-single-family",
        "execution_evidence_profile": "runner-exit-scope-memory-v5",
        "legacy_receipt_schema": "sixlab-jit-teardown-receipt-v1",
        "sidecar_evidence_schema": "sixlab-jit-launcher-evidence-v5",
        "scope_memory_schema": "sixlab-jit-scope-memory-evidence-v5",
        "sidecar_consumer_activation": "not-authorized",
        "installation_authorized": False,
        "token_mint_authorized": False,
    }
    return rendered, manifest


def _atomic(path: Path, raw: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink():
        raise GeneratorError("candidate output directory must not be a symlink")
    if path.exists() or path.is_symlink():
        raise GeneratorError("candidate destination already exists")
    descriptor, temporary = tempfile.mkstemp(prefix=".sixlab-jit-launcher.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise GeneratorError("candidate destination already exists") from error
        os.unlink(temporary)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def write_candidate(
    *, pull_number: int, expected_head: str, attempt: int, slot: str,
    output: Path, manifest_path: Path,
) -> dict[str, Any]:
    rendered, manifest = render(pull_number, expected_head, attempt, slot)
    if output.expanduser().resolve() == manifest_path.expanduser().resolve():
        raise GeneratorError("candidate output and manifest paths must differ")
    if output.name != manifest["output_name"]:
        raise GeneratorError("candidate output filename is not exact-bound")
    if manifest_path.name != manifest["manifest_name"]:
        raise GeneratorError("candidate manifest filename is not exact-bound")
    _atomic(output, rendered.encode("utf-8"), 0o755)
    try:
        _atomic(
            manifest_path,
            (json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8"),
            0o600,
        )
    except Exception:
        output.unlink(missing_ok=True)
        raise
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Render one local exact-head JIT launcher candidate")
    parser.add_argument("--pull-number", type=int, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--attempt", type=int, required=True)
    parser.add_argument("--slot", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        manifest = write_candidate(
            pull_number=arguments.pull_number,
            expected_head=arguments.expected_head,
            attempt=arguments.attempt,
            slot=arguments.slot,
            output=arguments.output,
            manifest_path=arguments.manifest,
        )
    except GeneratorError as error:
        print(json.dumps({
            "schema": "sixlab-jit-launcher-candidate-v1",
            "status": "CHECK-INCOMPLETE",
            "installation_authorized": False,
            "token_mint_authorized": False,
            "error": str(error),
        }, separators=(",", ":"), sort_keys=True))
        return 2
    print(json.dumps(manifest, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
