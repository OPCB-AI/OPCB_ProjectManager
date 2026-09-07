#!/usr/bin/env python3
"""Read-only live collector for the SIXLAB JIT shadow evaluator.

The collector calls fixed GitHub read endpoints and a fixed read-only host
probe.  It never requests a registration token and contains no Runner, label,
workflow, service, filesystem cleanup, merge, or deployment mutation.
"""

from __future__ import annotations

import argparse
import errno
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Any, Callable


import sixlab_jit_shadow_controller as shadow
from sixlab_jit_safe_input import read_regular


EXPECTED_HOST = "124.221.116.56"
EXPECTED_USER = "ubuntu"
EXPECTED_DEDICATED_UID = 1005
HISTORY_SCHEMA = "sixlab-jit-head-history-v1"
MAX_COMMAND_OUTPUT = 8 * 1024 * 1024
MAX_HISTORY_BYTES = 128 * 1024
MAX_HOST_CLOCK_LEAD_SECONDS = 5
RUNNER_PATTERN = re.compile(
    r"^sixlab-pr(?P<pr>[1-9][0-9]*)-"
    r"(?P<head>[0-9a-f]{5})r(?P<attempt>[1-9][0-9]*)-"
    r"(?P<slot>[0-9]{2})$"
)
SLOT_FAMILIES = {
    "01": "spa-detect",
    "02": "backend-detect",
    "03": "spa-tests",
    "04": "spa-tests",
    "05": "backend-tests",
    "06": "backend-unit",
    "07": "spa-checks",
}
HOST_PROBE_KEYS = {
    "schema",
    "observed_at",
    "hostname",
    "global_lock_held",
    "active_services",
    "service_details",
    "dedicated_process_count",
    "run_directories",
    "mounts",
    "egress_checked",
    "egress_rules",
    "user_manager_active",
    "load5",
    "root_free_bytes",
    "memory_available_bytes",
    "swap_free_bytes",
    "receipt_file",
}
HOST_RUNTIME_IDENTITY_KEYS = {
    "hostname",
    "global_lock_held",
    "active_services",
    "service_details",
    "dedicated_process_count",
    "run_directories",
    "mounts",
    "egress_checked",
    "egress_rules",
    "user_manager_active",
    "receipt_file",
}
WORKFLOW_PROFILES = {
    "spa": {
        "id": 279235114,
        "name": "test",
        "path": ".github/workflows/test.yml",
        "families": frozenset({"spa-detect", "spa-tests", "spa-checks"}),
    },
    "backend": {
        "id": 301447960,
        "name": "test-backend",
        "path": ".github/workflows/test-backend.yml",
        "families": frozenset({"backend-detect", "backend-tests", "backend-unit"}),
    },
}


REMOTE_PROBE = r'''import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time


DEDICATED_UID = 1005
TOOL_PATHS = {
    "systemctl": "/usr/bin/systemctl", "sudo": "/usr/bin/sudo",
    "nft": "/usr/sbin/nft", "iptables-save": "/usr/sbin/iptables-save",
}
COMMAND_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
PROBE_DEADLINE = time.monotonic() + 15
COMMAND_OUTPUT_LIMIT = 8 * 1024 * 1024


def trusted_tool(name):
    if name not in TOOL_PATHS:
        raise RuntimeError("unapproved probe tool")

    def check(path, depth=0):
        if depth > 64 or not path.is_absolute() or ".." in path.parts:
            raise RuntimeError("unsafe probe tool path")
        if path != path.parent:
            check(path.parent, depth + 1)
        metadata = path.lstat()
        if metadata.st_uid != 0:
            raise RuntimeError("probe tool path is not root-owned")
        if stat.S_ISLNK(metadata.st_mode):
            target = Path(os.readlink(path))
            if not target.is_absolute():
                target = path.parent / target
            # Normalize root-owned distribution links such as alternatives.
            target = Path(os.path.abspath(target))
            check(target, depth + 1)
        elif metadata.st_mode & 0o022:
            raise RuntimeError("probe tool path is writable")

    path = Path(TOOL_PATHS[name])
    check(path)
    resolved = path.resolve(strict=True)
    check(resolved)
    metadata = resolved.lstat()
    if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & stat.S_IXUSR:
        raise RuntimeError("probe tool is not an executable regular file")
    return str(resolved)


def command(arguments):
    arguments = list(arguments)
    name = arguments[0]
    arguments[0] = trusted_tool(name)
    if name == "sudo":
        if len(arguments) < 3 or arguments[1] != "-n" or arguments[2] not in {"nft", "iptables-save"}:
            raise RuntimeError("unapproved nested probe tool")
        arguments[2] = trusted_tool(arguments[2])
    remaining = PROBE_DEADLINE - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("probe command deadline exceeded")
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=COMMAND_ENV, start_new_session=True)
    selector = selectors.DefaultSelector()
    output = bytearray()
    total = 0
    killed = False
    try:
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while True:
            if time.monotonic() >= PROBE_DEADLINE:
                raise RuntimeError("probe command deadline exceeded")
            exited = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if exited is not None and not killed:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                killed = True
            if killed and not selector.get_map():
                break
            for item, _ in selector.select(min(0.05, max(0, PROBE_DEADLINE - time.monotonic()))):
                try:
                    chunk = os.read(item.fd, min(65536, COMMAND_OUTPUT_LIMIT - total + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(item.fileobj)
                    continue
                total += len(chunk)
                if total > COMMAND_OUTPUT_LIMIT:
                    raise RuntimeError("probe command output exceeds limit")
                if item.fileobj is process.stdout:
                    output.extend(chunk)
        return process.wait(timeout=1), output.decode("utf-8")
    finally:
        if not killed:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=1)
        selector.close()
        process.stdout.close()
        process.stderr.close()


def systemd_services():
    code, output = command([
        "systemctl", "list-units", "--all", "--type=service",
        "--no-legend", "sixlab-pr*",
    ])
    if code != 0:
        raise RuntimeError("systemd service enumeration failed")
    names = []
    for line in output.splitlines():
        tokens = line.split()
        match = next((token for token in tokens if token.endswith(".service")), None)
        if match is not None:
            names.append(match)
    details = []
    for name in sorted(set(names)):
        code, raw = command([
            "systemctl", "show", name, "--no-pager",
            "-p", "ActiveState", "-p", "SubState", "-p", "MainPID",
            "-p", "ControlGroup",
        ])
        if code != 0:
            raise RuntimeError("systemd service readback failed")
        values = {}
        for line in raw.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
        control_group = values.get("ControlGroup", "")
        pids = []
        if control_group.startswith("/"):
            process_file = Path("/sys/fs/cgroup" + control_group) / "cgroup.procs"
            if process_file.is_file():
                pids = sorted({
                    int(line) for line in process_file.read_text().splitlines()
                    if line.isdigit()
                })
        uids = []
        dedicated_pids = []
        for pid in pids:
            try:
                uid = os.stat(f"/proc/{pid}").st_uid
                uids.append(uid)
                if uid == DEDICATED_UID:
                    dedicated_pids.append(pid)
            except FileNotFoundError:
                pass
        details.append({
            "name": name,
            "active_state": values.get("ActiveState", "unknown"),
            "sub_state": values.get("SubState", "unknown"),
            "main_pid": int(values.get("MainPID", "0") or "0"),
            "control_group": control_group,
            "pids": pids,
            "uids": sorted(set(uids)),
            "dedicated_pids": sorted(dedicated_pids),
        })
    return details


def lock_held(path):
    target = Path(path)
    if not target.exists():
        return False
    metadata = target.stat()
    identity = f"{os.major(metadata.st_dev):02x}:{os.minor(metadata.st_dev):02x}:{metadata.st_ino}"
    for line in Path("/proc/locks").read_text().splitlines():
        fields = line.split()
        if len(fields) >= 6 and fields[5].lower() == identity.lower():
            return True
    return False


def memory_values():
    values = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, raw = line.split(":", 1)
        amount = raw.strip().split()[0]
        if amount.isdigit():
            values[key] = int(amount) * 1024
    return values


def uid_process_ids(uid):
    process_ids = []
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            if path.stat().st_uid == uid:
                process_ids.append(int(path.name))
        except FileNotFoundError:
            pass
    return sorted(process_ids)


def mount_targets():
    targets = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) > 4 and fields[4].startswith("/run/sj"):
            targets.append(fields[4])
    return sorted(set(targets))


def egress_tables():
    nft_code, nft_output = command(["sudo", "-n", "nft", "list", "tables"])
    iptables_code, iptables_output = command(["sudo", "-n", "iptables-save"])
    if nft_code != 0 or iptables_code != 0:
        return False, []
    rows = []
    tables = []
    for line in nft_output.splitlines():
        value = line.strip()
        if value.startswith("table ") and (
            "sixlab" in value
            or "pr" in value
            or re.fullmatch(r"table (?:inet|ip|ip6) s[1-9][0-9]{3,}(?:pc[0-9]+|[0-9]+)", value)
        ):
            fields = value.split()
            if len(fields) != 3:
                return False, []
            tables.append((fields[1], fields[2]))
    for family, name in tables:
        table_code, table_output = command(["sudo", "-n", "nft", "list", "table", family, name])
        if table_code != 0:
            return False, []
        for line in table_output.splitlines():
            value = line.strip()
            if value:
                rows.append(f"nft:{family}:{name}:{value}")
    for line in iptables_output.splitlines():
        value = line.strip()
        if "sixlab-pr" in value or "SLPR" in value or "SLPD" in value:
            rows.append(f"iptables:{value}")
    return True, rows


def receipt_file(path):
    if path == "-":
        return None
    prefix = "/var/lib/sixlab-ephemeral-v1/receipts/"
    if not path.startswith(prefix) or "/" in path[len(prefix):]:
        raise RuntimeError("receipt path is outside the fixed directory")
    import stat
    current = Path(path)
    while True:
        metadata = current.lstat()
        if (metadata.st_uid != 0 or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_mode & 0o022):
            raise RuntimeError("receipt ancestry is not root-safe")
        if current == current.parent:
            break
        current = current.parent
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        listed = Path(path).lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_dev != listed.st_dev
                or metadata.st_ino != listed.st_ino):
            raise RuntimeError("receipt is not a regular file")
        mode = stat.S_IMODE(metadata.st_mode)
        if metadata.st_uid != 0 or mode not in (0o400, 0o444):
            raise RuntimeError("receipt ownership or permissions are invalid")
        raw = b""
        while True:
            chunk = os.read(descriptor, 4097 - len(raw))
            if not chunk:
                break
            raw += chunk
            if len(raw) > 4096:
                raise RuntimeError("receipt is too large")
    finally:
        os.close(descriptor)
    return {
        "path": path,
        "mode": mode,
        "uid": metadata.st_uid,
        "text": raw.decode("utf-8"),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


services = systemd_services()
active = [
    row["name"] for row in services
    if row["active_state"] == "active"
]
dedicated_processes = uid_process_ids(DEDICATED_UID)
user_code, user_output = command([
    "systemctl", "is-active", f"user@{DEDICATED_UID}.service",
])
user_manager_active = user_code == 0 and user_output.strip() == "active"

memory = memory_values()
disk = os.statvfs("/")
egress_checked, egress = egress_tables()
payload = {
    "schema": "sixlab-jit-host-probe-v1",
    "observed_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "hostname": os.uname().nodename,
    "global_lock_held": lock_held("/run/lock/sixlab-pr-ephemeral-one-job.lock"),
    "active_services": sorted(active),
    "service_details": services,
    "dedicated_process_count": len(dedicated_processes),
    "run_directories": sorted(str(path) for path in Path("/run").glob("sj*") if path.is_dir()),
    "mounts": mount_targets(),
    "egress_checked": egress_checked,
    "egress_rules": egress,
    "user_manager_active": user_manager_active,
    "load5": float(os.getloadavg()[1]),
    "root_free_bytes": disk.f_bavail * disk.f_frsize,
    "memory_available_bytes": memory.get("MemAvailable", 0),
    "swap_free_bytes": memory.get("SwapFree", 0),
    "receipt_file": receipt_file(sys.argv[1] if len(sys.argv) > 1 else "-"),
}
print(json.dumps(payload, separators=(",", ":"), sort_keys=True))
'''


class CollectorError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _latest_observed_at(*values: object) -> str:
    parsed: list[datetime] = []
    for value in values:
        if not isinstance(value, str) or not value.endswith("Z"):
            raise CollectorError("observation timestamp is invalid")
        try:
            instant = datetime.fromisoformat(value[:-1] + "+00:00")
        except ValueError as error:
            raise CollectorError("observation timestamp is invalid") from error
        if instant.tzinfo != timezone.utc:
            raise CollectorError("observation timestamp is not UTC")
        parsed.append(instant)
    return max(parsed).strftime("%Y-%m-%dT%H:%M:%SZ")


def _trusted_snapshot_observed_at(local_value: object, host_value: object) -> str:
    local = _latest_observed_at(local_value)
    host = _latest_observed_at(host_value)
    local_instant = datetime.fromisoformat(local[:-1] + "+00:00")
    host_instant = datetime.fromisoformat(host[:-1] + "+00:00")
    if (host_instant - local_instant).total_seconds() > MAX_HOST_CLOCK_LEAD_SECONDS:
        raise CollectorError("host observation clock is ahead of the trusted local clock")
    return local


def _trusted_executable(name: str) -> str:
    raw = shutil.which(name)
    if raw is None:
        raise CollectorError(f"{name} is unavailable")
    resolved = Path(raw).resolve(strict=True)
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise CollectorError(f"{name} is not a regular file")
    if metadata.st_uid not in (0, os.getuid()) or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise CollectorError(f"{name} is not trusted")
    if not os.access(resolved, os.X_OK):
        raise CollectorError(f"{name} is not executable")
    return str(resolved)


def _private_key(path: Path) -> Path:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise CollectorError("SSH key is missing") from error
    except OSError as error:
        raise CollectorError("SSH key metadata is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise CollectorError("SSH key must be a regular non-symlink file")
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) not in (0o400, 0o600):
        raise CollectorError("SSH key ownership or permissions are unsafe")
    return path.resolve()


def _json_command(
    arguments: list[str],
    *,
    label: str = "read-only collector command",
    input_text: str | None = None,
    timeout: int = 30,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    try:
        completed = runner(
            arguments,
            input=input_text,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise CollectorError(f"{label} timed out") from None
    except OSError:
        raise CollectorError(f"{label} could not start") from None
    if completed.returncode != 0:
        raise CollectorError(f"{label} failed")
    if len(completed.stdout.encode("utf-8")) > MAX_COMMAND_OUTPUT:
        raise CollectorError("collector command output is too large")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise CollectorError("collector command output is not JSON") from error
    if not isinstance(payload, dict):
        raise CollectorError("collector command output is not an object")
    return payload


def _load_history(path: Path, pull_number: int) -> list[dict[str, str]]:
    try:
        content = read_regular(path, MAX_HISTORY_BYTES, uid=os.getuid(), modes=(0o400, 0o600))
    except FileNotFoundError:
        return []
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise CollectorError("head history file is unsafe") from error
        raise CollectorError("head history file metadata is unavailable") from error
    except ValueError as error:
        raise CollectorError("head history file is unsafe") from error
    try:
        raw = json.loads(content)
    except (UnicodeError, ValueError) as error:
        raise CollectorError("head history file is invalid") from error
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema", "repository", "pull_number", "observations"}
        or raw["schema"] != HISTORY_SCHEMA
        or raw["repository"] != shadow.EXPECTED_REPOSITORY
        or raw["pull_number"] != pull_number
        or not isinstance(raw["observations"], list)
        or len(raw["observations"]) > 16
    ):
        raise CollectorError("head history binding is invalid")
    observations: list[dict[str, str]] = []
    for item in raw["observations"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"observed_at", "head_sha"}
            or not isinstance(item["head_sha"], str)
            or shadow.SHA_PATTERN.fullmatch(item["head_sha"]) is None
        ):
            raise CollectorError("head history observation is invalid")
        _latest_observed_at(item["observed_at"])
        observations.append(item)
    return observations[-15:]


def _append_history(
    history: list[dict[str, str]], observed_at: str, head_sha: object,
) -> list[dict[str, str]]:
    row = {"observed_at": observed_at, "head_sha": head_sha}
    deduplicated: list[dict[str, str]] = []
    for item in [*history, row]:
        if deduplicated and deduplicated[-1].get("observed_at") == item.get("observed_at"):
            deduplicated[-1] = item
        else:
            deduplicated.append(item)
    return deduplicated[-16:]


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink():
        raise CollectorError("output directory must not be a symlink")
    descriptor, temporary = tempfile.mkstemp(prefix=".sixlab-jit-shadow.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = -1
            json.dump(payload, output, separators=(",", ":"), sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _exact_jobs(payload: dict[str, Any], run_id: int, attempt: int, head_sha: str) -> list[dict[str, Any]]:
    jobs = payload.get("jobs")
    if not isinstance(jobs, list) or payload.get("total_count") != len(jobs) or len(jobs) > shadow.MAX_JOBS:
        raise CollectorError("workflow job enumeration is incomplete")
    exact: list[dict[str, Any]] = []
    prefix = f"{shadow.EXACT_LABEL_PREFIX}{head_sha}-"
    for item in jobs:
        if not isinstance(item, dict):
            raise CollectorError("workflow job record is invalid")
        labels = item.get("labels")
        if not isinstance(labels, list) or any(not isinstance(label, str) for label in labels):
            raise CollectorError("workflow job labels are invalid")
        exact_rows = [label for label in labels if label.startswith(shadow.EXACT_LABEL_PREFIX)]
        if not exact_rows:
            continue
        if len(labels) != 1 or len(exact_rows) != 1 or not exact_rows[0].startswith(prefix):
            raise CollectorError("workflow job exact label is not current-head bound")
        family = exact_rows[0][len(prefix):]
        if family not in shadow.ALLOWED_FAMILIES:
            raise CollectorError("workflow job family is not allowed")
        row = {
            "id": item.get("id"),
            "run_id": item.get("run_id"),
            "run_attempt": item.get("run_attempt"),
            "name": item.get("name"),
            "family": family,
            "status": item.get("status"),
            "conclusion": item.get("conclusion"),
            "labels": labels,
            "runner_id": item.get("runner_id") or None,
            "runner_name": item.get("runner_name") or None,
            "created_at": item.get("created_at"),
        }
        if row["run_id"] != run_id or type(row["run_attempt"]) is not int or row["run_attempt"] > attempt:
            raise CollectorError("workflow job run binding is invalid")
        exact.append(row)
    if not exact:
        raise CollectorError("no exact JIT jobs were observed")
    return exact


def _jit_inventory(payload: dict[str, Any]) -> list[dict[str, Any]]:
    runners = payload.get("runners")
    if not isinstance(runners, list) or payload.get("total_count") != len(runners):
        raise CollectorError("Runner enumeration is incomplete")
    inventory = []
    for runner in runners:
        if not isinstance(runner, dict):
            raise CollectorError("Runner record is invalid")
        labels = runner.get("labels")
        if not isinstance(labels, list):
            raise CollectorError("Runner labels are invalid")
        names = []
        for label in labels:
            if isinstance(label, dict):
                name = label.get("name")
            else:
                name = label
            if not isinstance(name, str):
                raise CollectorError("Runner label is invalid")
            names.append(name)
        runner_name = runner.get("name")
        carries_exact_label = any(
            name.startswith(shadow.EXACT_LABEL_PREFIX) for name in names
        )
        if carries_exact_label and not isinstance(runner_name, str):
            raise CollectorError("exact-label Runner name is invalid")
        if not carries_exact_label and not (
            isinstance(runner_name, str) and runner_name.startswith("sixlab-pr")
        ):
            continue
        inventory.append({
            "id": runner.get("id"),
            "name": runner_name,
            "status": runner.get("status"),
            "busy": runner.get("busy"),
            "labels": names,
        })
    return sorted(inventory, key=lambda item: json.dumps(item, sort_keys=True))


def _validate_runner_inventory_readback(
    initial: dict[str, Any], final: dict[str, Any],
) -> list[dict[str, Any]]:
    initial_inventory = _jit_inventory(initial)
    final_inventory = _jit_inventory(final)
    if initial_inventory != final_inventory:
        raise CollectorError("JIT Runner inventory changed during evidence collection")
    return final_inventory


def _validate_host_probe(payload: object) -> dict[str, Any]:
    if (
        not isinstance(payload, dict)
        or set(payload) != HOST_PROBE_KEYS
        or payload.get("schema") != "sixlab-jit-host-probe-v1"
        or payload.get("hostname") != "VM-0-10-ubuntu"
        or payload.get("egress_checked") is not True
        or not isinstance(payload.get("service_details"), list)
    ):
        raise CollectorError("host probe coverage is incomplete")
    _latest_observed_at(payload.get("observed_at"))
    return payload


def _validate_host_readback(
    initial: object, final: object,
) -> dict[str, Any]:
    initial_probe = _validate_host_probe(initial)
    final_probe = _validate_host_probe(final)
    if _latest_observed_at(
        initial_probe["observed_at"], final_probe["observed_at"],
    ) != final_probe["observed_at"]:
        raise CollectorError("host probe readback time moved backwards")
    if any(
        initial_probe[key] != final_probe[key]
        for key in HOST_RUNTIME_IDENTITY_KEYS
    ):
        raise CollectorError("host runtime changed during evidence collection")
    return final_probe


def _runner_allocation(
    job: dict[str, Any], *, runner_id: object, runner_name: object,
    pull_number: int, run_id: int, attempt: int, run_head: str,
) -> dict[str, Any]:
    match = RUNNER_PATTERN.fullmatch(runner_name if isinstance(runner_name, str) else "")
    if match is None:
        raise CollectorError("active or terminal Runner name is not canonical")
    if (
        int(match.group("pr")) != pull_number
        or match.group("head") != run_head[:5]
        or int(match.group("attempt")) != attempt
    ):
        raise CollectorError("active or terminal Runner name binding drifted")
    if SLOT_FAMILIES.get(match.group("slot")) != job["family"]:
        raise CollectorError("active or terminal Runner slot and family drifted")
    service_name = (
        f"sixlab-pr{pull_number}-{run_head[:5]}r{attempt}-"
        f"ephemeral-{match.group('slot')}.service"
    )
    return {
        "repository": shadow.EXPECTED_REPOSITORY,
        "pull_number": pull_number,
        "head_sha": run_head,
        "run_id": run_id,
        "run_attempt": attempt,
        "job_id": job["id"],
        "family": job["family"],
        "exact_label": shadow.exact_label(run_head, job["family"]),
        "runner_id": runner_id,
        "runner_name": runner_name,
        "service_name": service_name,
    }


def _job_allocation(
    job: dict[str, Any], *, pull_number: int, run_id: int, attempt: int, run_head: str,
) -> dict[str, Any]:
    return _runner_allocation(
        job,
        runner_id=job["runner_id"],
        runner_name=job["runner_name"],
        pull_number=pull_number,
        run_id=run_id,
        attempt=attempt,
        run_head=run_head,
    )


def _awaiting_allocation(
    jobs: list[dict[str, Any]], inventory: list[dict[str, Any]], *,
    pull_number: int, run_id: int, attempt: int, run_head: str,
) -> dict[str, Any] | None:
    queued = [
        job for job in jobs
        if job["run_attempt"] == attempt and job["status"] == "queued"
    ]
    queued_labels = {
        shadow.exact_label(run_head, job["family"]) for job in queued
    }
    candidates: list[dict[str, Any]] = []
    for runner in inventory:
        runner_labels = runner.get("labels")
        if not isinstance(runner_labels, list):
            raise CollectorError("awaiting Runner labels are invalid")
        exact_rows = sorted(set(runner_labels) & queued_labels)
        if not exact_rows:
            continue
        if len(exact_rows) != 1:
            raise CollectorError("awaiting Runner has multiple current exact labels")
        if runner.get("status") != "online" or runner.get("busy") is not False:
            raise CollectorError("awaiting Runner is not online and idle")
        runner_name = runner.get("name")
        match = RUNNER_PATTERN.fullmatch(runner_name if isinstance(runner_name, str) else "")
        if match is None:
            raise CollectorError("awaiting Runner name is not canonical")
        if (
            int(match.group("pr")) != pull_number
            or match.group("head") != run_head[:5]
            or int(match.group("attempt")) != attempt
        ):
            raise CollectorError("awaiting Runner name binding drifted")
        family = SLOT_FAMILIES.get(match.group("slot"))
        if family is None or exact_rows[0] != shadow.exact_label(run_head, family):
            raise CollectorError("awaiting Runner slot and label drifted")
        eligible = [job for job in queued if job["family"] == family]
        if not eligible:
            raise CollectorError("awaiting Runner has no eligible queued job")
        if len(eligible) > 1 and family != "spa-tests":
            raise CollectorError("awaiting Runner matches multiple non-matrix jobs")
        selected = sorted(eligible, key=lambda job: (job["created_at"], job["id"]))[0]
        candidates.append(_runner_allocation(
            selected,
            runner_id=runner.get("id"),
            runner_name=runner_name,
            pull_number=pull_number,
            run_id=run_id,
            attempt=attempt,
            run_head=run_head,
        ))
    if len(candidates) > 1:
        raise CollectorError("multiple awaiting JIT allocations were observed")
    return candidates[0] if candidates else None


def _validate_run_pull(run: dict[str, Any], pull_number: int, run_head: str) -> None:
    rows = run.get("pull_requests")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise CollectorError("workflow run pull identity is incomplete or ambiguous")
    row = rows[0]
    head = row.get("head")
    base = row.get("base")
    if (
        row.get("number") != pull_number
        or not isinstance(head, dict)
        or head.get("sha") != run_head
        or not isinstance(base, dict)
        or base.get("ref") != shadow.EXPECTED_BASE
    ):
        raise CollectorError("workflow run pull identity drifted")


def _pull_revision(pull: object, pull_number: int) -> dict[str, Any]:
    if not isinstance(pull, dict) or pull.get("number") != pull_number:
        raise CollectorError("pull readback identity is invalid")
    base = pull.get("base")
    head = pull.get("head")
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise CollectorError("pull readback revision is incomplete")
    base_sha = base.get("sha")
    head_sha = head.get("sha")
    if (
        pull.get("state") not in {"open", "closed"}
        or type(pull.get("draft")) is not bool
        or not isinstance(base.get("ref"), str)
        or not base["ref"]
        or not isinstance(base_sha, str)
        or shadow.SHA_PATTERN.fullmatch(base_sha) is None
        or not isinstance(head_sha, str)
        or shadow.SHA_PATTERN.fullmatch(head_sha) is None
    ):
        raise CollectorError("pull readback revision is invalid")
    return {
        "number": pull_number,
        "state": pull["state"],
        "draft": pull["draft"],
        "base_ref": base["ref"],
        "base_sha": base_sha,
        "head_sha": head_sha,
    }


def _validate_pull_readback(initial: object, final: object, pull_number: int) -> None:
    if _pull_revision(initial, pull_number) != _pull_revision(final, pull_number):
        raise CollectorError("pull changed during evidence collection")


def _validate_run_jobs_readback(
    initial_run: object,
    final_run: object,
    initial_jobs: object,
    final_jobs: object,
) -> None:
    if not isinstance(initial_run, dict) or not isinstance(final_run, dict):
        raise CollectorError("workflow run readback is invalid")
    run_fields = {
        "id", "workflow_id", "name", "path", "event", "head_sha",
        "run_attempt", "status", "conclusion", "repository", "pull_requests",
    }
    initial_view = {key: initial_run.get(key) for key in run_fields}
    final_view = {key: final_run.get(key) for key in run_fields}
    if initial_view != final_view:
        raise CollectorError("workflow run changed during evidence collection")
    if not isinstance(initial_jobs, dict) or not isinstance(final_jobs, dict):
        raise CollectorError("workflow jobs readback is invalid")
    if initial_jobs != final_jobs:
        raise CollectorError("workflow jobs changed during evidence collection")


def _validate_run_workflow(run: dict[str, Any], jobs: list[dict[str, Any]]) -> None:
    families = {job["family"] for job in jobs}
    matches = [
        profile for profile in WORKFLOW_PROFILES.values()
        if families and families <= profile["families"]
    ]
    if len(matches) != 1:
        raise CollectorError("workflow run job families are ambiguous")
    expected = matches[0]
    if (
        run.get("workflow_id") != expected["id"]
        or run.get("name") != expected["name"]
        or run.get("path") != expected["path"]
    ):
        raise CollectorError("workflow run identity drifted")


def _current_run_ids(
    payload: dict[str, Any], pull_number: int, head_sha: str,
) -> list[int]:
    rows = payload.get("workflow_runs")
    if (
        not isinstance(rows, list)
        or payload.get("total_count") != len(rows)
        or len(rows) > shadow.MAX_RUNTIME_ROWS
    ):
        raise CollectorError("current-head run enumeration is incomplete")
    expected_profiles = {
        (profile["id"], profile["name"], profile["path"]): profile
        for profile in WORKFLOW_PROFILES.values()
    }
    found: dict[tuple[object, object, object], int] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise CollectorError("current-head run record is invalid")
        repository = row.get("repository")
        if (
            not isinstance(repository, dict)
            or repository.get("full_name") != shadow.EXPECTED_REPOSITORY
            or row.get("event") != "pull_request"
            or row.get("head_sha") != head_sha
        ):
            raise CollectorError("current-head run enumeration drifted")
        profile_key = (row.get("workflow_id"), row.get("name"), row.get("path"))
        if profile_key not in expected_profiles:
            continue
        pull_rows = row.get("pull_requests")
        if (
            not isinstance(pull_rows, list)
            or len(pull_rows) != 1
            or not isinstance(pull_rows[0], dict)
        ):
            raise CollectorError("current-head run pull identity is incomplete")
        if pull_rows[0].get("number") != pull_number:
            continue
        _validate_run_pull(row, pull_number, head_sha)
        run_id = row.get("id")
        if type(run_id) is not int or run_id <= 0 or profile_key in found:
            raise CollectorError("current-head workflow run identity is duplicated or invalid")
        found[profile_key] = run_id
    if set(found) != set(expected_profiles):
        raise CollectorError("canonical current-head workflow run set is incomplete")
    run_ids = sorted(found.values())
    if len(set(run_ids)) != len(run_ids):
        raise CollectorError("canonical current-head run IDs are duplicated")
    return run_ids


def _validate_service_binding(
    service_details: object, allocation: dict[str, Any], *, terminal: bool,
) -> None:
    if terminal:
        return
    if not isinstance(service_details, list):
        raise CollectorError("service detail inventory is invalid")
    rows = [
        row for row in service_details
        if isinstance(row, dict) and row.get("name") == allocation["service_name"]
    ]
    if len(service_details) != 1 or len(rows) != 1:
        raise CollectorError("allocated service identity is incomplete")
    row = rows[0]
    if (
        row.get("active_state") != "active"
        or type(row.get("main_pid")) is not int
        or row["main_pid"] <= 0
        or not isinstance(row.get("control_group"), str)
        or not row["control_group"].startswith("/")
        or not isinstance(row.get("pids"), list)
        or not row["pids"]
        or not isinstance(row.get("uids"), list)
        or EXPECTED_DEDICATED_UID not in row["uids"]
    ):
        raise CollectorError("allocated service cgroup binding is incomplete")


def _receipt_path(allocation: dict[str, Any]) -> str:
    match = RUNNER_PATTERN.fullmatch(allocation["runner_name"])
    assert match is not None
    return (
        "/var/lib/sixlab-ephemeral-v1/receipts/"
        f"sixlab-pr{allocation['pull_number']}-{allocation['head_sha'][:5]}"
        f"r{allocation['run_attempt']}-ephemeral-{match.group('slot')}.receipt"
    )


def _normalized_receipt(
    value: object, allocation: dict[str, Any], expected_path: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "path", "mode", "uid", "text", "sha256",
    }:
        raise CollectorError("terminal host receipt is missing")
    if value["path"] != expected_path or value["mode"] not in (0o400, 0o444) or value["uid"] != 0:
        raise CollectorError("terminal host receipt metadata is invalid")
    raw = value["text"]
    digest = value["sha256"]
    if not isinstance(raw, str) or not isinstance(digest, str):
        raise CollectorError("terminal host receipt payload is invalid")
    if hashlib.sha256(raw.encode("utf-8")).hexdigest() != digest:
        raise CollectorError("terminal host receipt digest is invalid")
    fields: dict[str, str] = {}
    for token in raw.strip().split():
        if "=" not in token:
            raise CollectorError("terminal host receipt token is invalid")
        key, item = token.split("=", 1)
        if key in fields:
            raise CollectorError("terminal host receipt contains a duplicate field")
        fields[key] = item
    if set(fields) != {"slot", "runner", "expected_head", "label", "exit", "finished"}:
        raise CollectorError("terminal host receipt fields are not canonical")
    match = RUNNER_PATTERN.fullmatch(allocation["runner_name"])
    assert match is not None
    if (
        fields["slot"] != match.group("slot")
        or fields["runner"] != allocation["runner_name"]
        or fields["expected_head"] != allocation["head_sha"]
        or fields["label"] != allocation["exact_label"]
        or not fields["exit"].isdigit()
    ):
        raise CollectorError("terminal host receipt binding drifted")
    try:
        finished = datetime.fromisoformat(fields["finished"])
    except ValueError as error:
        raise CollectorError("terminal host receipt time is invalid") from error
    if finished.tzinfo is None:
        raise CollectorError("terminal host receipt time lacks timezone")
    return {
        **allocation,
        "schema": shadow.RECEIPT_SCHEMA,
        "exit_code": int(fields["exit"]),
        "finished_at": finished.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_receipt_sha256": digest,
    }


def build_snapshot(
    *,
    pull: dict[str, Any],
    run: dict[str, Any],
    jobs_payload: dict[str, Any],
    runners_payload: dict[str, Any],
    host_probe: dict[str, Any],
    run_inventory_ids: list[int],
    observations: list[dict[str, str]],
    observed_at: str,
    terminal_job_id: int | None = None,
) -> dict[str, Any]:
    base = pull.get("base")
    head = pull.get("head")
    repository = run.get("repository")
    if not isinstance(base, dict) or not isinstance(head, dict) or not isinstance(repository, dict):
        raise CollectorError("PR or run revision binding is incomplete")
    if repository.get("full_name") != shadow.EXPECTED_REPOSITORY or run.get("event") != "pull_request":
        raise CollectorError("workflow run identity is invalid")
    pull_number = pull.get("number")
    run_id = run.get("id")
    attempt = run.get("run_attempt")
    run_head = run.get("head_sha")
    if type(pull_number) is not int or type(run_id) is not int or type(attempt) is not int:
        raise CollectorError("PR or run numeric binding is invalid")
    if not isinstance(run_head, str) or shadow.SHA_PATTERN.fullmatch(run_head) is None:
        raise CollectorError("workflow run head is invalid")
    _validate_run_pull(run, pull_number, run_head)
    jobs = _exact_jobs(jobs_payload, run_id, attempt, run_head)
    _validate_run_workflow(run, jobs)
    inventory = _jit_inventory(runners_payload)
    host_probe = _validate_host_probe(host_probe)

    active_jobs = [
        job for job in jobs
        if job["run_attempt"] == attempt
        and job["status"] == "in_progress"
        and job["runner_id"] is not None
        and isinstance(job["runner_name"], str)
        and job["runner_name"].startswith("sixlab-pr")
    ]
    if len(active_jobs) > 1:
        raise CollectorError("multiple active JIT jobs violate one-job admission")
    allocation = None
    terminal = None
    if terminal_job_id is not None:
        rows = [job for job in jobs if job["id"] == terminal_job_id]
        if len(rows) != 1 or rows[0]["status"] != "completed":
            raise CollectorError("requested terminal job is not completed")
        terminal = rows[0]
        allocation = _job_allocation(
            terminal, pull_number=pull_number, run_id=run_id,
            attempt=attempt, run_head=run_head,
        )
    elif active_jobs:
        allocation = _job_allocation(
            active_jobs[0], pull_number=pull_number, run_id=run_id,
            attempt=attempt, run_head=run_head,
        )
    else:
        allocation = _awaiting_allocation(
            jobs,
            inventory,
            pull_number=pull_number,
            run_id=run_id,
            attempt=attempt,
            run_head=run_head,
        )

    if allocation is not None:
        _validate_service_binding(
            host_probe.get("service_details"),
            allocation,
            terminal=terminal is not None,
        )

    host = {
        key: host_probe[key]
        for key in (
            "observed_at",
            "global_lock_held",
            "active_services",
            "service_details",
            "dedicated_process_count",
            "run_directories",
            "mounts",
            "egress_rules",
            "user_manager_active",
            "load5",
            "root_free_bytes",
            "memory_available_bytes",
            "swap_free_bytes",
        )
    }
    host["runner_inventory"] = inventory
    receipt = None
    if terminal is not None and allocation is not None:
        receipt = _normalized_receipt(
            host_probe.get("receipt_file"), allocation, _receipt_path(allocation)
        )
    return {
        "schema": shadow.SCHEMA,
        "observed_at": observed_at,
        "pull": {
            "number": pull_number,
            "state": pull.get("state"),
            "draft": pull.get("draft"),
            "base_ref": base.get("ref"),
            "head_sha": head.get("sha"),
        },
        "head_observations": observations,
        "run_inventory": run_inventory_ids,
        "run": {
            "id": run_id,
            "attempt": attempt,
            "head_sha": run_head,
            "status": run.get("status"),
        },
        "jobs": jobs,
        "host": host,
        "allocation": allocation,
        "receipt": receipt,
    }


def collect_live(
    *,
    pull_number: int,
    run_id: int,
    ssh_key: Path,
    history_file: Path,
    terminal_job_id: int | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    # This entry point used to let an operator nominate one PR and one run.
    # It is deliberately sealed: a one-run observation cannot establish the
    # all-open-PR inventory required by the serial scheduler.  Keep the name
    # only for callers to receive an explicit fail-closed migration error.
    raise CollectorError(
        "legacy single-PR/single-run collection is retired; use the paginated "
        "all-open-PR correlation -> v2 cycle -> bridge path"
    )
    gh = _trusted_executable("gh")
    ssh = _trusted_executable("ssh")
    key = _private_key(ssh_key)
    repository_path = f"repos/{shadow.EXPECTED_REPOSITORY}"
    initial_pull = _json_command(
        [gh, "api", "--hostname", "github.com", f"{repository_path}/pulls/{pull_number}"],
        label="GitHub pull read", runner=runner,
    )
    run = _json_command(
        [gh, "api", "--hostname", "github.com", f"{repository_path}/actions/runs/{run_id}"],
        label="GitHub run read", runner=runner,
    )
    jobs = _json_command([
        gh, "api", "--hostname", "github.com", f"{repository_path}/actions/runs/{run_id}/jobs?filter=all&per_page=100",
    ], label="GitHub jobs read", runner=runner)
    runners = _json_command([
        gh, "api", "--hostname", "github.com", f"{repository_path}/actions/runners?per_page=100",
    ], label="GitHub Runner inventory read", runner=runner)
    initial_head = initial_pull.get("head", {}).get("sha")
    if not isinstance(initial_head, str) or shadow.SHA_PATTERN.fullmatch(initial_head) is None:
        raise CollectorError("initial pull head is invalid")
    run_inventory_payload = _json_command([
        gh, "api", "--hostname", "github.com",
        f"{repository_path}/actions/runs?event=pull_request&head_sha={initial_head}&per_page=100",
    ], label="GitHub current-head run inventory read", runner=runner)
    receipt_path = "-"
    if terminal_job_id is not None:
        run_head = run.get("head_sha")
        attempt = run.get("run_attempt")
        if not isinstance(run_head, str) or type(attempt) is not int:
            raise CollectorError("terminal run binding is invalid")
        exact = _exact_jobs(jobs, run_id, attempt, run_head)
        rows = [job for job in exact if job["id"] == terminal_job_id]
        if len(rows) != 1 or rows[0]["status"] != "completed":
            raise CollectorError("requested terminal job is not completed")
        terminal_allocation = _job_allocation(
            rows[0], pull_number=pull_number, run_id=run_id,
            attempt=attempt, run_head=run_head,
        )
        receipt_path = _receipt_path(terminal_allocation)
    host = _json_command([
        ssh,
        "-i", str(key),
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        f"{EXPECTED_USER}@{EXPECTED_HOST}",
        "/usr/bin/python3", "-", receipt_path,
    ], label="JIT host probe", input_text=REMOTE_PROBE, timeout=40, runner=runner)
    final_runners = _json_command([
        gh, "api", "--hostname", "github.com", f"{repository_path}/actions/runners?per_page=100",
    ], label="GitHub Runner inventory readback", runner=runner)
    final_run_inventory_payload = _json_command([
        gh, "api", "--hostname", "github.com",
        f"{repository_path}/actions/runs?event=pull_request&head_sha={initial_head}&per_page=100",
    ], label="GitHub current-head run inventory readback", runner=runner)
    final_run = _json_command(
        [gh, "api", "--hostname", "github.com", f"{repository_path}/actions/runs/{run_id}"],
        label="GitHub run readback", runner=runner,
    )
    final_jobs = _json_command([
        gh, "api", "--hostname", "github.com", f"{repository_path}/actions/runs/{run_id}/jobs?filter=all&per_page=100",
    ], label="GitHub jobs readback", runner=runner)
    final_pull = _json_command(
        [gh, "api", "--hostname", "github.com", f"{repository_path}/pulls/{pull_number}"],
        label="GitHub pull readback", runner=runner,
    )
    _validate_pull_readback(initial_pull, final_pull, pull_number)
    _validate_run_jobs_readback(run, final_run, jobs, final_jobs)
    _validate_runner_inventory_readback(runners, final_runners)
    initial_run_inventory_ids = _current_run_ids(
        run_inventory_payload, pull_number, initial_head,
    )
    run_inventory_ids = _current_run_ids(
        final_run_inventory_payload, pull_number, initial_head,
    )
    if initial_run_inventory_ids != run_inventory_ids:
        raise CollectorError("current-head run inventory changed during evidence collection")
    final_host = _json_command([
        ssh,
        "-i", str(key),
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        f"{EXPECTED_USER}@{EXPECTED_HOST}",
        "/usr/bin/python3", "-", receipt_path,
    ], label="JIT host probe readback", input_text=REMOTE_PROBE, timeout=40, runner=runner)
    final_host = _validate_host_readback(host, final_host)
    closing_runners = _json_command([
        gh, "api", "--hostname", "github.com", f"{repository_path}/actions/runners?per_page=100",
    ], label="GitHub Runner inventory closing readback", runner=runner)
    closing_run_inventory_payload = _json_command([
        gh, "api", "--hostname", "github.com",
        f"{repository_path}/actions/runs?event=pull_request&head_sha={initial_head}&per_page=100",
    ], label="GitHub current-head run inventory closing readback", runner=runner)
    closing_run = _json_command(
        [gh, "api", "--hostname", "github.com", f"{repository_path}/actions/runs/{run_id}"],
        label="GitHub run closing readback", runner=runner,
    )
    closing_jobs = _json_command([
        gh, "api", "--hostname", "github.com", f"{repository_path}/actions/runs/{run_id}/jobs?filter=all&per_page=100",
    ], label="GitHub jobs closing readback", runner=runner)
    closing_pull = _json_command(
        [gh, "api", "--hostname", "github.com", f"{repository_path}/pulls/{pull_number}"],
        label="GitHub pull closing readback", runner=runner,
    )
    _validate_pull_readback(final_pull, closing_pull, pull_number)
    _validate_run_jobs_readback(final_run, closing_run, final_jobs, closing_jobs)
    _validate_runner_inventory_readback(final_runners, closing_runners)
    closing_run_inventory_ids = _current_run_ids(
        closing_run_inventory_payload, pull_number, initial_head,
    )
    if run_inventory_ids != closing_run_inventory_ids:
        raise CollectorError("current-head run inventory changed after closing host probe")
    observed_at = _trusted_snapshot_observed_at(_utc_now(), final_host.get("observed_at"))
    history = _append_history(
        _load_history(history_file, pull_number),
        observed_at,
        closing_pull.get("head", {}).get("sha"),
    )
    snapshot = build_snapshot(
        pull=closing_pull,
        run=closing_run,
        jobs_payload=closing_jobs,
        runners_payload=closing_runners,
        host_probe=final_host,
        run_inventory_ids=run_inventory_ids,
        observations=history,
        observed_at=observed_at,
        terminal_job_id=terminal_job_id,
    )
    _atomic_json(history_file, {
        "schema": HISTORY_SCHEMA,
        "repository": shadow.EXPECTED_REPOSITORY,
        "pull_number": pull_number,
        "observations": history,
    })
    return snapshot


def _canonical_input(path: Path, label: str) -> object:
    try:
        raw = read_regular(path, 8 * 1024 * 1024)
    except (OSError, ValueError) as error:
        raise CollectorError(f"{label} is unreadable") from error
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CollectorError(f"{label} is not valid JSON") from error


def build_canonical_cycle(selections: object, evidence_by_pull: object) -> dict[str, Any]:
    """Bridge B's freshly collected correlation into the A-side v2 cycle.

    B itself enumerates every open PR and workflow immediately before this
    bridge constructs the scheduler input; caller JSON cannot substitute a
    selected PR/run or create an actuator admission.
    """
    import sixlab_jit_pr_runner_bridge as bridge

    if not isinstance(selections, dict) or not isinstance(evidence_by_pull, dict):
        raise CollectorError("canonical bridge selections or evidence are invalid")
    try:
        normalized_selections = {int(key): value for key, value in selections.items()}
        normalized_evidence = {int(key): value for key, value in evidence_by_pull.items()}
    except (TypeError, ValueError) as error:
        raise CollectorError("canonical bridge PR keys must be integers") from error
    if (
        len(normalized_selections) != len(selections)
        or len(normalized_evidence) != len(evidence_by_pull)
        or any(str(key) != raw for raw, key in ((raw, int(raw)) for raw in selections))
        or any(str(key) != raw for raw, key in ((raw, int(raw)) for raw in evidence_by_pull))
    ):
        raise CollectorError("canonical bridge PR keys must be unique decimal integers")
    try:
        return bridge.build_cycle(normalized_selections, normalized_evidence)
    except bridge.BridgeError as error:
        raise CollectorError(str(error)) from error


def main() -> int:
    parser = argparse.ArgumentParser(description="Bridge all-open-PR JIT correlation into a local v2 cycle")
    parser.add_argument("--sixlab-live-collector", type=Path,
                        help="rejected compatibility-only external collector path")
    parser.add_argument("--selections", type=Path)
    parser.add_argument("--evidence", type=Path)
    # Compatibility-only: these values are rejected before any source read.
    parser.add_argument("--pr-number", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--run-id", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--ssh-key", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--history-file", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--terminal-job-id", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        if any(value is not None for value in (
            arguments.pr_number, arguments.run_id, arguments.ssh_key,
            arguments.history_file, arguments.terminal_job_id,
        )):
            raise CollectorError("legacy single-PR/single-run CLI is retired; it cannot create a schedulable admission")
        if arguments.sixlab_live_collector is not None:
            raise CollectorError("caller-supplied SIXLAB collector path is forbidden; use the vendored provenance-pinned source")
        if any(value is None for value in (arguments.selections, arguments.evidence)):
            raise CollectorError("vendored SIXLAB collector selections and evidence are required")
        snapshot = build_canonical_cycle(
            _canonical_input(arguments.selections, "selections"),
            _canonical_input(arguments.evidence, "evidence"),
        )
        if arguments.output is not None:
            _atomic_json(arguments.output, snapshot)
        print(json.dumps(snapshot, separators=(",", ":"), sort_keys=True))
        return 0
    except (CollectorError, shadow.ShadowError, OSError) as error:
        message = str(error) if isinstance(error, (CollectorError, shadow.ShadowError)) else "collector filesystem operation failed"
        result = {
            "schema": "sixlab-jit-shadow-collector-result-v1",
            "status": "CHECK-INCOMPLETE",
            "live_mutation_allowed": False,
            "error": message,
        }
        if arguments.output is not None:
            _atomic_json(arguments.output, result)
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
