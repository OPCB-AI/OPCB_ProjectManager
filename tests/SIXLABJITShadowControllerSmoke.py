#!/usr/bin/env python3
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile


project = Path(__file__).resolve().parent.parent
source = project / "ops" / "sixlab_jit_shadow_controller.py"
spec = importlib.util.spec_from_file_location("shadow", source)
shadow = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(shadow)


HEAD = "a" * 40
OLD_HEAD = "b" * 40
LABEL = shadow.exact_label(HEAD, "spa-tests")


def job(job_id=101, attempt=4, status="queued", family="spa-tests", created="2026-09-01T00:00:00Z"):
    runner_id = None if status == "queued" else 234
    runner_name = None if status == "queued" else "sixlab-pr1173-00b2r4-03"
    return {
        "id": job_id,
        "run_id": 9001,
        "run_attempt": attempt,
        "name": "spa-tests (1)" if family == "spa-tests" else family,
        "family": family,
        "status": status,
        "conclusion": "success" if status == "completed" else None,
        "labels": [shadow.exact_label(HEAD, family)],
        "runner_id": runner_id,
        "runner_name": runner_name,
        "created_at": created,
    }


def clean_host():
    return {
        "observed_at": "2026-09-01T00:02:45Z",
        "global_lock_held": False,
        "active_services": [],
        "service_details": [],
        "dedicated_process_count": 0,
        "run_directories": [],
        "mounts": [],
        "egress_rules": [],
        "runner_inventory": [],
        "user_manager_active": False,
        "load5": 0.7,
        "root_free_bytes": 20 * 1024 * 1024 * 1024,
        "memory_available_bytes": 3 * 1024 * 1024 * 1024,
        "swap_free_bytes": 1024 * 1024 * 1024,
    }


def snapshot():
    return {
        "schema": shadow.SCHEMA,
        "observed_at": "2026-09-01T00:03:00Z",
        "pull": {
            "number": 1173,
            "state": "open",
            "draft": False,
            "base_ref": "main",
            "head_sha": HEAD,
        },
        "head_observations": [
            {"observed_at": "2026-09-01T00:00:00Z", "head_sha": HEAD},
            {"observed_at": "2026-09-01T00:01:00Z", "head_sha": HEAD},
        ],
        "run_inventory": [9001],
        "run": {"id": 9001, "attempt": 4, "head_sha": HEAD, "status": "queued"},
        "jobs": [job()],
        "host": clean_host(),
        "allocation": None,
        "receipt": None,
    }


def allocation():
    return {
        "repository": shadow.EXPECTED_REPOSITORY,
        "pull_number": 1173,
        "head_sha": HEAD,
        "run_id": 9001,
        "run_attempt": 4,
        "job_id": 101,
        "family": "spa-tests",
        "exact_label": LABEL,
        "runner_id": 234,
        "runner_name": "sixlab-pr1173-00b2r4-03",
        "service_name": "sixlab-pr1173-slot03",
    }


def receipt():
    return {
        **allocation(),
        "schema": shadow.RECEIPT_SCHEMA,
        "exit_code": 0,
        "finished_at": "2026-09-01T00:02:30Z",
        "source_receipt_sha256": "0" * 64,
    }


base = snapshot()
decision = shadow.evaluate(base)
assert decision["status"] == "shadow-admit"
assert decision["token_allowed"] is False
assert decision["live_mutation_allowed"] is False
assert decision["selected_job"]["job_id"] == 101
assert decision["selected_job"]["run_attempt"] == 4
assert decision["eligible_job_ids"] == [101]
assert decision["selection_mode"] == "exact-one"

extra_required_label = snapshot()
extra_required_label["jobs"][0]["labels"].append("self-hosted")
try:
    shadow.evaluate(extra_required_label)
except shadow.ShadowError as error:
    assert "exact label binding" in str(error)
else:
    raise AssertionError("job with an additional required label was admitted")

first_cycle = snapshot()
first_cycle["head_observations"] = first_cycle["head_observations"][-1:]
result = shadow.evaluate(first_cycle)
assert result["status"] == "CHECK-INCOMPLETE"
assert "HEAD_STABILITY_WINDOW_INCOMPLETE" in result["blockers"]

subminute = snapshot()
subminute["head_observations"][-1]["observed_at"] = "2026-09-01T00:00:59Z"
result = shadow.evaluate(subminute)
assert result["status"] == "CHECK-INCOMPLETE"
assert "HEAD_STABILITY_WINDOW_INCOMPLETE" in result["blockers"]

# Same-label SPA matrix is ordered, not treated as a duplicate ambiguity.
matrix = snapshot()
matrix["jobs"].append(job(102, created="2026-09-01T00:00:01Z"))
matrix_decision = shadow.evaluate(matrix)
assert matrix_decision["selected_job"]["job_id"] == 101
assert matrix_decision["eligible_job_ids"] == [101, 102]
assert matrix_decision["selection_mode"] == "any-one-same-label"

# A terminal older attempt never proves the latest attempt terminal.
latest = snapshot()
latest["jobs"].insert(0, job(99, attempt=3, status="completed"))
assert shadow.evaluate(latest)["selected_job"]["run_attempt"] == 4

# A rerun must not admit its queued job while any earlier attempt is still active.
overlap = snapshot()
overlap["run"]["attempt"] = 5
overlap["jobs"] = [
    job(99, attempt=4, status="in_progress"),
    job(202, attempt=5, status="queued", created="2026-09-01T00:01:00Z"),
]
result = shadow.evaluate(overlap)
assert result["status"] == "CHECK-INCOMPLETE"
assert "ANY_ATTEMPT_JOB_ALREADY_ACTIVE" in result["blockers"]

latest_active = snapshot()
latest_active["jobs"] = [job(status="in_progress")]
result = shadow.evaluate(latest_active)
assert result["status"] == "CHECK-INCOMPLETE"
assert "ANY_ATTEMPT_JOB_ALREADY_ACTIVE" in result["blockers"]

cancelled_without_runner = snapshot()
cancelled = job(98, attempt=3, status="completed")
cancelled["conclusion"] = "cancelled"
cancelled["runner_id"] = None
cancelled["runner_name"] = None
cancelled_without_runner["jobs"].insert(0, cancelled)
assert shadow.evaluate(cancelled_without_runner)["status"] == "shadow-admit"

success_without_runner = snapshot()
unbound_success = job(98, attempt=3, status="completed")
unbound_success["runner_id"] = None
unbound_success["runner_name"] = None
success_without_runner["jobs"].insert(0, unbound_success)
try:
    shadow.evaluate(success_without_runner)
except shadow.ShadowError as error:
    assert "runner_id must be a positive integer" in str(error)
else:
    raise AssertionError("successful terminal job without a Runner was accepted")

drift = snapshot()
drift["head_observations"][0]["head_sha"] = OLD_HEAD
blocked = shadow.evaluate(drift)
assert blocked["status"] == "CHECK-INCOMPLETE"
assert "HEAD_STABILITY_WINDOW_INCOMPLETE" in blocked["blockers"]

latest_drift = snapshot()
latest_drift["head_observations"][-1]["head_sha"] = OLD_HEAD
assert "LATEST_HEAD_OBSERVATION_DRIFT" in shadow.evaluate(latest_drift)["blockers"]

future_history = snapshot()
future_history["head_observations"] = [
    {"observed_at": "2030-01-01T00:00:00Z", "head_sha": HEAD},
    {"observed_at": "2030-01-01T00:01:00Z", "head_sha": HEAD},
]
try:
    shadow.evaluate(future_history)
except shadow.ShadowError as error:
    assert "head observation is newer than snapshot" in str(error)
else:
    raise AssertionError("future head observations manufactured a stability window")

for field, value, blocker in (
    ("global_lock_held", True, "GLOBAL_LOCK_HELD"),
    ("active_services", ["sixlab-pr-old-slot"], "ACTIVE_SERVICE_REMAINS"),
    ("service_details", [{
        "name": "sixlab-pr-old-slot.service",
        "active_state": "inactive",
        "sub_state": "dead",
        "main_pid": 0,
        "control_group": "",
        "pids": [],
        "uids": [],
        "dedicated_pids": [],
    }], "SERVICE_DETAIL_REMAINS"),
    ("dedicated_process_count", 1, "DEDICATED_PROCESS_REMAINS"),
    ("user_manager_active", True, "USER_MANAGER_ACTIVE"),
    ("load5", 1.6, "LOAD5_COOLDOWN"),
    ("root_free_bytes", shadow.MIN_ROOT_FREE_BYTES - 1, "ROOT_DISK_COOLDOWN"),
):
    candidate = snapshot()
    candidate["host"][field] = value
    result = shadow.evaluate(candidate)
    assert result["status"] == "CHECK-INCOMPLETE", field
    assert blocker in result["blockers"], field

low_memory = snapshot()
low_memory["host"]["memory_available_bytes"] = shadow.MIN_MEMORY_SWAP_BYTES - 1
low_memory["host"]["swap_free_bytes"] = 0
assert "MEMORY_SWAP_COOLDOWN" in shadow.evaluate(low_memory)["blockers"]

for non_finite in (float("nan"), float("inf"), float("-inf")):
    invalid_load = snapshot()
    invalid_load["host"]["load5"] = non_finite
    try:
        shadow.evaluate(invalid_load)
    except shadow.ShadowError as error:
        assert "host.load5 is invalid" in str(error)
    else:
        raise AssertionError(f"non-finite load5 was accepted: {non_finite!r}")

running = snapshot()
running["allocation"] = allocation()
running["jobs"] = [job(status="in_progress")]
running["run"]["status"] = "in_progress"
running["host"]["global_lock_held"] = True
running["host"]["active_services"] = [allocation()["service_name"]]
running["host"]["service_details"] = [{
    "name": allocation()["service_name"],
    "active_state": "active",
    "sub_state": "running",
    "main_pid": 700,
    "control_group": f"/system.slice/{allocation()['service_name']}",
    "pids": [700, 701],
    "uids": [0, 1005],
    "dedicated_pids": [701],
}]
running["host"]["dedicated_process_count"] = 1
running["host"]["run_directories"] = ["/run/sj03"]
running["host"]["mounts"] = ["/run/sj03"]
running["host"]["egress_rules"] = [
    "nft:inet:s11732603:table inet s11732603 {",
    "nft:inet:s11732603:meta skuid 1005 ip daddr 127.0.0.1 tcp dport { 3306, 6379 } accept",
    "nft:inet:s11732603:meta skuid 1005 ip daddr 127.0.0.1 tcp dport 18080 accept",
    "nft:inet:s11732603:meta skuid 1005 ip daddr 127.0.0.1 udp dport 15353 accept",
    "nft:inet:s11732603:meta skuid 1005 ip daddr 127.0.0.1 tcp dport 15353 accept",
    "nft:inet:s11732603:meta skuid 1005 ip daddr 127.0.0.1 tcp dport 32768-60999 accept",
    "nft:inet:s11732603:meta skuid 1005 ip daddr { private-v4 } drop",
    "nft:inet:s11732603:meta skuid 1005 ip6 daddr { private-v6 } drop",
    "nft:inet:s11732603:meta skuid 1005 ip daddr 10.0.0.10 drop",
    "nft:inet:s11732603:meta skuid 1005 ip6 daddr 2402:4e00:c032:2e00:48a4:2b84:989c:0 drop",
    "nft:inet:s11732603:meta skuid 1005 drop",
    "iptables::SLPR117303 - [0:0]",
    "iptables::SLPD117303 - [0:0]",
    "iptables:-A SLPR117303 -d 127.0.0.1/32 -p tcp --dport 3306 -m comment --comment sixlab-pr1173-ephemeral-03 -j ACCEPT",
    "iptables:-A SLPR117303 -d 127.0.0.1/32 -p tcp --dport 6379 -m comment --comment sixlab-pr1173-ephemeral-03 -j ACCEPT",
    "iptables:-A SLPR117303 -d 127.0.0.1/32 -p tcp --dport 18080 -m comment --comment sixlab-pr1173-ephemeral-03 -j ACCEPT",
    "iptables:-A SLPR117303 -d 127.0.0.1/32 -p udp --dport 15353 -m comment --comment sixlab-pr1173-ephemeral-03 -j ACCEPT",
    "iptables:-A SLPR117303 -d 127.0.0.1/32 -p tcp --dport 15353 -m comment --comment sixlab-pr1173-ephemeral-03 -j ACCEPT",
    "iptables:-A SLPR117303 -d 127.0.0.1/32 -p tcp --dport 32768:60999 -m comment --comment sixlab-pr1173-ephemeral-03 -j ACCEPT",
    *[
        f"iptables:-A SLPR117303 -d 10.0.{index}.0/24 -m comment --comment sixlab-pr1173-ephemeral-03 -j DROP"
        for index in range(9)
    ],
    "iptables:-A SLPR117303 -m comment --comment sixlab-pr1173-ephemeral-03 -j DROP",
    "iptables:-A SLPD117303 -p udp -m udp --dport 53 -j REDIRECT --to-ports 15353",
    "iptables:-A SLPD117303 -p tcp -m tcp --dport 53 -j REDIRECT --to-ports 15353",
    "iptables:-A OUTPUT -m owner --uid-owner 1005 -m comment --comment sixlab-pr1173-ephemeral-03 -j SLPR117303",
    "iptables:-A OUTPUT -m owner --uid-owner 1005 -m comment --comment sixlab-pr1173-dns-03 -j SLPD117303",
]
running["host"]["user_manager_active"] = True
running["host"]["runner_inventory"] = [{
    "id": 234,
    "name": allocation()["runner_name"],
    "status": "online",
    "busy": True,
    "labels": ["Linux", "X64", "self-hosted", LABEL],
}]
assert shadow.evaluate(running)["status"] == "shadow-running"
assert shadow.evaluate(running)["selection_mode"] == "actual-binding"

offline_runner = copy.deepcopy(running)
offline_runner["host"]["runner_inventory"][0]["status"] = "offline"
result = shadow.evaluate(offline_runner)
assert result["status"] == "CHECK-INCOMPLETE"
assert result["blockers"] == ["RUNNING_JOB_RUNTIME_BINDING_INCOMPLETE"]

extra_runner = copy.deepcopy(running)
extra_runner["host"]["runner_inventory"].append({
    "id": 999,
    "name": "sixlab-pr-orphan",
    "status": "offline",
    "busy": False,
    "labels": ["Linux", "X64", "self-hosted", LABEL],
})
result = shadow.evaluate(extra_runner)
assert result["status"] == "CHECK-INCOMPLETE"
assert result["blockers"] == ["RUNNING_JOB_RUNTIME_BINDING_INCOMPLETE"]

lost_service = copy.deepcopy(running)
lost_service["host"]["active_services"] = []
result = shadow.evaluate(lost_service)
assert result["status"] == "CHECK-INCOMPLETE"
assert result["blockers"] == ["RUNNING_JOB_RUNTIME_BINDING_INCOMPLETE"]

for field, residue in (
    ("run_directories", "/run/sj99"),
    ("mounts", "/run/sj99"),
    ("egress_rules", "nft:table inet s99992699"),
):
    foreign_runtime = copy.deepcopy(running)
    foreign_runtime["host"][field].append(residue)
    result = shadow.evaluate(foreign_runtime)
    assert result["status"] == "CHECK-INCOMPLETE", field
    assert result["blockers"] == ["RUNNING_JOB_RUNTIME_BINDING_INCOMPLETE"], field

foreign_process = copy.deepcopy(running)
foreign_process["host"]["dedicated_process_count"] += 1
result = shadow.evaluate(foreign_process)
assert result["status"] == "CHECK-INCOMPLETE"
assert result["blockers"] == ["RUNNING_JOB_RUNTIME_BINDING_INCOMPLETE"]

flushed_policy = copy.deepcopy(running)
flushed_policy["host"]["egress_rules"] = [
    "nft:inet:s11732603:table inet s11732603 {",
    "iptables::SLPR117303 - [0:0]",
    "iptables::SLPD117303 - [0:0]",
]
result = shadow.evaluate(flushed_policy)
assert result["status"] == "CHECK-INCOMPLETE"
assert result["blockers"] == ["RUNNING_JOB_RUNTIME_BINDING_INCOMPLETE"]

permissive_policy = copy.deepcopy(running)
permissive_policy["host"]["egress_rules"].insert(
    10, "nft:inet:s11732603:meta skuid 1005 accept",
)
result = shadow.evaluate(permissive_policy)
assert result["status"] == "CHECK-INCOMPLETE"
assert result["blockers"] == ["RUNNING_JOB_RUNTIME_BINDING_INCOMPLETE"]

# A rerun creates attempt 5; the attempt 4 allocation must be reconciled, not stopped as closed.
rerun = copy.deepcopy(running)
rerun["run"]["attempt"] = 5
rerun["jobs"].append(job(202, attempt=5, status="queued", created="2026-09-01T00:04:00Z"))
result = shadow.evaluate(rerun)
assert result["status"] == "shadow-reconcile-required"
assert "ALLOCATION_NOT_LATEST_ATTEMPT" in result["blockers"]

overlapping_reconciliation = copy.deepcopy(running)
overlapping_reconciliation["run"]["attempt"] = 5
overlapping_reconciliation["run"]["status"] = "queued"
overlapping_reconciliation["jobs"] = [
    job(101, attempt=4, status="in_progress"),
    job(202, attempt=5, status="queued", created="2026-09-01T00:04:00Z"),
]
overlapping_reconciliation["allocation"]["run_attempt"] = 5
overlapping_reconciliation["allocation"]["job_id"] = 202
overlapping_reconciliation["host"]["runner_inventory"][0]["busy"] = False
result = shadow.evaluate(overlapping_reconciliation)
assert result["status"] == "shadow-reconcile-required"
assert "OTHER_JOB_ALREADY_ACTIVE" in result["blockers"]

terminal = snapshot()
terminal["allocation"] = allocation()
terminal["receipt"] = receipt()
terminal["jobs"] = [job(status="completed")]
terminal["run"]["status"] = "completed"
result = shadow.evaluate(terminal)
assert result["status"] == "shadow-teardown-verified"
assert result["evidence"]["job_conclusion"] == "success"
assert result["evidence"]["receipt_exit_code"] == 0
assert result["evidence"]["source_receipt_sha256"] == "0" * 64

teardown_failed = copy.deepcopy(terminal)
teardown_failed["receipt"]["exit_code"] = shadow.TEARDOWN_FAILURE_EXIT
result = shadow.evaluate(teardown_failed)
assert result["status"] == "CHECK-INCOMPLETE"
assert result["blockers"] == ["RECEIPT_REPORTED_TEARDOWN_FAILURE"]

old_attempt_terminal = copy.deepcopy(terminal)
old_attempt_terminal["jobs"][0]["run_attempt"] = 3
result = shadow.evaluate(old_attempt_terminal)
assert result["status"] == "shadow-reconcile-required"
assert "ALLOCATED_JOB_NOT_LATEST_ATTEMPT" in result["blockers"]
assert result["selected_job"]["run_attempt"] == 3

residue = copy.deepcopy(terminal)
residue["host"]["runner_inventory"] = [{
    "id": 234,
    "name": allocation()["runner_name"],
    "status": "offline",
    "busy": False,
    "labels": ["Linux", "X64", "self-hosted", LABEL],
}]
result = shadow.evaluate(residue)
assert result["status"] == "shadow-reconcile-required"
assert "RUNNER_INVENTORY_REMAINS" in result["blockers"]

wrong_receipt = copy.deepcopy(terminal)
wrong_receipt["receipt"]["runner_id"] = 999
result = shadow.evaluate(wrong_receipt)
assert result["status"] == "CHECK-INCOMPLETE"
assert result["blockers"] == ["TERMINAL_RECEIPT_BINDING_DRIFT"]

future_receipt = copy.deepcopy(terminal)
future_receipt["receipt"]["finished_at"] = "2026-09-01T00:04:00Z"
try:
    shadow.evaluate(future_receipt)
except shadow.ShadowError as error:
    assert "receipt is newer than snapshot" in str(error)
else:
    raise AssertionError("future receipt was accepted")

pre_job_receipt = copy.deepcopy(terminal)
pre_job_receipt["receipt"]["finished_at"] = "2026-08-31T23:59:59Z"
result = shadow.evaluate(pre_job_receipt)
assert result["status"] == "CHECK-INCOMPLETE"
assert result["blockers"] == ["TERMINAL_RECEIPT_TIME_DRIFT"]

unknown = snapshot()
unknown["host"]["unexpected"] = True
try:
    shadow.evaluate(unknown)
except shadow.ShadowError as error:
    assert "host fields are not canonical" in str(error)
else:
    raise AssertionError("unknown host field was accepted")

with tempfile.TemporaryDirectory(prefix="sixlab-jit-shadow.") as temporary:
    root = Path(temporary)
    input_path = root / "snapshot.json"
    input_path.write_text(json.dumps(snapshot()), encoding="utf-8")
    completed = subprocess.run(
        [str(source), "--input", str(input_path), "--output", str(root / "decision.json")],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["status"] == "shadow-admit"
    decision_path = root / "decision.json"
    assert decision_path.stat().st_mode & 0o777 == 0o600
    assert json.loads(decision_path.read_text())["status"] == "shadow-admit"
    input_path.write_text("{}\n", encoding="utf-8")
    stale_rejected = subprocess.run(
        [str(source), "--input", str(input_path), "--output", str(decision_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert stale_rejected.returncode == 2
    assert json.loads(decision_path.read_text())["status"] == "CHECK-INCOMPLETE"
    inaccessible = root / "inaccessible"
    inaccessible.mkdir()
    inaccessible_input = inaccessible / "snapshot.json"
    inaccessible_input.write_text(json.dumps(snapshot()), encoding="utf-8")
    inaccessible.chmod(0)
    try:
        inaccessible_rejected = subprocess.run(
            [str(source), "--input", str(inaccessible_input), "--output", str(decision_path)],
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        inaccessible.chmod(0o700)
    assert inaccessible_rejected.returncode == 2
    assert json.loads(decision_path.read_text())["status"] == "CHECK-INCOMPLETE"
    input_path.write_text(json.dumps(snapshot()), encoding="utf-8")
    linked = root / "linked.json"
    linked.symlink_to(input_path)
    rejected = subprocess.run(
        [str(source), "--input", str(linked)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 2
    assert json.loads(rejected.stdout)["status"] == "CHECK-INCOMPLETE"

text = source.read_text(encoding="utf-8")
for forbidden in (
    "urllib",
    "requests",
    "subprocess",
    "registration-token",
    "systemctl",
    "gh api",
):
    assert forbidden not in text, forbidden
for required in (
    "token_allowed\": False",
    "live_mutation_allowed\": False",
    "ALLOCATION_NOT_LATEST_ATTEMPT",
    "ALLOCATED_JOB_NOT_LATEST_ATTEMPT",
    "math.isfinite",
    "HEAD_STABILITY_WINDOW_INCOMPLETE",
    "head observation is newer than snapshot",
    "RUNNER_INVENTORY_REMAINS",
):
    assert required in text, required

print("SIXLABJITShadowControllerSmoke: PASS · fail-closed admission + latest-attempt teardown")
