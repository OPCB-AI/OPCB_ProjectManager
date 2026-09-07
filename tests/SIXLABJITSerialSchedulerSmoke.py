#!/usr/bin/env python3
"""Contract smoke test for the R1-backed all-open-PR serial scheduler."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile


project = Path(__file__).resolve().parent.parent
ops = project / "ops"
sys.path.insert(0, str(ops))


def load(name):
    source = ops / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


scheduler = load("sixlab_jit_serial_scheduler")
actuator = load("sixlab_jit_actuator_admission")
generator = load("sixlab_jit_launcher_generator")
shadow = scheduler.inventory.shadow

HEAD = "a" * 40


def snapshot(pull_number, run_id, job_id, family, created_at):
    label = shadow.exact_label(HEAD, family)
    return {
        "schema": shadow.SCHEMA,
        "observed_at": "2026-09-01T00:02:00Z",
        "pull": {"number": pull_number, "state": "open", "draft": False, "base_ref": "main", "head_sha": HEAD},
        "head_observations": [
            {"observed_at": "2026-09-01T00:00:00Z", "head_sha": HEAD},
            {"observed_at": "2026-09-01T00:01:00Z", "head_sha": HEAD},
        ],
        "run_inventory": [9001, 9002],
        "run": {"id": run_id, "attempt": 1, "head_sha": HEAD, "status": "queued"},
        "jobs": [{
            "id": job_id, "run_id": run_id, "run_attempt": 1, "name": family,
            "family": family, "status": "queued", "conclusion": None,
            "labels": [label], "runner_id": None, "runner_name": None,
            "created_at": created_at,
        }],
        "host": {
            "observed_at": "2026-09-01T00:02:00Z", "global_lock_held": False,
            "active_services": [], "service_details": [], "dedicated_process_count": 0,
            "run_directories": [], "mounts": [], "egress_rules": [], "runner_inventory": [],
            "user_manager_active": False, "load5": 0.2,
            "root_free_bytes": 20 * 1024 * 1024 * 1024,
            "memory_available_bytes": 4 * 1024 * 1024 * 1024,
            "swap_free_bytes": 1024 * 1024 * 1024,
        },
        "allocation": None,
        "receipt": None,
    }


first = snapshot(1173, 9001, 1001, "spa-detect", "2026-09-01T00:01:30Z")
second = snapshot(1198, 9002, 1002, "backend-detect", "2026-09-01T00:01:31Z")
cycle = {
    "schema": scheduler.CYCLE_SCHEMA,
    "observed_at": "2026-09-01T00:02:00Z",
    "open_pull_numbers": [1173, 1198],
    "snapshots": [first, second],
}

schedule = scheduler.evaluate(cycle)
assert schedule["status"] == "shadow-serial-ready"
assert schedule["selected_job"]["job_id"] == 1001
assert schedule["evaluated_open_pull_numbers"] == [1173, 1198]
assert schedule["next_action"] == "actuator-admission-required"
assert schedule["token_allowed"] is False
assert schedule["runner_mutation_allowed"] is False
assert schedule["token_transport"] == "stdin-short-lived-only"

rendered, manifest = generator.render(1173, HEAD, 1, "01")
for host_time in ("2020-01-01T00:00:00Z", cycle["observed_at"]):
    untrusted = copy.deepcopy(cycle)
    for snapshot in untrusted["snapshots"]:
        snapshot["host"]["observed_at"] = host_time
    try:
        actuator.admit(scheduler.evaluate(untrusted), untrusted, manifest, rendered.encode())
    except actuator.ActuatorAdmissionError as error:
        assert "trusted same-window" in str(error)
    else:
        raise AssertionError("caller-provided host evidence admitted")

missing = copy.deepcopy(cycle)
missing["open_pull_numbers"] = [1173]
try:
    scheduler.evaluate(missing)
except scheduler.SerialSchedulerError as error:
    assert "inventory" in str(error)
else:
    raise AssertionError("missing open PR was accepted")

drifted_manifest = copy.deepcopy(manifest)
drifted_manifest["expected_head"] = "b" * 40
try:
    actuator.admit(schedule, cycle, drifted_manifest, rendered.encode())
except actuator.ActuatorAdmissionError as error:
    assert "reviewed canonical render" in str(error)
else:
    raise AssertionError("manifest head drift was accepted")

drifted_cycle = copy.deepcopy(cycle)
drifted_cycle["snapshots"][0]["jobs"][0]["id"] = 7777
try:
    actuator.admit(schedule, drifted_cycle, manifest, rendered.encode())
except actuator.ActuatorAdmissionError as error:
    assert "selected job drifted" in str(error)
else:
    raise AssertionError("fresh selected job drift was accepted")

# A matching SHA in a caller-supplied manifest is not a trust root.  The
# admission path must derive every canonical field and rendered byte from the
# reviewed template, so a forged launcher/manifest pair never becomes ready.
forged_launcher = rendered + "# attacker-controlled launcher\n"
forged_manifest = copy.deepcopy(manifest)
forged_manifest["rendered_sha256"] = hashlib.sha256(forged_launcher.encode()).hexdigest()
try:
    actuator.admit(schedule, cycle, forged_manifest, forged_launcher.encode())
except actuator.ActuatorAdmissionError as error:
    assert "reviewed canonical render" in str(error)
else:
    raise AssertionError("forged launcher and synchronized manifest were accepted")

unknown_manifest_key = copy.deepcopy(manifest)
unknown_manifest_key["launcher_source"] = "unreviewed"
try:
    actuator.admit(schedule, cycle, unknown_manifest_key, rendered.encode())
except actuator.ActuatorAdmissionError as error:
    assert "reviewed canonical render" in str(error)
else:
    raise AssertionError("manifest with unrecognized authority field was accepted")

with tempfile.TemporaryDirectory(prefix="sixlab-jit-serial.") as temporary:
    root = Path(temporary)
    cycle_path = root / "cycle.json"
    schedule_path = root / "schedule.json"
    cycle_path.write_text(json.dumps(cycle), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(ops / "sixlab_jit_serial_scheduler.py"), "--cycle", str(cycle_path), "--output", str(schedule_path)],
        check=False, capture_output=True, text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["status"] == "shadow-serial-ready"
    assert schedule_path.stat().st_mode & 0o777 == 0o600
    cycle_path.write_text("{}\n", encoding="utf-8")
    rejected = subprocess.run(
        [sys.executable, str(ops / "sixlab_jit_serial_scheduler.py"), "--cycle", str(cycle_path), "--output", str(schedule_path)],
        check=False, capture_output=True, text=True,
    )
    assert rejected.returncode == 2
    assert json.loads(schedule_path.read_text())["status"] == "CHECK-INCOMPLETE"
    cycle_path.write_text(json.dumps(cycle), encoding="utf-8")
    restored = subprocess.run(
        [sys.executable, str(ops / "sixlab_jit_serial_scheduler.py"), "--cycle", str(cycle_path), "--output", str(schedule_path)],
        check=False, capture_output=True, text=True,
    )
    assert restored.returncode == 0, restored.stderr
    manifest_path = root / "launcher.manifest.json"
    launcher_path = root / "launcher.sh"
    admission_path = root / "admission.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    launcher_path.write_text(rendered, encoding="utf-8")
    launcher_path.chmod(0o700)
    admitted = subprocess.run(
        [sys.executable, str(ops / "sixlab_jit_actuator_admission.py"), "--schedule", str(schedule_path), "--cycle", str(cycle_path), "--launcher-manifest", str(manifest_path), "--launcher", str(launcher_path), "--output", str(admission_path)],
        check=False, capture_output=True, text=True,
    )
    assert admitted.returncode == 2, admitted.stderr
    assert json.loads(admission_path.read_text())["status"] == "CHECK-INCOMPLETE"
    assert "trusted same-window" in json.loads(admission_path.read_text())["blockers"][0]
    launcher_path.write_text(rendered + "# drift\n", encoding="utf-8")
    rejected = subprocess.run(
        [sys.executable, str(ops / "sixlab_jit_actuator_admission.py"), "--schedule", str(schedule_path), "--cycle", str(cycle_path), "--launcher-manifest", str(manifest_path), "--launcher", str(launcher_path)],
        check=False, capture_output=True, text=True,
    )
    assert rejected.returncode == 2
    assert json.loads(rejected.stdout)["status"] == "CHECK-INCOMPLETE"

for source in (ops / "sixlab_jit_serial_scheduler.py", ops / "sixlab_jit_actuator_admission.py"):
    text = source.read_text(encoding="utf-8")
    assert "subprocess" not in text
    assert "stdin.read" not in text
assert "token_allowed" in (ops / "sixlab_jit_serial_scheduler.py").read_text(encoding="utf-8")
assert "token_read" in (ops / "sixlab_jit_actuator_admission.py").read_text(encoding="utf-8")

print("SIXLABJITSerialSchedulerSmoke: PASS · all-open-PR serial selection + no-token actuator boundary")
