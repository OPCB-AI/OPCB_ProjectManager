#!/usr/bin/env python3
"""Validate the B-fixed bridge without a fixed worktree path."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys


if len(sys.argv) != 3:
    raise SystemExit("usage: SIXLABJITProjectManagerBridgePairSmoke.py <validator.mjs> <correlation.json>")

project = Path(__file__).resolve().parent.parent
ops = project / "ops"
sys.path.insert(0, str(ops))
spec = importlib.util.spec_from_file_location("bridge", ops / "sixlab_jit_pr_runner_bridge.py")
bridge = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bridge)

validator, correlation_path = map(Path, sys.argv[1:])
assert validator.is_file() and correlation_path.is_file()
validated = subprocess.run(["node", str(validator), "--validate-snapshot", str(correlation_path)], capture_output=True, text=True)
assert validated.returncode == 0, validated.stderr
correlation = json.loads(correlation_path.read_text(encoding="utf-8"))

host = {"observed_at": "2026-09-04T00:02:00Z", "global_lock_held": False, "active_services": [], "service_details": [], "dedicated_process_count": 0, "run_directories": [], "mounts": [], "egress_rules": [], "runner_inventory": [], "user_manager_active": False, "load5": 0.2, "root_free_bytes": 20 * 1024 * 1024 * 1024, "memory_available_bytes": 4 * 1024 * 1024 * 1024, "swap_free_bytes": 1024 * 1024 * 1024}
evidence = {42: {"headObservations": [{"observed_at": "2026-09-04T00:00:00Z", "head_sha": "a" * 40}, {"observed_at": "2026-09-04T00:01:00Z", "head_sha": "a" * 40}], "host": host, "allocation": None, "receipt": None}}
assert bridge.validate_test_fixture(correlation, {42: "test"}, evidence, validator)["status"] == "CHECK-INCOMPLETE"
attack = copy.deepcopy(correlation)
attack["runs"][0]["jobs"].append(copy.deepcopy(attack["runs"][1]["jobs"][0]))
attack["runs"][0]["jobs"][-1].update({"runId": 101, "runAttempt": 2})
try:
    bridge.validate_test_fixture(attack, {42: "test"}, evidence, validator)
except bridge.BridgeError as error:
    assert "canonical SIXLAB contract rejected correlation" in str(error)
else:
    raise AssertionError("cross-workflow job bypass was accepted")

missing_backend = copy.deepcopy(correlation)
missing_backend["runs"] = [row for row in missing_backend["runs"] if row["workflow"] != "test-backend"]
try:
    bridge.validate_test_fixture(missing_backend, {42: "test"}, evidence, validator)
except bridge.BridgeError as error:
    assert "canonical SIXLAB contract rejected correlation" in str(error)
else:
    raise AssertionError("B contract accepted an incomplete workflow matrix")

# A correlation snapshot cannot become a replacement validator either.
try:
    bridge.validate_test_fixture(correlation, {42: "test"}, evidence, correlation_path)
except bridge.BridgeError as error:
    assert "validator path" in str(error)
else:
    raise AssertionError("bridge accepted a caller-supplied replacement map")

print("SIXLABJITProjectManagerBridgePairSmoke: PASS · fixture safety + B contract attacks")
