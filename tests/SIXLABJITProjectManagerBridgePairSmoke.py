#!/usr/bin/env python3
"""Validate A's self-contained, provenance-pinned B bridge."""

import copy
import importlib.util
import json
from pathlib import Path
import sys


if len(sys.argv) != 1:
    raise SystemExit("usage: SIXLABJITProjectManagerBridgePairSmoke.py")

project = Path(__file__).resolve().parent.parent
ops = project / "ops"
sys.path.insert(0, str(ops))
spec = importlib.util.spec_from_file_location("bridge", ops / "sixlab_jit_pr_runner_bridge.py")
bridge = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bridge)

correlation_path = project / "tests" / "fixtures" / "sixlab-pr-runner-correlation-v2.json"
assert correlation_path.is_file()
correlation = json.loads(correlation_path.read_text(encoding="utf-8"))

host = {"observed_at": "2026-09-04T00:02:00Z", "global_lock_held": False, "active_services": [], "service_details": [], "dedicated_process_count": 0, "run_directories": [], "mounts": [], "egress_rules": [], "runner_inventory": [], "user_manager_active": False, "load5": 0.2, "root_free_bytes": 20 * 1024 * 1024 * 1024, "memory_available_bytes": 4 * 1024 * 1024 * 1024, "swap_free_bytes": 1024 * 1024 * 1024}
evidence = {42: {"headObservations": [{"observed_at": "2026-09-04T00:00:00Z", "head_sha": "a" * 40}, {"observed_at": "2026-09-04T00:01:00Z", "head_sha": "a" * 40}], "host": host, "allocation": None, "receipt": None}}
assert bridge.validate_test_fixture(correlation, {42: "test"}, evidence)["status"] == "CHECK-INCOMPLETE"
attack = copy.deepcopy(correlation)
attack["runs"][0]["jobs"].append(copy.deepcopy(attack["runs"][1]["jobs"][0]))
attack["runs"][0]["jobs"][-1].update({"runId": 101, "runAttempt": 2})
try:
    bridge.validate_test_fixture(attack, {42: "test"}, evidence)
except bridge.BridgeError as error:
    assert "canonical SIXLAB contract rejected correlation" in str(error)
else:
    raise AssertionError("cross-workflow job bypass was accepted")

missing_backend = copy.deepcopy(correlation)
missing_backend["runs"] = [row for row in missing_backend["runs"] if row["workflow"] != "test-backend"]
try:
    bridge.validate_test_fixture(missing_backend, {42: "test"}, evidence)
except bridge.BridgeError as error:
    assert "canonical SIXLAB contract rejected correlation" in str(error)
else:
    raise AssertionError("B contract accepted an incomplete workflow matrix")

# A correlation snapshot cannot become a replacement validator either, and
# production never accepts a caller path for the vendored B source.
try:
    bridge.build_cycle(correlation, {42: "test"}, evidence)
except TypeError:
    pass
else:
    raise AssertionError("bridge accepted caller-supplied production correlation")

print("SIXLABJITProjectManagerBridgePairSmoke: PASS · fixture safety + B contract attacks")
