#!/usr/bin/env python3
"""Cross-worktree regression for the SIXLAB v2 runner correlation contract."""

import copy
import importlib.util
import json
from pathlib import Path
import shutil
import sys


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


bridge = load("sixlab_jit_pr_runner_bridge")
scheduler = load("sixlab_jit_serial_scheduler")

fixtures = project / "tests" / "fixtures"
fixture_path = fixtures / "sixlab-pr-runner-correlation-v2.json"
assert fixture_path.is_file(), f"missing paired SIXLAB bridge fixture: {fixture_path}"
correlation = json.loads(fixture_path.read_text(encoding="utf-8"))
test_node = Path(shutil.which("node") or "").resolve(strict=True)

host = {
    "observed_at": "2026-09-04T00:02:00Z", "global_lock_held": False,
    "active_services": [], "service_details": [], "dedicated_process_count": 0,
    "run_directories": [], "mounts": [], "egress_rules": [], "runner_inventory": [],
    "user_manager_active": False, "load5": 0.2,
    "root_free_bytes": 20 * 1024 * 1024 * 1024,
    "memory_available_bytes": 4 * 1024 * 1024 * 1024,
    "swap_free_bytes": 1024 * 1024 * 1024,
}
evidence = {
    42: {
        "headObservations": [
            {"observed_at": "2026-09-04T00:00:00Z", "head_sha": "a" * 40},
            {"observed_at": "2026-09-04T00:01:00Z", "head_sha": "a" * 40},
        ],
        "host": host,
        "allocation": None,
        "receipt": None,
    }
}

# Caller-provided JSON is a fixture-only seam.  It remains useful for shape
# attacks, but cannot produce a cycle that a scheduler or actuator can admit.
fixture = bridge.validate_test_fixture(correlation, {42: "test"}, evidence, test_node=test_node)
assert fixture == {
    "schema": "sixlab-jit-bridge-test-fixture-v1",
    "status": "CHECK-INCOMPLETE",
    "token_allowed": False,
    "live_mutation_allowed": False,
    "next_action": "test-fixture-cannot-enter-scheduler-or-actuator",
}
try:
    scheduler.evaluate(fixture)
except scheduler.SerialSchedulerError:
    pass
else:
    raise AssertionError("fixture result reached shadow-serial-ready scheduler input")

missing_selection = copy.deepcopy(evidence)
try:
    bridge.validate_test_fixture(correlation, {}, missing_selection, test_node=test_node)
except bridge.BridgeError as error:
    assert "every open PR" in str(error)
else:
    raise AssertionError("bridge accepted a missing all-open-PR workflow selection")

attempt_drift = copy.deepcopy(correlation)
attempt_drift["runs"][0]["run"]["attempt"] = 1
try:
    bridge.validate_test_fixture(attempt_drift, {42: "test"}, evidence, test_node=test_node)
except bridge.BridgeError as error:
    assert "canonical SIXLAB contract rejected correlation" in str(error)
else:
    raise AssertionError("bridge accepted stale attempt drift")

cross_family = copy.deepcopy(correlation)
cross_family["runs"][0]["jobs"].append(copy.deepcopy(cross_family["runs"][1]["jobs"][0]))
cross_family["runs"][0]["jobs"][-1]["runId"] = 101
cross_family["runs"][0]["jobs"][-1]["runAttempt"] = 2
try:
    bridge.validate_test_fixture(cross_family, {42: "test"}, evidence, test_node=test_node)
except bridge.BridgeError as error:
    assert "canonical SIXLAB contract rejected correlation" in str(error)
else:
    raise AssertionError("bridge accepted backend-detect inside test workflow")

# A caller cannot remove the backend run then bring an equally reduced map:
# there is no map input and B's fixed contract rejects the incomplete matrix.
missing_backend = copy.deepcopy(correlation)
missing_backend["runs"] = [row for row in missing_backend["runs"] if row["workflow"] != "test-backend"]
try:
    bridge.validate_test_fixture(missing_backend, {42: "test"}, evidence, test_node=test_node)
except bridge.BridgeError as error:
    assert "canonical SIXLAB contract rejected correlation" in str(error)
else:
    raise AssertionError("bridge accepted a reduced workflow matrix")

# Removing every PR/run from a previously valid fixture may still be internally
# self-consistent.  That is precisely why fixture input is non-admitting and
# the production API accepts no correlation argument at all.
removed_pr = copy.deepcopy(correlation)
removed_pr["openPullRequests"] = []
removed_pr["runs"] = []
try:
    bridge.build_cycle(removed_pr, {42: "test"}, evidence)
except TypeError:
    pass
else:
    raise AssertionError("production bridge accepted caller-supplied correlation JSON")

# The manifest-gated production process boundary is tested separately.  This
# fixture file intentionally has no production Node trust shortcut.
print("SIXLABJITProjectManagerBridgeSmoke: PASS · fixture safe + production collector-only")
