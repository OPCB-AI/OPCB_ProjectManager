#!/usr/bin/env python3
"""Cross-worktree regression for the SIXLAB v2 runner correlation contract."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
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
fixture = bridge.validate_test_fixture(correlation, {42: "test"}, evidence)
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
    bridge.validate_test_fixture(correlation, {}, missing_selection)
except bridge.BridgeError as error:
    assert "every open PR" in str(error)
else:
    raise AssertionError("bridge accepted a missing all-open-PR workflow selection")

attempt_drift = copy.deepcopy(correlation)
attempt_drift["runs"][0]["run"]["attempt"] = 1
try:
    bridge.validate_test_fixture(attempt_drift, {42: "test"}, evidence)
except bridge.BridgeError as error:
    assert "canonical SIXLAB contract rejected correlation" in str(error)
else:
    raise AssertionError("bridge accepted stale attempt drift")

cross_family = copy.deepcopy(correlation)
cross_family["runs"][0]["jobs"].append(copy.deepcopy(cross_family["runs"][1]["jobs"][0]))
cross_family["runs"][0]["jobs"][-1]["runId"] = 101
cross_family["runs"][0]["jobs"][-1]["runAttempt"] = 2
try:
    bridge.validate_test_fixture(cross_family, {42: "test"}, evidence)
except bridge.BridgeError as error:
    assert "canonical SIXLAB contract rejected correlation" in str(error)
else:
    raise AssertionError("bridge accepted backend-detect inside test workflow")

# A caller cannot remove the backend run then bring an equally reduced map:
# there is no map input and B's fixed contract rejects the incomplete matrix.
missing_backend = copy.deepcopy(correlation)
missing_backend["runs"] = [row for row in missing_backend["runs"] if row["workflow"] != "test-backend"]
try:
    bridge.validate_test_fixture(missing_backend, {42: "test"}, evidence)
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

# The production seam has no caller-supplied collector or Node executable. It
# fails closed before a subprocess starts without a token and rejects a Node
# loader injection instead of inheriting it.
previous_token = os.environ.get("GITHUB_TOKEN")
previous_options = os.environ.get("NODE_OPTIONS")
previous_path = os.environ.get("NODE_PATH")
try:
    os.environ.pop("GITHUB_TOKEN", None)
    try:
        bridge.build_cycle({42: "test"}, evidence)
    except bridge.BridgeError as error:
        assert "requires GITHUB_TOKEN" in str(error)
    else:
        raise AssertionError("tokenless production bridge produced a cycle")

    os.environ["GITHUB_TOKEN"] = "test-token-not-a-live-secret"
    for name, value in (("NODE_OPTIONS", "--require=/tmp/attacker.cjs"), ("NODE_PATH", "/tmp/attacker-modules")):
        os.environ[name] = value
        real_run = bridge.subprocess.run
        captured = {}
        try:
            def deny_collector(command, **kwargs):
                captured["command"] = command
                captured["environment"] = kwargs["env"]
                return subprocess.CompletedProcess(command, 1, "", "test collector denied")
            bridge.subprocess.run = deny_collector
            try:
                bridge.build_cycle({42: "test"}, evidence)
            except bridge.BridgeError as error:
                assert "live collector failed" in str(error)
            else:
                raise AssertionError("non-admitting collector seam produced a cycle")
        finally:
            bridge.subprocess.run = real_run
        assert captured["command"][0] == str(bridge._trusted_node())
        assert name not in captured["environment"]
        assert "GITHUB_TOKEN" in captured["environment"]
        os.environ.pop(name, None)
finally:
    if previous_token is None:
        os.environ.pop("GITHUB_TOKEN", None)
    else:
        os.environ["GITHUB_TOKEN"] = previous_token
    if previous_options is None:
        os.environ.pop("NODE_OPTIONS", None)
    else:
        os.environ["NODE_OPTIONS"] = previous_options
    if previous_path is None:
        os.environ.pop("NODE_PATH", None)
    else:
        os.environ["NODE_PATH"] = previous_path

print("SIXLABJITProjectManagerBridgeSmoke: PASS · fixture safe + production collector-only")
