#!/usr/bin/env python3
"""Exercise the production Node/process boundary without a GitHub request."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys


project = Path(__file__).resolve().parent.parent
ops = project / "ops"
sys.path.insert(0, str(ops))
spec = importlib.util.spec_from_file_location("bridge", ops / "sixlab_jit_pr_runner_bridge.py")
bridge = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bridge)

test_node = Path(shutil.which("node") or "").resolve(strict=True)
validator = bridge._fixture_pinned_validator()
collector = bridge._vendored_b()["scripts/ci/collect-pr-runner-correlation.mjs"]

# A developer machine cannot self-admit a Homebrew/UID-owned Node. Production
# activation needs the fixed root-owned manifest, absent from this checkout.
try:
    bridge._trusted_node()
except bridge.BridgeError as error:
    assert "Node trust manifest" in str(error)
else:
    raise AssertionError("uninstalled production trust manifest admitted Node")

previous = {name: os.environ.get(name) for name in (
    "GITHUB_TOKEN", "NODE_OPTIONS", "NODE_PATH", "PATH", "HTTPS_PROXY",
    "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "NODE_EXTRA_CA_CERTS", "SSL_CERT_DIR", "SSL_CERT_FILE",
)}
os.environ.update({
    "GITHUB_TOKEN": "test-token-not-a-live-secret",
    "NODE_OPTIONS": "--require=/tmp/attacker.cjs",
    "NODE_PATH": "/tmp/attacker-modules",
    "PATH": "/tmp/attacker-bin",
    "HTTPS_PROXY": "http://attacker.invalid:8080",
    "HTTP_PROXY": "http://attacker.invalid:8080",
    "ALL_PROXY": "socks5://attacker.invalid:1080",
    "NO_PROXY": "attacker.invalid",
    "NODE_EXTRA_CA_CERTS": "/tmp/attacker-ca.pem",
    "SSL_CERT_DIR": "/tmp/attacker-ca-dir",
    "SSL_CERT_FILE": "/tmp/attacker-cert.pem",
})

real_run = bridge._run_bounded_process
calls = []


def fake_run(command, **kwargs):
    calls.append((command, kwargs))
    return fake_run.responses.pop(0)


try:
    bridge._run_bounded_process = fake_run
    # A GitHub-side 503 is represented by B's nonzero collector exit, and
    # cannot cause a retry or a partially parsed cycle.
    fake_run.responses = [subprocess.CompletedProcess([str(test_node), str(collector)], 1, b"", b"HTTP 503")]
    try:
        bridge._collect_live_correlation(test_node)
    except bridge.BridgeError as error:
        assert str(error) == "canonical SIXLAB live collector failed"
    else:
        raise AssertionError("collector 503 was accepted")
    command, kwargs = calls.pop()
    assert command == [str(test_node), str(collector), "--stdout"]
    assert kwargs["env"] == {"GITHUB_TOKEN": "test-token-not-a-live-secret"}
    assert kwargs["input_bytes"] is None
    assert kwargs["timeout_seconds"] == bridge.COLLECTOR_TIMEOUT_SECONDS
    assert kwargs["stdout_limit_bytes"] == bridge.COLLECTOR_STDOUT_LIMIT_BYTES
    assert kwargs["stderr_limit_bytes"] == bridge.COLLECTOR_STDERR_LIMIT_BYTES
    assert kwargs["label"] == "canonical SIXLAB live collector"

    fake_run.responses = [subprocess.CompletedProcess([str(test_node), str(collector)], 0, b"not-json", b"")]
    try:
        bridge._collect_live_correlation(test_node)
    except bridge.BridgeError as error:
        assert str(error) == "canonical SIXLAB live collector returned invalid JSON"
    else:
        raise AssertionError("bad collector JSON was accepted")

    fake_run.responses = [subprocess.CompletedProcess([str(test_node), str(validator)], 1, b"", b"invalid")]
    try:
        bridge._canonical_validation({}, validator, test_node)
    except bridge.BridgeError as error:
        assert str(error) == "canonical SIXLAB contract rejected correlation"
    else:
        raise AssertionError("nonzero validator was accepted")
    command, kwargs = calls.pop()
    assert command == [str(test_node), str(validator), "--validate-snapshot-stdin"]
    assert kwargs["env"] == {}
    assert b"test-token-not-a-live-secret" not in kwargs["input_bytes"]
    assert kwargs["timeout_seconds"] == bridge.VALIDATOR_TIMEOUT_SECONDS
    assert kwargs["stdout_limit_bytes"] == bridge.VALIDATOR_STDOUT_LIMIT_BYTES
    assert kwargs["stderr_limit_bytes"] == bridge.VALIDATOR_STDERR_LIMIT_BYTES
    assert kwargs["label"] == "canonical SIXLAB validator"

    fake_run.responses = [subprocess.CompletedProcess([str(test_node), str(validator)], 0, b"not-json", b"")]
    try:
        bridge._canonical_validation({}, validator, test_node)
    except bridge.BridgeError as error:
        assert str(error) == "canonical SIXLAB validator returned invalid JSON"
    else:
        raise AssertionError("bad validator JSON was accepted")

    # Validator input is rejected before a process can start; the collector's
    # larger runtime budget does not leak into this separate local boundary.
    original_input_limit = bridge.VALIDATOR_INPUT_LIMIT_BYTES
    bridge.VALIDATOR_INPUT_LIMIT_BYTES = 1
    call_count = len(calls)
    try:
        bridge._canonical_validation({}, validator, test_node)
    except bridge.BridgeError as error:
        assert str(error) == "canonical SIXLAB validator input exceeds byte limit"
    else:
        raise AssertionError("oversized validator input started a process")
    finally:
        bridge.VALIDATOR_INPUT_LIMIT_BYTES = original_input_limit
    assert len(calls) == call_count
finally:
    bridge._run_bounded_process = real_run
    for name, value in previous.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value

# Production cannot promote caller-supplied evidence, even with plausible
# timestamps or a forged trusted marker. Rejection precedes live collection.
original_collect = bridge._collect_live_correlation
def no_live_collection(*args, **kwargs):
    raise AssertionError("disabled evidence path attempted live collection")
bridge._collect_live_correlation = no_live_collection
try:
    for evidence in ({}, {42: {"trusted": True, "host": {"observed_at": "2020-01-01T00:00:00Z"}}}):
        try:
            bridge.build_cycle({42: "test"}, evidence)
        except bridge.BridgeError as error:
            assert "trusted same-window" in str(error)
        else:
            raise AssertionError("untrusted evidence admitted")
finally:
    bridge._collect_live_correlation = original_collect

print("SIXLABJITProjectManagerBridgeProductionCollectorSmoke: PASS · manifest gate + isolated Node processes")
