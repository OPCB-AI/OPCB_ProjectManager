#!/usr/bin/env python3
"""Exercise A's non-admitting production collector boundary.

Successful collection is proved by the vendored B test suite.  This test never
uses NODE_OPTIONS or a mocked subprocess: it verifies that A accepts no
external collector path and fails closed before a real GitHub request.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys


project = Path(__file__).resolve().parent.parent
ops = project / "ops"
sys.path.insert(0, str(ops))
spec = importlib.util.spec_from_file_location("bridge", ops / "sixlab_jit_pr_runner_bridge.py")
bridge = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bridge)

assert bridge._trusted_node().is_file()
assert bridge._pinned_validator().is_file()
assert bridge._vendored_b()["scripts/ci/collect-pr-runner-correlation.mjs"].is_file()

previous_token = os.environ.get("GITHUB_TOKEN")
try:
    os.environ.pop("GITHUB_TOKEN", None)
    try:
        bridge._collect_live_correlation()
    except bridge.BridgeError as error:
        assert "requires GITHUB_TOKEN" in str(error)
    else:
        raise AssertionError("tokenless production collection was accepted")
finally:
    if previous_token is not None:
        os.environ["GITHUB_TOKEN"] = previous_token

print("SIXLABJITProjectManagerBridgeProductionCollectorSmoke: PASS · no-token production path fails closed")
