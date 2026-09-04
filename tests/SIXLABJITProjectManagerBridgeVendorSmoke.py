#!/usr/bin/env python3
"""Prove B provenance is self-contained and fails closed on drift."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import shutil
import sys
import tempfile


project = Path(__file__).resolve().parent.parent
ops = project / "ops"
sys.path.insert(0, str(ops))
spec = importlib.util.spec_from_file_location("bridge", ops / "sixlab_jit_pr_runner_bridge.py")
bridge = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bridge)

assert bridge.SOURCE_REPOSITORY == "Steven-ZYH/sixlab"
assert bridge.SOURCE_PULL_REQUEST == 1201
assert bridge.SOURCE_HEAD == "1efdfd2d754822d29d4f0a4f93b48117a663116f"
assert bridge._digest((bridge.VENDOR_ROOT / "provenance.json").read_bytes()) == bridge.CANONICAL_MANIFEST_SHA256
assert bridge._digest((bridge.VENDOR_ROOT / "scripts/ci/collect-pr-runner-correlation.mjs").read_bytes()) == bridge.CANONICAL_COLLECTOR_SHA256

with tempfile.TemporaryDirectory(prefix="opcb-pm-vendor-smoke-") as temporary:
    root = Path(temporary) / "vendor"
    shutil.copytree(bridge.VENDOR_ROOT, root)
    original_root = bridge.VENDOR_ROOT
    try:
        bridge.VENDOR_ROOT = root
        pinned = bridge._vendored_b()
        assert set(pinned) == set(bridge.VENDOR_FILES)

        collector = root / "scripts/ci/collect-pr-runner-correlation.mjs"
        collector.write_bytes(collector.read_bytes() + b"\n// drift\n")
        try:
            bridge._vendored_b()
        except bridge.BridgeError as error:
            assert "file digest drifted" in str(error)
        else:
            raise AssertionError("modified vendor collector was accepted")

        shutil.copyfile(original_root / "scripts/ci/collect-pr-runner-correlation.mjs", collector)
        manifest = root / "provenance.json"
        manifest.write_bytes(manifest.read_bytes() + b"\n")
        try:
            bridge._vendored_b()
        except bridge.BridgeError as error:
            assert "provenance manifest digest drifted" in str(error)
        else:
            raise AssertionError("replacement provenance manifest was accepted")
    finally:
        bridge.VENDOR_ROOT = original_root

print("SIXLABJITProjectManagerBridgeVendorSmoke: PASS · provenance + vendor drift rejected")
