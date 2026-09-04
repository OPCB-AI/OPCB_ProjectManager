#!/usr/bin/env python3
"""Exercise the production installed-vendor trust boundary without installing it.

The temporary tree is intentionally only a model of a root-administered
installation.  It never calls ``build_cycle`` and never supplies a live token.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
from types import SimpleNamespace


project = Path(__file__).resolve().parent.parent
ops = project / "ops"
sys.path.insert(0, str(ops))
spec = importlib.util.spec_from_file_location("bridge", ops / "sixlab_jit_pr_runner_bridge.py")
bridge = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bridge)


def rejected(action, needle: str) -> None:
    try:
        action()
    except bridge.BridgeError as error:
        assert needle in str(error), str(error)
    else:
        raise AssertionError(f"unsafe case was accepted: {needle}")


# Owner/mode gates are independently deterministic, including writable vendor
# directories and parents.  The process running this smoke cannot chown a
# temporary directory to root, so this tests the metadata gate directly and
# uses a separate modeled root installation below.
rejected(
    lambda: bridge._safe_root_metadata(SimpleNamespace(st_uid=501, st_mode=stat.S_IFDIR | 0o755), "vendor root"),
    "not root-owned",
)
rejected(
    lambda: bridge._safe_root_metadata(SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o775), "vendor root"),
    "unsafe write permissions",
)
rejected(
    lambda: bridge._safe_root_metadata(SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o757), "vendor parent"),
    "unsafe write permissions",
)
rejected(
    lambda: bridge._safe_root_metadata(SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o644), "collector", immutable=True),
    "not immutable",
)

with tempfile.TemporaryDirectory(prefix="opcb-pm-installed-vendor-") as temporary:
    root = Path(temporary) / "installed" / "sixlab-pr1201"
    root.parent.mkdir(parents=True)
    shutil.copytree(bridge.VENDOR_ROOT, root)
    old_root = bridge.INSTALLED_VENDOR_ROOT
    old_manifest = bridge.NODE_TRUST_MANIFEST
    old_safe_path = bridge._root_owned_safe_path
    old_verified_file = bridge._verified_root_owned_file
    bridge.INSTALLED_VENDOR_ROOT = root
    bridge.NODE_TRUST_MANIFEST = Path(temporary) / "trust.json"

    # This smoke models only the root ownership that production checks in the
    # helper above.  It keeps the actual lstat/read/digest/inode checks live.
    bridge._root_owned_safe_path = lambda path, label: None

    def modeled_verified(path: Path, label: str, expected: str | None, **_kwargs):
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise bridge.BridgeError(f"{label} changed while it was verified")
        raw = path.read_bytes()
        if expected is not None and bridge._digest(raw) != expected:
            raise bridge.BridgeError(f"{label} digest drifted")
        return bridge._VerifiedFile(
            path, metadata.st_dev, metadata.st_ino, stat.S_IMODE(metadata.st_mode), 0,
            bridge._digest(raw), raw,
        )

    bridge._verified_root_owned_file = modeled_verified
    try:
        manifest = {
            "schema": bridge.NODE_TRUST_SCHEMA,
            "node": {"path": "/root-owned-node-not-executed", "sha256": "0" * 64},
            "vendor": {
                "root": str(root),
                "provenance_sha256": bridge.CANONICAL_MANIFEST_SHA256,
                "files": bridge.VENDOR_FILES,
            },
        }
        # The node verification is intentionally replaced: this test exercises
        # vendor admission only and must not install or invoke a real Node.
        bridge._verified_root_owned_file = lambda path, label, digest, **kwargs: (
            modeled_verified(path, label, digest) if path != Path(manifest["node"]["path"])
            else bridge._VerifiedFile(path, 1, 1, 0o755, 0, digest)
        )
        bridge.NODE_TRUST_MANIFEST.write_text(__import__("json").dumps(manifest))
        node, bundle = bridge._trusted_runtime()
        assert bundle.root == root
        collector = bundle.executable_path("scripts/ci/collect-pr-runner-correlation.mjs")
        assert collector.parent == root / "scripts/ci"
        assert node.path == Path("/root-owned-node-not-executed")

        # A post-check permission change is detected from the same pathname.
        collector.chmod(0o600)
        rejected(lambda: bundle.executable_path("scripts/ci/collect-pr-runner-correlation.mjs"), "identity drifted")
        collector.chmod(0o644)
        _node, bundle = bridge._trusted_runtime()

        # A post-check content change cannot keep its old digest binding.
        collector.write_bytes(collector.read_bytes() + b"\n// drift\n")
        rejected(lambda: bridge._trusted_runtime(), "digest drifted")
        shutil.copyfile(bridge.VENDOR_ROOT / "scripts/ci/collect-pr-runner-correlation.mjs", collector)
        _node, bundle = bridge._trusted_runtime()

        # Replacing a digest-matching-looking path after verification changes
        # the inode and is rejected just before execution.
        original = collector.read_bytes()
        replacement = collector.with_suffix(".replacement")
        replacement.write_bytes(original)
        os.replace(replacement, collector)
        rejected(lambda: bundle.executable_path("scripts/ci/collect-pr-runner-correlation.mjs"), "identity drifted")

        # A symlink fails before a collector could start.
        shutil.copyfile(bridge.VENDOR_ROOT / "scripts/ci/collect-pr-runner-correlation.mjs", collector)
        collector.unlink()
        collector.symlink_to(bridge.VENDOR_ROOT / "scripts/ci/collect-pr-runner-correlation.mjs")
        rejected(lambda: bridge._trusted_runtime(), "changed while it was verified")
    finally:
        bridge.INSTALLED_VENDOR_ROOT = old_root
        bridge.NODE_TRUST_MANIFEST = old_manifest
        bridge._root_owned_safe_path = old_safe_path
        bridge._verified_root_owned_file = old_verified_file

print("SIXLABJITProjectManagerBridgeInstalledVendorSmoke: PASS · installed root + owner/mode/symlink/inode/digest drift rejected")
