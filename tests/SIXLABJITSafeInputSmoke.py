#!/usr/bin/env python3
"""Adversarial regular-file boundaries, without host or token access."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ops"))
import sixlab_jit_safe_input as safe
import sixlab_jit_actuator_admission as actuator
import sixlab_jit_serial_scheduler as scheduler
import sixlab_jit_shadow_collector as collector


def rejects(callback):
    try:
        callback()
    except (OSError, ValueError, RuntimeError):
        return
    raise AssertionError("unsafe input accepted")


def main():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        regular = root / "regular"
        regular.write_bytes(b"{}")
        regular.chmod(0o600)
        assert safe.read_regular(regular, 2) == b"{}"
        rejects(lambda: safe.read_regular(regular, 1))
        symlink = root / "link"
        symlink.symlink_to(regular)
        fifo = root / "fifo"
        os.mkfifo(fifo)
        # Run potentially blocking FIFO cases in a bounded subprocess.
        if len(sys.argv) > 1:
            raise AssertionError("unexpected arguments")
        for path in (symlink, fifo, root):
            code = """import sys
sys.path.insert(0, sys.argv[1])
import sixlab_jit_actuator_admission as a
import sixlab_jit_serial_scheduler as s
import sixlab_jit_shadow_collector as c
for callback in (lambda: a._load(__import__('pathlib').Path(sys.argv[2]), 'input'), lambda: a._launcher(__import__('pathlib').Path(sys.argv[2])), lambda: s.load_cycle(__import__('pathlib').Path(sys.argv[2])), lambda: c._canonical_input(__import__('pathlib').Path(sys.argv[2]), 'input'), lambda: c._load_history(__import__('pathlib').Path(sys.argv[2]), 2)):
    try: callback()
    except (RuntimeError, ValueError, OSError): pass
    else: raise AssertionError('unsafe input accepted')
"""
            subprocess.run([sys.executable, "-c", code, sys.path[0], str(path)], check=True, timeout=5)
        regular.chmod(0o622)
        rejects(lambda: actuator._launcher(regular))
        rejects(lambda: collector._load_history(regular, 2))
        regular.chmod(0o600)
        # Simulate growth after fstat: the stream never ends, despite st_size=2.
        reads = []
        descriptors = []
        actual_close = os.close
        def growing(descriptor, count):
            reads.append(count)
            return b"x" * count
        def close(descriptor):
            descriptors.append(descriptor)
            actual_close(descriptor)
        with mock.patch.object(safe.os, "read", side_effect=growing), mock.patch.object(safe.os, "close", side_effect=close):
            rejects(lambda: safe.read_regular(regular, 100000))
        assert sum(reads) == 100001 and len(descriptors) == 1
        assert collector._load_history(root / "missing", 2) == []
    print("SIXLAB JIT safe input smoke: PASS")


if __name__ == "__main__":
    main()
