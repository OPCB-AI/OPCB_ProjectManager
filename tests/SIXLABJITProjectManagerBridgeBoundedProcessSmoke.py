#!/usr/bin/env python3
"""Exercise hard deadlines, bounded streaming, and process-group cleanup."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time


project = Path(__file__).resolve().parent.parent
ops = project / "ops"
sys.path.insert(0, str(ops))
spec = importlib.util.spec_from_file_location("bridge", ops / "sixlab_jit_pr_runner_bridge.py")
bridge = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bridge)
fixture = project / "tests" / "fixtures" / "sixlab-jit-bounded-child.py"


def run_fixture(
    mode: str, *arguments: str, input_bytes: bytes | None = None,
    timeout: float = 1.0, stdout_limit: int = 128, stderr_limit: int = 128,
    env: dict[str, str] | None = None,
):
    return bridge._run_bounded_process(
        [sys.executable, str(fixture), mode, *arguments],
        input_bytes=input_bytes,
        env={} if env is None else env,
        timeout_seconds=timeout,
        stdout_limit_bytes=stdout_limit,
        stderr_limit_bytes=stderr_limit,
        label=f"fixture {mode}",
    )


def expect_error(expected: str, callback) -> float:
    started = time.monotonic()
    try:
        callback()
    except bridge.BridgeError as error:
        assert str(error) == expected, (str(error), expected)
    else:
        raise AssertionError(f"missing BridgeError: {expected}")
    return time.monotonic() - started


def read_pid(path: Path) -> int:
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if path.exists():
            return int(path.read_text(encoding="ascii"))
        time.sleep(0.01)
    raise AssertionError(f"fixture did not publish pid: {path}")


def assert_gone(pid: int) -> None:
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.02)
    raise AssertionError(f"subprocess survived cleanup: {pid}")


# Exact boundaries are accepted; one byte beyond either stream is rejected
# while streaming, without first buffering the full hostile output.
completed = run_fixture("normal", "128")
assert completed.returncode == 0 and completed.stdout == b"n" * 128
expect_error(
    "fixture normal stdout exceeds byte limit",
    lambda: run_fixture("normal", "129"),
)

completed = run_fixture("stdin-length", input_bytes=b"v" * 4096)
assert completed.returncode == 0 and completed.stdout == b"4096"

completed = run_fixture("nonzero")
assert completed.returncode == 7 and completed.stderr == b"expected failure"

# Every failure after Popen must still kill and reap the direct child.  Force
# selector construction to fail and inspect the captured Popen object.
original_popen = bridge.subprocess.Popen
original_selector = bridge.selectors.DefaultSelector
captured_processes = []


def capture_popen(*args, **kwargs):
    process = original_popen(*args, **kwargs)
    captured_processes.append(process)
    return process


def fail_selector():
    raise OSError("forced selector setup failure")


try:
    bridge.subprocess.Popen = capture_popen
    bridge.selectors.DefaultSelector = fail_selector
    expect_error(
        "fixture hang process setup failed",
        lambda: run_fixture("hang", "/dev/null"),
    )
finally:
    bridge.subprocess.Popen = original_popen
    bridge.selectors.DefaultSelector = original_selector
assert len(captured_processes) == 1 and captured_processes[0].poll() is not None

# Pipe EOF is not leader completion.  A leader may close both streams and keep
# doing valid work; preserve its eventual status instead of killing it early.
for returncode in (0, 7):
    started = time.monotonic()
    completed = run_fixture("leader-closes-pipes", "0.2", str(returncode))
    assert completed.returncode == returncode
    assert time.monotonic() - started >= 0.15

# Linux pidfds may be allocated above select(2)'s FD_SETSIZE.  Force a real
# high-numbered pidfd when the process limit permits it; DefaultSelector must
# still observe the child exit (epoll on Linux).
if hasattr(os, "pidfd_open"):
    held_fds: list[int] = []
    try:
        while not held_fds or held_fds[-1] < 1100:
            held_fds.append(os.open("/dev/null", os.O_RDONLY))
        completed = run_fixture("normal", "1")
        assert completed.returncode == 0 and completed.stdout == b"n"
    except OSError as error:
        if error.errno != 24:  # EMFILE means a high descriptor cannot exist here.
            raise
    finally:
        for descriptor in held_fds:
            os.close(descriptor)

with tempfile.TemporaryDirectory(prefix="opcb-bridge-bounded-") as directory:
    root = Path(directory)
    stdout_pid = root / "stdout.pid"
    expect_error(
        "fixture stdout stdout exceeds byte limit",
        lambda: run_fixture("stdout", str(stdout_pid), stdout_limit=1024),
    )
    assert_gone(read_pid(stdout_pid))

    stderr_pid = root / "stderr.pid"
    expect_error(
        "fixture stderr stderr exceeds byte limit",
        lambda: run_fixture("stderr", str(stderr_pid), stderr_limit=1024),
    )
    assert_gone(read_pid(stderr_pid))

    hang_pid = root / "hang.pid"
    elapsed = expect_error(
        "fixture hang timed out",
        lambda: run_fixture(
            "hang", str(hang_pid), timeout=0.2,
            env={"GITHUB_TOKEN": "ephemeral-test-token"},
        ),
    )
    assert elapsed < 0.2 + bridge.PROCESS_REAP_TIMEOUT_SECONDS + 0.5
    assert_gone(read_pid(hang_pid))

    descendant_pid = root / "descendant.pid"
    elapsed = expect_error(
        "fixture descendant-holds-pipe timed out",
        lambda: run_fixture("descendant-holds-pipe", str(descendant_pid), timeout=1.0),
    )
    assert elapsed < 1.0 + bridge.PROCESS_REAP_TIMEOUT_SECONDS + 0.5
    assert_gone(read_pid(descendant_pid))

    exited_pid = root / "exited-leader-descendant.pid"
    completed = run_fixture("leader-exits-with-pipe-holder", str(exited_pid), timeout=3.0)
    assert completed.returncode == 0
    assert_gone(read_pid(exited_pid))

    # A leader's normal or nonzero exit does not authorize a detached member
    # of its process group to retain the collector environment after return.
    for returncode in (0, 7):
        closed_pipe_pid = root / f"closed-pipe-{returncode}.pid"
        completed = run_fixture(
            "descendant-closes-pipes", str(closed_pipe_pid), str(returncode),
            env={"GITHUB_TOKEN": "ephemeral-test-token"},
        )
        assert completed.returncode == returncode
        assert_gone(read_pid(closed_pipe_pid))

print("SIXLABJITProjectManagerBridgeBoundedProcessSmoke: PASS · bounded streams + deadline + group cleanup")
