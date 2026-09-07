#!/usr/bin/env python3
"""Hostile subprocess fixture for the ProjectManager bridge boundary."""

from pathlib import Path
import os
import signal
import subprocess
import sys
import time


mode = sys.argv[1]
arguments = sys.argv[2:]


def record_pid(path: str) -> None:
    Path(path).write_text(str(os.getpid()), encoding="ascii")


if mode == "stdout":
    record_pid(arguments[0])
    while True:
        os.write(sys.stdout.fileno(), b"o" * 65536)
elif mode == "stderr":
    record_pid(arguments[0])
    while True:
        os.write(sys.stderr.fileno(), b"e" * 65536)
elif mode == "hang":
    record_pid(arguments[0])
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(60)
elif mode == "descendant-holds-pipe":
    subprocess.Popen(
        [sys.executable, __file__, "hang", arguments[0]],
        stdin=subprocess.DEVNULL,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    deadline = time.monotonic() + 2.0
    while not Path(arguments[0]).exists() and time.monotonic() < deadline:
        time.sleep(0.01)
elif mode == "descendant-closes-pipes":
    subprocess.Popen(
        [sys.executable, __file__, "hang", arguments[0]],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 2.0
    while not Path(arguments[0]).exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    raise SystemExit(int(arguments[1]))
elif mode == "leader-closes-pipes":
    os.close(sys.stdout.fileno())
    os.close(sys.stderr.fileno())
    time.sleep(float(arguments[0]))
    os._exit(int(arguments[1]))
elif mode == "normal":
    os.write(sys.stdout.fileno(), b"n" * int(arguments[0]))
elif mode == "stdin-length":
    raw = sys.stdin.buffer.read()
    os.write(sys.stdout.fileno(), str(len(raw)).encode("ascii"))
elif mode == "nonzero":
    os.write(sys.stderr.fileno(), b"expected failure")
    raise SystemExit(7)
else:
    raise SystemExit(64)
