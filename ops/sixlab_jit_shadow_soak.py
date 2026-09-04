#!/usr/bin/env python3
"""Append-only local soak journal for SIXLAB JIT shadow decisions."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
from typing import Any


import sixlab_jit_shadow_controller as shadow


SCHEMA = "sixlab-jit-shadow-soak-v1"
MAX_INPUT_BYTES = 1024 * 1024
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
MAX_EVENTS = 2000
_PROCESS_JOURNAL_LOCK = threading.RLock()
EVENT_KEYS = {
    "event_id",
    "observed_at",
    "status",
    "terminal_complete",
    "binding",
    "snapshot_sha256",
    "decision_sha256",
    "source_receipt_sha256",
    "snapshot",
    "decision",
}
SUMMARY_KEYS = {
    "events",
    "terminal_complete_jobs",
    "target_terminal_jobs",
    "gate_satisfied",
}


class SoakError(RuntimeError):
    pass


def _load(
    path: Path, label: str, maximum_bytes: int = MAX_INPUT_BYTES,
) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise SoakError(f"{label} is missing") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_size > maximum_bytes:
        raise SoakError(f"{label} is unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SoakError(f"{label} is invalid JSON") from error
    if not isinstance(value, dict):
        raise SoakError(f"{label} is not an object")
    return value


def _digest(value: dict[str, Any]) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink():
        raise SoakError("journal directory must not be a symlink")
    raw = (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    if len(raw) > MAX_JOURNAL_BYTES:
        raise SoakError("soak journal size limit reached")
    descriptor, temporary = tempfile.mkstemp(prefix=".sixlab-jit-soak.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = -1
            output.write(raw.decode("utf-8"))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


@contextmanager
def _locked_journal(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink():
        raise SoakError("journal directory must not be a symlink")
    lock_path = path.with_name(path.name + ".lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    with _PROCESS_JOURNAL_LOCK:
        try:
            descriptor = os.open(lock_path, flags, 0o600)
        except OSError as error:
            raise SoakError("soak journal lock is unsafe") from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise SoakError("soak journal lock is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def _decision_binding(decision: dict[str, Any]) -> dict[str, Any]:
    selected = decision.get("selected_job")
    if isinstance(selected, dict):
        return selected
    evidence = decision.get("evidence")
    if not isinstance(evidence, dict):
        raise SoakError("decision has no evidence binding")
    return {
        "repository": evidence.get("repository"),
        "pull_number": evidence.get("pull_number"),
        "head_sha": evidence.get("current_head"),
        "run_id": evidence.get("run_id"),
        "run_attempt": evidence.get("latest_attempt"),
        "job_id": None,
        "family": None,
        "exact_label": None,
    }


def _event(snapshot: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
    recomputed = shadow.evaluate(snapshot)
    if recomputed != decision:
        raise SoakError("decision does not match the canonical evaluator")
    snapshot_digest = _digest(snapshot)
    decision_digest = _digest(decision)
    event_id = hashlib.sha256(
        f"{snapshot_digest}:{decision_digest}".encode("utf-8")
    ).hexdigest()
    terminal = decision.get("status") == "shadow-teardown-verified"
    return {
        "event_id": event_id,
        "observed_at": decision.get("observed_at"),
        "status": decision.get("status"),
        "terminal_complete": terminal,
        "binding": _decision_binding(decision),
        "snapshot_sha256": snapshot_digest,
        "decision_sha256": decision_digest,
        "source_receipt_sha256": (
            decision.get("evidence", {}).get("source_receipt_sha256")
            if terminal else None
        ),
        "snapshot": snapshot,
        "decision": decision,
    }


def _validate_event(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != EVENT_KEYS:
        raise SoakError("persisted soak event fields are invalid")
    snapshot = value.get("snapshot")
    decision = value.get("decision")
    if not isinstance(snapshot, dict) or not isinstance(decision, dict):
        raise SoakError("persisted soak evidence is missing")
    try:
        expected = _event(snapshot, decision)
    except shadow.ShadowError as error:
        raise SoakError("persisted soak evidence is not canonical") from error
    if value != expected:
        raise SoakError("persisted soak event failed canonical validation")
    return value


def _summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    terminal_keys = {
        (
            item["binding"].get("repository"),
            item["binding"].get("head_sha"),
            item["binding"].get("run_id"),
            item["binding"].get("run_attempt"),
            item["binding"].get("job_id"),
        )
        for item in events
        if item["terminal_complete"] is True
    }
    return {
        "events": len(events),
        "terminal_complete_jobs": len(terminal_keys),
        "target_terminal_jobs": 20,
        "gate_satisfied": len(terminal_keys) >= 20,
    }


def _journal(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "schema": SCHEMA,
            "repository": shadow.EXPECTED_REPOSITORY,
            "events": [],
            "summary": {
                "events": 0,
                "terminal_complete_jobs": 0,
                "target_terminal_jobs": 20,
                "gate_satisfied": False,
            },
        }
    value = _load(path, "soak journal", MAX_JOURNAL_BYTES)
    if (
        set(value) != {"schema", "repository", "events", "summary"}
        or value["schema"] != SCHEMA
        or value["repository"] != shadow.EXPECTED_REPOSITORY
        or not isinstance(value["events"], list)
        or len(value["events"]) > MAX_EVENTS
        or not isinstance(value["summary"], dict)
        or set(value["summary"]) != SUMMARY_KEYS
    ):
        raise SoakError("soak journal binding is invalid")
    events = [_validate_event(item) for item in value["events"]]
    if len({item["event_id"] for item in events}) != len(events):
        raise SoakError("soak journal contains duplicate events")
    if value["summary"] != _summary(events):
        raise SoakError("soak journal summary is not canonical")
    return value


def append_event(
    *, snapshot: dict[str, Any], decision: dict[str, Any], journal_path: Path,
) -> dict[str, Any]:
    event = _event(snapshot, decision)
    with _locked_journal(journal_path):
        journal = _journal(journal_path)
        if not any(item["event_id"] == event["event_id"] for item in journal["events"]):
            if len(journal["events"]) >= MAX_EVENTS:
                raise SoakError("soak journal event limit reached")
            journal["events"].append(event)
        journal["summary"] = _summary(journal["events"])
        _atomic(journal_path, journal)
        return journal


def main() -> int:
    parser = argparse.ArgumentParser(description="Append one SIXLAB JIT shadow soak event")
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--decision", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        journal = append_event(
            snapshot=_load(arguments.snapshot, "snapshot"),
            decision=_load(arguments.decision, "decision"),
            journal_path=arguments.journal,
        )
    except (SoakError, shadow.ShadowError) as error:
        print(json.dumps({
            "schema": SCHEMA,
            "status": "CHECK-INCOMPLETE",
            "live_mutation_allowed": False,
            "error": str(error),
        }, separators=(",", ":"), sort_keys=True))
        return 2
    print(json.dumps(journal["summary"], separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
