#!/usr/bin/env python3
"""Authorize a future actuator without ever handling a Runner token.

This is the narrow shadow-to-actuator boundary.  It re-evaluates a fresh
all-open-PR cycle and immutable launcher manifest.  Its output is an auditable
token-pending command contract, never a host command.  A separately authorized
runtime may supply a short-lived token on stdin at dispatch time; this module
does not accept, read, log, or persist that stream.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any

import sixlab_jit_serial_scheduler as scheduler
import sixlab_jit_launcher_generator as generator


SCHEMA = "sixlab-jit-actuator-admission-v1"
MANIFEST_SCHEMA = "sixlab-jit-launcher-candidate-v1"


class ActuatorAdmissionError(RuntimeError):
    pass


def _digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, separators=(",", ":"), sort_keys=True).encode()).hexdigest()


def _manifest(value: object, selected: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != MANIFEST_SCHEMA:
        raise ActuatorAdmissionError("launcher manifest schema is invalid")
    slot = value.get("slot")
    if not isinstance(slot, str) or generator.SLOT_FAMILIES.get(slot) != selected["family"]:
        raise ActuatorAdmissionError("launcher manifest slot and family drifted")
    try:
        _rendered, expected = generator.render(
            selected["pull_number"], selected["head_sha"], selected["run_attempt"], slot,
        )
    except generator.GeneratorError as error:
        raise ActuatorAdmissionError("reviewed launcher template is unavailable") from error
    # A manifest is an assertion made by untrusted input until every field is
    # equal to a fresh render from the reviewed, digest-pinned template.  This
    # also rejects unknown keys and a forged launcher/digest pair.
    if value != expected:
        raise ActuatorAdmissionError("launcher manifest is not the reviewed canonical render")
    return expected


def admit(schedule: object, cycle: object, manifest: object, launcher: bytes) -> dict[str, Any]:
    if not isinstance(schedule, dict) or schedule.get("schema") != scheduler.SCHEMA:
        raise ActuatorAdmissionError("schedule schema is invalid")
    fresh = scheduler.evaluate(cycle)
    if schedule.get("status") != "shadow-serial-ready" or fresh.get("status") != "shadow-serial-ready":
        raise ActuatorAdmissionError("serial scheduler is not ready for actuator admission")
    selected = scheduler._binding(schedule.get("selected_job"))
    if selected != scheduler._binding(fresh.get("selected_job")):
        raise ActuatorAdmissionError("fresh cycle selected job drifted")
    validated_manifest = _manifest(manifest, selected)
    expected_launcher, _expected_manifest = generator.render(
        selected["pull_number"], selected["head_sha"], selected["run_attempt"],
        validated_manifest["slot"],
    )
    if launcher != expected_launcher.encode("utf-8") or hashlib.sha256(launcher).hexdigest() != validated_manifest["rendered_sha256"]:
        raise ActuatorAdmissionError("immutable launcher digest drifted")
    return {
        "schema": SCHEMA,
        "status": "actuator-token-pending",
        "schedule_digest": _digest(schedule),
        "selected_job": selected,
        "launcher_rendered_sha256": validated_manifest["rendered_sha256"],
        "launcher_source_sha256": validated_manifest["source_sha256"],
        "token_transport": "stdin-short-lived-only",
        "token_read": False,
        "token_persisted": False,
        "runner_mutation_allowed": False,
        "required_readbacks": [
            "fresh-open-pr-inventory", "fresh-current-head", "fresh-latest-attempt-job",
            "fresh-clean-host", "runner-service-receipt-binding",
        ],
        "next_action": "external-explicit-authorization-required",
    }


def _load(path: Path, label: str) -> object:
    if path.is_symlink():
        raise ActuatorAdmissionError(f"{label} must not be a symlink")
    try:
        return json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActuatorAdmissionError(f"{label} is unreadable") from error


def _launcher(path: Path) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ActuatorAdmissionError("launcher must be a regular non-symlink file")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ActuatorAdmissionError("launcher must not be group- or world-writable")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    except OSError as error:
        raise ActuatorAdmissionError("launcher is unreadable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".sixlab-jit-actuator.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = -1
            json.dump(value, output, separators=(",", ":"), sort_keys=True)
            output.write("\n")
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a no-token SIXLAB JIT actuator admission contract")
    parser.add_argument("--schedule", required=True, type=Path)
    parser.add_argument("--cycle", required=True, type=Path)
    parser.add_argument("--launcher-manifest", required=True, type=Path)
    parser.add_argument("--launcher", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        result = admit(
            _load(arguments.schedule, "schedule"), _load(arguments.cycle, "cycle"),
            _load(arguments.launcher_manifest, "launcher manifest"), _launcher(arguments.launcher),
        )
        if arguments.output is not None:
            _atomic(arguments.output, result)
    except (ActuatorAdmissionError, scheduler.SerialSchedulerError, scheduler.inventory.InventoryError, scheduler.inventory.shadow.ShadowError) as error:
        result = {"schema": SCHEMA, "status": "CHECK-INCOMPLETE", "token_read": False, "runner_mutation_allowed": False, "blockers": [str(error)]}
        if arguments.output is not None:
            _atomic(arguments.output, result)
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 2
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
