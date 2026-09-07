#!/usr/bin/env python3
"""Recollect trusted evidence in-process; JSON output is not a capability.

This emits no command or Runner token. A future privileged consumer must
recollect for itself; a saved token-pending report is never authorization.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import sys
from typing import Any

# Isolated installed entrypoint only. -I excludes the script directory and
# -S disables site hooks; never bootstrap a caller-selected import directory.
if __name__ == "__main__" and sys.flags.isolated and sys.flags.no_site:
    sys.path[:] = [entry for entry in sys.path if entry and Path(entry).exists()]
    sys.path.insert(0, "/var/lib/opcb/sixlab-jit/projectmanager/ops")

import sixlab_jit_serial_scheduler as scheduler
import sixlab_jit_launcher_generator as generator
from sixlab_jit_safe_input import read_regular


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


def admit(schedule: object, cycle: object, manifest: object, launcher: bytes, *,
          selections: object = None) -> dict[str, Any]:
    if not isinstance(schedule, dict) or schedule.get("schema") != scheduler.SCHEMA:
        raise ActuatorAdmissionError("schedule schema is invalid")
    collected = None
    if cycle is None:
        # No caller-supplied evidence enters the production branch. The fixed
        # root deployment gate precedes credential access or network reads.
        import sixlab_jit_trusted_deployment as deployment
        import sixlab_jit_trusted_cycle as trusted
        try:
            runtime = deployment.load_runtime()
            collected = trusted._collect(runtime, selections)
        except (deployment.bridge.BridgeError, trusted.TrustedCycleError,
                trusted.collector.CollectorError) as error:
            raise ActuatorAdmissionError(str(error)) from error
        fresh = scheduler.evaluate(collected.cycle)
    else:
        # Compatibility diagnostics retain structural error reporting, never
        # admission authority even if --selections is provided as well.
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
    if collected is None:
        raise ActuatorAdmissionError("trusted same-window evidence requires in-process collection, not caller cycle")
    try:
        collected.assert_fresh()
    except (deployment.bridge.BridgeError, trusted.TrustedCycleError) as error:
        raise ActuatorAdmissionError(str(error)) from error
    return {
        "schema": SCHEMA, "status": "actuator-token-pending",
        "schedule_digest": _digest(fresh), "selected_job": selected,
        "launcher_rendered_sha256": validated_manifest["rendered_sha256"],
        "launcher_source_sha256": validated_manifest["source_sha256"],
        "token_transport": "stdin-short-lived-only", "token_read": False,
        "token_persisted": False, "runner_mutation_allowed": False,
        "evidence_mode": "same-process-root-installed-recollection",
        "required_readbacks": ["fresh-open-pr-inventory", "fresh-current-head",
            "fresh-latest-attempt-job", "fresh-clean-host", "runner-service-receipt-binding"],
        "next_action": "external-explicit-authorization-and-recollection-required",
    }


def _load(path: Path, label: str) -> object:
    try:
        return json.loads(read_regular(path, 8 * 1024 * 1024))
    except (OSError, ValueError) as error:
        raise ActuatorAdmissionError(f"{label} is unreadable") from error


def _launcher(path: Path) -> bytes:
    try:
        return read_regular(path, 1024 * 1024, reject_writable=True)
    except (OSError, ValueError) as error:
        raise ActuatorAdmissionError("launcher is unreadable") from error


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
    parser.add_argument("--cycle", type=Path, help="legacy diagnostic input; cannot admit")
    parser.add_argument("--selections", type=Path, help="explicit PR-to-workflow intent; never evidence")
    parser.add_argument("--launcher-manifest", required=True, type=Path)
    parser.add_argument("--launcher", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.output is not None and (arguments.cycle is None or os.geteuid() == 0):
        parser.error("production/root admission reports use stdout only; no caller-selected output writes")
    try:
        result = admit(
            _load(arguments.schedule, "schedule"), _load(arguments.cycle, "cycle") if arguments.cycle else None,
            _load(arguments.launcher_manifest, "launcher manifest"), _launcher(arguments.launcher),
            selections=_load(arguments.selections, "selections") if arguments.selections else None,
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
