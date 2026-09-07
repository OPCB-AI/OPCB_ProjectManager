#!/usr/bin/env python3
"""Fail-closed, one-job scheduler above the R1 SIXLAB JIT shadow contracts.

This module is deliberately a pure evaluator.  A read-only collector supplies
one bounded cycle containing every currently-open PR's latest-attempt snapshot;
the scheduler chooses no more than one exact job.  It neither mints nor reads a
token, starts a Runner, invokes GitHub, or touches the host.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from typing import Any

import sixlab_jit_shadow_inventory as inventory


SCHEMA = "sixlab-jit-serial-schedule-v1"
CYCLE_SCHEMA = "sixlab-jit-open-pr-cycle-v1"
MAX_SNAPSHOTS = inventory.MAX_SNAPSHOTS
REQUIRED_BINDING = frozenset({
    "repository", "pull_number", "head_sha", "run_id", "run_attempt",
    "job_id", "family", "exact_label",
})


class SerialSchedulerError(RuntimeError):
    pass


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise SerialSchedulerError("cycle.observed_at is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise SerialSchedulerError("cycle.observed_at is invalid") from error
    if parsed.tzinfo != timezone.utc:
        raise SerialSchedulerError("cycle.observed_at is not UTC")
    return parsed


def _cycle(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema", "observed_at", "open_pull_numbers", "snapshots",
    }:
        raise SerialSchedulerError("cycle fields are not canonical")
    if value["schema"] != CYCLE_SCHEMA:
        raise SerialSchedulerError("cycle.schema is invalid")
    _timestamp(value["observed_at"])
    pulls = value["open_pull_numbers"]
    snapshots = value["snapshots"]
    if (
        not isinstance(pulls, list)
        or not pulls
        or len(pulls) > MAX_SNAPSHOTS
        or any(type(pull) is not int or pull <= 0 for pull in pulls)
        or len(set(pulls)) != len(pulls)
        or not isinstance(snapshots, list)
        or len(snapshots) != len(pulls)
        or any(not isinstance(snapshot, dict) for snapshot in snapshots)
    ):
        raise SerialSchedulerError("open PR inventory is invalid")
    snapshot_pulls = [snapshot.get("pull", {}).get("number") for snapshot in snapshots]
    if any(type(pull) is not int for pull in snapshot_pulls) or set(snapshot_pulls) != set(pulls):
        raise SerialSchedulerError("open PR inventory is incomplete")
    return value


def _binding(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != REQUIRED_BINDING:
        raise SerialSchedulerError("selected job binding is not canonical")
    if (
        value["repository"] != inventory.shadow.EXPECTED_REPOSITORY
        or type(value["pull_number"]) is not int
        or type(value["run_id"]) is not int
        or type(value["run_attempt"]) is not int
        or type(value["job_id"]) is not int
        or value["family"] not in inventory.shadow.ALLOWED_FAMILIES
        or value["exact_label"] != inventory.shadow.exact_label(value["head_sha"], value["family"])
    ):
        raise SerialSchedulerError("selected job binding is invalid")
    inventory.shadow._sha(value["head_sha"], "selected_job.head_sha")
    return value


def evaluate(cycle: object) -> dict[str, Any]:
    source = _cycle(cycle)
    global_decision = inventory.select_global(source["snapshots"])
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "observed_at": source["observed_at"],
        "repository": inventory.shadow.EXPECTED_REPOSITORY,
        "evaluated_open_pull_numbers": sorted(source["open_pull_numbers"]),
        "status": "CHECK-INCOMPLETE",
        "selected_job": None,
        "eligible_job_ids": [],
        "selection_mode": "none",
        "next_action": "hold",
        "token_transport": "stdin-short-lived-only",
        "token_allowed": False,
        "runner_mutation_allowed": False,
        "launcher_digest_required": True,
        "blockers": [],
    }
    status = global_decision["status"]
    if status == "shadow-global-admit":
        selected = _binding(global_decision["selected_job"])
        result.update({
            "status": "shadow-serial-ready",
            "selected_job": selected,
            "eligible_job_ids": global_decision["eligible_job_ids"],
            "selection_mode": global_decision["selection_mode"],
            "next_action": "actuator-admission-required",
        })
    elif status == "shadow-global-running":
        result.update({
            "status": "shadow-serial-await-terminal-teardown",
            "selected_job": _binding(global_decision["selected_job"]),
            "eligible_job_ids": global_decision["eligible_job_ids"],
            "selection_mode": "actual-binding",
            "next_action": "reconcile-terminal-teardown",
        })
    elif status == "shadow-global-idle":
        result.update({"status": "shadow-serial-idle", "next_action": "collect-next-bounded-cycle"})
    else:
        result["blockers"] = global_decision.get("blockers", ["GLOBAL_DECISION_INCOMPLETE"])
    return result


def load_cycle(path: Path) -> dict[str, Any]:
    from sixlab_jit_safe_input import read_regular
    try:
        raw = read_regular(path, 8 * 1024 * 1024)
    except (OSError, ValueError) as error:
        raise SerialSchedulerError("cycle input is inaccessible") from error
    try:
        return _cycle(json.loads(raw))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SerialSchedulerError("cycle input is not valid JSON") from error


def _atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink():
        raise SerialSchedulerError("schedule output directory must not be a symlink")
    descriptor, temporary = tempfile.mkstemp(prefix=".sixlab-jit-serial.", dir=path.parent)
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
    parser = argparse.ArgumentParser(description="Select exactly one SIXLAB JIT job from all open PRs")
    parser.add_argument("--cycle", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        result = evaluate(load_cycle(arguments.cycle))
        if arguments.output is not None:
            _atomic(arguments.output, result)
    except (SerialSchedulerError, inventory.InventoryError, inventory.shadow.ShadowError) as error:
        result = {
            "schema": SCHEMA, "status": "CHECK-INCOMPLETE", "token_allowed": False,
            "runner_mutation_allowed": False, "blockers": [str(error)],
        }
        if arguments.output is not None:
            _atomic(arguments.output, result)
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 2
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
