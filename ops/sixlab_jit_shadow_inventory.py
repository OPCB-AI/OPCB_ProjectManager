#!/usr/bin/env python3
"""Fail-closed global selector across read-only SIXLAB JIT run snapshots."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from typing import Any


import sixlab_jit_shadow_controller as shadow


SCHEMA = "sixlab-jit-shadow-global-decision-v1"
MAX_SNAPSHOTS = 100
MAX_SNAPSHOT_SKEW_SECONDS = 60
ACTIVE_ALLOCATION_ADMISSION_BLOCKERS = frozenset({
    "GLOBAL_LOCK_HELD",
    "ACTIVE_SERVICE_REMAINS",
    "SERVICE_DETAIL_REMAINS",
    "DEDICATED_PROCESS_REMAINS",
    "RUN_DIRECTORY_REMAINS",
    "MOUNT_REMAINS",
    "EGRESS_RULE_REMAINS",
    "RUNNER_INVENTORY_REMAINS",
    "USER_MANAGER_ACTIVE",
    "LOAD5_COOLDOWN",
    "ROOT_DISK_COOLDOWN",
    "MEMORY_SWAP_COOLDOWN",
})
ACTIVE_HOST_IDENTITY_FIELDS = (
    "global_lock_held",
    "active_services",
    "service_details",
    "run_directories",
    "mounts",
    "egress_rules",
    "user_manager_active",
)


class InventoryError(RuntimeError):
    pass


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise InventoryError("snapshot observation time is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise InventoryError("snapshot observation time is invalid") from error
    if parsed.tzinfo != timezone.utc:
        raise InventoryError("snapshot observation time is not UTC")
    return parsed


def _job_created(snapshot: dict[str, Any], job_id: int) -> tuple[datetime, int]:
    rows = [job for job in snapshot.get("jobs", []) if job.get("id") == job_id]
    if len(rows) != 1:
        raise InventoryError("selected job is missing from snapshot")
    return _timestamp(rows[0].get("created_at")), job_id


def _runner_matches_allocation(runner: object, allocation: dict[str, Any]) -> bool:
    return (
        isinstance(runner, dict)
        and runner.get("id") == allocation.get("runner_id")
        and runner.get("name") == allocation.get("runner_name")
        and runner.get("status") == "online"
        and isinstance(runner.get("busy"), bool)
        and isinstance(runner.get("labels"), list)
        and allocation.get("exact_label") in runner["labels"]
    )


def _compatible_active_host_observation(
    snapshot: dict[str, Any],
    decision: dict[str, Any],
    active_snapshot: dict[str, Any],
) -> bool:
    if snapshot.get("allocation") is not None or snapshot.get("receipt") is not None:
        return False
    if decision.get("status") != "CHECK-INCOMPLETE":
        return False
    blockers = decision.get("blockers")
    if (
        not isinstance(blockers, list)
        or not blockers
        or any(blocker not in ACTIVE_ALLOCATION_ADMISSION_BLOCKERS for blocker in blockers)
    ):
        return False
    allocation = active_snapshot.get("allocation")
    active_host = active_snapshot.get("host")
    host = snapshot.get("host")
    if not isinstance(allocation, dict) or not isinstance(active_host, dict) or not isinstance(host, dict):
        return False
    service_name = allocation.get("service_name")
    if (
        not isinstance(service_name, str)
        or active_host.get("active_services") != [service_name]
        or host.get("active_services") != [service_name]
        or active_host.get("global_lock_held") is not True
        or host.get("global_lock_held") is not True
        or type(active_host.get("dedicated_process_count")) is not int
        or type(host.get("dedicated_process_count")) is not int
        or active_host["dedicated_process_count"] <= 0
        or host["dedicated_process_count"] <= 0
    ):
        return False
    for field in ACTIVE_HOST_IDENTITY_FIELDS:
        if host.get(field) != active_host.get(field):
            return False
    active_runners = active_host.get("runner_inventory")
    runners = host.get("runner_inventory")
    if (
        not isinstance(active_runners, list)
        or not isinstance(runners, list)
        or len(active_runners) != 1
        or len(runners) != 1
        or not _runner_matches_allocation(active_runners[0], allocation)
        or not _runner_matches_allocation(runners[0], allocation)
        or runners[0].get("busy") != active_runners[0].get("busy")
        or host["dedicated_process_count"] != active_host["dedicated_process_count"]
    ):
        return False
    return True


def select_global(snapshots: list[dict[str, Any]]) -> dict[str, Any]:
    if not snapshots or len(snapshots) > MAX_SNAPSHOTS:
        raise InventoryError(f"snapshot inventory must contain 1..{MAX_SNAPSHOTS} rows")
    observed = [_timestamp(snapshot.get("observed_at")) for snapshot in snapshots]
    if (max(observed) - min(observed)).total_seconds() > MAX_SNAPSHOT_SKEW_SECONDS:
        raise InventoryError("snapshot inventory is not from one bounded control cycle")
    decisions = [shadow.evaluate(snapshot) for snapshot in snapshots]
    run_ids = [decision.get("evidence", {}).get("run_id") for decision in decisions]
    if any(type(run_id) is not int for run_id in run_ids) or len(set(run_ids)) != len(run_ids):
        raise InventoryError("snapshot run inventory is invalid or duplicated")
    declared_inventories = [
        decision.get("evidence", {}).get("run_inventory") for decision in decisions
    ]
    if (
        any(not isinstance(row, list) for row in declared_inventories)
        or any(row != declared_inventories[0] for row in declared_inventories[1:])
        or sorted(run_ids) != declared_inventories[0]
    ):
        raise InventoryError("snapshot inventory is not complete for the canonical run set")

    result = {
        "schema": SCHEMA,
        "observed_at": max(observed).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "CHECK-INCOMPLETE",
        "token_allowed": False,
        "live_mutation_allowed": False,
        "selected_job": None,
        "eligible_job_ids": [],
        "selection_mode": "none",
        "evaluated_runs": sorted(run_ids),
        "blockers": [],
    }

    active = [
        (snapshot, decision)
        for snapshot, decision in zip(snapshots, decisions)
        if decision.get("status") in {"shadow-running", "shadow-awaiting-binding"}
    ]
    if len(active) > 1:
        result["blockers"] = ["MULTIPLE_ACTIVE_JIT_ALLOCATIONS"]
        return result
    if active:
        active_snapshot, decision = active[0]
        active_observed = _timestamp(active_snapshot.get("observed_at"))
        if any(
            peer_decision.get("status") == "shadow-teardown-verified"
            and _timestamp(snapshot.get("observed_at")) > active_observed
            for snapshot, peer_decision in zip(snapshots, decisions)
        ):
            result["blockers"] = ["ACTIVE_ALLOCATION_OBSERVATION_STALE"]
            return result
        incompatible: list[dict[str, Any]] = []
        for snapshot, peer_decision in zip(snapshots, decisions):
            if peer_decision is decision:
                continue
            if peer_decision.get("status") == "shadow-teardown-verified":
                continue
            if _compatible_active_host_observation(snapshot, peer_decision, active_snapshot):
                continue
            incompatible.append(peer_decision)
        if incompatible:
            peer_blockers = {
                blocker
                for peer_decision in incompatible
                for blocker in peer_decision.get("blockers", [])
            }
            if any(not peer_decision.get("blockers") for peer_decision in incompatible):
                peer_blockers.add("ACTIVE_ALLOCATION_WITH_INCONSISTENT_PEER_SNAPSHOT")
            result["blockers"] = sorted(
                peer_blockers | {"ACTIVE_ALLOCATION_WITH_INCOMPLETE_INVENTORY"}
            )
            return result
        result.update({
            "status": "shadow-global-running",
            "selected_job": decision["selected_job"],
            "eligible_job_ids": decision["eligible_job_ids"],
            "selection_mode": "actual-binding",
        })
        return result
    blocked = [
        decision for decision in decisions
        if decision.get("status") in {"CHECK-INCOMPLETE", "shadow-reconcile-required"}
    ]
    if blocked:
        result["blockers"] = sorted({
            blocker
            for decision in blocked
            for blocker in decision.get("blockers", [])
        })
        return result

    candidates: list[tuple[tuple[datetime, int], dict[str, Any]]] = []
    for snapshot, decision in zip(snapshots, decisions):
        status = decision.get("status")
        if status == "shadow-teardown-verified":
            continue
        if status != "shadow-admit":
            raise InventoryError("snapshot decision is not globally classifiable")
        selected = decision.get("selected_job")
        if not isinstance(selected, dict) or type(selected.get("job_id")) is not int:
            raise InventoryError("admission decision lacks exact selected job")
        candidates.append((_job_created(snapshot, selected["job_id"]), decision))
    if not candidates:
        result["status"] = "shadow-global-idle"
        return result
    _, selected_decision = min(candidates, key=lambda item: item[0])
    result.update({
        "status": "shadow-global-admit",
        "selected_job": selected_decision["selected_job"],
        "eligible_job_ids": selected_decision["eligible_job_ids"],
        "selection_mode": selected_decision["selection_mode"],
    })
    return result


def _atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink():
        raise InventoryError("global decision directory must not be a symlink")
    descriptor, temporary = tempfile.mkstemp(prefix=".sixlab-jit-global.", dir=path.parent)
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
    parser = argparse.ArgumentParser(description="Select one global SIXLAB JIT shadow candidate")
    parser.add_argument("--snapshot", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        snapshots = [shadow.load_snapshot(path) for path in arguments.snapshot]
        decision = select_global(snapshots)
        if arguments.output is not None:
            _atomic(arguments.output, decision)
    except (InventoryError, shadow.ShadowError) as error:
        decision = {
            "schema": SCHEMA,
            "status": "CHECK-INCOMPLETE",
            "token_allowed": False,
            "live_mutation_allowed": False,
            "blockers": [str(error)],
        }
        if arguments.output is not None:
            _atomic(arguments.output, decision)
        print(json.dumps(decision, separators=(",", ":"), sort_keys=True))
        return 2
    print(json.dumps(decision, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
