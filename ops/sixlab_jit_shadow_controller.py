#!/usr/bin/env python3
"""Pure, fail-closed shadow evaluator for the SIXLAB one-job JIT lane.

This module never calls GitHub, reads a credential, mints a token, starts or
stops a service, changes a Runner label, or removes runtime state.  A trusted
collector may feed it canonical observations and compare the decision with the
current manual controller while the persistent/shared CI topology stays live.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any


SCHEMA = "sixlab-jit-shadow-observation-v1"
RECEIPT_SCHEMA = "sixlab-jit-teardown-receipt-v1"
TEARDOWN_FAILURE_EXIT = 70
EXPECTED_REPOSITORY = "Steven-ZYH/sixlab"
EXPECTED_BASE = "main"
EXACT_LABEL_PREFIX = "sixlab-pr-job-"
ALLOWED_FAMILIES = {
    "backend-detect",
    "backend-tests",
    "backend-unit",
    "spa-checks",
    "spa-detect",
    "spa-tests",
}
JOB_STATUSES = {"queued", "in_progress", "completed"}
RUN_STATUSES = {"queued", "in_progress", "completed"}
RUNNER_STATUSES = {"online", "offline"}
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")
MAX_JOBS = 200
MAX_RUNTIME_ROWS = 64
MAX_INPUT_BYTES = 1024 * 1024
MIN_HEAD_STABILITY_SECONDS = 60

# Initial shadow-only cooldown policy.  It cannot authorize a live launch.
MAX_LOAD5 = 1.5
MIN_ROOT_FREE_BYTES = 8 * 1024 * 1024 * 1024
MIN_MEMORY_SWAP_BYTES = 2 * 1024 * 1024 * 1024

SNAPSHOT_KEYS = {
    "schema",
    "observed_at",
    "pull",
    "head_observations",
    "run_inventory",
    "run",
    "jobs",
    "host",
    "allocation",
    "receipt",
}
PULL_KEYS = {"number", "state", "draft", "base_ref", "head_sha"}
HEAD_OBSERVATION_KEYS = {"observed_at", "head_sha"}
RUN_KEYS = {"id", "attempt", "head_sha", "status"}
JOB_KEYS = {
    "id",
    "run_id",
    "run_attempt",
    "name",
    "family",
    "status",
    "conclusion",
    "labels",
    "runner_id",
    "runner_name",
    "created_at",
}
HOST_KEYS = {
    "observed_at",
    "global_lock_held",
    "active_services",
    "service_details",
    "dedicated_process_count",
    "run_directories",
    "mounts",
    "egress_rules",
    "runner_inventory",
    "user_manager_active",
    "load5",
    "root_free_bytes",
    "memory_available_bytes",
    "swap_free_bytes",
}
RUNNER_KEYS = {"id", "name", "status", "busy", "labels"}
SERVICE_KEYS = {
    "name", "active_state", "sub_state", "main_pid", "control_group", "pids", "uids",
    "dedicated_pids",
}
ALLOCATION_KEYS = {
    "repository",
    "pull_number",
    "head_sha",
    "run_id",
    "run_attempt",
    "job_id",
    "family",
    "exact_label",
    "runner_id",
    "runner_name",
    "service_name",
}
RECEIPT_KEYS = ALLOCATION_KEYS | {
    "schema", "exit_code", "finished_at", "source_receipt_sha256",
}


class ShadowError(RuntimeError):
    pass


def _record(value: object, label: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ShadowError(f"{label} fields are not canonical")
    return value


def _positive_int(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ShadowError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ShadowError(f"{label} must be a non-negative integer")
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA_PATTERN.fullmatch(value) is None:
        raise ShadowError(f"{label} must be a lowercase 40-hex SHA")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ShadowError(f"{label} is invalid")
    return value


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ShadowError(f"{label} must be an RFC 3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ShadowError(f"{label} must be an RFC 3339 UTC timestamp") from error
    if parsed.tzinfo != timezone.utc:
        raise ShadowError(f"{label} must be an RFC 3339 UTC timestamp")
    return parsed


def _strings(value: object, label: str, maximum: int = MAX_RUNTIME_ROWS) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > maximum
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        raise ShadowError(f"{label} must be a unique bounded string list")
    return sorted(value)


def _ordered_strings(value: object, label: str, maximum: int = MAX_RUNTIME_ROWS) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > maximum
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        raise ShadowError(f"{label} must be a unique bounded string list")
    return list(value)


def exact_label(head_sha: str, family: str) -> str:
    if family not in ALLOWED_FAMILIES:
        raise ShadowError("job family is not allowed")
    return f"{EXACT_LABEL_PREFIX}{head_sha}-{family}"


def _normalize_pull(value: object) -> dict[str, Any]:
    pull = _record(value, "pull", PULL_KEYS)
    if pull["state"] not in {"open", "closed"}:
        raise ShadowError("pull.state is invalid")
    if type(pull["draft"]) is not bool:
        raise ShadowError("pull.draft must be a boolean")
    if not isinstance(pull["base_ref"], str) or not pull["base_ref"]:
        raise ShadowError("pull.base_ref is invalid")
    return {
        "number": _positive_int(pull["number"], "pull.number"),
        "state": pull["state"],
        "draft": pull["draft"],
        "base_ref": pull["base_ref"],
        "head_sha": _sha(pull["head_sha"], "pull.head_sha"),
    }


def _normalize_run(value: object) -> dict[str, Any]:
    run = _record(value, "run", RUN_KEYS)
    if run["status"] not in RUN_STATUSES:
        raise ShadowError("run.status is invalid")
    return {
        "id": _positive_int(run["id"], "run.id"),
        "attempt": _positive_int(run["attempt"], "run.attempt"),
        "head_sha": _sha(run["head_sha"], "run.head_sha"),
        "status": run["status"],
    }


def _normalize_run_inventory(value: object, run_id: int) -> list[int]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > MAX_RUNTIME_ROWS
        or any(type(item) is not int or item <= 0 for item in value)
        or value != sorted(set(value))
        or run_id not in value
    ):
        raise ShadowError("run_inventory must be a sorted unique current-run list")
    return value


def _normalize_jobs(value: object, run: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > MAX_JOBS:
        raise ShadowError(f"jobs must contain 1..{MAX_JOBS} records")
    jobs: list[dict[str, Any]] = []
    seen: set[int] = set()
    for index, item in enumerate(value):
        job = _record(item, f"jobs[{index}]", JOB_KEYS)
        job_id = _positive_int(job["id"], f"jobs[{index}].id")
        if job_id in seen:
            raise ShadowError("jobs contains a duplicate id")
        seen.add(job_id)
        run_id = _positive_int(job["run_id"], f"jobs[{index}].run_id")
        attempt = _positive_int(job["run_attempt"], f"jobs[{index}].run_attempt")
        if run_id != run["id"] or attempt > run["attempt"]:
            raise ShadowError("job run binding is invalid")
        family = job["family"]
        if family not in ALLOWED_FAMILIES:
            raise ShadowError("job family is not allowed")
        status = job["status"]
        if status not in JOB_STATUSES:
            raise ShadowError("job.status is invalid")
        conclusion = job["conclusion"]
        if status == "completed":
            if not isinstance(conclusion, str) or not conclusion:
                raise ShadowError("completed job conclusion is missing")
        elif conclusion is not None:
            raise ShadowError("non-terminal job conclusion must be null")
        labels = _strings(job["labels"], f"jobs[{index}].labels", 16)
        expected = exact_label(run["head_sha"], family)
        if labels != [expected]:
            raise ShadowError("job exact label binding is invalid")
        runner_id = job["runner_id"]
        runner_name = job["runner_name"]
        if status == "queued":
            if runner_id not in (None, 0) or runner_name not in (None, ""):
                raise ShadowError("queued job already has a runner binding")
            runner_id = None
            runner_name = None
        elif (
            status == "completed"
            and conclusion in {"cancelled", "skipped", "stale"}
            and runner_id in (None, 0)
            and runner_name in (None, "")
        ):
            runner_id = None
            runner_name = None
        else:
            runner_id = _positive_int(runner_id, f"jobs[{index}].runner_id")
            runner_name = _identifier(runner_name, f"jobs[{index}].runner_name")
        created_at = _timestamp(job["created_at"], f"jobs[{index}].created_at")
        if not isinstance(job["name"], str) or not job["name"]:
            raise ShadowError("job.name is invalid")
        jobs.append({
            "id": job_id,
            "run_id": run_id,
            "run_attempt": attempt,
            "name": job["name"],
            "family": family,
            "status": status,
            "conclusion": conclusion,
            "labels": labels,
            "runner_id": runner_id,
            "runner_name": runner_name,
            "created_at": created_at,
        })
    return jobs


def _normalize_runner(value: object, index: int) -> dict[str, Any]:
    runner = _record(value, f"host.runner_inventory[{index}]", RUNNER_KEYS)
    if runner["status"] not in RUNNER_STATUSES or type(runner["busy"]) is not bool:
        raise ShadowError("runner inventory status is invalid")
    return {
        "id": _positive_int(runner["id"], "runner.id"),
        "name": _identifier(runner["name"], "runner.name"),
        "status": runner["status"],
        "busy": runner["busy"],
        "labels": _strings(runner["labels"], "runner.labels", 16),
    }


def _normalize_service(value: object, index: int) -> dict[str, Any]:
    service = _record(value, f"host.service_details[{index}]", SERVICE_KEYS)
    name = _identifier(service["name"], f"host.service_details[{index}].name")
    active_state = _identifier(
        service["active_state"], f"host.service_details[{index}].active_state"
    )
    sub_state = _identifier(
        service["sub_state"], f"host.service_details[{index}].sub_state"
    )
    control_group = service["control_group"]
    if not isinstance(control_group, str) or (control_group and not control_group.startswith("/")):
        raise ShadowError("service control group is invalid")
    pids = service["pids"]
    uids = service["uids"]
    dedicated_pids = service["dedicated_pids"]
    if (
        not isinstance(pids, list)
        or len(pids) > 256
        or any(type(pid) is not int or pid <= 0 for pid in pids)
        or len(set(pids)) != len(pids)
    ):
        raise ShadowError("service pid inventory is invalid")
    if (
        not isinstance(uids, list)
        or len(uids) > MAX_RUNTIME_ROWS
        or any(type(uid) is not int or uid < 0 for uid in uids)
        or len(set(uids)) != len(uids)
    ):
        raise ShadowError("service uid inventory is invalid")
    if (
        not isinstance(dedicated_pids, list)
        or len(dedicated_pids) > 256
        or any(type(pid) is not int or pid <= 0 for pid in dedicated_pids)
        or len(set(dedicated_pids)) != len(dedicated_pids)
        or any(pid not in pids for pid in dedicated_pids)
    ):
        raise ShadowError("service dedicated pid inventory is invalid")
    return {
        "name": name,
        "active_state": active_state,
        "sub_state": sub_state,
        "main_pid": _nonnegative_int(
            service["main_pid"], f"host.service_details[{index}].main_pid"
        ),
        "control_group": control_group,
        "pids": sorted(pids),
        "uids": sorted(uids),
        "dedicated_pids": sorted(dedicated_pids),
    }


def _normalize_host(value: object) -> dict[str, Any]:
    host = _record(value, "host", HOST_KEYS)
    if type(host["global_lock_held"]) is not bool or type(host["user_manager_active"]) is not bool:
        raise ShadowError("host booleans are invalid")
    load5 = host["load5"]
    if (
        type(load5) not in (int, float)
        or not math.isfinite(float(load5))
        or load5 < 0
    ):
        raise ShadowError("host.load5 is invalid")
    inventory = host["runner_inventory"]
    if not isinstance(inventory, list) or len(inventory) > MAX_RUNTIME_ROWS:
        raise ShadowError("host.runner_inventory is invalid")
    runners = [_normalize_runner(item, index) for index, item in enumerate(inventory)]
    if len({runner["id"] for runner in runners}) != len(runners):
        raise ShadowError("host.runner_inventory contains a duplicate id")
    service_inventory = host["service_details"]
    if not isinstance(service_inventory, list) or len(service_inventory) > MAX_RUNTIME_ROWS:
        raise ShadowError("host.service_details is invalid")
    services = [
        _normalize_service(item, index) for index, item in enumerate(service_inventory)
    ]
    if len({service["name"] for service in services}) != len(services):
        raise ShadowError("host.service_details contains a duplicate name")
    return {
        "observed_at": _timestamp(host["observed_at"], "host.observed_at"),
        "global_lock_held": host["global_lock_held"],
        "active_services": _strings(host["active_services"], "host.active_services"),
        "service_details": sorted(services, key=lambda service: service["name"]),
        "dedicated_process_count": _nonnegative_int(
            host["dedicated_process_count"], "host.dedicated_process_count"
        ),
        "run_directories": _strings(host["run_directories"], "host.run_directories"),
        "mounts": _strings(host["mounts"], "host.mounts"),
        "egress_rules": _ordered_strings(host["egress_rules"], "host.egress_rules"),
        "runner_inventory": runners,
        "user_manager_active": host["user_manager_active"],
        "load5": float(load5),
        "root_free_bytes": _nonnegative_int(host["root_free_bytes"], "host.root_free_bytes"),
        "memory_available_bytes": _nonnegative_int(
            host["memory_available_bytes"], "host.memory_available_bytes"
        ),
        "swap_free_bytes": _nonnegative_int(host["swap_free_bytes"], "host.swap_free_bytes"),
    }


def _normalize_binding(value: object, label: str, receipt: bool = False) -> dict[str, Any]:
    keys = RECEIPT_KEYS if receipt else ALLOCATION_KEYS
    row = _record(value, label, keys)
    if row["repository"] != EXPECTED_REPOSITORY:
        raise ShadowError(f"{label}.repository is invalid")
    family = row["family"]
    if family not in ALLOWED_FAMILIES:
        raise ShadowError(f"{label}.family is invalid")
    normalized = {
        "repository": row["repository"],
        "pull_number": _positive_int(row["pull_number"], f"{label}.pull_number"),
        "head_sha": _sha(row["head_sha"], f"{label}.head_sha"),
        "run_id": _positive_int(row["run_id"], f"{label}.run_id"),
        "run_attempt": _positive_int(row["run_attempt"], f"{label}.run_attempt"),
        "job_id": _positive_int(row["job_id"], f"{label}.job_id"),
        "family": family,
        "exact_label": row["exact_label"],
        "runner_id": _positive_int(row["runner_id"], f"{label}.runner_id"),
        "runner_name": _identifier(row["runner_name"], f"{label}.runner_name"),
        "service_name": _identifier(row["service_name"], f"{label}.service_name"),
    }
    if normalized["exact_label"] != exact_label(normalized["head_sha"], family):
        raise ShadowError(f"{label}.exact_label is invalid")
    if receipt:
        if row["schema"] != RECEIPT_SCHEMA:
            raise ShadowError("receipt.schema is invalid")
        normalized.update({
            "schema": row["schema"],
            "exit_code": _nonnegative_int(row["exit_code"], "receipt.exit_code"),
            "finished_at": _timestamp(row["finished_at"], "receipt.finished_at"),
            "source_receipt_sha256": row["source_receipt_sha256"],
        })
        if DIGEST_PATTERN.fullmatch(normalized["source_receipt_sha256"] or "") is None:
            raise ShadowError("receipt.source_receipt_sha256 is invalid")
    return normalized


def _binding_matches(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return all(left[key] == right[key] for key in ALLOCATION_KEYS)


def _pull_blockers(pull: dict[str, Any], run: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    if pull["state"] != "open":
        blockers.append("PR_NOT_OPEN")
    if type(pull["draft"]) is not bool or pull["draft"]:
        blockers.append("PR_DRAFT_OR_INVALID")
    if pull["base_ref"] != EXPECTED_BASE:
        blockers.append("BASE_NOT_MAIN")
    if pull["head_sha"] != run["head_sha"]:
        blockers.append("CURRENT_HEAD_RUN_DRIFT")
    return blockers


def _stability_blockers(
    value: object, current_head: str, snapshot_observed_at: datetime,
) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 16:
        raise ShadowError("head_observations must contain 1..16 records")
    rows: list[tuple[datetime, str]] = []
    for index, item in enumerate(value):
        row = _record(item, f"head_observations[{index}]", HEAD_OBSERVATION_KEYS)
        rows.append((
            _timestamp(row["observed_at"], f"head_observations[{index}].observed_at"),
            _sha(row["head_sha"], f"head_observations[{index}].head_sha"),
        ))
    if any(rows[index][0] >= rows[index + 1][0] for index in range(len(rows) - 1)):
        raise ShadowError("head_observations timestamps must increase")
    if any(observed_at > snapshot_observed_at for observed_at, _ in rows):
        raise ShadowError("head observation is newer than snapshot")
    if rows[-1][1] != current_head:
        return ["LATEST_HEAD_OBSERVATION_DRIFT"]
    current_suffix: list[tuple[datetime, str]] = []
    for row in reversed(rows):
        if row[1] != current_head:
            break
        current_suffix.append(row)
    if len(current_suffix) < 2:
        return ["HEAD_STABILITY_WINDOW_INCOMPLETE"]
    if (
        current_suffix[0][0] - current_suffix[-1][0]
    ).total_seconds() < MIN_HEAD_STABILITY_SECONDS:
        return ["HEAD_STABILITY_WINDOW_INCOMPLETE"]
    return []


def _clean_host_blockers(host: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    if host["global_lock_held"]:
        blockers.append("GLOBAL_LOCK_HELD")
    if host["active_services"]:
        blockers.append("ACTIVE_SERVICE_REMAINS")
    if host["service_details"]:
        blockers.append("SERVICE_DETAIL_REMAINS")
    if host["dedicated_process_count"]:
        blockers.append("DEDICATED_PROCESS_REMAINS")
    if host["run_directories"]:
        blockers.append("RUN_DIRECTORY_REMAINS")
    if host["mounts"]:
        blockers.append("MOUNT_REMAINS")
    if host["egress_rules"]:
        blockers.append("EGRESS_RULE_REMAINS")
    if host["runner_inventory"]:
        blockers.append("RUNNER_INVENTORY_REMAINS")
    if host["user_manager_active"]:
        blockers.append("USER_MANAGER_ACTIVE")
    return blockers


def _resource_blockers(host: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    if host["load5"] > MAX_LOAD5:
        blockers.append("LOAD5_COOLDOWN")
    if host["root_free_bytes"] < MIN_ROOT_FREE_BYTES:
        blockers.append("ROOT_DISK_COOLDOWN")
    if host["memory_available_bytes"] + host["swap_free_bytes"] < MIN_MEMORY_SWAP_BYTES:
        blockers.append("MEMORY_SWAP_COOLDOWN")
    return blockers


def _has_runtime_row(rows: list[str], *fragments: str) -> bool:
    return any(all(fragment in row for fragment in fragments) for row in rows)


def _job_binding(pull: dict[str, Any], run: dict[str, Any], job: dict[str, Any]) -> dict[str, Any]:
    return {
        "repository": EXPECTED_REPOSITORY,
        "pull_number": pull["number"],
        "head_sha": run["head_sha"],
        "run_id": run["id"],
        "run_attempt": job["run_attempt"],
        "job_id": job["id"],
        "family": job["family"],
        "exact_label": exact_label(run["head_sha"], job["family"]),
    }


def evaluate(snapshot: object) -> dict[str, Any]:
    source = _record(snapshot, "snapshot", SNAPSHOT_KEYS)
    if source["schema"] != SCHEMA:
        raise ShadowError("snapshot.schema is invalid")
    observed_at = _timestamp(source["observed_at"], "observed_at")
    pull = _normalize_pull(source["pull"])
    run = _normalize_run(source["run"])
    run_inventory = _normalize_run_inventory(source["run_inventory"], run["id"])
    jobs = _normalize_jobs(source["jobs"], run)
    host = _normalize_host(source["host"])
    if host["observed_at"] > observed_at:
        raise ShadowError("host observation is newer than snapshot")

    blockers = _pull_blockers(pull, run)
    blockers.extend(_stability_blockers(
        source["head_observations"], pull["head_sha"], observed_at,
    ))
    latest = [job for job in jobs if job["run_attempt"] == run["attempt"]]
    allocation = None if source["allocation"] is None else _normalize_binding(
        source["allocation"], "allocation"
    )
    receipt = None if source["receipt"] is None else _normalize_binding(
        source["receipt"], "receipt", receipt=True
    )
    if receipt is not None and receipt["finished_at"] > observed_at:
        raise ShadowError("receipt is newer than snapshot")

    base = {
        "schema": "sixlab-jit-shadow-decision-v1",
        "observed_at": source["observed_at"],
        "mode": "admission" if allocation is None else "reconciliation",
        "token_allowed": False,
        "live_mutation_allowed": False,
        "selected_job": None,
        "eligible_job_ids": [],
        "selection_mode": "none",
        "blockers": [],
        "evidence": {
            "repository": EXPECTED_REPOSITORY,
            "pull_number": pull["number"],
            "current_head": pull["head_sha"],
            "run_id": run["id"],
            "run_inventory": run_inventory,
            "latest_attempt": run["attempt"],
            "load5": host["load5"],
            "root_free_bytes": host["root_free_bytes"],
            "memory_swap_available_bytes": (
                host["memory_available_bytes"] + host["swap_free_bytes"]
            ),
        },
    }

    if allocation is None:
        blockers.extend(_clean_host_blockers(host))
        blockers.extend(_resource_blockers(host))
        if receipt is not None:
            blockers.append("RECEIPT_WITHOUT_ALLOCATION")
        active = [job for job in jobs if job["status"] == "in_progress"]
        queued = [job for job in latest if job["status"] == "queued"]
        if active:
            blockers.append("ANY_ATTEMPT_JOB_ALREADY_ACTIVE")
        if not queued:
            blockers.append("NO_LATEST_ATTEMPT_QUEUED_JOB")
        if blockers:
            base["status"] = "CHECK-INCOMPLETE"
            base["blockers"] = sorted(set(blockers))
            return base
        selected = sorted(queued, key=lambda job: (job["created_at"], job["id"]))[0]
        selected_label = exact_label(run["head_sha"], selected["family"])
        same_label = [
            job for job in queued
            if exact_label(run["head_sha"], job["family"]) == selected_label
        ]
        if len(same_label) > 1 and selected["family"] != "spa-tests":
            base["status"] = "CHECK-INCOMPLETE"
            base["blockers"] = ["MULTIPLE_NON_MATRIX_JOBS_SAME_LABEL"]
            return base
        base["status"] = "shadow-admit"
        base["selected_job"] = _job_binding(pull, run, selected)
        base["eligible_job_ids"] = sorted(job["id"] for job in same_label)
        base["selection_mode"] = (
            "any-one-same-label" if len(same_label) > 1 else "exact-one"
        )
        return base

    selected_jobs = [job for job in jobs if job["id"] == allocation["job_id"]]
    if any(
        job["status"] == "in_progress" and job["id"] != allocation["job_id"]
        for job in jobs
    ):
        blockers.append("OTHER_JOB_ALREADY_ACTIVE")
    if len(selected_jobs) != 1:
        blockers.append("ALLOCATED_JOB_MISSING")
        selected_job = None
    else:
        selected_job = selected_jobs[0]
        base["selected_job"] = _job_binding(pull, run, selected_job)
        base["eligible_job_ids"] = [selected_job["id"]]
        base["selection_mode"] = "actual-binding"
        if allocation["run_attempt"] != run["attempt"]:
            blockers.append("ALLOCATION_NOT_LATEST_ATTEMPT")
        if selected_job["run_attempt"] != run["attempt"]:
            blockers.append("ALLOCATED_JOB_NOT_LATEST_ATTEMPT")
        if not _binding_matches(allocation, {
            **base["selected_job"],
            "runner_id": allocation["runner_id"],
            "runner_name": allocation["runner_name"],
            "service_name": allocation["service_name"],
        }):
            blockers.append("ALLOCATION_JOB_BINDING_DRIFT")

    matching_runner = [
        runner for runner in host["runner_inventory"]
        if runner["id"] == allocation["runner_id"]
        and runner["name"] == allocation["runner_name"]
    ]
    service_active = allocation["service_name"] in host["active_services"]
    matching_service = [
        service for service in host["service_details"]
        if service["name"] == allocation["service_name"]
    ]
    service_identity_bound = (
        len(host["service_details"]) == 1
        and len(matching_service) == 1
        and matching_service[0]["active_state"] == "active"
        and matching_service[0]["main_pid"] > 0
        and bool(matching_service[0]["control_group"])
        and bool(matching_service[0]["pids"])
        and 1005 in matching_service[0]["uids"]
        and bool(matching_service[0]["dedicated_pids"])
        and host["dedicated_process_count"] == len(matching_service[0]["dedicated_pids"])
    )
    slot_match = re.search(r"-([0-9]{2})$", allocation["runner_name"])
    expected_run_root = None if slot_match is None else f"/run/sj{slot_match.group(1)}"
    egress_markers: tuple[str, ...] = ()
    nft_prefix = ""
    chain = dns_chain = comment = dns_comment = ""
    if slot_match is not None:
        slot = slot_match.group(1)
        nft_table = f"s{allocation['pull_number']}26{slot}"
        chain = f"SLPR{allocation['pull_number']}{slot}"
        dns_chain = f"SLPD{allocation['pull_number']}{slot}"
        comment = f"sixlab-pr{allocation['pull_number']}-ephemeral-{slot}"
        dns_comment = f"sixlab-pr{allocation['pull_number']}-dns-{slot}"
        nft_prefix = f"nft:inet:{nft_table}:"
        egress_markers = (
            nft_prefix,
            chain,
            dns_chain,
            comment,
            dns_comment,
        )
    egress_identity_bound = (
        bool(egress_markers)
        and all(any(marker in row for row in host["egress_rules"]) for marker in egress_markers)
        and all(
            row.startswith(nft_prefix)
            or any(marker in row for marker in egress_markers[1:])
            for row in host["egress_rules"]
        )
        and _has_runtime_row(host["egress_rules"], nft_prefix, "meta skuid 1005", "tcp dport 18080", "accept")
        and _has_runtime_row(host["egress_rules"], nft_prefix, "meta skuid 1005", "udp dport 15353", "accept")
        and _has_runtime_row(host["egress_rules"], nft_prefix, "meta skuid 1005", "tcp dport 15353", "accept")
        and _has_runtime_row(host["egress_rules"], nft_prefix, "meta skuid 1005", "drop")
        and _has_runtime_row(host["egress_rules"], f"-A {chain}", comment, "-j DROP")
        and _has_runtime_row(host["egress_rules"], f"-A {dns_chain}", "-p udp", "--dport 53", "-j REDIRECT", "--to-ports 15353")
        and _has_runtime_row(host["egress_rules"], f"-A {dns_chain}", "-p tcp", "--dport 53", "-j REDIRECT", "--to-ports 15353")
        and _has_runtime_row(host["egress_rules"], "-A OUTPUT", "--uid-owner 1005", comment, f"-j {chain}")
        and _has_runtime_row(host["egress_rules"], "-A OUTPUT", "--uid-owner 1005", dns_comment, f"-j {dns_chain}")
    )
    nft_uid_rows = [
        row for row in host["egress_rules"]
        if row.startswith(nft_prefix) and "meta skuid 1005" in row
    ]
    nft_accept_rows = [row for row in nft_uid_rows if row.endswith(" accept")]
    chain_rows = [
        row for row in host["egress_rules"] if f"iptables:-A {chain} " in row
    ]
    chain_accept_rows = [row for row in chain_rows if row.endswith(" -j ACCEPT")]
    canonical_policy_shape = (
        len(nft_uid_rows) == 10
        and len(nft_accept_rows) == 5
        and nft_uid_rows[-1].endswith("meta skuid 1005 drop")
        and all(
            any(fragment in row for fragment in (
                "tcp dport { 3306, 6379 }",
                "tcp dport 18080",
                "udp dport 15353",
                "tcp dport 15353",
                "tcp dport 32768-60999",
            ))
            for row in nft_accept_rows
        )
        and len(chain_rows) == 16
        and len(chain_accept_rows) == 6
        and chain_rows[-1].endswith("-j DROP")
        and all(
            comment in row
            and "-d 127.0.0.1/32" in row
            and any(fragment in row for fragment in (
                "--dport 3306",
                "--dport 6379",
                "--dport 18080",
                "--dport 15353",
                "--dport 32768:60999",
            ))
            for row in chain_accept_rows
        )
    )
    egress_identity_bound = egress_identity_bound and canonical_policy_shape
    runtime_exclusive = (
        host["global_lock_held"]
        and host["active_services"] == [allocation["service_name"]]
        and len(host["runner_inventory"]) == 1
        and len(matching_runner) == 1
        and allocation["exact_label"] in matching_runner[0]["labels"]
        and matching_runner[0]["status"] == "online"
        and service_identity_bound
        and host["run_directories"] == [expected_run_root]
        and host["mounts"] == [expected_run_root]
        and egress_identity_bound
        and host["user_manager_active"]
    )

    if blockers:
        base["status"] = "shadow-reconcile-required"
        base["blockers"] = sorted(set(blockers))
        return base
    assert selected_job is not None

    if selected_job["status"] == "queued":
        if not service_active or not runtime_exclusive or matching_runner[0]["busy"]:
            base["status"] = "CHECK-INCOMPLETE"
            base["blockers"] = ["ALLOCATED_RUNNER_NOT_OBSERVED"]
            return base
        base["status"] = "shadow-awaiting-binding"
        return base

    if selected_job["status"] == "in_progress":
        if (
            not service_active
            or not runtime_exclusive
            or matching_runner[0]["status"] != "online"
            or not matching_runner[0]["busy"]
            or selected_job["runner_id"] != allocation["runner_id"]
            or selected_job["runner_name"] != allocation["runner_name"]
        ):
            base["status"] = "CHECK-INCOMPLETE"
            base["blockers"] = ["RUNNING_JOB_RUNTIME_BINDING_INCOMPLETE"]
            return base
        base["status"] = "shadow-running"
        return base

    if receipt is None:
        base["status"] = "CHECK-INCOMPLETE"
        base["blockers"] = ["TERMINAL_RECEIPT_MISSING"]
        return base
    if not _binding_matches(allocation, receipt):
        base["status"] = "CHECK-INCOMPLETE"
        base["blockers"] = ["TERMINAL_RECEIPT_BINDING_DRIFT"]
        return base
    if receipt["finished_at"] < selected_job["created_at"]:
        base["status"] = "CHECK-INCOMPLETE"
        base["blockers"] = ["TERMINAL_RECEIPT_TIME_DRIFT"]
        return base
    if receipt["finished_at"] > host["observed_at"]:
        base["status"] = "CHECK-INCOMPLETE"
        base["blockers"] = ["TEARDOWN_OBSERVATION_PRECEDES_RECEIPT"]
        return base
    if receipt["exit_code"] == TEARDOWN_FAILURE_EXIT:
        base["status"] = "CHECK-INCOMPLETE"
        base["blockers"] = ["RECEIPT_REPORTED_TEARDOWN_FAILURE"]
        return base
    if (
        selected_job["runner_id"] != allocation["runner_id"]
        or selected_job["runner_name"] != allocation["runner_name"]
    ):
        base["status"] = "CHECK-INCOMPLETE"
        base["blockers"] = ["TERMINAL_JOB_RUNNER_BINDING_DRIFT"]
        return base
    teardown = _clean_host_blockers(host)
    if teardown:
        base["status"] = "shadow-reconcile-required"
        base["blockers"] = sorted(set(teardown))
        return base
    base["status"] = "shadow-teardown-verified"
    base["evidence"]["job_conclusion"] = selected_job["conclusion"]
    base["evidence"]["receipt_exit_code"] = receipt["exit_code"]
    base["evidence"]["source_receipt_sha256"] = receipt["source_receipt_sha256"]
    return base


def load_snapshot(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise ShadowError("snapshot file is missing") from error
    except OSError as error:
        raise ShadowError("snapshot file metadata is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise ShadowError("snapshot must be a regular non-symlink file")
    if metadata.st_size > MAX_INPUT_BYTES:
        raise ShadowError("snapshot is too large")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ShadowError("snapshot is not valid JSON") from error
    if not isinstance(raw, dict):
        raise ShadowError("snapshot is not a JSON object")
    return raw


def write_decision(path: Path, decision: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink():
        raise ShadowError("decision directory must not be a symlink")
    descriptor, temporary = tempfile.mkstemp(prefix=".sixlab-jit-decision.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = -1
            json.dump(decision, output, separators=(",", ":"), sort_keys=True)
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
    parser = argparse.ArgumentParser(description="Evaluate one SIXLAB JIT shadow snapshot")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    try:
        decision = evaluate(load_snapshot(arguments.input))
    except ShadowError as error:
        decision = {
            "schema": "sixlab-jit-shadow-decision-v1",
            "status": "CHECK-INCOMPLETE",
            "token_allowed": False,
            "live_mutation_allowed": False,
            "blockers": [str(error)],
        }
        if arguments.output is not None:
            write_decision(arguments.output, decision)
        print(json.dumps(decision, separators=(",", ":"), sort_keys=True))
        return 2
    if arguments.output is not None:
        write_decision(arguments.output, decision)
    print(json.dumps(decision, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
