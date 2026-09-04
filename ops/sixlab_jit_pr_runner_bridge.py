#!/usr/bin/env python3
"""Collect and map a vendored B correlation into R1 shadow observations.

The production bridge executes only the exact bytes reviewed in SIXLAB PR
#1201.  It supplies an empty-by-default Node environment, so neither callers
nor an ambient shell can inject Node loaders, module paths, or inspectors.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
import hashlib
import json
import os
import re
import stat
import subprocess

import sixlab_jit_shadow_controller as shadow


CORRELATION_SCHEMA = "sixlab-jit-pr-runner-correlation-v2"
BRIDGE_SCHEMA = "sixlab-jit-open-pr-cycle-v1"
SOURCE_REPOSITORY = "Steven-ZYH/sixlab"
SOURCE_PULL_REQUEST = 1201
SOURCE_HEAD = "1efdfd2d754822d29d4f0a4f93b48117a663116f"
CANONICAL_MANIFEST_SHA256 = "9595d39c7ff80dce09cd33cf328efb0cf90d6709f14b32e51371df6e882ebc9e"
CANONICAL_VALIDATOR_SHA256 = "70a8cdb5fea2d0a5a04fb896336041dce80dd8cdf51663115bc96d65114e3e31"
CANONICAL_CONTRACT_SHA256 = "57a0fd3d88a344bab7b6174742b3a1b10f02f0fd16e582bff1fba99bd2d83d61"
CANONICAL_COLLECTOR_SHA256 = "c3611524baf3e535ad4815898fa1c6cc791f777815e121674af280e3838cf021"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
VENDOR_ROOT = PROJECT_ROOT / "vendor" / "sixlab-pr1201"
VENDOR_FILES = {
    ".claude/ci-runner-automation-contract.v1.json": CANONICAL_CONTRACT_SHA256,
    ".github/workflows/test-backend.yml": "233f8ecfa172361bc54d3c8c87ff0df5d0bf1d961fc23e54f6547631d2595ec8",
    ".github/workflows/test.yml": "aee582274151a53c4b9ca27eee068f37fcc38b8dc460d1b09ad523daa644bd4a",
    ".github/workflows/pr-peer-review-gate.yml": "7fed9a4e58a1d4c0cc665be804ac5071d3384ea02da08b3b9e36662b7c5ce7fc",
    "scripts/ci/collect-pr-runner-correlation.mjs": CANONICAL_COLLECTOR_SHA256,
    "scripts/ci/collect-pr-runner-correlation.test.mjs": "ba774eda78b020edf5a9189863f1f0529cc1cf80838a07b88178f9fe670b763f",
    "scripts/ci/pr-runner-contract.mjs": CANONICAL_VALIDATOR_SHA256,
}
# Installation is a separate, root-administered activation step.  In
# particular, this is not derived from PATH, a user configuration directory,
# or a developer's Homebrew installation.
NODE_TRUST_MANIFEST = Path("/etc/opcb/sixlab-jit-node-trust-v1.json")
NODE_TRUST_SCHEMA = "opcb-sixlab-jit-node-trust-v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class BridgeError(RuntimeError):
    pass


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _record(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise BridgeError(f"{label} fields are not canonical")
    return value


def _regular_bytes(path: Path, label: str) -> bytes:
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError as error:
        raise BridgeError(f"{label} is unreadable") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or not raw:
        raise BridgeError(f"{label} must be a regular non-symlink file")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise BridgeError(f"{label} has unsafe write permissions")
    return raw


def _vendored_b() -> dict[str, Path]:
    """Return only the path/digest/provenance-pinned B files in this repo."""
    root = VENDOR_ROOT
    manifest = root / "provenance.json"
    manifest_raw = _regular_bytes(manifest, "vendored SIXLAB provenance manifest")
    if _digest(manifest_raw) != CANONICAL_MANIFEST_SHA256:
        raise BridgeError("vendored SIXLAB provenance manifest digest drifted")
    try:
        parsed = json.loads(manifest_raw)
    except json.JSONDecodeError as error:
        raise BridgeError("vendored SIXLAB provenance manifest is invalid JSON") from error
    if parsed != {
        "schema": "opcb-projectmanager-vendored-sixlab-pr1201-v1",
        "source": {"repository": SOURCE_REPOSITORY, "pullRequest": SOURCE_PULL_REQUEST, "head": SOURCE_HEAD},
        "files": VENDOR_FILES,
    }:
        raise BridgeError("vendored SIXLAB provenance manifest is not the reviewed source")
    files: dict[str, Path] = {}
    for relative, expected_digest in VENDOR_FILES.items():
        path = root / relative
        raw = _regular_bytes(path, f"vendored SIXLAB file {relative}")
        if _digest(raw) != expected_digest:
            raise BridgeError(f"vendored SIXLAB file digest drifted: {relative}")
        files[relative] = path
    return files


def _pinned_validator() -> Path:
    return _vendored_b()["scripts/ci/pr-runner-contract.mjs"]


def _canonical_validation(correlation: object, validator: Path, node: Path) -> dict[str, Any]:
    """Run B's fixed validator and retain only its contract-derived output."""
    pinned_validator = _pinned_validator()
    if validator != pinned_validator:
        raise BridgeError("canonical SIXLAB validator path is invalid")
    validator = pinned_validator
    try:
        source = json.dumps(correlation, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError) as error:
        raise BridgeError("correlation cannot be encoded for canonical validation") from error
    completed = subprocess.run(
        [str(node), str(validator), "--validate-snapshot-stdin"],
        input=source,
        capture_output=True,
        text=True,
        # Validator input is untrusted correlation JSON.  It has no need for a
        # credential, PATH, Node flags/module paths, proxy, or CA settings.
        env={},
        check=False,
    )
    if completed.returncode != 0:
        raise BridgeError("canonical SIXLAB contract rejected correlation")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise BridgeError("canonical SIXLAB validator returned invalid JSON") from error
    _record(result, {"schemaVersion", "repository", "openPullRequests", "selectedRuns"}, "canonical SIXLAB validation")
    if result["schemaVersion"] != 2 or result["repository"] != shadow.EXPECTED_REPOSITORY:
        raise BridgeError("canonical SIXLAB validation identity is invalid")
    if not isinstance(result["openPullRequests"], list) or not result["openPullRequests"]:
        raise BridgeError("canonical SIXLAB validation open PR inventory is invalid")
    if not isinstance(result["selectedRuns"], list) or not result["selectedRuns"]:
        raise BridgeError("canonical SIXLAB validation workflow inventory is invalid")
    return result


def _root_owned_safe_path(path: Path, label: str) -> None:
    """Require a root-owned, non-writable path and every absolute parent."""
    current = path
    while True:
        try:
            metadata = current.lstat()
        except OSError as error:
            raise BridgeError(f"{label} is unreadable") from error
        if current.is_symlink() or metadata.st_uid != 0:
            raise BridgeError(f"{label} is not root-owned")
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise BridgeError(f"{label} has unsafe write permissions")
        if current == current.parent:
            return
        current = current.parent


def _trusted_node() -> Path:
    """Load one root-administered path/digest-pinned Node executable."""
    manifest = NODE_TRUST_MANIFEST
    _root_owned_safe_path(manifest, "Node trust manifest")
    manifest_raw = _regular_bytes(manifest, "Node trust manifest")
    try:
        parsed = json.loads(manifest_raw)
    except json.JSONDecodeError as error:
        raise BridgeError("Node trust manifest is invalid JSON") from error
    if (not isinstance(parsed, dict) or set(parsed) != {"schema", "node"}
            or parsed.get("schema") != NODE_TRUST_SCHEMA
            or not isinstance(parsed.get("node"), dict)
            or set(parsed["node"]) != {"path", "sha256"}):
        raise BridgeError("Node trust manifest fields are not canonical")
    node_path = parsed["node"]["path"]
    expected_digest = parsed["node"]["sha256"]
    if (not isinstance(node_path, str) or not node_path.startswith("/")
            or not isinstance(expected_digest, str) or not _SHA256.fullmatch(expected_digest)):
        raise BridgeError("Node trust manifest binding is invalid")
    node = Path(node_path)
    _root_owned_safe_path(node, "trusted Node executable")
    try:
        metadata = node.lstat()
        raw = node.read_bytes()
    except OSError as error:
        raise BridgeError("trusted Node executable is unreadable") from error
    if (node.is_symlink() or not stat.S_ISREG(metadata.st_mode)
            or not (metadata.st_mode & stat.S_IXUSR)
            or _digest(raw) != expected_digest):
        raise BridgeError("trusted Node executable binding is invalid")
    return node


def _test_node(test_node: Path | None) -> Path:
    """Verify an explicit test-only Node override for fixture validation.

    This never reaches ``build_cycle`` and returns a non-admitting fixture, so
    it cannot become an installation shortcut or a production trust root.
    """
    if test_node is None or not test_node.is_absolute():
        raise BridgeError("test fixture requires an explicit absolute test-only Node executable")
    try:
        metadata = test_node.lstat()
    except OSError as error:
        raise BridgeError("test-only Node executable is unreadable") from error
    if test_node.is_symlink() or not stat.S_ISREG(metadata.st_mode) or not (metadata.st_mode & stat.S_IXUSR):
        raise BridgeError("test-only Node executable is invalid")
    return test_node


def _collector_environment() -> dict[str, str]:
    """Pass only the short-lived GitHub read token to the collector."""
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise BridgeError("canonical SIXLAB live collector requires GITHUB_TOKEN")
    return {"GITHUB_TOKEN": token}


def _collect_live_correlation(node: Path) -> object:
    """Run B's read-only GitHub collector; caller data cannot replace this."""
    files = _vendored_b()
    collector = files["scripts/ci/collect-pr-runner-correlation.mjs"]
    completed = subprocess.run(
        [str(node), str(collector), "--stdout"], env=_collector_environment(),
        capture_output=True, text=True, check=False,
    )
    if completed.returncode != 0:
        raise BridgeError("canonical SIXLAB live collector failed")
    if len(completed.stdout.encode("utf-8")) > 8 * 1024 * 1024:
        raise BridgeError("canonical SIXLAB live collector output exceeds byte limit")
    try:
        correlation = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise BridgeError("canonical SIXLAB live collector returned invalid JSON") from error
    _record(correlation, {"schema", "observedAt", "repository", "openPullRequests", "runs"}, "live correlation")
    return correlation


def _build_from_validated_correlation(
    correlation: object,
    selections: object,
    evidence_by_pull: object,
    canonical_validator: Path,
    node: Path,
) -> dict[str, Any]:
    """Build R1 observations after the SIXLAB validator accepts correlation.

    ``selections`` maps every open PR number to one exact workflow name. Each
    evidence row supplies ProjectManager-only head observations and host/receipt
    evidence; the GitHub correlation remains the sole source for PR/run/job
    identity. This private helper only serves the trusted collector entrypoint
    and non-admitting fixture validation.
    """
    validated = _canonical_validation(correlation, canonical_validator, node)
    source = _record(correlation, {"schema", "observedAt", "repository", "openPullRequests", "runs"}, "correlation")
    if source["schema"] != CORRELATION_SCHEMA or source["repository"] != shadow.EXPECTED_REPOSITORY:
        raise BridgeError("correlation schema or repository is invalid")
    if not isinstance(selections, dict) or not isinstance(evidence_by_pull, dict):
        raise BridgeError("bridge selections or evidence are invalid")
    pulls: dict[int, dict[str, Any]] = {}
    for index, raw in enumerate(validated["openPullRequests"]):
        pull = _record(raw, {"number", "state", "draft", "baseRef", "headSha"}, f"openPullRequests[{index}]")
        number = pull["number"]
        if type(number) is not int or number <= 0 or number in pulls:
            raise BridgeError("open PR numbers are invalid")
        if pull["state"] != "open" or pull["draft"] is not False or pull["baseRef"] != shadow.EXPECTED_BASE:
            raise BridgeError("open PR is not ready for the main JIT lane")
        shadow._sha(pull["headSha"], f"openPullRequests[{index}].headSha")
        pulls[number] = pull
    if set(selections) != set(pulls) or set(evidence_by_pull) != set(pulls):
        raise BridgeError("every open PR requires one explicit selection and one evidence row")

    canonical_runs: dict[tuple[int, str], dict[str, Any]] = {}
    for index, raw in enumerate(validated["selectedRuns"]):
        row = _record(raw, {"pullRequestNumber", "workflow", "workflowSourcePath", "workflowApiId", "requiredContext", "runId", "attempt", "jobFamily", "headSha", "exactLabels"}, f"canonical selectedRuns[{index}]")
        key = (row["pullRequestNumber"], row["workflow"])
        if (type(row["pullRequestNumber"]) is not int or row["pullRequestNumber"] not in pulls
                or not isinstance(row["workflow"], str) or not row["workflow"]
                or not isinstance(row["workflowSourcePath"], str) or not row["workflowSourcePath"]
                or not isinstance(row["workflowApiId"], str) or not row["workflowApiId"]
                or key in canonical_runs or row["headSha"] != pulls[row["pullRequestNumber"]]["headSha"]
                or not isinstance(row["exactLabels"], list) or not row["exactLabels"]):
            raise BridgeError("canonical SIXLAB workflow binding is invalid")
        canonical_runs[key] = row
    if set(number for number, _ in canonical_runs) != set(pulls):
        raise BridgeError("canonical SIXLAB validation omitted an open PR")

    selected_runs: list[tuple[int, dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    for number, pull in pulls.items():
        workflow = selections[number]
        if not isinstance(workflow, str) or not workflow:
            raise BridgeError("selected workflow is invalid")
        canonical = canonical_runs.get((number, workflow))
        if canonical is None:
            raise BridgeError("selected workflow is not allowed")
        matches = [row for row in source["runs"] if isinstance(row, dict) and row.get("pullRequestNumber") == number and row.get("workflow") == workflow and row.get("run", {}).get("id") == canonical["runId"]]
        if len(matches) != 1:
            raise BridgeError("selected workflow does not have one exact current PR run")
        row = _record(matches[0], {"pullRequestNumber", "workflow", "run", "jobs"}, "selected run")
        run = _record(row["run"], {"id", "headSha", "attempt", "latestAttempt", "status"}, "selected run.run")
        if run["headSha"] != pull["headSha"] or run["attempt"] != run["latestAttempt"]:
            raise BridgeError("selected run head or attempt drifted")
        if not isinstance(row["jobs"], list) or not row["jobs"]:
            raise BridgeError("selected run jobs are invalid")
        evidence = _record(evidence_by_pull[number], {"headObservations", "host", "allocation", "receipt"}, "ProjectManager evidence")
        expected_jobs: dict[str, int] = {}
        for expected_index, raw_expected in enumerate(canonical["exactLabels"]):
            expected = _record(raw_expected, {"jobId", "instances", "label"}, f"canonical exactLabels[{expected_index}]")
            if (not isinstance(expected["jobId"], str) or not expected["jobId"]
                    or type(expected["instances"]) is not int or expected["instances"] <= 0
                    or expected["jobId"] in expected_jobs
                    or expected["label"] != shadow.exact_label(pull["headSha"], expected["jobId"])):
                raise BridgeError("canonical SIXLAB job map is invalid")
            expected_jobs[expected["jobId"]] = expected["instances"]
        observed_jobs: dict[str, int] = {}
        for index, raw in enumerate(row["jobs"]):
            job = _record(raw, {"id", "runId", "runAttempt", "name", "family", "status", "conclusion", "labels", "runnerId", "runnerName", "createdAt"}, f"selected jobs[{index}]")
            if job["runId"] != run["id"] or job["runAttempt"] != run["attempt"]:
                raise BridgeError("selected job run binding drifted")
            name = job["name"]
            family = job["family"]
            base_name = re.sub(r" \([^)]*\)$", "", name) if isinstance(name, str) else ""
            if base_name not in expected_jobs or family != base_name:
                raise BridgeError("selected job is undeclared or crosses workflow family")
            if job["labels"] != [shadow.exact_label(pull["headSha"], family)]:
                raise BridgeError("selected job exact label binding drifted")
            observed_jobs[base_name] = observed_jobs.get(base_name, 0) + 1
        if observed_jobs != expected_jobs:
            raise BridgeError("selected workflow job instances are incomplete or duplicated")
        selected_runs.append((number, pull, row, evidence))

    run_inventory = sorted(run["id"] for _, _, row, _ in selected_runs for run in [row["run"]])
    if len(set(run_inventory)) != len(run_inventory):
        raise BridgeError("selected run inventory is duplicated")
    snapshots = []
    for number, pull, row, evidence in selected_runs:
        run = row["run"]
        jobs = []
        for index, raw in enumerate(row["jobs"]):
            job = _record(raw, {"id", "runId", "runAttempt", "name", "family", "status", "conclusion", "labels", "runnerId", "runnerName", "createdAt"}, f"selected jobs[{index}]")
            if job["runId"] != run["id"] or job["runAttempt"] != run["attempt"]:
                raise BridgeError("selected job run binding drifted")
            jobs.append({
                "id": job["id"], "run_id": job["runId"], "run_attempt": job["runAttempt"],
                "name": job["name"], "family": job["family"], "status": job["status"],
                "conclusion": job["conclusion"], "labels": job["labels"],
                "runner_id": job["runnerId"], "runner_name": job["runnerName"],
                "created_at": job["createdAt"],
            })
        snapshots.append({
            "schema": shadow.SCHEMA,
            "observed_at": source["observedAt"],
            "pull": {"number": number, "state": pull["state"], "draft": pull["draft"], "base_ref": pull["baseRef"], "head_sha": pull["headSha"]},
            "head_observations": evidence["headObservations"],
            "run_inventory": run_inventory,
            "run": {"id": run["id"], "attempt": run["attempt"], "head_sha": run["headSha"], "status": run["status"]},
            "jobs": jobs,
            "host": evidence["host"],
            "allocation": evidence["allocation"],
            "receipt": evidence["receipt"],
        })
    return {"schema": BRIDGE_SCHEMA, "observed_at": source["observedAt"], "open_pull_numbers": sorted(pulls), "snapshots": snapshots}


def build_cycle(selections: object, evidence_by_pull: object) -> dict[str, Any]:
    """Build a schedulable cycle from B's freshly collected live inventory."""
    # Verify the executable once, then use those exact verified bytes for both
    # collector and validator in this cycle.
    node = _trusted_node()
    correlation = _collect_live_correlation(node)
    return _build_from_validated_correlation(
        correlation, selections, evidence_by_pull,
        _pinned_validator(), node,
    )


def validate_test_fixture(
    correlation: object,
    selections: object,
    evidence_by_pull: object,
    *,
    test_node: Path | None,
) -> dict[str, Any]:
    """Validate a fixture without returning a cycle that scheduling can consume."""
    _build_from_validated_correlation(
        correlation, selections, evidence_by_pull, _pinned_validator(), _test_node(test_node),
    )
    return {
        "schema": "sixlab-jit-bridge-test-fixture-v1",
        "status": "CHECK-INCOMPLETE",
        "token_allowed": False,
        "live_mutation_allowed": False,
        "next_action": "test-fixture-cannot-enter-scheduler-or-actuator",
    }
