#!/usr/bin/env python3
import copy
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


project = Path(__file__).resolve().parent.parent
ops = project / "ops"
import sys
sys.path.insert(0, str(ops))

source = ops / "sixlab_jit_shadow_collector.py"
spec = importlib.util.spec_from_file_location("collector", source)
collector = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(collector)
shadow = collector.shadow
import sixlab_jit_pr_runner_bridge as bridge


HEAD = "f" * 40
BASE_SHA = "b" * 40
LABEL = shadow.exact_label(HEAD, "backend-tests")
RUNNER = "sixlab-pr1173-fffffr1-05"
SERVICE = "sixlab-pr1173-fffffr1-ephemeral-05.service"


def pull():
    return {
        "number": 1173,
        "state": "open",
        "draft": False,
        "base": {"ref": "main", "sha": BASE_SHA},
        "head": {"sha": HEAD},
    }


def run():
    return {
        "id": 9001,
        "workflow_id": collector.WORKFLOW_PROFILES["backend"]["id"],
        "name": collector.WORKFLOW_PROFILES["backend"]["name"],
        "path": collector.WORKFLOW_PROFILES["backend"]["path"],
        "run_attempt": 1,
        "head_sha": HEAD,
        "status": "in_progress",
        "event": "pull_request",
        "repository": {"full_name": shadow.EXPECTED_REPOSITORY},
        "pull_requests": [{
            "number": 1173,
            "head": {"sha": HEAD},
            "base": {"ref": "main"},
        }],
    }


def jobs():
    rows = [
        {
            "id": 1001,
            "run_id": 9001,
            "run_attempt": 1,
            "name": "backend-detect",
            "status": "completed",
            "conclusion": "success",
            "labels": [shadow.exact_label(HEAD, "backend-detect")],
            "runner_id": 239,
            "runner_name": "sixlab-pr1173-fffffr1-02",
            "created_at": "2026-09-01T00:00:00Z",
        },
        {
            "id": 1002,
            "run_id": 9001,
            "run_attempt": 1,
            "name": "backend-tests",
            "status": "in_progress",
            "conclusion": None,
            "labels": [LABEL],
            "runner_id": 240,
            "runner_name": RUNNER,
            "created_at": "2026-09-01T00:01:00Z",
        },
    ]
    return {"total_count": len(rows), "jobs": rows}


def runners():
    rows = [{
        "id": 240,
        "name": RUNNER,
        "status": "online",
        "busy": True,
        "labels": [{"name": LABEL}],
    }]
    return {"total_count": len(rows), "runners": rows}


def host():
    return {
        "schema": "sixlab-jit-host-probe-v1",
        "observed_at": "2026-09-01T00:02:00Z",
        "hostname": "VM-0-10-ubuntu",
        "global_lock_held": True,
        "active_services": [SERVICE],
        "service_details": [{
            "name": SERVICE,
            "active_state": "active",
            "sub_state": "running",
            "main_pid": 700,
            "control_group": f"/system.slice/{SERVICE}",
            "pids": [700, 701, 702, 703, 704, 705, 706, 707],
            "uids": [0, 1005],
            "dedicated_pids": [701, 702, 703, 704, 705, 706, 707],
        }],
        "dedicated_process_count": 7,
        "run_directories": ["/run/sj05"],
        "mounts": ["/run/sj05"],
        "egress_checked": True,
        "egress_rules": [
            "nft:inet:s11732605:table inet s11732605 {",
            "nft:inet:s11732605:meta skuid 1005 ip daddr 127.0.0.1 tcp dport { 3306, 6379 } accept",
            "nft:inet:s11732605:meta skuid 1005 ip daddr 127.0.0.1 tcp dport 18080 accept",
            "nft:inet:s11732605:meta skuid 1005 ip daddr 127.0.0.1 udp dport 15353 accept",
            "nft:inet:s11732605:meta skuid 1005 ip daddr 127.0.0.1 tcp dport 15353 accept",
            "nft:inet:s11732605:meta skuid 1005 ip daddr 127.0.0.1 tcp dport 32768-60999 accept",
            "nft:inet:s11732605:meta skuid 1005 ip daddr { private-v4 } drop",
            "nft:inet:s11732605:meta skuid 1005 ip6 daddr { private-v6 } drop",
            "nft:inet:s11732605:meta skuid 1005 ip daddr 10.0.0.10 drop",
            "nft:inet:s11732605:meta skuid 1005 ip6 daddr 2402:4e00:c032:2e00:48a4:2b84:989c:0 drop",
            "nft:inet:s11732605:meta skuid 1005 drop",
            "iptables::SLPR117305 - [0:0]",
            "iptables::SLPD117305 - [0:0]",
            "iptables:-A SLPR117305 -d 127.0.0.1/32 -p tcp --dport 3306 -m comment --comment sixlab-pr1173-ephemeral-05 -j ACCEPT",
            "iptables:-A SLPR117305 -d 127.0.0.1/32 -p tcp --dport 6379 -m comment --comment sixlab-pr1173-ephemeral-05 -j ACCEPT",
            "iptables:-A SLPR117305 -d 127.0.0.1/32 -p tcp --dport 18080 -m comment --comment sixlab-pr1173-ephemeral-05 -j ACCEPT",
            "iptables:-A SLPR117305 -d 127.0.0.1/32 -p udp --dport 15353 -m comment --comment sixlab-pr1173-ephemeral-05 -j ACCEPT",
            "iptables:-A SLPR117305 -d 127.0.0.1/32 -p tcp --dport 15353 -m comment --comment sixlab-pr1173-ephemeral-05 -j ACCEPT",
            "iptables:-A SLPR117305 -d 127.0.0.1/32 -p tcp --dport 32768:60999 -m comment --comment sixlab-pr1173-ephemeral-05 -j ACCEPT",
            *[
                f"iptables:-A SLPR117305 -d 10.0.{index}.0/24 -m comment --comment sixlab-pr1173-ephemeral-05 -j DROP"
                for index in range(9)
            ],
            "iptables:-A SLPR117305 -m comment --comment sixlab-pr1173-ephemeral-05 -j DROP",
            "iptables:-A SLPD117305 -p udp -m udp --dport 53 -j REDIRECT --to-ports 15353",
            "iptables:-A SLPD117305 -p tcp -m tcp --dport 53 -j REDIRECT --to-ports 15353",
            "iptables:-A OUTPUT -m owner --uid-owner 1005 -m comment --comment sixlab-pr1173-ephemeral-05 -j SLPR117305",
            "iptables:-A OUTPUT -m owner --uid-owner 1005 -m comment --comment sixlab-pr1173-dns-05 -j SLPD117305",
        ],
        "user_manager_active": True,
        "load5": 0.2,
        "root_free_bytes": 40 * 1024 * 1024 * 1024,
        "memory_available_bytes": 5 * 1024 * 1024 * 1024,
        "swap_free_bytes": 1024 * 1024 * 1024,
        "receipt_file": None,
    }


observations = [
    {"observed_at": "2026-09-01T00:00:00Z", "head_sha": HEAD},
    {"observed_at": "2026-09-01T00:01:00Z", "head_sha": HEAD},
]
snapshot = collector.build_snapshot(
    pull=pull(),
    run=run(),
    jobs_payload=jobs(),
    runners_payload=runners(),
    host_probe=host(),
    run_inventory_ids=[9001],
    observations=observations,
    observed_at="2026-09-01T00:03:00Z",
)
assert snapshot["allocation"]["service_name"] == SERVICE
assert snapshot["jobs"][1]["labels"] == [LABEL]
decision = shadow.evaluate(snapshot)
assert decision["status"] == "shadow-running", decision
assert decision["token_allowed"] is False
assert decision["live_mutation_allowed"] is False
assert collector._latest_observed_at(
    "2026-09-01T00:00:00Z", "2026-09-01T00:00:01Z"
) == "2026-09-01T00:00:01Z"
try:
    collector._trusted_snapshot_observed_at(
        "2026-09-01T00:00:00Z", "2026-09-01T00:00:06Z"
    )
except collector.CollectorError as error:
    assert "trusted local clock" in str(error)
else:
    raise AssertionError("future host clock manufactured a later observation")
assert collector._trusted_snapshot_observed_at(
    "2026-09-01T00:00:10Z", "2026-09-01T00:00:00Z"
) == "2026-09-01T00:00:10Z"
compile(collector.REMOTE_PROBE, "sixlab-jit-remote-probe.py", "exec")


def timeout_runner(*_args, **_kwargs):
    raise subprocess.TimeoutExpired(
        cmd=["ssh", "-i", "/private/secret/runner.pem"], timeout=1,
    )


try:
    collector._json_command(
        ["ssh", "-i", "/private/secret/runner.pem"],
        label="JIT host probe",
        runner=timeout_runner,
    )
except collector.CollectorError as error:
    assert str(error) == "JIT host probe timed out"
    assert "runner.pem" not in str(error)
else:
    raise AssertionError("collector timeout escaped without CHECK-INCOMPLETE classification")

collector._validate_pull_readback(pull(), copy.deepcopy(pull()), 1173)
for mutate in (
    lambda value: value["head"].update({"sha": "e" * 40}),
    lambda value: value["base"].update({"sha": "c" * 40}),
    lambda value: value.update({"state": "closed"}),
):
    changed_pull = copy.deepcopy(pull())
    mutate(changed_pull)
    try:
        collector._validate_pull_readback(pull(), changed_pull, 1173)
    except collector.CollectorError as error:
        assert "changed during evidence collection" in str(error)
    else:
        raise AssertionError("concurrent pull drift was accepted")


def inventory_run(profile_name, run_id):
    row = run()
    profile = collector.WORKFLOW_PROFILES[profile_name]
    row.update({
        "id": run_id,
        "workflow_id": profile["id"],
        "name": profile["name"],
        "path": profile["path"],
    })
    return row


run_inventory_payload = {
    "total_count": 2,
    "workflow_runs": [inventory_run("backend", 9001), inventory_run("spa", 8001)],
}
assert collector._current_run_ids(run_inventory_payload, 1173, HEAD) == [8001, 9001]
try:
    collector._current_run_ids(
        {"total_count": 1, "workflow_runs": [inventory_run("backend", 9001)]},
        1173,
        HEAD,
    )
except collector.CollectorError as error:
    assert "workflow run set is incomplete" in str(error)
else:
    raise AssertionError("incomplete current-head run inventory was accepted")

collector._validate_run_jobs_readback(run(), copy.deepcopy(run()), jobs(), copy.deepcopy(jobs()))
new_attempt = copy.deepcopy(run())
new_attempt["run_attempt"] = 2
try:
    collector._validate_run_jobs_readback(run(), new_attempt, jobs(), jobs())
except collector.CollectorError as error:
    assert "run changed" in str(error)
else:
    raise AssertionError("latest run attempt drift was accepted")
changed_jobs = copy.deepcopy(jobs())
changed_jobs["jobs"][1]["status"] = "completed"
changed_jobs["jobs"][1]["conclusion"] = "success"
try:
    collector._validate_run_jobs_readback(run(), run(), jobs(), changed_jobs)
except collector.CollectorError as error:
    assert "jobs changed" in str(error)
else:
    raise AssertionError("workflow job readback drift was accepted")

wrong_pull_run = run()
wrong_pull_run["pull_requests"][0]["number"] = 9999
try:
    collector.build_snapshot(
        pull=pull(), run=wrong_pull_run, jobs_payload=jobs(),
        runners_payload=runners(), host_probe=host(), run_inventory_ids=[9001], observations=observations,
        observed_at="2026-09-01T00:03:00Z",
    )
except collector.CollectorError as error:
    assert "pull identity" in str(error)
else:
    raise AssertionError("workflow run from another PR was rebound")

wrong_workflow_run = run()
wrong_workflow_run["workflow_id"] = collector.WORKFLOW_PROFILES["spa"]["id"]
wrong_workflow_run["name"] = collector.WORKFLOW_PROFILES["spa"]["name"]
wrong_workflow_run["path"] = collector.WORKFLOW_PROFILES["spa"]["path"]
try:
    collector.build_snapshot(
        pull=pull(), run=wrong_workflow_run, jobs_payload=jobs(),
        runners_payload=runners(), host_probe=host(), run_inventory_ids=[9001], observations=observations,
        observed_at="2026-09-01T00:03:00Z",
    )
except collector.CollectorError as error:
    assert "workflow run identity" in str(error)
else:
    raise AssertionError("exact jobs from an unintended workflow were accepted")

wrong_slot_jobs = jobs()
wrong_slot_jobs["jobs"][1]["runner_name"] = "sixlab-pr1173-fffffr1-07"
wrong_slot_runners = runners()
wrong_slot_runners["runners"][0]["name"] = "sixlab-pr1173-fffffr1-07"
wrong_slot_host = host()
wrong_slot_service = "sixlab-pr1173-fffffr1-ephemeral-07.service"
wrong_slot_host["active_services"] = [wrong_slot_service]
wrong_slot_host["service_details"][0].update({
    "name": wrong_slot_service,
    "control_group": f"/system.slice/{wrong_slot_service}",
})
try:
    collector.build_snapshot(
        pull=pull(), run=run(), jobs_payload=wrong_slot_jobs,
        runners_payload=wrong_slot_runners, host_probe=wrong_slot_host,
        run_inventory_ids=[9001], observations=observations,
        observed_at="2026-09-01T00:03:00Z",
    )
except collector.CollectorError as error:
    assert "slot and family drifted" in str(error)
else:
    raise AssertionError("active job was accepted on a slot for another family")

awaiting_jobs = jobs()
awaiting_jobs["jobs"][1].update({
    "status": "queued",
    "conclusion": None,
    "runner_id": None,
    "runner_name": None,
})
awaiting_runners = runners()
awaiting_runners["runners"][0]["busy"] = False
awaiting_snapshot = collector.build_snapshot(
    pull=pull(),
    run={**run(), "status": "queued"},
    jobs_payload=awaiting_jobs,
    runners_payload=awaiting_runners,
    host_probe=host(),
    run_inventory_ids=[9001],
    observations=observations,
    observed_at="2026-09-01T00:03:00Z",
)
assert awaiting_snapshot["allocation"]["job_id"] == 1002
assert shadow.evaluate(awaiting_snapshot)["status"] == "shadow-awaiting-binding"

noncanonical_exact_runner = runners()
noncanonical_exact_runner["runners"][0]["name"] = "persistent-renamed-runner"
noncanonical_exact_runner["runners"][0]["busy"] = False
try:
    collector.build_snapshot(
        pull=pull(),
        run={**run(), "status": "queued"},
        jobs_payload=awaiting_jobs,
        runners_payload=noncanonical_exact_runner,
        host_probe=host(),
        run_inventory_ids=[9001],
        observations=observations,
        observed_at="2026-09-01T00:03:00Z",
    )
except collector.CollectorError as error:
    assert "awaiting Runner name is not canonical" in str(error)
else:
    raise AssertionError("noncanonical exact-label Runner was omitted from inventory")

missing_name_exact_runner = runners()
missing_name_exact_runner["runners"][0]["name"] = None
try:
    collector._jit_inventory(missing_name_exact_runner)
except collector.CollectorError as error:
    assert "exact-label Runner name is invalid" in str(error)
else:
    raise AssertionError("nameless exact-label Runner was omitted from inventory")

assert collector._validate_runner_inventory_readback(
    runners(), copy.deepcopy(runners()),
) == collector._jit_inventory(runners())
for mutate_runner in (
    lambda value: value["runners"][0].update({"status": "offline"}),
    lambda value: value["runners"][0].update({"busy": False}),
    lambda value: value["runners"][0]["labels"].append({"name": "unexpected"}),
    lambda value: (
        value["runners"].append({
            "id": 241,
            "name": "sixlab-pr1173-fffffr1-06",
            "status": "online",
            "busy": False,
            "labels": [{"name": shadow.exact_label(HEAD, "backend-unit")}],
        }),
        value.update({"total_count": 2}),
    ),
):
    changed_inventory = copy.deepcopy(runners())
    mutate_runner(changed_inventory)
    try:
        collector._validate_runner_inventory_readback(runners(), changed_inventory)
    except collector.CollectorError as error:
        assert "Runner inventory changed" in str(error)
    else:
        raise AssertionError("JIT Runner inventory drift was accepted")

incomplete_host = host()
incomplete_host.pop("memory_available_bytes")
try:
    collector.build_snapshot(
        pull=pull(), run=run(), jobs_payload=jobs(), runners_payload=runners(),
        host_probe=incomplete_host, run_inventory_ids=[9001], observations=observations,
        observed_at="2026-09-01T00:03:00Z",
    )
except collector.CollectorError as error:
    assert "host probe coverage is incomplete" in str(error)
else:
    raise AssertionError("incomplete host probe escaped structured failure")

closing_host = copy.deepcopy(host())
closing_host["observed_at"] = "2026-09-01T00:02:01Z"
closing_host["load5"] = 0.3
closing_host["root_free_bytes"] -= 4096
assert collector._validate_host_readback(host(), closing_host) == closing_host
for field, value in (
    ("global_lock_held", False),
    ("active_services", []),
    ("dedicated_process_count", 8),
    ("run_directories", []),
    ("mounts", []),
    ("egress_rules", ["iptables:drift"]),
    ("user_manager_active", False),
    ("receipt_file", {"unexpected": True}),
):
    changed_host = copy.deepcopy(closing_host)
    changed_host[field] = value
    try:
        collector._validate_host_readback(host(), changed_host)
    except collector.CollectorError as error:
        assert "host runtime changed" in str(error)
    else:
        raise AssertionError(f"host runtime drift was accepted: {field}")
backwards_host = copy.deepcopy(host())
backwards_host["observed_at"] = "2026-09-01T00:01:59Z"
try:
    collector._validate_host_readback(host(), backwards_host)
except collector.CollectorError as error:
    assert "time moved backwards" in str(error)
else:
    raise AssertionError("backwards host readback time was accepted")

wrong_service_host = host()
wrong_service_host["service_details"][0]["uids"] = [0]
wrong_service_host["service_details"][0]["dedicated_pids"] = []
try:
    collector.build_snapshot(
        pull=pull(), run=run(), jobs_payload=jobs(), runners_payload=runners(),
        host_probe=wrong_service_host, run_inventory_ids=[9001], observations=observations,
        observed_at="2026-09-01T00:03:00Z",
    )
except collector.CollectorError as error:
    assert "service cgroup binding" in str(error)
else:
    raise AssertionError("service without dedicated UID membership was accepted")

first = dict(snapshot)
first["head_observations"] = observations[:1]
result = shadow.evaluate(first)
assert result["status"] == "shadow-reconcile-required"
assert "HEAD_STABILITY_WINDOW_INCOMPLETE" in result["blockers"]

stale = jobs()
stale["jobs"][1]["labels"] = [shadow.exact_label("e" * 40, "backend-tests")]
try:
    collector.build_snapshot(
        pull=pull(), run=run(), jobs_payload=stale, runners_payload=runners(),
        host_probe=host(), run_inventory_ids=[9001], observations=observations, observed_at="2026-09-01T00:03:00Z",
    )
except collector.CollectorError as error:
    assert "current-head bound" in str(error)
else:
    raise AssertionError("stale exact label was accepted")

orphan = runners()
orphan["runners"].append({
    "id": 241,
    "name": "sixlab-pr9999-eeeee-r1-09",
    "status": "offline",
    "busy": False,
    "labels": [{"name": LABEL}],
})
orphan["total_count"] += 1
orphan_snapshot = collector.build_snapshot(
    pull=pull(), run=run(), jobs_payload=jobs(), runners_payload=orphan,
    host_probe=host(), run_inventory_ids=[9001], observations=observations, observed_at="2026-09-01T00:03:00Z",
)
result = shadow.evaluate(orphan_snapshot)
assert result["status"] == "CHECK-INCOMPLETE"
assert result["blockers"] == ["RUNNING_JOB_RUNTIME_BINDING_INCOMPLETE"]

terminal_jobs = jobs()
terminal_jobs["jobs"][1]["status"] = "completed"
terminal_jobs["jobs"][1]["conclusion"] = "success"
terminal_host = host()
terminal_host["observed_at"] = "2026-09-01T01:00:00Z"
terminal_host["global_lock_held"] = False
terminal_host["active_services"] = []
terminal_host["service_details"] = []
terminal_host["dedicated_process_count"] = 0
terminal_host["run_directories"] = []
terminal_host["mounts"] = []
terminal_host["egress_rules"] = []
terminal_host["user_manager_active"] = False
receipt_text = (
    f"slot=05 runner={RUNNER} expected_head={HEAD} label={LABEL} "
    "exit=0 finished=2026-09-01T08:59:30+08:00\n"
)
receipt_path = (
    "/var/lib/sixlab-ephemeral-v1/receipts/"
    "sixlab-pr1173-fffffr1-ephemeral-05.receipt"
)
terminal_host["receipt_file"] = {
    "path": receipt_path,
    "mode": 0o444,
    "uid": 0,
    "text": receipt_text,
    "sha256": hashlib.sha256(receipt_text.encode()).hexdigest(),
}
terminal_snapshot = collector.build_snapshot(
    pull=pull(),
    run={**run(), "status": "completed"},
    jobs_payload=terminal_jobs,
    runners_payload={"total_count": 0, "runners": []},
    host_probe=terminal_host,
    run_inventory_ids=[9001],
    observations=observations,
    observed_at="2026-09-01T01:01:00Z",
    terminal_job_id=1002,
)
result = shadow.evaluate(terminal_snapshot)
assert result["status"] == "shadow-teardown-verified", result
assert result["evidence"]["source_receipt_sha256"] == hashlib.sha256(
    receipt_text.encode()
).hexdigest()

iptables_residue_host = dict(terminal_host)
iptables_residue_host["egress_rules"] = [
    "iptables:-A OUTPUT -m owner --uid-owner 1005 -j SLPR117305"
]
iptables_residue_snapshot = collector.build_snapshot(
    pull=pull(),
    run={**run(), "status": "completed"},
    jobs_payload=terminal_jobs,
    runners_payload={"total_count": 0, "runners": []},
    host_probe=iptables_residue_host,
    run_inventory_ids=[9001],
    observations=observations,
    observed_at="2026-09-01T01:01:00Z",
    terminal_job_id=1002,
)
result = shadow.evaluate(iptables_residue_snapshot)
assert result["status"] == "shadow-reconcile-required", result
assert "EGRESS_RULE_REMAINS" in result["blockers"]

with tempfile.TemporaryDirectory(prefix="sixlab-jit-collector.") as temporary:
    root = Path(temporary)
    root.chmod(0o700)
    history = root / "history.json"
    try:
        collector.collect_live(
            pull_number=1173, run_id=9001, ssh_key=root / "unused.pem",
            history_file=history,
        )
    except collector.CollectorError as error:
        assert "retired" in str(error)
    else:
        raise AssertionError("legacy single-run collector remained callable")

    correlation = json.loads((project / "tests" / "fixtures" / "sixlab-pr-runner-correlation-v2.json").read_text())
    bridge_host = {
        "observed_at": "2026-09-04T00:02:00Z", "global_lock_held": False,
        "active_services": [], "service_details": [], "dedicated_process_count": 0,
        "run_directories": [], "mounts": [], "egress_rules": [], "runner_inventory": [],
        "user_manager_active": False, "load5": 0.2,
        "root_free_bytes": 20 * 1024 * 1024 * 1024,
        "memory_available_bytes": 4 * 1024 * 1024 * 1024,
        "swap_free_bytes": 1024 * 1024 * 1024,
    }
    selections_path = root / "selections.json"
    evidence_path = root / "evidence.json"
    selections_path.write_text(json.dumps({"42": "test"}), encoding="utf-8")
    evidence_path.write_text(json.dumps({"42": {
        "headObservations": [
            {"observed_at": "2026-09-04T00:00:00Z", "head_sha": "a" * 40},
            {"observed_at": "2026-09-04T00:01:00Z", "head_sha": "a" * 40},
        ], "host": bridge_host, "allocation": None, "receipt": None,
    }}), encoding="utf-8")
    cycle_output = root / "cycle.json"
    # A correlation file can only exercise fixture validation; neither the
    # fixture nor the old CLI can make a schedulable production cycle.
    fixture_evidence = json.loads(evidence_path.read_text())
    fixture = bridge.validate_test_fixture(correlation, {42: "test"}, {42: fixture_evidence["42"]})
    assert fixture["status"] == "CHECK-INCOMPLETE"
    assert fixture["live_mutation_allowed"] is False
    assert fixture["token_allowed"] is False
    canonical = subprocess.run(
        [sys.executable, str(source), "--sixlab-live-collector", "/tmp/attacker-collector.mjs", "--selections", str(selections_path),
         "--evidence", str(evidence_path), "--output", str(cycle_output)],
        check=False, capture_output=True, text=True,
    )
    assert canonical.returncode == 2, canonical.stderr
    failed = json.loads(cycle_output.read_text())
    assert failed["status"] == "CHECK-INCOMPLETE"
    assert failed["live_mutation_allowed"] is False
    assert "caller-supplied SIXLAB collector path is forbidden" in failed["error"]

    collector._atomic_json(history, {
        "schema": collector.HISTORY_SCHEMA,
        "repository": shadow.EXPECTED_REPOSITORY,
        "pull_number": 1173,
        "observations": observations,
    })
    stat_mode = history.stat().st_mode & 0o777
    assert stat_mode == 0o600
    assert collector._load_history(history, 1173) == observations
    malformed = root / "malformed-history.json"
    collector._atomic_json(malformed, {
        "schema": collector.HISTORY_SCHEMA,
        "repository": shadow.EXPECTED_REPOSITORY,
        "pull_number": 1173,
        "observations": [None],
    })
    try:
        collector._load_history(malformed, 1173)
    except collector.CollectorError as error:
        assert "history observation" in str(error)
    else:
        raise AssertionError("malformed persisted history was accepted")
    replaced = collector._append_history(
        observations,
        observations[-1]["observed_at"],
        "e" * 40,
    )
    assert len(replaced) == len(observations)
    assert replaced[-1] == {
        "observed_at": observations[-1]["observed_at"],
        "head_sha": "e" * 40,
    }
    assert observations[-1]["head_sha"] == HEAD
    appended = collector._append_history(
        replaced,
        "2026-09-01T00:02:00Z",
        HEAD,
    )
    assert len(appended) == len(replaced) + 1
    assert len({row["observed_at"] for row in appended}) == len(appended)
    recovered = collector._append_history(
        [*observations, dict(observations[-1])],
        "2026-09-01T00:02:00Z",
        HEAD,
    )
    assert [row["observed_at"] for row in recovered] == [
        "2026-09-01T00:00:00Z",
        "2026-09-01T00:01:00Z",
        "2026-09-01T00:02:00Z",
    ]
    linked = root / "linked.json"
    linked.symlink_to(history)
    try:
        collector._load_history(linked, 1173)
    except collector.CollectorError as error:
        assert "unsafe" in str(error)
    else:
        raise AssertionError("symlinked history was accepted")
    stale_output = root / "collector-output.json"
    stale_output.write_text('{"status":"shadow-admit"}\n', encoding="utf-8")
    rejected = subprocess.run(
        [
            str(source),
            "--pr-number", "0",
            "--run-id", "1",
            "--ssh-key", str(root / "missing.pem"),
            "--history-file", str(history),
            "--output", str(stale_output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 2
    assert json.loads(stale_output.read_text())["status"] == "CHECK-INCOMPLETE"
    inaccessible = root / "inaccessible-history"
    inaccessible.mkdir()
    inaccessible_history = inaccessible / "history.json"
    inaccessible_history.write_text(history.read_text(encoding="utf-8"), encoding="utf-8")
    inaccessible.chmod(0)
    try:
        try:
            collector._load_history(inaccessible_history, 1173)
        except collector.CollectorError as error:
            assert "metadata is unavailable" in str(error)
        else:
            raise AssertionError("inaccessible history metadata was accepted")
    finally:
        inaccessible.chmod(0o700)

text = source.read_text(encoding="utf-8")
for forbidden in (
    "shell=True",
    "registration-token",
    "actions/runners/registration-token",
    "systemctl stop",
    "systemctl start",
    "systemctl restart",
    "gh workflow",
    "gh run rerun",
):
    assert forbidden not in text, forbidden
for required in (
    "pulls/{pull_number}",
    "actions/runs/{run_id}",
    "actions/runners?per_page=100",
    '"live_mutation_allowed": False',
    'shutil.which("iptables-save")',
    'rows.append(f"iptables:{value}")',
    'rows.append(f"nft:{family}:{name}:{value}")',
    '"api", "--hostname", "github.com"',
    'or "SLPD" in value',
    're.fullmatch(r"table (?:inet|ip|ip6) s[1-9][0-9]{3,}(?:pc[0-9]+|[0-9]+)", value)',
    "DEDICATED_UID = 1005",
    "dedicated_processes = uid_process_ids(DEDICATED_UID)",
    'f"user@{DEDICATED_UID}.service"',
    'raise CollectorError(f"{label} timed out") from None',
    'run.get("pull_requests")',
    'run.get("workflow_id")',
    'run.get("path")',
    'label="GitHub pull readback"',
    'label="GitHub run readback"',
    'label="GitHub jobs readback"',
    'label="GitHub current-head run inventory readback"',
    'label="GitHub Runner inventory readback"',
    'label="JIT host probe readback"',
    'label="GitHub Runner inventory closing readback"',
    'label="GitHub current-head run inventory closing readback"',
    'label="GitHub run closing readback"',
    'label="GitHub jobs closing readback"',
    'label="GitHub pull closing readback"',
    "_validate_pull_readback(",
    "_validate_run_jobs_readback(",
    "_validate_runner_inventory_readback(",
    "_validate_host_readback(",
    "_current_run_ids(",
    "HOST_PROBE_KEYS",
    "active or terminal Runner slot and family drifted",
    "carries_exact_label",
    "_awaiting_allocation(",
    "legacy single-PR/single-run collection is retired",
    "build_canonical_cycle(",
    "allocated service cgroup binding is incomplete",
    '"dedicated_pids": sorted(dedicated_pids)',
):
    assert required in text, required

print("SIXLABJITShadowCollectorSmoke: PASS · live-read normalization + exact allocation")
