#!/usr/bin/env python3
import importlib.util
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile


project = Path(__file__).resolve().parent.parent
ops = project / "ops"
sys.path.insert(0, str(ops))
source = ops / "sixlab_jit_shadow_inventory.py"
spec = importlib.util.spec_from_file_location("inventory", source)
inventory = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(inventory)
shadow = inventory.shadow


HEAD = "a" * 40


def snapshot(run_id, job_id, family, created_at, observed_at="2026-09-01T00:02:00Z"):
    label = shadow.exact_label(HEAD, family)
    return {
        "schema": shadow.SCHEMA,
        "observed_at": observed_at,
        "pull": {"number": 1173, "state": "open", "draft": False, "base_ref": "main", "head_sha": HEAD},
        "head_observations": [
            {"observed_at": "2026-09-01T00:00:00Z", "head_sha": HEAD},
            {"observed_at": "2026-09-01T00:01:00Z", "head_sha": HEAD},
        ],
        "run_inventory": [run_id],
        "run": {"id": run_id, "attempt": 1, "head_sha": HEAD, "status": "queued"},
        "jobs": [{
            "id": job_id,
            "run_id": run_id,
            "run_attempt": 1,
            "name": family,
            "family": family,
            "status": "queued",
            "conclusion": None,
            "labels": [label],
            "runner_id": None,
            "runner_name": None,
            "created_at": created_at,
        }],
        "host": {
            "observed_at": observed_at,
            "global_lock_held": False,
            "active_services": [],
            "service_details": [],
            "dedicated_process_count": 0,
            "run_directories": [],
            "mounts": [],
            "egress_rules": [],
            "runner_inventory": [],
            "user_manager_active": False,
            "load5": 0.2,
            "root_free_bytes": 20 * 1024 * 1024 * 1024,
            "memory_available_bytes": 4 * 1024 * 1024 * 1024,
            "swap_free_bytes": 1024 * 1024 * 1024,
        },
        "allocation": None,
        "receipt": None,
    }


def complete(*snapshots):
    run_ids = sorted(snapshot["run"]["id"] for snapshot in snapshots)
    for item in snapshots:
        item["run_inventory"] = run_ids
    return list(snapshots)


spa = snapshot(9001, 1001, "spa-detect", "2026-09-01T00:01:30Z")
backend = snapshot(9002, 1002, "backend-detect", "2026-09-01T00:01:30Z")
decision = inventory.select_global(complete(backend, spa))
assert decision["status"] == "shadow-global-admit"
assert decision["selected_job"]["job_id"] == 1001
assert decision["evaluated_runs"] == [9001, 9002]
assert decision["token_allowed"] is False
assert decision["live_mutation_allowed"] is False

active = snapshot(9010, 1010, "spa-tests", "2026-09-01T00:01:20Z")
active_label = shadow.exact_label(HEAD, "spa-tests")
active_runner = "sixlab-pr1173-aaaaar1-03"
active_service = "sixlab-pr1173-aaaaar1-ephemeral-03.service"
active["run"]["status"] = "in_progress"
active["jobs"][0].update({
    "status": "in_progress",
    "runner_id": 77,
    "runner_name": active_runner,
})
active["allocation"] = {
    "repository": shadow.EXPECTED_REPOSITORY,
    "pull_number": 1173,
    "head_sha": HEAD,
    "run_id": 9010,
    "run_attempt": 1,
    "job_id": 1010,
    "family": "spa-tests",
    "exact_label": active_label,
    "runner_id": 77,
    "runner_name": active_runner,
    "service_name": active_service,
}
active["host"].update({
    "global_lock_held": True,
    "active_services": [active_service],
    "service_details": [{
        "name": active_service,
        "active_state": "active",
        "sub_state": "running",
        "main_pid": 700,
        "control_group": f"/system.slice/{active_service}",
        "pids": [700, 701, 702, 703],
        "uids": [0, 1005],
        "dedicated_pids": [701, 702, 703],
    }],
    "dedicated_process_count": 3,
    "run_directories": ["/run/sj03"],
    "mounts": ["/run/sj03"],
    "egress_rules": [
        "nft:inet:s11732603:table inet s11732603 {",
        "nft:inet:s11732603:meta skuid 1005 ip daddr 127.0.0.1 tcp dport { 3306, 6379 } accept",
        "nft:inet:s11732603:meta skuid 1005 ip daddr 127.0.0.1 tcp dport 18080 accept",
        "nft:inet:s11732603:meta skuid 1005 ip daddr 127.0.0.1 udp dport 15353 accept",
        "nft:inet:s11732603:meta skuid 1005 ip daddr 127.0.0.1 tcp dport 15353 accept",
        "nft:inet:s11732603:meta skuid 1005 ip daddr 127.0.0.1 tcp dport 32768-60999 accept",
        "nft:inet:s11732603:meta skuid 1005 ip daddr { private-v4 } drop",
        "nft:inet:s11732603:meta skuid 1005 ip6 daddr { private-v6 } drop",
        "nft:inet:s11732603:meta skuid 1005 ip daddr 10.0.0.10 drop",
        "nft:inet:s11732603:meta skuid 1005 ip6 daddr 2402:4e00:c032:2e00:48a4:2b84:989c:0 drop",
        "nft:inet:s11732603:meta skuid 1005 drop",
        "iptables::SLPR117303 - [0:0]",
        "iptables::SLPD117303 - [0:0]",
        "iptables:-A SLPR117303 -d 127.0.0.1/32 -p tcp --dport 3306 -m comment --comment sixlab-pr1173-ephemeral-03 -j ACCEPT",
        "iptables:-A SLPR117303 -d 127.0.0.1/32 -p tcp --dport 6379 -m comment --comment sixlab-pr1173-ephemeral-03 -j ACCEPT",
        "iptables:-A SLPR117303 -d 127.0.0.1/32 -p tcp --dport 18080 -m comment --comment sixlab-pr1173-ephemeral-03 -j ACCEPT",
        "iptables:-A SLPR117303 -d 127.0.0.1/32 -p udp --dport 15353 -m comment --comment sixlab-pr1173-ephemeral-03 -j ACCEPT",
        "iptables:-A SLPR117303 -d 127.0.0.1/32 -p tcp --dport 15353 -m comment --comment sixlab-pr1173-ephemeral-03 -j ACCEPT",
        "iptables:-A SLPR117303 -d 127.0.0.1/32 -p tcp --dport 32768:60999 -m comment --comment sixlab-pr1173-ephemeral-03 -j ACCEPT",
        *[
            f"iptables:-A SLPR117303 -d 10.0.{index}.0/24 -m comment --comment sixlab-pr1173-ephemeral-03 -j DROP"
            for index in range(9)
        ],
        "iptables:-A SLPR117303 -m comment --comment sixlab-pr1173-ephemeral-03 -j DROP",
        "iptables:-A SLPD117303 -p udp -m udp --dport 53 -j REDIRECT --to-ports 15353",
        "iptables:-A SLPD117303 -p tcp -m tcp --dport 53 -j REDIRECT --to-ports 15353",
        "iptables:-A OUTPUT -m owner --uid-owner 1005 -m comment --comment sixlab-pr1173-ephemeral-03 -j SLPR117303",
        "iptables:-A OUTPUT -m owner --uid-owner 1005 -m comment --comment sixlab-pr1173-dns-03 -j SLPD117303",
    ],
    "user_manager_active": True,
    "runner_inventory": [{
        "id": 77,
        "name": active_runner,
        "status": "online",
        "busy": True,
        "labels": [active_label],
    }],
})

peer = snapshot(9011, 1011, "backend-tests", "2026-09-01T00:01:21Z")
for field in (
    "global_lock_held",
    "active_services",
    "service_details",
    "dedicated_process_count",
    "run_directories",
    "mounts",
    "egress_rules",
    "runner_inventory",
    "user_manager_active",
):
    peer["host"][field] = copy.deepcopy(active["host"][field])
running = inventory.select_global(complete(active, peer))
assert running["status"] == "shadow-global-running"
assert running["selected_job"]["job_id"] == 1010
assert running["evaluated_runs"] == [9010, 9011]
assert running["blockers"] == []

busy_drift = copy.deepcopy(peer)
busy_drift["host"]["runner_inventory"][0]["busy"] = False
busy_result = inventory.select_global(complete(active, busy_drift))
assert busy_result["status"] == "CHECK-INCOMPLETE"
assert "ACTIVE_ALLOCATION_WITH_INCOMPLETE_INVENTORY" in busy_result["blockers"]

process_drift = copy.deepcopy(peer)
process_drift["host"]["dedicated_process_count"] += 1
process_result = inventory.select_global(complete(active, process_drift))
assert process_result["status"] == "CHECK-INCOMPLETE"
assert "ACTIVE_ALLOCATION_WITH_INCOMPLETE_INVENTORY" in process_result["blockers"]

foreign = copy.deepcopy(peer)
foreign["run"]["id"] = 9012
foreign["jobs"][0]["run_id"] = 9012
foreign["jobs"][0]["id"] = 1012
foreign["host"]["active_services"].append("sixlab-pr9999-fffffr1-ephemeral-01.service")
foreign_result = inventory.select_global(complete(active, foreign))
assert foreign_result["status"] == "CHECK-INCOMPLETE"
assert "ACTIVE_ALLOCATION_WITH_INCOMPLETE_INVENTORY" in foreign_result["blockers"]

clean_peer = snapshot(9013, 1013, "backend-unit", "2026-09-01T00:01:22Z")
inconsistent = inventory.select_global(complete(active, clean_peer))
assert inconsistent["status"] == "CHECK-INCOMPLETE"
assert "ACTIVE_ALLOCATION_WITH_INCONSISTENT_PEER_SNAPSHOT" in inconsistent["blockers"]

blocked = snapshot(9003, 1003, "backend-tests", "2026-09-01T00:01:31Z")
blocked["host"]["load5"] = shadow.MAX_LOAD5 + 0.1
result = inventory.select_global(complete(spa, blocked))
assert result["status"] == "CHECK-INCOMPLETE"
assert "LOAD5_COOLDOWN" in result["blockers"]

terminal = snapshot(9005, 1005, "backend-unit", "2026-09-01T00:01:25Z")
terminal_runner = "sixlab-pr1173-aaaaar1-06"
terminal_service = "sixlab-pr1173-aaaaar1-ephemeral-06.service"
terminal["run"]["status"] = "completed"
terminal["jobs"][0].update({
    "status": "completed",
    "conclusion": "success",
    "runner_id": 88,
    "runner_name": terminal_runner,
})
terminal["allocation"] = {
    "repository": shadow.EXPECTED_REPOSITORY,
    "pull_number": 1173,
    "head_sha": HEAD,
    "run_id": 9005,
    "run_attempt": 1,
    "job_id": 1005,
    "family": "backend-unit",
    "exact_label": shadow.exact_label(HEAD, "backend-unit"),
    "runner_id": 88,
    "runner_name": terminal_runner,
    "service_name": terminal_service,
}
terminal["receipt"] = {
    **terminal["allocation"],
    "schema": shadow.RECEIPT_SCHEMA,
    "exit_code": 0,
    "finished_at": "2026-09-01T00:01:40Z",
    "source_receipt_sha256": "1" * 64,
}
decision = inventory.select_global(complete(terminal, spa))
assert decision["status"] == "shadow-global-admit", decision
assert decision["selected_job"]["job_id"] == 1001
assert decision["evaluated_runs"] == [9001, 9005]
idle = inventory.select_global(complete(terminal))
assert idle["status"] == "shadow-global-idle", idle
assert idle["selected_job"] is None

active_with_terminal = inventory.select_global(complete(active, terminal))
assert active_with_terminal["status"] == "shadow-global-running", active_with_terminal
assert active_with_terminal["selected_job"]["job_id"] == 1010
assert active_with_terminal["evaluated_runs"] == [9005, 9010]

newer_terminal = copy.deepcopy(terminal)
newer_terminal["observed_at"] = "2026-09-01T00:02:30Z"
newer_terminal["host"]["observed_at"] = "2026-09-01T00:02:30Z"
stale_active = inventory.select_global(complete(active, newer_terminal))
assert stale_active["status"] == "CHECK-INCOMPLETE", stale_active
assert stale_active["blockers"] == ["ACTIVE_ALLOCATION_OBSERVATION_STALE"]

late = snapshot(
    9004, 1004, "backend-unit", "2026-09-01T00:01:32Z",
    observed_at="2026-09-01T00:03:01Z",
)
try:
    inventory.select_global(complete(spa, late))
except inventory.InventoryError as error:
    assert "bounded control cycle" in str(error)
else:
    raise AssertionError("cross-cycle snapshot inventory was accepted")

missing_peer = snapshot(9020, 1020, "backend-tests", "2026-09-01T00:01:33Z")
subset = snapshot(9021, 1021, "spa-checks", "2026-09-01T00:01:34Z")
complete(missing_peer, subset)
try:
    inventory.select_global([subset])
except inventory.InventoryError as error:
    assert "not complete" in str(error)
else:
    raise AssertionError("caller-selected run subset was treated as globally complete")

with tempfile.TemporaryDirectory(prefix="sixlab-jit-inventory.") as temporary:
    root = Path(temporary)
    invalid_snapshot = root / "invalid.json"
    invalid_snapshot.write_text("{}\n", encoding="utf-8")
    stale_output = root / "global-decision.json"
    stale_output.write_text('{"status":"shadow-global-admit"}\n', encoding="utf-8")
    rejected = subprocess.run(
        [str(source), "--snapshot", str(invalid_snapshot), "--output", str(stale_output)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 2
    assert json.loads(stale_output.read_text())["status"] == "CHECK-INCOMPLETE"
    inaccessible = root / "inaccessible"
    inaccessible.mkdir()
    inaccessible_snapshot = inaccessible / "snapshot.json"
    inaccessible_snapshot.write_text("{}\n", encoding="utf-8")
    inaccessible.chmod(0)
    try:
        rejected = subprocess.run(
            [str(source), "--snapshot", str(inaccessible_snapshot), "--output", str(stale_output)],
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        inaccessible.chmod(0o700)
    assert rejected.returncode == 2
    assert json.loads(stale_output.read_text())["status"] == "CHECK-INCOMPLETE"

text = source.read_text(encoding="utf-8")
for forbidden in ("subprocess", "urllib", "registration-token", "systemctl", "gh api"):
    assert forbidden not in text, forbidden

print("SIXLABJITShadowInventorySmoke: PASS · one global candidate across runs")
