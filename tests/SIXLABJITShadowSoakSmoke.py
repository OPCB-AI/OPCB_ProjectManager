#!/usr/bin/env python3
import copy
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path
import tempfile
import sys


project = Path(__file__).resolve().parent.parent
ops = project / "ops"
sys.path.insert(0, str(ops))

source = ops / "sixlab_jit_shadow_soak.py"
spec = importlib.util.spec_from_file_location("soak", source)
soak = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(soak)
shadow = soak.shadow


HEAD = "a" * 40
LABEL = shadow.exact_label(HEAD, "backend-tests")
ALLOCATION = {
    "repository": shadow.EXPECTED_REPOSITORY,
    "pull_number": 1173,
    "head_sha": HEAD,
    "run_id": 9001,
    "run_attempt": 1,
    "job_id": 1001,
    "family": "backend-tests",
    "exact_label": LABEL,
    "runner_id": 240,
    "runner_name": "sixlab-pr1173-aaaaar1-05",
    "service_name": "sixlab-pr1173-aaaaar1-ephemeral-05.service",
}


def snapshot(status="in_progress", terminal=False):
    host = {
        "observed_at": "2026-09-01T00:03:00Z",
        "global_lock_held": not terminal,
        "active_services": [] if terminal else [ALLOCATION["service_name"]],
        "service_details": [] if terminal else [{
            "name": ALLOCATION["service_name"],
            "active_state": "active",
            "sub_state": "running",
            "main_pid": 700,
            "control_group": f"/system.slice/{ALLOCATION['service_name']}",
            "pids": [700, 701, 702],
            "uids": [0, 1005],
            "dedicated_pids": [701, 702],
        }],
        "dedicated_process_count": 0 if terminal else 2,
        "run_directories": [] if terminal else ["/run/sj05"],
        "mounts": [] if terminal else ["/run/sj05"],
        "egress_rules": [] if terminal else [
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
        "runner_inventory": [] if terminal else [{
            "id": 240,
            "name": ALLOCATION["runner_name"],
            "status": "online",
            "busy": True,
            "labels": [LABEL],
        }],
        "user_manager_active": not terminal,
        "load5": 0.2,
        "root_free_bytes": 20 * 1024 * 1024 * 1024,
        "memory_available_bytes": 4 * 1024 * 1024 * 1024,
        "swap_free_bytes": 1024 * 1024 * 1024,
    }
    receipt = None
    if terminal:
        receipt = {
            **ALLOCATION,
            "schema": shadow.RECEIPT_SCHEMA,
            "exit_code": 0,
            "finished_at": "2026-09-01T00:02:30Z",
            "source_receipt_sha256": "1" * 64,
        }
    return {
        "schema": shadow.SCHEMA,
        "observed_at": "2026-09-01T00:04:00Z",
        "pull": {"number": 1173, "state": "open", "draft": False, "base_ref": "main", "head_sha": HEAD},
        "head_observations": [
            {"observed_at": "2026-09-01T00:00:00Z", "head_sha": HEAD},
            {"observed_at": "2026-09-01T00:01:00Z", "head_sha": HEAD},
        ],
        "run_inventory": [9001],
        "run": {"id": 9001, "attempt": 1, "head_sha": HEAD, "status": "completed" if terminal else "in_progress"},
        "jobs": [{
            "id": 1001,
            "run_id": 9001,
            "run_attempt": 1,
            "name": "backend-tests",
            "family": "backend-tests",
            "status": "completed" if terminal else status,
            "conclusion": "success" if terminal else None,
            "labels": [LABEL],
            "runner_id": 240,
            "runner_name": ALLOCATION["runner_name"],
            "created_at": "2026-09-01T00:01:30Z",
        }],
        "host": host,
        "allocation": dict(ALLOCATION),
        "receipt": receipt,
    }


with tempfile.TemporaryDirectory(prefix="sixlab-jit-soak.") as temporary:
    journal_path = Path(temporary) / "journal.json"
    running = snapshot()
    running_decision = shadow.evaluate(running)
    journal = soak.append_event(
        snapshot=running, decision=running_decision, journal_path=journal_path,
    )
    assert journal["summary"]["events"] == 1
    assert journal["summary"]["terminal_complete_jobs"] == 0
    assert journal["summary"]["gate_satisfied"] is False
    assert journal_path.stat().st_mode & 0o777 == 0o600
    assert journal["events"][0]["snapshot"] == running
    assert journal["events"][0]["decision"] == running_decision

    blocked = snapshot()
    blocked["allocation"] = None
    blocked["jobs"][0]["status"] = "queued"
    blocked["jobs"][0]["runner_id"] = None
    blocked["jobs"][0]["runner_name"] = None
    blocked["host"]["global_lock_held"] = False
    blocked["host"]["active_services"] = []
    blocked["host"]["service_details"] = []
    blocked["host"]["dedicated_process_count"] = 0
    blocked["host"]["run_directories"] = []
    blocked["host"]["mounts"] = []
    blocked["host"]["runner_inventory"] = []
    blocked["host"]["load5"] = shadow.MAX_LOAD5 + 0.1
    blocked_decision = shadow.evaluate(blocked)
    assert blocked_decision["selected_job"] is None
    journal = soak.append_event(
        snapshot=blocked, decision=blocked_decision, journal_path=journal_path,
    )
    assert journal["summary"]["events"] == 2
    assert journal["events"][-1]["binding"]["job_id"] is None

    terminal = snapshot(terminal=True)
    terminal_decision = shadow.evaluate(terminal)
    assert terminal_decision["status"] == "shadow-teardown-verified"
    journal = soak.append_event(
        snapshot=terminal, decision=terminal_decision, journal_path=journal_path,
    )
    assert journal["summary"]["events"] == 3
    assert journal["summary"]["terminal_complete_jobs"] == 1
    assert journal["events"][-1]["source_receipt_sha256"] == "1" * 64

    duplicate = soak.append_event(
        snapshot=terminal, decision=terminal_decision, journal_path=journal_path,
    )
    assert duplicate["summary"]["events"] == 3

    large = copy.deepcopy(running)
    baseline = len(json.dumps(large, separators=(",", ":"), sort_keys=True).encode())
    large["jobs"][0]["name"] = "x" * (
        soak.MAX_INPUT_BYTES - baseline + len(large["jobs"][0]["name"]) - 256
    )
    large_raw = json.dumps(large, separators=(",", ":"), sort_keys=True).encode()
    assert len(large_raw) <= soak.MAX_INPUT_BYTES
    large_decision = shadow.evaluate(large)
    large_journal_path = Path(temporary) / "large-journal.json"
    soak.append_event(
        snapshot=large, decision=large_decision, journal_path=large_journal_path,
    )
    assert large_journal_path.stat().st_size > soak.MAX_INPUT_BYTES
    assert soak._journal(large_journal_path)["summary"]["events"] == 1
    assert soak.append_event(
        snapshot=large, decision=large_decision, journal_path=large_journal_path,
    )["summary"]["events"] == 1

    def concurrent_event(index):
        candidate = copy.deepcopy(running)
        run_id = 9100 + index
        job_id = 1100 + index
        candidate["run"]["id"] = run_id
        candidate["run_inventory"] = [run_id]
        candidate["jobs"][0]["id"] = job_id
        candidate["jobs"][0]["run_id"] = run_id
        candidate["allocation"]["run_id"] = run_id
        candidate["allocation"]["job_id"] = job_id
        return candidate, shadow.evaluate(candidate)

    concurrent_rows = [concurrent_event(index) for index in range(12)]
    concurrent_journal_path = Path(temporary) / "concurrent-journal.json"
    with ThreadPoolExecutor(max_workers=6) as executor:
        list(executor.map(
            lambda row: soak.append_event(
                snapshot=row[0], decision=row[1], journal_path=concurrent_journal_path,
            ),
            concurrent_rows,
        ))
    concurrent_journal = soak._journal(concurrent_journal_path)
    assert concurrent_journal["summary"]["events"] == len(concurrent_rows)
    assert len({event["event_id"] for event in concurrent_journal["events"]}) == len(concurrent_rows)

    wrong = dict(terminal_decision)
    wrong["status"] = "shadow-running"
    try:
        soak.append_event(snapshot=terminal, decision=wrong, journal_path=journal_path)
    except soak.SoakError as error:
        assert "canonical evaluator" in str(error)
    else:
        raise AssertionError("non-canonical decision was journaled")

    corrupted = json.loads(journal_path.read_text())
    corrupted["events"][0]["terminal_complete"] = True
    journal_path.write_text(json.dumps(corrupted))
    journal_path.chmod(0o600)
    try:
        soak.append_event(snapshot=running, decision=running_decision, journal_path=journal_path)
    except soak.SoakError as error:
        assert "canonical validation" in str(error)
    else:
        raise AssertionError("corrupted persisted soak event was counted")

text = source.read_text(encoding="utf-8")
for forbidden in (
    "subprocess",
    "urllib",
    "registration-token",
    "systemctl",
    "gh api",
):
    assert forbidden not in text, forbidden
for required in (
    "MAX_JOURNAL_BYTES",
    "fcntl.flock(descriptor, fcntl.LOCK_EX)",
    "_locked_journal(journal_path)",
    "soak journal size limit reached",
):
    assert required in text, required

print("SIXLABJITShadowSoakSmoke: PASS · append-only digest journal + 20-job gate")
