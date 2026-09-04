#!/usr/bin/env python3
"""Execute the digest-pinned B collector through A's production bridge seam.

The collector receives a stable, local GitHub REST window via Node's fetch
preload.  This is deliberately not an injected Python subprocess result: A
must execute B's real collector after its path and content digest are pinned.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile


project = Path(__file__).resolve().parent.parent
ops = project / "ops"
sys.path.insert(0, str(ops))
spec = importlib.util.spec_from_file_location("bridge", ops / "sixlab_jit_pr_runner_bridge.py")
bridge = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bridge)

validator = Path(os.environ["SIXLAB_CI_CONTRACT_VALIDATOR"])
collector = validator.with_name("collect-pr-runner-correlation.mjs")
fixture_path = project / "tests" / "fixtures" / "sixlab-pr-runner-correlation-v2.json"
fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
EXPECTED_B_COLLECTOR_SHA256 = "c3611524baf3e535ad4815898fa1c6cc791f777815e121674af280e3838cf021"

assert collector.is_file(), f"missing paired B collector: {collector}"
assert bridge.CANONICAL_COLLECTOR_SHA256 == EXPECTED_B_COLLECTOR_SHA256
assert hashlib.sha256(collector.read_bytes()).hexdigest() == EXPECTED_B_COLLECTOR_SHA256

host = {
    "observed_at": "2026-09-04T00:02:00Z", "global_lock_held": False,
    "active_services": [], "service_details": [], "dedicated_process_count": 0,
    "run_directories": [], "mounts": [], "egress_rules": [], "runner_inventory": [],
    "user_manager_active": False, "load5": 0.2,
    "root_free_bytes": 20 * 1024 * 1024 * 1024,
    "memory_available_bytes": 4 * 1024 * 1024 * 1024,
    "swap_free_bytes": 1024 * 1024 * 1024,
}
evidence = {
    42: {
        "headObservations": [
            {"observed_at": "2026-09-04T00:00:00Z", "head_sha": "a" * 40},
            {"observed_at": "2026-09-04T00:01:00Z", "head_sha": "a" * 40},
        ],
        "host": host,
        "allocation": None,
        "receipt": None,
    },
}


def node_fetch_preload(status: int) -> str:
    pulls = [
        {"number": row["number"], "state": row["state"], "draft": row["draft"],
         "base": {"ref": row["baseRef"]}, "head": {"sha": row["headSha"]}}
        for row in fixture["openPullRequests"]
    ]
    runs = {
        str(row["run"]["id"]): {
            "id": row["run"]["id"], "run_attempt": row["run"]["attempt"],
            "event": "pull_request", "head_sha": row["run"]["headSha"],
            "status": row["run"]["status"], "created_at": "2026-09-04T00:01:00Z",
            "pull_requests": [{"number": row["pullRequestNumber"]}],
        }
        for row in fixture["runs"]
    }
    by_workflow = {row["workflow"]: runs[str(row["run"]["id"])] for row in fixture["runs"]}
    jobs = {
        str(row["run"]["id"]): [
            {"id": job["id"], "name": job["name"], "status": job["status"],
             "conclusion": job["conclusion"], "labels": job["labels"],
             "runner_id": job["runnerId"], "runner_name": job["runnerName"],
             "created_at": job["createdAt"]}
            for job in row["jobs"]
        ]
        for row in fixture["runs"]
    }
    fixture_js = json.dumps({"pulls": pulls, "runs": runs, "byWorkflow": by_workflow, "jobs": jobs})
    return f'''const fixture = {fixture_js};
globalThis.fetch = async (rawUrl) => {{
  if ({status} !== 200) return new Response("mock collector failure", {{ status: {status} }});
  const url = new URL(rawUrl);
  let body;
  if (url.pathname.endsWith("/pulls")) body = fixture.pulls;
  else if (url.pathname.includes("/actions/workflows/")) {{
    const workflow = decodeURIComponent(url.pathname).includes("test-backend.yml") ? "test-backend" : "test";
    body = {{ total_count: 1, workflow_runs: [fixture.byWorkflow[workflow]] }};
  }} else {{
    const match = url.pathname.match(/\\/actions\\/runs\\/(\\d+)/);
    if (!match) throw new Error(`unexpected mocked collector URL: ${{url}}`);
    const run = fixture.runs[match[1]];
    body = url.pathname.includes("/attempts/")
      ? {{ total_count: fixture.jobs[match[1]].length, jobs: fixture.jobs[match[1]] }}
      : run;
  }}
  return new Response(JSON.stringify(body), {{ status: 200 }});
}};
'''


previous_token = os.environ.get("GITHUB_TOKEN")
previous_options = os.environ.get("NODE_OPTIONS")
try:
    os.environ["GITHUB_TOKEN"] = "local-cross-worktree-collector-token"
    with tempfile.TemporaryDirectory(prefix="opcb-pm-collector-smoke-") as temporary:
        temp = Path(temporary)
        preload = temp / "mock-github-fetch.cjs"
        preload.write_text(node_fetch_preload(200), encoding="utf-8")
        os.environ["NODE_OPTIONS"] = f"--require={preload}"

        # This is the actual B file launched by build_cycle, not a mocked
        # subprocess result.  A change to B now fails at this content pin.
        cycle = bridge.build_cycle({42: "test"}, evidence, collector)
        assert cycle["schema"] == bridge.BRIDGE_SCHEMA
        assert cycle["open_pull_numbers"] == [42]
        assert [snapshot["run"]["id"] for snapshot in cycle["snapshots"]] == [101]

        # A genuine collector execution with a failing REST response must not
        # fall back to the fixture or produce a cycle.
        preload.write_text(node_fetch_preload(503), encoding="utf-8")
        try:
            bridge.build_cycle({42: "test"}, evidence, collector)
        except bridge.BridgeError as error:
            assert "live collector failed" in str(error)
        else:
            raise AssertionError("failing production collector response produced a cycle")

        wrong_digest = temp / "tampered" / "scripts" / "ci" / collector.name
        wrong_digest.parent.mkdir(parents=True)
        wrong_digest.write_bytes(collector.read_bytes() + b"\\n// tampered\\n")
        try:
            bridge._canonical_collector(wrong_digest)
        except bridge.BridgeError as error:
            assert "collector digest or path drifted" in str(error)
        else:
            raise AssertionError("collector digest drift was accepted")

        wrong_path = temp / "wrong-path" / "scripts" / "ci" / "other-collector.mjs"
        wrong_path.parent.mkdir(parents=True)
        wrong_path.write_bytes(collector.read_bytes())
        try:
            bridge._canonical_collector(wrong_path)
        except bridge.BridgeError as error:
            assert "collector digest or path drifted" in str(error)
        else:
            raise AssertionError("collector path drift was accepted")
finally:
    if previous_token is None:
        os.environ.pop("GITHUB_TOKEN", None)
    else:
        os.environ["GITHUB_TOKEN"] = previous_token
    if previous_options is None:
        os.environ.pop("NODE_OPTIONS", None)
    else:
        os.environ["NODE_OPTIONS"] = previous_options

print("SIXLABJITProjectManagerBridgeProductionCollectorSmoke: PASS · pinned B collector executed with stable mock success/failure")
