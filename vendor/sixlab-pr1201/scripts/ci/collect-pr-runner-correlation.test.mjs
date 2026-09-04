import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { collectSnapshot, validatePrExecutionWorkflowBindings } from "./collect-pr-runner-correlation.mjs";

const contract = JSON.parse(readFileSync(".claude/ci-runner-automation-contract.v1.json", "utf8"));
const HEAD_A = "a".repeat(40);
const HEAD_B = "b".repeat(40);
const APPROVED_WORKFLOW_ENDPOINTS = new Map([
  ["test.yml", ".github/workflows/test.yml"],
  ["test-backend.yml", ".github/workflows/test-backend.yml"],
]);

function response(body, next = null) {
  return new Response(JSON.stringify(body), { status: 200, headers: next ? { link: `<${next}>; rel="next"` } : {} });
}

function runRecord(runId, headSha, pullNumber, attempt = 2) {
  return { id: runId, run_attempt: attempt, event: "pull_request", head_sha: headSha, status: "queued", created_at: "2026-09-04T00:00:00Z", pull_requests: [{ number: pullNumber }] };
}

function pull(number, headSha) {
  return { number, state: "open", draft: false, base: { ref: "main" }, head: { sha: headSha } };
}

function jobs(runId, headSha, family) {
  const names = family === "spa" ? ["spa-detect", "spa-tests (1)", "spa-tests (2)", "spa-checks"] : ["backend-detect", "backend-tests", "backend-unit"];
  return names.map((name, index) => ({
    id: runId * 10 + index,
    name,
    status: "queued",
    conclusion: null,
    labels: [`sixlab-pr-job-${headSha}-${name.replace(/ \([^)]*\)$/, "")}`],
    runner_id: null,
    runner_name: null,
    created_at: `2026-09-04T00:0${index}:00Z`,
  }));
}

function workflowEndpoint(value, configuredContract) {
  const match = value.pathname.match(/^\/repos\/Steven-ZYH\/sixlab\/actions\/workflows\/([^/]+)\/runs$/);
  assert.ok(match, `unexpected workflow endpoint: ${value.pathname}`);
  const workflowApiId = match[1];
  assert.ok(!workflowApiId.includes("%"), `workflow API ID must not be encoded: ${workflowApiId}`);
  const expectedSourcePath = APPROVED_WORKFLOW_ENDPOINTS.get(workflowApiId);
  assert.ok(expectedSourcePath, `unknown workflow API ID: ${workflowApiId}`);
  const configured = configuredContract.prExecutionWorkflows.find((workflow) => workflow.workflowApiId === workflowApiId);
  assert.ok(configured, `workflow API ID is absent from the contract: ${workflowApiId}`);
  assert.equal(configured.sourcePath, expectedSourcePath, `sourcePath/workflowApiId mismatch for ${workflowApiId}`);
  assert.deepEqual([...value.searchParams.entries()], [
    ["event", "pull_request"],
    ["head_sha", value.searchParams.get("head_sha")],
    ["per_page", "100"],
    ["page", "1"],
  ], "workflow-runs URL query drifted");
  return workflowApiId;
}

function requestFor({ drift = false, duplicate = false, removeEntirePullOnClosingRead = false, rerunAfterJobs = false, badRunCount = false, badJobCount = false, configuredContract = contract } = {}) {
  let pullReads = 0;
  const directReads = new Map();
  return async (url) => {
    const value = new URL(url);
    if (value.pathname.endsWith("/pulls")) {
      pullReads += 1;
      if (value.searchParams.get("page") === "1") return response([pull(42, HEAD_A)], `${value.origin}${value.pathname}?state=open&base=main&per_page=100&page=2`);
      return response(duplicate ? [pull(42, HEAD_A)] : removeEntirePullOnClosingRead && pullReads > 2 ? [] : drift && pullReads > 2 ? [pull(44, HEAD_B)] : [pull(43, HEAD_B)]);
    }
    if (value.pathname.includes("/actions/workflows/")) {
      const isBackend = workflowEndpoint(value, configuredContract) === "test-backend.yml";
      const pullNumber = value.searchParams.get("head_sha") === HEAD_A ? 42 : 43;
      const runId = (isBackend ? 200 : 100) + pullNumber;
      return response({ total_count: badRunCount ? 2 : 1, workflow_runs: [runRecord(runId, value.searchParams.get("head_sha"), pullNumber)] });
    }
    const runId = Number(value.pathname.match(/runs\/(\d+)/)[1]);
    const isBackend = runId >= 200;
    const headSha = runId % 100 === 42 ? HEAD_A : HEAD_B;
    const pullNumber = runId % 100;
    if (!value.pathname.includes("/attempts/")) {
      const reads = (directReads.get(runId) ?? 0) + 1;
      directReads.set(runId, reads);
      return response(runRecord(runId, headSha, pullNumber, rerunAfterJobs && reads >= 2 ? 3 : 2));
    }
    const rows = jobs(runId, headSha, isBackend ? "backend" : "spa");
    return response({ total_count: badJobCount ? rows.length + 1 : rows.length, jobs: rows });
  };
}

function requestWithNewClosingRuns(observedRunIds, configuredContract = contract) {
  let closingPhase = false;
  const directReads = new Map();
  return async (url) => {
    const value = new URL(url);
    if (value.pathname.endsWith("/pulls")) return response([pull(42, HEAD_A)]);
    if (value.pathname.includes("/actions/workflows/")) {
      const isBackend = workflowEndpoint(value, configuredContract) === "test-backend.yml";
      const initialId = isBackend ? 201 : 101;
      const closingId = isBackend ? 202 : 102;
      const runId = closingPhase ? closingId : initialId;
      observedRunIds.push(runId);
      // Both workflow families begin at [101, 201]; all closing enumerations
      // expose their newer [102, 202] run, so stale selection is inadmissible.
      if (isBackend) closingPhase = true;
      return response({ total_count: 1, workflow_runs: [runRecord(runId, HEAD_A, 42)] });
    }
    const runId = Number(value.pathname.match(/runs\/(\d+)/)[1]);
    const isBackend = runId >= 200;
    if (!value.pathname.includes("/attempts/")) {
      directReads.set(runId, (directReads.get(runId) ?? 0) + 1);
      return response(runRecord(runId, HEAD_A, 42));
    }
    return response({ total_count: jobs(runId, HEAD_A, isBackend ? "backend" : "spa").length, jobs: jobs(runId, HEAD_A, isBackend ? "backend" : "spa") });
  };
}

function requestWithWorkflowRunRows({ spaRuns, backendRuns = [runRecord(201, HEAD_A, 42)], configuredContract = contract }) {
  return async (url) => {
    const value = new URL(url);
    if (value.pathname.endsWith("/pulls")) return response([pull(42, HEAD_A)]);
    if (value.pathname.includes("/actions/workflows/")) {
      const rows = workflowEndpoint(value, configuredContract) === "test-backend.yml" ? backendRuns : spaRuns;
      return response({ total_count: rows.length, workflow_runs: rows });
    }
    const runId = Number(value.pathname.match(/runs\/(\d+)/)[1]);
    const isBackend = runId >= 200;
    if (!value.pathname.includes("/attempts/")) return response(runRecord(runId, HEAD_A, 42));
    const rows = jobs(runId, HEAD_A, isBackend ? "backend" : "spa");
    return response({ total_count: rows.length, jobs: rows });
  };
}

test("collects every paginated open main PR and every required workflow in one stable window", async () => {
  const snapshot = await collectSnapshot({ contract, request: requestFor(), apiBase: "https://example.test", observedAt: () => "2026-09-04T00:10:00Z" });
  assert.deepEqual(snapshot.openPullRequests.map((pull) => pull.number), [42, 43]);
  assert.equal(snapshot.runs.length, 4);
  assert.deepEqual(snapshot.runs.map((run) => run.workflow), ["test", "test-backend", "test", "test-backend"]);
});

test("uses the reviewed workflow API filename, never the source path, in every workflow-runs URL", async () => {
  const snapshot = await collectSnapshot({ contract, request: requestFor(), apiBase: "https://example.test", observedAt: () => "2026-09-04T00:10:00Z" });
  assert.equal(snapshot.runs.length, 4);
});

test("production binding validator rejects unknown, normalized, encoded, separator, and duplicate workflow pairs", () => {
  for (const mutate of [
    (invalid) => { invalid.prExecutionWorkflows[0].sourcePath = ".github/workflows/./test.yml"; },
    (invalid) => { invalid.prExecutionWorkflows[0].sourcePath = ".github\\workflows\\test.yml"; },
    (invalid) => { invalid.prExecutionWorkflows[0].sourcePath = ".github/workflows/test%2Eyml"; },
    (invalid) => { invalid.prExecutionWorkflows[0].sourcePath = ".github/workflows/test.yml/"; },
    (invalid) => { invalid.prExecutionWorkflows[0].workflowApiId = "test%2Eyml"; },
    (invalid) => { invalid.prExecutionWorkflows[0].workflowApiId = "test.yml/"; },
    (invalid) => { invalid.prExecutionWorkflows[0].workflowApiId = ".github\\workflows\\test.yml"; },
    (invalid) => { invalid.prExecutionWorkflows[0].workflowApiId = "123456"; },
    (invalid) => { invalid.prExecutionWorkflows[0].workflowApiId = "unknown.yml"; },
    (invalid) => {
      invalid.prExecutionWorkflows[1].sourcePath = ".github/workflows/test.yml";
      invalid.prExecutionWorkflows[1].workflowApiId = "test.yml";
    },
  ]) {
    const invalid = structuredClone(contract);
    mutate(invalid);
    assert.throws(() => validatePrExecutionWorkflowBindings(invalid), /(unapproved|duplicate) PR execution workflow/);
  }
});

test("rejects an invalid sourcePath to workflowApiId binding before any REST request", async () => {
  const mismatched = structuredClone(contract);
  mismatched.prExecutionWorkflows[0].sourcePath = ".github/workflows/test-backend.yml";
  let requestCount = 0;
  await assert.rejects(
    () => collectSnapshot({
      contract: mismatched,
      request: async () => {
        requestCount += 1;
        return response([]);
      },
      apiBase: "https://example.test",
    }),
    /unapproved PR execution workflow sourcePath\/workflowApiId pair/,
  );
  assert.equal(requestCount, 0);
});

test("rejects an open-PR inventory that changes before the stable-window read closes", async () => {
  const unstable = requestFor({ drift: true });
  await assert.rejects(() => collectSnapshot({ contract, request: unstable, apiBase: "https://example.test" }), /open PR inventory drifted/);
});

test("rejects deletion of an entire previously observed PR and all of its runs", async () => {
  const removed = requestFor({ removeEntirePullOnClosingRead: true });
  await assert.rejects(() => collectSnapshot({ contract, request: removed, apiBase: "https://example.test" }), /open PR inventory drifted/);
});

test("rejects a duplicated PR page instead of silently dropping it", async () => {
  await assert.rejects(() => collectSnapshot({ contract, request: requestFor({ duplicate: true }), apiBase: "https://example.test" }), /open PR pagination is incomplete or duplicated/);
});

test("rejects a GitHub REST workflow-runs or jobs envelope whose total_count cannot account for every page", async () => {
  await assert.rejects(() => collectSnapshot({ contract, request: requestFor({ badRunCount: true }), apiBase: "https://example.test" }), /pagination is incomplete/);
  await assert.rejects(() => collectSnapshot({ contract, request: requestFor({ badJobCount: true }), apiBase: "https://example.test" }), /pagination is incomplete/);
});

test("fails closed when a rerun starts after an attempt's jobs are read", async () => {
  await assert.rejects(() => collectSnapshot({ contract, request: requestFor({ rerunAfterJobs: true }), apiBase: "https://example.test" }), /latest attempt drifted/);
});

test("rejects newly created latest runs during closing enumeration instead of admitting initial [101, 201]", async () => {
  const observedRunIds = [];
  await assert.rejects(
    () => collectSnapshot({ contract, request: requestWithNewClosingRuns(observedRunIds), apiBase: "https://example.test" }),
    /latest run or attempt drifted during closing readback/,
  );
  assert.deepEqual(observedRunIds, [101, 201, 102, 202]);
});

test("rejects duplicate, out-of-order, or timestamp-ambiguous workflow-run pages", async () => {
  const older = { ...runRecord(102, HEAD_A, 42), created_at: "2026-09-04T00:00:01Z" };
  const newest = { ...runRecord(101, HEAD_A, 42), created_at: "2026-09-04T00:00:02Z" };
  await assert.rejects(
    () => collectSnapshot({ contract, request: requestWithWorkflowRunRows({ spaRuns: [newest, { ...older, id: 101 }] }), apiBase: "https://example.test" }),
    /pagination is duplicated or malformed/,
  );
  await assert.rejects(
    () => collectSnapshot({ contract, request: requestWithWorkflowRunRows({ spaRuns: [older, newest] }), apiBase: "https://example.test" }),
    /order or created_at is ambiguous/,
  );
  await assert.rejects(
    () => collectSnapshot({ contract, request: requestWithWorkflowRunRows({ spaRuns: [newest, { ...older, created_at: newest.created_at }] }), apiBase: "https://example.test" }),
    /order or created_at is ambiguous/,
  );
});
