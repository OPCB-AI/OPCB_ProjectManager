#!/usr/bin/env node

// Build the v2 ProjectManager hand-off from one stable GitHub REST window.
// This is intentionally a collector, not an authority to launch a Runner.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { validateSnapshot } from "./pr-runner-contract.mjs";

const ROOT = resolve(new URL("../..", import.meta.url).pathname);
const CONTRACT_PATH = resolve(ROOT, ".claude/ci-runner-automation-contract.v1.json");
// This is deliberately a collector-owned, version-controlled boundary rather
// than a test fixture or a value supplied by a caller.  GitHub accepts both
// workflow file names and numeric IDs in its REST route, but this collector
// must only correlate the two reviewed PR candidate workflows.
const APPROVED_PR_EXECUTION_WORKFLOW_PAIRS = new Map([
  [".github/workflows/test.yml", "test.yml"],
  [".github/workflows/test-backend.yml", "test-backend.yml"],
]);

function fail(message) {
  throw new Error(message);
}

function canonicalTimestamp(value) {
  return new Date(value).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function nextLink(headers) {
  const link = headers.get("link");
  if (!link) return null;
  const match = link.split(",").map((part) => part.trim()).find((part) => /rel="next"/.test(part));
  if (!match) return null;
  const url = match.match(/^<([^>]+)>/);
  if (!url) fail("GitHub pagination link is malformed");
  return url[1];
}

function paginationUrl(url, firstUrl, expectedPage) {
  const candidate = new URL(url);
  const first = new URL(firstUrl);
  if (candidate.origin !== first.origin || candidate.pathname !== first.pathname) fail("GitHub pagination escaped its endpoint");
  const expectedKeys = new Set([...first.searchParams.keys()]);
  if ([...candidate.searchParams.keys()].some((key) => !expectedKeys.has(key))
    || [...expectedKeys].some((key) => candidate.searchParams.getAll(key).length !== 1)) {
    fail("GitHub pagination query is malformed");
  }
  if (candidate.searchParams.get("page") !== String(expectedPage)
    || candidate.searchParams.get("per_page") !== "100") fail("GitHub pagination page is invalid");
  for (const [key, value] of first.searchParams) {
    if (key !== "page" && candidate.searchParams.get(key) !== value) fail("GitHub pagination query drifted");
  }
  return candidate.toString();
}

export async function pagedJson(firstUrl, request, { envelopeKey = null } = {}) {
  const rows = [];
  const seen = new Set();
  let url = firstUrl;
  let page = 1;
  let totalCount = null;
  while (url) {
    url = paginationUrl(url, firstUrl, page);
    if (seen.has(url)) fail("GitHub pagination loop detected");
    seen.add(url);
    const response = await request(url);
    if (!response.ok) fail(`GitHub request failed: ${response.status} ${url}`);
    const payload = await response.json();
    const pageRows = envelopeKey === null ? payload : payload?.[envelopeKey];
    if (!Array.isArray(pageRows)) fail(`GitHub paginated response lacks ${envelopeKey ?? "array"} rows`);
    if (envelopeKey !== null) {
      if (!Number.isSafeInteger(payload.total_count) || payload.total_count < 0) fail("GitHub pagination total_count is invalid");
      if (totalCount === null) totalCount = payload.total_count;
      if (totalCount !== payload.total_count) fail("GitHub pagination total_count drifted");
    }
    rows.push(...pageRows);
    const link = nextLink(response.headers);
    if (link === null) {
      if (totalCount !== null && totalCount !== rows.length) fail("GitHub pagination is incomplete");
      url = null;
    } else {
      page += 1;
      url = link;
    }
  }
  return rows;
}

function uniqueOpenMainPulls(pulls) {
  const seen = new Set();
  return pulls.map((pull) => {
    if (!Number.isInteger(pull.number) || pull.number <= 0 || seen.has(pull.number)) fail("open PR pagination is incomplete or duplicated");
    seen.add(pull.number);
    if (pull.state !== "open" || pull.draft !== false || pull.base?.ref !== "main" || !/^[0-9a-f]{40}$/.test(pull.head?.sha ?? "")) {
      fail("open PR response is not an open non-draft main PR");
    }
    return { number: pull.number, state: "open", draft: false, baseRef: "main", headSha: pull.head.sha };
  }).sort((left, right) => left.number - right.number);
}

function samePullWindow(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

export function validatePrExecutionWorkflowBindings(contract) {
  const workflows = contract?.prExecutionWorkflows;
  if (!Array.isArray(workflows) || workflows.length !== APPROVED_PR_EXECUTION_WORKFLOW_PAIRS.size) {
    fail("CI Runner contract must list every approved PR execution workflow exactly once");
  }
  const seenSourcePaths = new Set();
  const seenApiIds = new Set();
  for (const workflow of workflows) {
    const sourcePath = workflow?.sourcePath;
    const workflowApiId = workflow?.workflowApiId;
    if (typeof sourcePath !== "string" || typeof workflowApiId !== "string") {
      fail("PR execution workflow sourcePath and workflowApiId must be strings");
    }
    // Check duplication before equivalence so a duplicated endpoint is never
    // obscured by its companion source-path mismatch.
    if (seenApiIds.has(workflowApiId)) fail(`duplicate PR execution workflowApiId: ${workflowApiId}`);
    if (seenSourcePaths.has(sourcePath)) fail(`duplicate PR execution workflow sourcePath: ${sourcePath}`);
    seenApiIds.add(workflowApiId);
    seenSourcePaths.add(sourcePath);
    if (APPROVED_PR_EXECUTION_WORKFLOW_PAIRS.get(sourcePath) !== workflowApiId) {
      fail(`unapproved PR execution workflow sourcePath/workflowApiId pair: ${sourcePath} -> ${workflowApiId}`);
    }
  }
  for (const [sourcePath, workflowApiId] of APPROVED_PR_EXECUTION_WORKFLOW_PAIRS) {
    if (!seenSourcePaths.has(sourcePath) || !seenApiIds.has(workflowApiId)) {
      fail("CI Runner contract must list every approved PR execution workflow exactly once");
    }
  }
}

function runForPull(runs, pull, workflow) {
  const seenIds = new Set();
  let previousCreatedAt = null;
  for (const run of runs) {
    if (!run || typeof run !== "object" || !Number.isInteger(run.id) || run.id <= 0 || seenIds.has(run.id)) {
      fail(`PR ${pull.number} ${workflow.workflow}: workflow-runs pagination is duplicated or malformed`);
    }
    seenIds.add(run.id);
    if (typeof run.created_at !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(run.created_at)
      || Number.isNaN(Date.parse(run.created_at))) {
      fail(`PR ${pull.number} ${workflow.workflow}: workflow-runs created_at is invalid`);
    }
    const createdAt = Date.parse(run.created_at);
    // The endpoint's documented newest-first order is part of how "latest" is
    // selected.  Do not sort locally: a duplicate, out-of-order page, or equal
    // timestamp would make that selection ambiguous, so reject the window.
    if (previousCreatedAt !== null && createdAt >= previousCreatedAt) {
      fail(`PR ${pull.number} ${workflow.workflow}: workflow-runs order or created_at is ambiguous`);
    }
    previousCreatedAt = createdAt;
  }
  const matches = runs.filter((run) => run.head_sha === pull.headSha
    && run.event === "pull_request"
    && Array.isArray(run.pull_requests)
    && run.pull_requests.some((candidate) => candidate.number === pull.number));
  if (matches.length === 0) fail(`PR ${pull.number} ${workflow.workflow}: missing current-head workflow run`);
  // Keep the API ordering intact.  Sorting here would convert a corrupt or
  // ambiguous pagination window into apparently authoritative evidence.
  const run = matches[0];
  if (!Number.isInteger(run.id) || !Number.isInteger(run.run_attempt) || run.run_attempt <= 0) fail(`PR ${pull.number} ${workflow.workflow}: selected run identity is invalid`);
  return run;
}

async function selectLatestRun({ repository, apiBase, request, pull, workflow }) {
  const runsUrl = `${apiBase}/repos/${repository}/actions/workflows/${workflow.workflowApiId}/runs?event=pull_request&head_sha=${pull.headSha}&per_page=100&page=1`;
  return runForPull(await pagedJson(runsUrl, request, { envelopeKey: "workflow_runs" }), pull, workflow);
}

function normalizedJob(job, run) {
  return {
    id: job.id,
    runId: run.id,
    runAttempt: run.run_attempt,
    name: job.name,
    family: String(job.name).replace(/ \([^)]*\)$/, ""),
    status: job.status,
    conclusion: job.conclusion,
    labels: job.labels,
    runnerId: job.runner_id,
    runnerName: job.runner_name,
    createdAt: canonicalTimestamp(job.created_at),
  };
}

function currentRun(run, pull, workflow, expectedRun = null) {
  if (!run || typeof run !== "object" || !Number.isInteger(run.id) || run.id <= 0
    || !Number.isInteger(run.run_attempt) || run.run_attempt <= 0
    || run.head_sha !== pull.headSha || run.event !== "pull_request"
    || !Array.isArray(run.pull_requests) || !run.pull_requests.some((candidate) => candidate.number === pull.number)) {
    fail(`PR ${pull.number} ${workflow.workflow}: latest run readback drifted`);
  }
  if (expectedRun !== null && (run.id !== expectedRun.id || run.run_attempt !== expectedRun.run_attempt)) {
    fail(`PR ${pull.number} ${workflow.workflow}: latest attempt drifted`);
  }
  return run;
}

async function readRun({ repository, apiBase, request, pull, workflow, selectedRun }) {
  const runUrl = `${apiBase}/repos/${repository}/actions/runs/${selectedRun.id}`;
  const response = await request(runUrl);
  if (!response.ok) fail(`GitHub request failed: ${response.status} ${runUrl}`);
  return currentRun(await response.json(), pull, workflow, selectedRun);
}

export async function collectSnapshot({ contract, request, apiBase = "https://api.github.com", observedAt = () => new Date().toISOString() }) {
  const repository = contract.repository;
  if (typeof repository !== "string" || !Array.isArray(contract.prExecutionWorkflows)) fail("CI Runner contract is invalid");
  // Validate before the first REST URL is constructed or request is issued.
  validatePrExecutionWorkflowBindings(contract);
  const pullsUrl = `${apiBase}/repos/${repository}/pulls?state=open&base=main&per_page=100&page=1`;
  const firstPulls = uniqueOpenMainPulls(await pagedJson(pullsUrl, request));
  if (firstPulls.length === 0) fail("open PR inventory is empty; refuse a partial correlation cycle");
  const runs = [];
  for (const pull of firstPulls) {
    for (const workflow of contract.prExecutionWorkflows) {
      const selectedRun = await selectLatestRun({ repository, apiBase, request, pull, workflow });
      const run = await readRun({ repository, apiBase, request, pull, workflow, selectedRun });
      const jobsUrl = `${apiBase}/repos/${repository}/actions/runs/${run.id}/attempts/${run.run_attempt}/jobs?per_page=100&page=1`;
      const jobs = await pagedJson(jobsUrl, request, { envelopeKey: "jobs" });
      if (jobs.length === 0) fail(`PR ${pull.number} ${workflow.workflow}: selected attempt has no jobs`);
      // The jobs endpoint is attempt-addressed.  Re-read the run immediately so
      // a rerun between those reads cannot be mislabeled as the latest attempt.
      await readRun({ repository, apiBase, request, pull, workflow, selectedRun: run });
      runs.push({
        pullRequestNumber: pull.number,
        workflow: workflow.workflow,
        run: { id: run.id, headSha: pull.headSha, attempt: run.run_attempt, latestAttempt: run.run_attempt, status: run.status },
        jobs: jobs.map((job) => normalizedJob(job, run)),
      });
    }
  }
  // A second complete enumeration makes the result a stable window rather than
  // a mixture of an old page 1 and a newer page N.
  const finalPulls = uniqueOpenMainPulls(await pagedJson(pullsUrl, request));
  if (!samePullWindow(firstPulls, finalPulls)) fail("open PR inventory drifted during collection");
  // A direct GET of the originally selected ID cannot discover a newly created
  // run.  First re-enumerate every PR/head/workflow page and reselect its live
  // latest run before accepting any closing jobs readback.
  const closingSelections = [];
  for (const row of runs) {
    const pull = firstPulls.find((candidate) => candidate.number === row.pullRequestNumber);
    const workflow = contract.prExecutionWorkflows.find((candidate) => candidate.workflow === row.workflow);
    if (!pull || !workflow) fail("selected run closing binding is invalid");
    const latestRun = await selectLatestRun({ repository, apiBase, request, pull, workflow });
    closingSelections.push({ row, pull, workflow, latestRun });
  }
  for (const { row, pull, workflow, latestRun } of closingSelections) {
    if (latestRun.id !== row.run.id || latestRun.run_attempt !== row.run.attempt) {
      fail(`PR ${pull.number} ${workflow.workflow}: latest run or attempt drifted during closing readback`);
    }
  }
  // Close the window by independently re-reading every selected run and its
  // current attempt jobs.  A second paginated latest-run selection after jobs
  // catches a new run that appears during the jobs read itself.
  for (const { row, pull, workflow, latestRun } of closingSelections) {
    await readRun({ repository, apiBase, request, pull, workflow, selectedRun: latestRun });
    const closingJobsUrl = `${apiBase}/repos/${repository}/actions/runs/${latestRun.id}/attempts/${latestRun.run_attempt}/jobs?per_page=100&page=1`;
    const closingJobs = await pagedJson(closingJobsUrl, request, { envelopeKey: "jobs" });
    await readRun({ repository, apiBase, request, pull, workflow, selectedRun: latestRun });
    const finalLatestRun = await selectLatestRun({ repository, apiBase, request, pull, workflow });
    if (finalLatestRun.id !== row.run.id || finalLatestRun.run_attempt !== row.run.attempt) {
      fail(`PR ${pull.number} ${workflow.workflow}: latest run or attempt drifted during closing jobs readback`);
    }
    const normalized = closingJobs.map((job) => normalizedJob(job, latestRun));
    if (JSON.stringify(normalized) !== JSON.stringify(row.jobs)) fail(`PR ${pull.number} ${workflow.workflow}: jobs changed during closing readback`);
    row.run.status = latestRun.status;
  }
  const closingPulls = uniqueOpenMainPulls(await pagedJson(pullsUrl, request));
  if (!samePullWindow(firstPulls, closingPulls)) fail("open PR inventory drifted during closing readback");
  const snapshot = { schema: contract.projectManagerBridge.schema, observedAt: canonicalTimestamp(observedAt()), repository, openPullRequests: firstPulls, runs };
  validateSnapshot(contract, snapshot);
  return snapshot;
}

async function main(argv) {
  if (argv.length !== 1 || argv[0] !== "--stdout") fail("usage: node scripts/ci/collect-pr-runner-correlation.mjs --stdout");
  const token = process.env.GITHUB_TOKEN;
  if (!token) fail("GITHUB_TOKEN is required for the read-only GitHub collector");
  const contract = JSON.parse(readFileSync(CONTRACT_PATH, "utf8"));
  const snapshot = await collectSnapshot({
    contract,
    request: (url) => fetch(url, { headers: { accept: "application/vnd.github+json", authorization: `Bearer ${token}` } }),
  });
  process.stdout.write(`${JSON.stringify(snapshot)}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`CI_RUNNER_COLLECTOR_INVALID: ${error.message}\n`);
    process.exitCode = 1;
  });
}
