#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = resolve(new URL("../..", import.meta.url).pathname);
const CONTRACT_PATH = resolve(ROOT, ".claude/ci-runner-automation-contract.v1.json");
const SHA = /^[0-9a-f]{40}$/;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const RUN_STATUSES = new Set(["queued", "in_progress", "completed"]);
const JOB_STATUSES = new Set(["queued", "in_progress", "completed"]);
// GitHub can terminally skip/cancel a job before it is ever assigned.  Every
// other completed result has to retain its observed runner binding.
const UNBOUND_TERMINAL_CONCLUSIONS = new Set(["cancelled", "skipped", "stale"]);

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function fail(message) {
  throw new Error(message);
}

function required(condition, message) {
  if (!condition) fail(message);
}

function expectedLabel(template, headSha, jobId) {
  return template.replace("{headSha}", headSha).replace("{jobId}", jobId);
}

function baseJobName(name) {
  return String(name).replace(/ \([^)]*\)$/, "");
}

function exactKeys(value, keys, label) {
  required(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  required(Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key)), `${label} fields are not canonical`);
}

function positiveInteger(value, label) {
  required(Number.isInteger(value) && value > 0, `${label} must be a positive integer`);
}

function canonicalTimestamp(value, label) {
  required(typeof value === "string" && UTC_TIMESTAMP.test(value) && !Number.isNaN(Date.parse(value)), `${label} must be a UTC timestamp`);
}

function validateSource(contract) {
  for (const workflow of contract.prExecutionWorkflows) {
    const source = readFileSync(resolve(ROOT, workflow.sourcePath), "utf8");
    required(source.includes("  pull_request:\n"), `${workflow.sourcePath}: missing pull_request trigger`);
    required(!source.includes("pull_request_target:"), `${workflow.sourcePath}: PR candidate workflow must not use pull_request_target`);
    required(!source.includes("sixlab-pr-trusted-persistent-canary"), `${workflow.sourcePath}: trusted persistent fallback is forbidden`);
    for (const job of workflow.jobs) {
      const exact = `sixlab-pr-job-{0}-${job.id}`;
      required(source.includes(exact), `${workflow.sourcePath}:${job.id}: missing exact head/job label template`);
    }
    required(source.includes(workflow.heavyConcurrencyTemplate.split("{prNumber}").join("{0}").split("{headSha}").join("{1}").split("{shard}").join("{2}")), `${workflow.sourcePath}: missing exact PR heavy concurrency template`);
    if (workflow.jobFamily === "spa") {
      required(source.includes("        shard: [1, 2]"), `${workflow.sourcePath}: SPA shard matrix drifted`);
      required(source.includes("      max-parallel: 1"), `${workflow.sourcePath}: SPA shard execution must remain serial`);
    }
  }

  for (const workflow of contract.trustedControlWorkflows) {
    const source = readFileSync(resolve(ROOT, workflow.sourcePath), "utf8");
    required(source.includes("  pull_request_target:"), `${workflow.sourcePath}: trusted event missing`);
    required(!source.includes("actions/checkout"), `${workflow.sourcePath}: trusted control plane must not checkout PR code`);
    required(!source.includes("pull-requests: write"), `${workflow.sourcePath}: trusted control plane must not write PRs`);
    required(!source.includes("contents: write"), `${workflow.sourcePath}: trusted control plane must not write contents`);
  }
}

export function validateSnapshot(contract, snapshot) {
  exactKeys(snapshot, ["schema", "observedAt", "repository", "openPullRequests", "runs"], "snapshot");
  required(snapshot.schema === contract.projectManagerBridge.schema, "snapshot schema does not match ProjectManager bridge contract");
  canonicalTimestamp(snapshot.observedAt, "snapshot.observedAt");
  required(snapshot?.repository === contract.repository, "snapshot repository does not match contract");
  required(Array.isArray(snapshot.openPullRequests) && snapshot.openPullRequests.length > 0, "snapshot openPullRequests must be a non-empty array");
  required(Array.isArray(snapshot.runs), "snapshot runs must be an array");

  const pulls = new Map();
  for (const [index, pr] of snapshot.openPullRequests.entries()) {
    exactKeys(pr, ["number", "state", "draft", "baseRef", "headSha"], `snapshot.openPullRequests[${index}]`);
    positiveInteger(pr.number, `snapshot.openPullRequests[${index}].number`);
    required(pr.state === "open" && pr.draft === false && pr.baseRef === "main", `snapshot.openPullRequests[${index}] is not an open ready main PR`);
    required(typeof pr.headSha === "string" && SHA.test(pr.headSha), `snapshot.openPullRequests[${index}].headSha must be a lowercase 40-character SHA`);
    required(!pulls.has(pr.number), `snapshot contains duplicate open PR ${pr.number}`);
    pulls.set(pr.number, pr);
  }

  const normalized = [];
  for (const pr of pulls.values()) {
    for (const workflow of contract.prExecutionWorkflows) {
      const matches = snapshot.runs.filter((entry) => entry?.pullRequestNumber === pr.number && entry?.workflow === workflow.workflow);
      required(matches.length === 1, `PR ${pr.number} ${workflow.workflow}: expected exactly one selected latest run`);
      const entry = matches[0];
      exactKeys(entry, ["pullRequestNumber", "workflow", "run", "jobs"], `PR ${pr.number} ${workflow.workflow}`);
      const run = entry.run;
      exactKeys(run, ["id", "headSha", "attempt", "latestAttempt", "status"], `PR ${pr.number} ${workflow.workflow}.run`);
      positiveInteger(run.id, `PR ${pr.number} ${workflow.workflow}: run.id`);
      required(run.headSha === pr.headSha, `PR ${pr.number} ${workflow.workflow}: run head SHA does not match current PR head`);
      positiveInteger(run.attempt, `PR ${pr.number} ${workflow.workflow}: run.attempt`);
      required(run.attempt === run.latestAttempt, `PR ${pr.number} ${workflow.workflow}: selected run is not the latest attempt`);
      required(RUN_STATUSES.has(run.status), `PR ${pr.number} ${workflow.workflow}: run.status is invalid`);
      required(Array.isArray(entry.jobs), `PR ${pr.number} ${workflow.workflow}: jobs must be an array`);

      const expectedInstances = new Map(workflow.jobs.map((job) => [job.id, job.instances]));
      const observed = new Map();
      const observedIds = new Set();
      for (const [index, job] of entry.jobs.entries()) {
        exactKeys(job, ["id", "runId", "runAttempt", "name", "family", "status", "conclusion", "labels", "runnerId", "runnerName", "createdAt"], `PR ${pr.number} ${workflow.workflow}.jobs[${index}]`);
        positiveInteger(job.id, `PR ${pr.number} ${workflow.workflow}.jobs[${index}].id`);
        required(!observedIds.has(job.id), `PR ${pr.number} ${workflow.workflow}: duplicate job id ${job.id}`);
        observedIds.add(job.id);
        positiveInteger(job.runId, `PR ${pr.number} ${workflow.workflow}.jobs[${index}].runId`);
        required(job.runId === run.id && job.runAttempt === run.attempt, `PR ${pr.number} ${workflow.workflow}: job run binding drifted`);
        const jobId = baseJobName(job.name);
        required(expectedInstances.has(jobId), `PR ${pr.number} ${workflow.workflow}: undeclared or cross-workflow job ${jobId}`);
        required(job.family === jobId, `PR ${pr.number} ${workflow.workflow}:${jobId}: exact family mismatch`);
        required(JOB_STATUSES.has(job.status), `PR ${pr.number} ${workflow.workflow}:${jobId}: job.status is invalid`);
        required(Array.isArray(job.labels), `PR ${pr.number} ${workflow.workflow}:${jobId}: job labels are required`);
        const exact = expectedLabel(workflow.exactLabelTemplate, pr.headSha, jobId);
        required(job.labels.length === 1 && job.labels[0] === exact, `PR ${pr.number} ${workflow.workflow}:${jobId}: exact label mismatch`);
        canonicalTimestamp(job.createdAt, `PR ${pr.number} ${workflow.workflow}:${jobId}.createdAt`);
        if (job.status === "queued") {
          required(job.conclusion === null && job.runnerId === null && job.runnerName === null, `PR ${pr.number} ${workflow.workflow}:${jobId}: queued job has a binding`);
        } else if (job.status === "in_progress") {
          required(job.conclusion === null, `PR ${pr.number} ${workflow.workflow}:${jobId}: running job has a conclusion`);
          positiveInteger(job.runnerId, `PR ${pr.number} ${workflow.workflow}:${jobId}.runnerId`);
          required(typeof job.runnerName === "string" && job.runnerName.length > 0, `PR ${pr.number} ${workflow.workflow}:${jobId}.runnerName is required`);
        } else {
          required(typeof job.conclusion === "string" && job.conclusion.length > 0, `PR ${pr.number} ${workflow.workflow}:${jobId}: completed job conclusion is missing`);
          const unboundTerminal = UNBOUND_TERMINAL_CONCLUSIONS.has(job.conclusion)
            && job.runnerId === null && job.runnerName === null;
          if (!unboundTerminal) {
            positiveInteger(job.runnerId, `PR ${pr.number} ${workflow.workflow}:${jobId}.runnerId`);
            required(typeof job.runnerName === "string" && job.runnerName.length > 0, `PR ${pr.number} ${workflow.workflow}:${jobId}.runnerName is required`);
          }
        }
        observed.set(jobId, (observed.get(jobId) ?? 0) + 1);
      }
      for (const [jobId, count] of expectedInstances) {
        required(observed.get(jobId) === count, `PR ${pr.number} ${workflow.workflow}:${jobId}: expected ${count} exact job instance(s), got ${observed.get(jobId) ?? 0}`);
      }
      normalized.push({
        pullRequestNumber: pr.number,
        workflow: workflow.workflow,
        workflowSourcePath: workflow.sourcePath,
        workflowApiId: workflow.workflowApiId,
        requiredContext: workflow.requiredContext,
        runId: run.id,
        attempt: run.attempt,
        jobFamily: workflow.jobFamily,
        headSha: pr.headSha,
        exactLabels: workflow.jobs.map((job) => ({
          jobId: job.id,
          instances: job.instances,
          label: expectedLabel(workflow.exactLabelTemplate, pr.headSha, job.id),
        })),
      });
    }
  }
  required(snapshot.runs.length === normalized.length, "snapshot has an unexpected PR or workflow run");
  return { schemaVersion: 2, repository: contract.repository, openPullRequests: [...pulls.values()], selectedRuns: normalized };
}

function main(argv) {
  const contract = readJson(CONTRACT_PATH);
  validateSource(contract);
  if (argv.length === 0 || argv[0] === "--print-contract") {
    process.stdout.write(`${JSON.stringify(contract, null, 2)}\n`);
    return;
  }
  if (argv.length === 2 && argv[0] === "--validate-snapshot") {
    process.stdout.write(`${JSON.stringify(validateSnapshot(contract, readJson(resolve(argv[1]))), null, 2)}\n`);
    return;
  }
  // The ProjectManager bridge uses this mode instead of copying the fixed
  // workflow/job map into its own caller-provided input.
  if (argv.length === 1 && argv[0] === "--validate-snapshot-stdin") {
    process.stdout.write(`${JSON.stringify(validateSnapshot(contract, JSON.parse(readFileSync(0, "utf8"))), null, 2)}\n`);
    return;
  }
  fail("usage: node scripts/ci/pr-runner-contract.mjs [--print-contract | --validate-snapshot <snapshot.json> | --validate-snapshot-stdin]");
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`CI_RUNNER_CONTRACT_INVALID: ${error.message}\n`);
    process.exitCode = 1;
  }
}
