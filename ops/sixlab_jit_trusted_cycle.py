#!/usr/bin/env python3
"""Private same-process production collection, never a JSON provenance API.

All I/O seams below are private and are replaced only by offline tests. The
public actuator loads a fixed verified deployment before calling this module.
No persistent journal is needed: two real full-universe observations span
the existing 60-second stability interval within one 120-second budget.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
import time

import sixlab_jit_pr_runner_bridge as bridge
import sixlab_jit_shadow_collector as collector
import sixlab_jit_shadow_controller as shadow
import sixlab_jit_serial_scheduler as scheduler

COLLECTION_WINDOW_SECONDS = 120.0
FINAL_MAX_AGE_SECONDS = 30.0
MAX_CLOCK_SKEW_SECONDS = 5.0
MAX_RUNNERS = 4096
MAX_RECEIPTS = 64

# No URL, proxy, loader, executable or pagination input is caller-selected.
# Parent process enforces an absolute remaining deadline and bounded pipes.
_RUNNERS_JS = r'''
const rows = [], seen = new Set(); let total;
for (let page = 1; page <= 42; page++) {
  const r = await fetch(`https://api.github.com/repos/Steven-ZYH/sixlab/actions/runners?per_page=100&page=${page}`, {
    redirect: 'error', headers: {Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
  });
  if (!r.ok) throw Error('Runner inventory read failed');
  let text = '', size = 0; const decoder = new TextDecoder('utf-8', {fatal: true});
  for await (const chunk of r.body) {
    size += chunk.length; if (size > 8388608) throw Error('Runner page too large');
    text += decoder.decode(chunk, {stream: true});
  }
  text += decoder.decode();
  const p = JSON.parse(text);
  if (!Number.isSafeInteger(p.total_count) || p.total_count < 0 || p.total_count > 4096 ||
      !Array.isArray(p.runners) || p.runners.length > 100 ||
      (total !== undefined && p.total_count !== total)) throw Error('Runner denominator drift');
  total = p.total_count;
  for (const x of p.runners) {
    if (!Number.isSafeInteger(x.id) || x.id <= 0 || seen.has(x.id)) throw Error('Runner duplicate');
    seen.add(x.id); rows.push(x);
  }
  if (rows.length > total || (rows.length < total && p.runners.length !== 100)) throw Error('Runner page incomplete');
  if (rows.length === total) {
    process.stdout.write(JSON.stringify({total_count: total, runners: rows})); break;
  }
  if (page === 42) throw Error('Runner pagination budget exhausted');
}
'''


class TrustedCycleError(RuntimeError):
    pass


def _utc() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(value: datetime) -> str:
    return value.isoformat().replace('+00:00', 'Z')


def _parse(value: object) -> datetime:
    try:
        return scheduler._timestamp(value)
    except scheduler.SerialSchedulerError as error:
        raise TrustedCycleError('trusted observation timestamp is invalid') from error


class _Window:
    def __init__(self):
        self.started = time.monotonic()
        self.utc_started = _utc()

    def remaining(self, cap=COLLECTION_WINDOW_SECONDS):
        elapsed = time.monotonic() - self.started
        wall_elapsed = (_utc() - self.utc_started).total_seconds()
        if elapsed < 0 or abs(wall_elapsed - elapsed) > MAX_CLOCK_SKEW_SECONDS:
            raise TrustedCycleError('collection clock drifted')
        remaining = COLLECTION_WINDOW_SECONDS - elapsed
        if remaining <= 0:
            raise TrustedCycleError('shared collection deadline expired')
        return min(cap, remaining)

    def observation(self, value, began, ended, *, host=False):
        self.remaining()
        observed = _parse(value)
        skew = MAX_CLOCK_SKEW_SECONDS if host else 0
        # ISO seconds may truncate by less than one second; no arbitrary old
        # timestamp is accepted merely because its JSON was just received.
        if (observed - began).total_seconds() < -skew - 1 or (observed - ended).total_seconds() > skew:
            raise TrustedCycleError('observation is outside its collection window')

    def fresh(self, values):
        self.remaining()
        now = _utc()
        for value in values:
            age = (now - _parse(value)).total_seconds()
            if age > FINAL_MAX_AGE_SECONDS or age < -MAX_CLOCK_SKEW_SECONDS:
                raise TrustedCycleError('final evidence is stale or future-dated')


def _json_result(completed, label):
    if completed.returncode != 0:
        raise TrustedCycleError(f'{label} failed')
    try:
        return json.loads(completed.stdout)
    except (UnicodeError, ValueError) as error:
        raise TrustedCycleError(f'{label} returned invalid JSON') from error


def _correlation(runtime, window):
    runtime.validate()
    began = _utc()
    value = bridge._collect_live_correlation(runtime.node.path, runtime.vendor,
                                            timeout_seconds=window.remaining())
    ended = _utc()
    window.observation(value.get('observedAt'), began, ended)
    validator = runtime.vendor.executable_path('scripts/ci/pr-runner-contract.mjs')
    bridge._canonical_validation(value, validator, runtime.node.path,
        expected_validator=validator, timeout_seconds=window.remaining(bridge.VALIDATOR_TIMEOUT_SECONDS))
    window.remaining()
    return value


def _runners(runtime, window):
    runtime.validate()
    value = _json_result(bridge._run_bounded_process(
        [str(runtime.node.path), '--input-type=module', '--eval', _RUNNERS_JS],
        input_bytes=None, env=bridge._collector_environment(),
        timeout_seconds=window.remaining(30), stdout_limit_bytes=8 * 1024 * 1024,
        stderr_limit_bytes=256 * 1024, label='paginated Runner inventory'), 'Runner inventory')
    window.remaining()
    _runner_identity(value)
    return value


def _runner_identity(value):
    if not isinstance(value, dict) or set(value) != {'total_count', 'runners'}:
        raise TrustedCycleError('Runner inventory envelope is invalid')
    rows = value['runners']
    if (type(value['total_count']) is not int or not isinstance(rows, list)
            or value['total_count'] != len(rows) or len(rows) > MAX_RUNNERS):
        raise TrustedCycleError('Runner inventory denominator is incomplete')
    ids = [row.get('id') for row in rows if isinstance(row, dict)]
    if len(ids) != len(rows) or any(type(i) is not int or i <= 0 for i in ids) or len(set(ids)) != len(ids):
        raise TrustedCycleError('Runner inventory has invalid or duplicate identity')
    return sorted(rows, key=lambda row: row['id'])


def _probe(runtime, window, receipt_path):
    runtime.validate()
    began = _utc()
    command = [str(runtime.ssh.path), '-F', '/dev/null', '-i', str(runtime.key.path),
        '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
        '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no',
        '-o', f'UserKnownHostsFile={runtime.known_hosts.path}',
        '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=10',
        '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none', '-o', 'ClearAllForwardings=yes',
        '-o', 'PermitLocalCommand=no', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
        f'{collector.EXPECTED_USER}@{collector.EXPECTED_HOST}',
        '/usr/bin/python3', '-I', '-S', '-', receipt_path]
    value = _json_result(bridge._run_bounded_process(command,
        input_bytes=("import os\nos.environ.clear()\nos.environ.update({'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})\n"
                     + collector.REMOTE_PROBE).encode(), env={},
        timeout_seconds=window.remaining(40), stdout_limit_bytes=8 * 1024 * 1024,
        stderr_limit_bytes=256 * 1024, label='fixed JIT host probe'), 'host probe')
    value = collector._validate_host_probe(value)
    window.observation(value['observed_at'], began, _utc(), host=True)
    return value


def _universe(value):
    source = copy.deepcopy(value)
    source.pop('observedAt', None)
    return source


def _jobs(row):
    return [{
        'id': j['id'], 'run_id': j['runId'], 'run_attempt': j['runAttempt'],
        'name': j['name'], 'family': j['family'], 'status': j['status'],
        'conclusion': j['conclusion'], 'labels': j['labels'],
        'runner_id': j['runnerId'], 'runner_name': j['runnerName'], 'created_at': j['createdAt'],
    } for j in row['jobs']]


def _terminals(correlation):
    terminals = {}
    for row in correlation['runs']:
        for job in _jobs(row):
            if job['status'] == 'in_progress' or (job['status'] == 'queued' and
                    (job['runner_id'] is not None or job['runner_name'] is not None)):
                raise TrustedCycleError('an existing job allocation forbids new admission')
            if job['status'] != 'completed':
                continue
            if (job['runner_id'] is None and job['runner_name'] is None and
                    job['conclusion'] in {'cancelled', 'skipped', 'stale'}):
                continue
            allocation = collector._job_allocation(job, pull_number=row['pullRequestNumber'],
                run_id=row['run']['id'], attempt=row['run']['attempt'], run_head=row['run']['headSha'])
            path = collector._receipt_path(allocation)
            if path in terminals or len(terminals) >= MAX_RECEIPTS:
                raise TrustedCycleError('terminal receipt mapping is ambiguous or over budget')
            terminals[path] = (row, job, allocation)
    return terminals


def _host(probe, runners):
    value = {key: probe[key] for key in collector.HOST_PROBE_KEYS - {
        'schema', 'hostname', 'egress_checked', 'receipt_file'}}
    value['runner_inventory'] = collector._jit_inventory(runners)
    if shadow._clean_host_blockers(shadow._normalize_host(value)):
        raise TrustedCycleError('host or repository JIT Runner inventory is not clean')
    return value


def _compare_probes(left, right, *, same_receipt=True):
    if not same_receipt:
        left, right = copy.deepcopy(left), copy.deepcopy(right)
        left['receipt_file'] = right['receipt_file'] = None
    collector._validate_host_readback(left, right)


def _selections(value):
    if not isinstance(value, dict) or not value or len(value) > scheduler.MAX_SNAPSHOTS:
        raise TrustedCycleError('one explicit workflow selection per open PR is required')
    result = {}
    for key, workflow in value.items():
        if type(key) is int and 0 < key <= 2**53 - 1:
            number = key
        elif isinstance(key, str) and len(key) <= 16 and key.isascii() and key.isdecimal() and str(int(key)) == key and 0 < int(key) <= 2**53 - 1:
            number = int(key)
        else:
            raise TrustedCycleError('selection PR number is not canonical')
        if number in result or workflow not in ('test', 'test-backend'):
            raise TrustedCycleError('workflow selection is invalid or duplicated')
        result[number] = workflow
    return result


class _Collected:
    def __init__(self, cycle, runtime, window, final_times):
        self.cycle, self.runtime, self.window, self.final_times = cycle, runtime, window, final_times

    def assert_fresh(self):
        self.runtime.validate()
        self.window.fresh(self.final_times)


def _collect(runtime, selections):
    """Trusted I/O-only orchestration; no evidence/clock/runner public arguments."""
    window = _Window()
    selections = _selections(selections)
    first = _correlation(runtime, window)
    first_time, first_mono = _utc(), time.monotonic()
    if set(selections) != {p['number'] for p in first['openPullRequests']}:
        raise TrustedCycleError('selection does not cover all open PRs')
    terminals = _terminals(first)
    runners = _runners(runtime, window)
    initial = _probe(runtime, window, '-')
    _host(initial, runners)
    initial_receipts = {}
    for path in terminals:
        probe = _probe(runtime, window, path)
        _compare_probes(initial, probe, same_receipt=False)
        initial_receipts[path] = probe
    # One extra second avoids false stability from second-granularity remote
    # clocks. The actual head observations are local read completion times.
    delay = shadow.MIN_HEAD_STABILITY_SECONDS + 1 - (time.monotonic() - first_mono)
    if delay > 0:
        if delay >= window.remaining():
            raise TrustedCycleError('insufficient shared budget for head stability')
        time.sleep(delay)
    window.remaining()
    second = _correlation(runtime, window)
    if _universe(first) != _universe(second):
        raise TrustedCycleError('all-PR run/attempt/job universe drifted')
    final_receipts = {}
    for path in terminals:
        probe = _probe(runtime, window, path)
        _compare_probes(initial_receipts[path], probe)
        final_receipts[path] = probe
    final = _probe(runtime, window, '-')
    _compare_probes(initial, final)
    for probe in final_receipts.values():
        _compare_probes(probe, final, same_receipt=False)
    final_runners = _runners(runtime, window)
    runner_time = _stamp(_utc())
    if _runner_identity(runners) != _runner_identity(final_runners):
        raise TrustedCycleError('repository Runner inventory changed')
    host = _host(final, final_runners)
    closing = _correlation(runtime, window)
    if _universe(first) != _universe(closing):
        raise TrustedCycleError('closing current-head/latest-attempt/job readback drifted')
    last_time = _utc()
    if (last_time - first_time).total_seconds() < shadow.MIN_HEAD_STABILITY_SECONDS:
        raise TrustedCycleError('head stability interval is incomplete')
    observations = {p['number']: [
        {'observed_at': _stamp(first_time), 'head_sha': p['headSha']},
        {'observed_at': _stamp(last_time), 'head_sha': p['headSha']},
    ] for p in closing['openPullRequests']}
    # Local closing time is the snapshot clock. B's actual observation time
    # remains separately age-checked below; it is never laundered by this.
    source = copy.deepcopy(closing)
    source['observedAt'] = _stamp(last_time)
    evidence = {number: {'headObservations': history, 'host': host, 'allocation': None, 'receipt': None}
                for number, history in observations.items()}
    validator = runtime.vendor.executable_path('scripts/ci/pr-runner-contract.mjs')
    cycle = bridge._build_from_validated_correlation(source, selections, evidence,
        validator, runtime.node.path, installed_vendor=runtime.vendor,
        timeout_seconds=window.remaining(bridge.VALIDATOR_TIMEOUT_SECONDS))
    # A clean host alone does not prove previous jobs were torn down. Verify
    # every completed bound job across ALL workflows, including unselected ones.
    pulls = {p['number']: p for p in source['openPullRequests']}
    for path, (row, job, allocation) in terminals.items():
        receipt = collector._normalized_receipt(final_receipts[path]['receipt_file'], allocation, path)
        pull = pulls[row['pullRequestNumber']]
        terminal_snapshot = {
            'schema': shadow.SCHEMA, 'observed_at': source['observedAt'],
            'pull': {'number': pull['number'], 'state': pull['state'], 'draft': pull['draft'],
                     'base_ref': pull['baseRef'], 'head_sha': pull['headSha']},
            'head_observations': observations[pull['number']], 'run_inventory': [row['run']['id']],
            'run': {'id': row['run']['id'], 'attempt': row['run']['attempt'],
                    'head_sha': row['run']['headSha'], 'status': row['run']['status']},
            'jobs': _jobs(row), 'host': host, 'allocation': allocation, 'receipt': receipt,
        }
        if shadow.evaluate(terminal_snapshot)['status'] != 'shadow-teardown-verified':
            raise TrustedCycleError('terminal teardown evidence is incomplete')
    times = [final['observed_at'], closing['observedAt'], runner_time]
    times.extend(p['observed_at'] for p in final_receipts.values())
    result = _Collected(cycle, runtime, window, times)
    result.assert_fresh()
    return result
