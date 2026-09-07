#!/usr/bin/env python3
"""Offline positive/rejection tests at private transport and clock seams."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'ops'))
import sixlab_jit_trusted_cycle as trusted
import sixlab_jit_trusted_deployment as deployment
import sixlab_jit_actuator_admission as actuator
import sixlab_jit_launcher_generator as generator

bridge = trusted.bridge
fixture = json.loads((ROOT / 'tests/fixtures/sixlab-pr-runner-correlation-v2.json').read_bytes())
test_node = Path(shutil.which('node')).resolve()
files = bridge._vendored_b()
runtime = SimpleNamespace(node=SimpleNamespace(path=test_node),
    vendor=SimpleNamespace(executable_path=lambda name: files[name]),
    ssh=SimpleNamespace(path=Path('/fixed/ssh')), key=SimpleNamespace(path=Path('/fixed/key')),
    known_hosts=SimpleNamespace(path=Path('/fixed/known_hosts')), validate=lambda: None)
original_run = bridge._run_bounded_process
original_collect = bridge._collect_live_correlation
original_time, original_utc = trusted.time, trusted._utc
original_load = deployment.load_runtime
BASE = datetime(2026, 9, 4, 0, 2, 0, tzinfo=timezone.utc)


class Clock:
    seconds = 0.0
    def monotonic(self): return self.seconds
    def sleep(self, delay): self.seconds += delay


def exercise(attack=None, terminal=False, public=False):
    clock = Clock()
    trusted.time = clock
    trusted._utc = lambda: BASE + timedelta(seconds=clock.seconds)
    calls, correlations, inventories, probes = [], 0, 0, 0
    state = copy.deepcopy(fixture)
    if terminal:
        j = state['runs'][0]['jobs'][0]
        j.update(status='completed', conclusion='success', runnerId=777, runnerName='sixlab-pr42-aaaaar2-01')
    def correlation(node, vendor, **kw):
        nonlocal correlations
        correlations += 1
        calls.append(('correlation', kw['timeout_seconds']))
        assert 0 < kw['timeout_seconds'] <= 120 - clock.seconds
        clock.seconds += 1
        if attack == 'deadline' and correlations == 1: clock.seconds += 121
        if attack == 'stale-final' and correlations == 3: clock.seconds += 31
        result = copy.deepcopy(state)
        result['observedAt'] = trusted._stamp(trusted._utc())
        if attack == 'old-github': result['observedAt'] = '2020-01-01T00:00:00Z'
        if (attack == 'head-drift' and correlations == 2) or (attack == 'closing-drift' and correlations == 3):
            result['runs'][0]['jobs'][0]['createdAt'] = '2026-09-04T00:01:04Z'
        if attack == 'unselected-active':
            result['runs'][1]['jobs'][0]['status'] = 'in_progress'
        return result
    def run(command, **kw):
        nonlocal inventories, probes
        if kw['label'] == 'canonical SIXLAB validator':
            return original_run(command, **kw)
        assert 0 < kw['timeout_seconds'] <= 120 - clock.seconds
        calls.append((kw['label'], kw['timeout_seconds']))
        clock.seconds += 1
        if kw['label'] == 'paginated Runner inventory':
            inventories += 1
            assert command[:3] == [str(test_node), '--input-type=module', '--eval']
            assert kw['env'] == {'GITHUB_TOKEN': 'offline-fixture-read-token'}
            result = {'total_count': 0, 'runners': []}
            if attack == 'orphan':
                result = {'total_count': 1, 'runners': [{'id': 9, 'name': 'sixlab-pr99-orphan',
                    'status': 'offline', 'busy': False, 'labels': []}]}
            if attack == 'runner-drift' and inventories == 2:
                result = {'total_count': 1, 'runners': [{'id': 9, 'name': 'other',
                    'status': 'offline', 'busy': False, 'labels': []}]}
            if attack == 'duplicate-runner':
                result = {'total_count': 2, 'runners': [{'id': 9}, {'id': 9}]}
            return subprocess.CompletedProcess(command, 0, json.dumps(result).encode(), b'')
        assert kw['label'] == 'fixed JIT host probe'
        probes += 1
        assert command[:3] == ['/fixed/ssh', '-F', '/dev/null'] and kw['env'] == {}
        for item in ['StrictHostKeyChecking=yes', 'IdentityAgent=none', 'ControlPath=none',
                     'UserKnownHostsFile=/fixed/known_hosts', 'ProxyCommand=none']:
            assert item in command
        assert command[-5:-1] == ['/usr/bin/python3', '-I', '-S', '-']
        assert b'os.environ.clear()' in kw['input_bytes']
        observed = trusted._stamp(trusted._utc())
        if attack == 'old-host': observed = '2020-01-01T00:00:00Z'
        if attack == 'future-host': observed = trusted._stamp(trusted._utc() + timedelta(seconds=6))
        result = {'schema': 'sixlab-jit-host-probe-v1', 'observed_at': observed,
            'hostname': 'VM-0-10-ubuntu', 'global_lock_held': False, 'active_services': [],
            'service_details': [], 'dedicated_process_count': 0, 'run_directories': [],
            'mounts': [], 'egress_checked': True, 'egress_rules': [], 'user_manager_active': False,
            'load5': .2, 'root_free_bytes': 40 * 1024**3, 'memory_available_bytes': 4 * 1024**3,
            'swap_free_bytes': 1024**3, 'receipt_file': None}
        if attack == 'host-drift' and probes == 2: result['global_lock_held'] = True
        if command[-1] != '-':
            raw = ('slot=01 runner=sixlab-pr42-aaaaar2-01 expected_head=' + 'a'*40 +
                ' label=sixlab-pr-job-' + 'a'*40 + '-spa-detect exit=0 finished=2026-09-04T00:02:00+00:00')
            if attack == 'receipt-binding': raw = raw.replace('slot=01', 'slot=07')
            result['receipt_file'] = {'path': command[-1], 'mode': 0o444, 'uid': 0,
                'text': raw, 'sha256': hashlib.sha256(raw.encode()).hexdigest()}
        return subprocess.CompletedProcess(command, 0, json.dumps(result).encode(), b'')
    bridge._collect_live_correlation, bridge._run_bounded_process = correlation, run
    deployment.load_runtime = lambda: runtime
    import os
    from unittest.mock import patch
    with patch.dict(os.environ, {'GITHUB_TOKEN': 'offline-fixture-read-token'}):
        if public:
            expected = {'repository': 'Steven-ZYH/sixlab', 'pull_number': 42, 'head_sha': 'a'*40,
                'run_id': 101, 'run_attempt': 2, 'job_id': 1001, 'family': 'spa-detect',
                'exact_label': 'sixlab-pr-job-'+'a'*40+'-spa-detect'}
            schedule = {'schema': trusted.scheduler.SCHEMA, 'status': 'shadow-serial-ready', 'selected_job': expected}
            launcher, manifest = generator.render(42, 'a'*40, 2, '01')
            result = actuator.admit(schedule, None, manifest, launcher.encode(), selections={'42': 'test'})
            assert result['status'] == 'actuator-token-pending'
            assert result['token_read'] is False and result['runner_mutation_allowed'] is False
        else:
            result = trusted._collect(runtime, {'42': 'test'})
            assert result.cycle['snapshots'][0]['head_observations'][0]['observed_at'] != result.cycle['observed_at']
            decision = trusted.scheduler.evaluate(result.cycle)
            assert decision['status'] == 'shadow-serial-ready', decision
            assert decision['selected_job']['job_id'] == (1002 if terminal else 1001)
            result.assert_fresh()
            clock.seconds += 31
            try: result.assert_fresh()
            except trusted.TrustedCycleError: pass
            else: raise AssertionError('saved evidence retained admission validity')
    assert correlations == 3 and inventories == 2
    return calls


try:
    exercise()
    exercise(terminal=True)
    exercise(public=True)
    for attack in ('old-host', 'future-host', 'old-github', 'head-drift', 'closing-drift',
                   'unselected-active', 'orphan', 'runner-drift', 'duplicate-runner',
                   'host-drift', 'deadline', 'stale-final', 'receipt-binding'):
        try: exercise(attack, terminal=attack == 'receipt-binding')
        except (trusted.TrustedCycleError, bridge.BridgeError, trusted.collector.CollectorError): pass
        else: raise AssertionError('accepted attack: ' + attack)
finally:
    bridge._run_bounded_process, bridge._collect_live_correlation = original_run, original_collect
    trusted.time, trusted._utc = original_time, original_utc
    deployment.load_runtime = original_load

# The real public production entrypoint never accepts these private fixtures
# on an uninstalled developer machine, even if the intent looks valid.
try:
    actuator.admit({'schema': trusted.scheduler.SCHEMA}, None, {}, b'', selections={'42': 'test'})
except actuator.ActuatorAdmissionError as error:
    assert 'trust manifest' in str(error)
else:
    raise AssertionError('public fixture path bypassed deployment trust')

# Execute the exact private pagination program with an in-process fake fetch;
# no fetch preload, custom loader, HTTP listener or real REST request is used.
for attack in ('none', 'empty', 'duplicate', 'count-drift', 'short-page', 'over-limit', 'http-error'):
    prelude = r'''
const attack = ATTACK; let calls = 0;
globalThis.fetch = async (url, options) => {
  calls++;
  if (url !== `https://api.github.com/repos/Steven-ZYH/sixlab/actions/runners?per_page=100&page=${calls}` ||
      options.redirect !== 'error') throw Error('unexpected request');
  let total = 101, rows = calls === 1 ? Array.from({length:100}, (_,i)=>({id:i+1,name:'fixture-中'})) : [{id:101}];
  if (attack === 'empty') { total = 0; rows = []; }
  if (attack === 'duplicate' && calls === 2) rows[0].id = 1;
  if (attack === 'count-drift' && calls === 2) total = 102;
  if (attack === 'short-page' && calls === 1) rows.pop();
  if (attack === 'over-limit') total = 4097;
  const bytes = Buffer.from(JSON.stringify({total_count:total,runners:rows}));
  return {ok:attack !== 'http-error', body:(async function*(){
    for(let i=0;i<bytes.length;i+=17) yield bytes.subarray(i,i+17);
  })()};
};
'''.replace('ATTACK', json.dumps(attack))
    process = subprocess.run([str(test_node), '--input-type=module', '--eval', prelude + trusted._RUNNERS_JS],
        capture_output=True, timeout=5, env={})
    if attack in ('none', 'empty'):
        assert process.returncode == 0, process.stderr
        result = json.loads(process.stdout)
        assert len(result['runners']) == (101 if attack == 'none' else 0)
        if result['runners']: assert result['runners'][0]['name'] == 'fixture-中'
    else:
        assert process.returncode != 0, attack

for value in ({'0':'test'}, {'042':'test'}, {'9'*10000:'test'}, {42:'other'}, {True:'test'}, {42:'test', '42':'test'}):
    try: trusted._selections(value)
    except trusted.TrustedCycleError: pass
    else: raise AssertionError('noncanonical intent accepted')
print('SIXLABJITTrustedCycleSmoke: PASS · same-process production orchestration via offline private I/O')
