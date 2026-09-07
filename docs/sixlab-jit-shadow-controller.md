# SIXLAB JIT shadow controller

Status: R1 implementation-only shadow contract. It does not authorize or
perform a workflow change, Runner registration, label mutation, token mint,
service action, rerun, merge, deploy, migration, or Provider call.

## Purpose

`ops/sixlab_jit_shadow_controller.py` turns one canonical GitHub/host snapshot
into a deterministic, fail-closed decision. It is designed to run beside the
current manual exact-head one-job process so controller decisions can be soaked
without changing the existing persistent/shared CI topology.

The evaluator has no network or process API. It does not read a credential and
hard-codes both `token_allowed=false` and `live_mutation_allowed=false` in every
successful decision. A separate, future, explicitly authorized actuator would
have to re-read all live evidence before it could act.

When a controller, collector, or global-selector CLI is given `--output`, both
success and failure atomically replace that path. A malformed or incomplete
new observation, including an inaccessible input whose metadata cannot be
read, therefore cannot leave a stale admission decision available to downstream
consumers.

## Admission

The shadow controller returns `shadow-admit` only when all of these are true:

- the PR is open, non-draft, targets `main`, and the run head equals the live
  current head;
- the current head occupies a contiguous suffix of at least two strictly
  ordered observations spanning at least 60 seconds; the production heartbeat
  interval remains the stronger 10-minute outer cycle, while the inner guard
  prevents two run collectors in one heartbeat from fabricating stability;
- the selected job belongs to the latest run attempt, is still queued, has no
  Runner binding, and its GitHub job request contains exactly one exact label
  of the form
  `sixlab-pr-job-<40-hex-head>-<fixed-family>` with no additional required
  labels, matching the generated `--no-default-labels` Runner registration;
- no global lock, active service, dedicated process, run directory, mount,
  egress rule, user manager, or Runner inventory remains;
- load, disk, and memory+swap pass the shadow cooldown policy.

SPA matrix jobs intentionally share one exact `spa-tests` label. The evaluator
uses the oldest queued row only as a deterministic representative, emits both
job IDs in `eligible_job_ids`, and sets `selection_mode=any-one-same-label`;
it never pretends that a slot can preselect a shard. Once GitHub binds a real
Runner, reconciliation switches to `selection_mode=actual-binding`. A second
shard is eligible only after the first allocation has independently reached
terminal teardown.

GitHub job labels and registered Runner inventory are intentionally normalized
as different evidence layers. Current SIXLAB jobs request only the one exact
label; the Runner inventory may carry platform labels. The evaluator never
requires `self-hosted/Linux/X64` to be echoed on the job record, and separately
requires the allocated Runner inventory to contain the exact label.

## Reconciliation

An allocation binds repository, PR, head, run, attempt, job, family, exact
label, Runner ID/name, and service name. The evaluator distinguishes:

- `shadow-awaiting-binding`: service and Runner exist, but the job is queued;
- `shadow-running`: the latest-attempt job, Runner, and service bindings agree;
- `shadow-teardown-verified`: the exact job is terminal, the receipt matches,
  and every runtime residue plus Runner inventory is zero;
- `shadow-reconcile-required`: head/attempt drift or runtime residue exists;
- `CHECK-INCOMPLETE`: required evidence or an exact binding is missing.

A rerun may reuse a run ID while creating a later attempt and new job IDs.
Therefore an old-attempt terminal job never authorizes stopping or declaring
closure for the latest attempt. An offline or busy orphan Runner also prevents
the next admission until it disappears from inventory. While an allocation is
running, the snapshot must show exactly one active JIT service and exactly one
matching Runner under the held global lock; a second service or Runner fails
closed. The service reports its exact dedicated PID set; its size must equal
the global UID-1005 process count, while run directory, mount, user manager and
all firewall rows must bind only the allocation's slot. Receipt completion must follow job creation and precede the host
teardown observation.

Before a clean-host admission, no `in_progress` job may exist in any attempt.
A queued latest attempt therefore remains blocked while an earlier attempt is
still active, even when host evidence otherwise appears clean. The same
all-attempt exclusion applies after a latest-attempt Runner registers: an older
active job blocks `shadow-awaiting-binding` and every reconciliation state.
The normalized receipt also binds the SHA-256 digest of the immutable host
receipt line; enrichment with run/job/Runner IDs cannot silently replace or
rewrite the launcher receipt source.

## Shadow thresholds

The initial non-authoritative cooldown constants are `load5 <= 1.5`, at least
8 GiB free on the root filesystem, and at least 2 GiB combined available
memory plus free swap. They are deliberately part of reviewed controller code,
not candidate input. They must be calibrated with host soak before any future
actuator is considered.

## Validation

```bash
python3 tests/SIXLABJITShadowControllerSmoke.py
python3 tests/SIXLABJITShadowCollectorSmoke.py
python3 tests/SIXLABJITShadowInventorySmoke.py
python3 tests/SIXLABJITLauncherGeneratorSmoke.py
python3 tests/SIXLABJITShadowSoakSmoke.py
```

The smoke test covers stable-head admission, same-label SPA ordering, old versus
latest attempts, resource gates, missing service detection, terminal receipt
binding, offline Runner residue, unknown-field rejection, and symlinked input
rejection.

The reviewed launcher generator now emits the
`runner-exit-scope-memory-v5` execution-evidence profile. It selects the
Actions Runner `RUNNER_MANUALLY_TRAP_SIG` path so a non-zero `run.sh` status is
not converted to zero by the default wrapper. The launcher preserves the
legacy, immutable six-field `sixlab-jit-teardown-receipt-v1` line for current
collector compatibility and writes a separate immutable
`sixlab-jit-launcher-evidence-v5` JSON sidecar. The sidecar records runner,
controller, teardown, and telemetry-cleanup states separately. A controller
exit is never relabeled as a Runner exit: listener observation is recorded with
an unknown Runner exit code unless an independent Runner-exit source is added.
Telemetry freshness is independently revalidated against the finalizer's UTC
publication clock, so teardown elapsed time is included and a sample older
than two seconds becomes `unknown/stale_sample`. The finalizer repeats this
check after both immutable files have been staged and fsynced, immediately
before linking the evidence/receipt commit pair, so slow staging also fails
closed. All
telemetry transient cleanup completes before the immutable receipt/sidecar pair
is published. A teardown failure is exit 70 only
when no earlier non-zero runner/controller/signal status exists; missing or
stale scope evidence similarly produces exit 75 only when the execution status
was otherwise zero. This preserves the first abnormal execution status while
still making auxiliary-evidence failures non-zero.

The bounded root-side sampler keeps only its latest validated snapshot and
reads no environment, command line, token, full log, or core. It binds an
explicit `.scope` unit to UID 1005 and a bounded PID inventory. Before the
scope starts, the controller records the device/inode identity of the copied
`Runner.Listener`; only a `/proc/<pid>/exe` matching that exact executable
identity counts as listener observation. A scope that never exposes that
verified listener becomes `unknown/runner_listener_not_observed` and cannot
produce a zero evidence exit. The collector also rejects
symlinked or out-of-root cgroup paths, and allows only scalar fields from
`memory.current`, `memory.peak`, `memory.events`, `memory.events.local`, and
`memory.pressure`. Missing, stale, malformed, ambiguously bound, or oversized
evidence is recorded as `unknown`; it is never interpreted as proof that an
OOM did or did not occur. Existing shadow collector/controller code does not
ingest this sidecar, so installing it or activating a new consumer remains a
separate reviewed and explicitly authorized change.

`ops/sixlab_jit_shadow_collector.py` is the matching read-only collector. It
uses fixed GitHub `pull`, `run`, `jobs`, current-head run-inventory, and
Runner-inventory GET endpoints plus a fixed Python probe sent to the Tencent
host over SSH stdin. The host probe
reads systemd service/cgroup membership, the global lock inode, `/run/sj*`
directories and mounts, nft table names, load, disk, memory and user-manager
state. It never reads process arguments or Runner credential files. The only
local writes are mode-0600 head-history, snapshot, and decision JSON files.
The snapshot/history timestamp always comes from the trusted local collector
clock. A host timestamp more than five seconds ahead is rejected; an older host
timestamp may be retained as evidence but cannot extend the head-stability
window. Malformed or non-UTC times still fail closed.
The collector reads the PR a second time after all dependent GitHub and host
evidence. Any head SHA, base SHA/ref, state, draft flag or PR identity drift
during collection rejects the snapshot. The current-head run enumeration must
contain exactly one target-PR run for each fixed `test` and `test-backend`
workflow profile; its sorted run-ID set is embedded in every snapshot.
Read failures identify only the safe evidence layer (`pull`, `run`, `jobs`,
Runner inventory, or host probe) and never echo stderr, command payloads, key
paths, tokens, or process arguments. Every relative `gh api` request is pinned
with `--hostname github.com`; ambient `GH_HOST` cannot redirect canonical
evidence to an enterprise or test host.
For an explicitly selected completed job, it reads only the expected root-owned
immutable receipt under `/var/lib/sixlab-ephemeral-v1/receipts/`, verifies its
canonical six fields, and binds the source SHA-256 into the normalized receipt.

Collector activation still requires reviewed merged control-repository code.
Running this unmerged implementation for development may only produce a
read-only shadow snapshot; its output cannot authorize token mint or service
actuation.

`ops/sixlab_jit_shadow_soak.py` independently re-evaluates every saved
snapshot, rejects a decision that differs from canonical output, and appends a
mode-0600 digest event to the local soak journal. Only distinct
`shadow-teardown-verified` job bindings increment the 20-job migration gate;
running, blocked, duplicate, or late receipt observations never count. A
resource-blocked admission may have no selected job; it is journaled against
the repository/PR/head/run/attempt context with a null job ID.
Journal read-modify-write runs under a mode-0600 no-follow lock shared across
threads and processes. Snapshot and decision inputs remain bounded at 1 MiB,
while the accumulating journal uses a separate 64 MiB read/write ceiling; the
writer rejects an event before producing a journal it cannot read back.

`ops/sixlab_jit_shadow_inventory.py` is the final read-only arbitration layer
across run snapshots. It requires one bounded control-cycle inventory, rejects
duplicate runs or multiple active allocations, and requires every snapshot to
declare the same canonical current-head run-ID set. The supplied snapshot run
IDs must equal that set exactly, so a caller-selected subset cannot receive a
global admission. It propagates any incomplete run fail-closed and emits only
the globally earliest `(created_at, job_id)` candidate. Per-run `shadow-admit`
decisions therefore cannot become two simultaneous global admissions.

While one snapshot has a verified `shadow-running` or
`shadow-awaiting-binding` allocation, peer queued-run snapshots naturally see
the same global lock, service, Runner, mount and egress state as admission
blockers. The global selector suppresses only those admission-only blockers
when the peer host identity exactly matches the active allocation's single
service and Runner and contains no foreign runtime residue. A clean-host peer,
head/attempt drift, extra service/Runner, missing allocation identity or any
non-admission blocker remains `CHECK-INCOMPLETE`. This lets one legitimate
global allocation stay observable without weakening the one-job invariant.

`ops/sixlab_jit_launcher_generator.py` renders a local candidate from the
reviewed root-owned PR #1173 launcher template whose SHA-256 is pinned in code.
It requires a positive pull number, lowercase full head, numeric attempt and a
reviewed slot-to-family mapping, then binds all four values into a single-slot,
single-family launcher. Exact source-template bindings are valid no-op renders.
The generator verifies exact replacement counts and required safety clauses,
rejects identical or pre-existing output/manifest destinations, and writes an
exact filename mode-0755 launcher plus mode-0600 manifest containing
source/rendered digests and the exact job label. Both `installation_authorized` and
`token_mint_authorized` are fixed false. The generator has no network, SSH,
service, token, or installer capability; host installation remains a separate
reviewed and authorized operation.

The current local review artifact is bound to PR #1201 head
`fe4c0c3be00a4ad264eadf6dd44ec1cf9e5f0668`, attempt 1, slot 03,
`spa-tests`. Its versioned `exitmemv5` launcher and manifest live under
`artifacts/jit-candidates/pr1201/`; earlier `exitmemv1` through `exitmemv4`
candidates remain immutable historical review artifacts. The v5 manifest binds exact label
`sixlab-pr-job-fe4c0c3be00a4ad264eadf6dd44ec1cf9e5f0668-spa-tests` and rendered
SHA-256 `1661b270bf7fc576403e74a8e4ac85837b08564ae4947eeb76b8181b50fcf3ac`.
This is review evidence only and grants no host installation, token mint, or
Runner start authority.

The PR #1198 `us-proxy-v5` launcher remains only as a historical regression
fixture under `artifacts/jit-candidates/pr1198/`, with rendered SHA-256 `9a0ccd27df990e6c98446bc544f0c08d5b3992b6103ce8c049bf5f447b62b133`;
it is not the current review artifact.

The `us-proxy-v5` candidate supersedes `us-proxy-v4` without changing or
overwriting the installed v4 launcher. It keeps the canonical
Runner/service/receipt name binding while giving the immutable launcher a
separate versioned path. A
root-owned loopback relay accepts only CONNECT:443 for reviewed GitHub, Actions,
npm and provider-controlled endpoints, explicitly excluding broad
tenant-controlled cloud suffixes such as `amazonaws.com` and
`blob.core.windows.net`, and forwards only to the fixed US upstream
`47.88.16.146:8443`. The dedicated Runner UID can reach the relay, DB/cache
loopback, test ephemeral ports and only the approved IPv4 DNS resolvers, but
all other IPv4/IPv6 direct public egress is dropped. IP
literals, private targets, deceptive suffixes and non-443 CONNECT are rejected.
UID 1005 has no direct recursive-resolver access: all IPv4 TCP/UDP port 53
traffic is redirected to the root-owned loopback relay, which parses one DNS
question and forwards only A/AAAA queries whose name matches the same reviewed
hostname allowlist. IPv6 DNS remains blocked. Forbidden names receive REFUSED,
and DNS redirect chains/listeners are included in teardown readback.
The nft UID filter runs at `filter + 10`, after IPv4 nat OUTPUT redirection, so
resolver-bound packets reach the loopback DNS relay before the final UID drop.
`--proxy-canary` exercises allowed endpoints, private-target rejection, direct
egress denial and automatic firewall/process/file teardown without reading or
minting a registration token. Positive endpoint probes use HEAD so a slow HTML
body cannot turn successful TLS/HTTP reachability into a false timeout. The
relay permits immediate same-port restart only after the no-listener and global
lock gates pass. Canary and job cleanup propagate teardown failures, then read
back process, listener, firewall, mount and file residue before writing success.
HUP, INT and TERM use explicit nonzero exit codes in the outer, canary and inner
cleanup traps, so a signal cannot create a success receipt.
HTTP and DNS TCP/UDP handlers share one bounded semaphore; the root-owned relay
cannot create an unbounded thread set outside the dedicated job's resource
scope when untrusted code floods loopback.
Direct `--run` admission refuses an existing receipt, and cleanup creates the
root-owned mode-0444 receipt with no-follow exclusive-create flags; even root
cannot truncate a previous receipt through the launcher path.
Cleanup stops the root relay, user manager and all dedicated UID processes
before removing network controls. It escalates TERM to KILL with bounded
readback; unless the manager is inactive and the UID process set is empty, the
egress fence remains installed and teardown fails closed.
Admission rejects every pre-existing dedicated UID process, not only a named
Runner worker. After the nftables/iptables fence, proxy/DNS canaries, and a
second zero-process check are complete, the scoped payload reads exactly one
token line from controller stdin. It never stages the token in a job-path file
and unsets the shell variable immediately after Runner configuration.
Exit 70 is reserved for a cleanup/readback failure only when no earlier
non-zero job, controller, signal, or evidence status exists. The evaluator
refuses to classify that receipt as teardown
verified, even if a later manual action removes the observed residue.
The collector independently reads both nftables and iptables residue. A canary
PASS is still not job-start authority. Active-state verification reads each
slot nft table's full rule body plus iptables-save rows and requires the proxy,
DNS, final UID drop, OUTPUT jumps and DNS redirect structure; surviving marker
names with flushed policy rules, extra permissive rules, or incorrect ordering
cannot count as a fenced runtime. The launcher
also requires the `timeout` executable before interpreting the direct-egress
negative canary. Every preflight firewall enumeration must itself succeed
before absence checks are evaluated; command failure is never treated as a
clean host.

The host probe counts processes for fixed dedicated UID 1005 and reads
`user@1005.service` directly, independent of whether the launcher service cgroup
still exists. Local `gh`/SSH command timeouts are redacted into structured
`CHECK-INCOMPLETE` collector failures. Head-stability observations newer than the
enclosing snapshot are rejected, so future-dated history cannot manufacture an
admission window. When two collections finish in the same UTC second, the
collector replaces the equal-timestamp tail observation and collapses any
existing adjacent duplicate before persisting history, preserving the strict
timestamp order required by the evaluator. Every persisted history row must
have exactly one valid UTC timestamp and one lowercase full SHA; malformed rows
fail as structured collector errors before append.
After initial host evidence collection, the collector re-reads the JIT Runner inventory,
current-head run inventory, selected run, complete jobs and PR, then performs a
closing host probe. Any Runner
status/busy/label/presence drift, run attempt, job, run inventory, head, base or
PR-state change rejects the mixed snapshot. The two host probes must retain the
same lock, service/cgroup, dedicated UID process count, run directories, mounts,
firewall, user-manager and receipt identity; the snapshot uses closing resource
and timestamp values. Host probe payloads
must contain the exact canonical field set; missing fields become structured
`CHECK-INCOMPLETE` rather than an uncaught lookup error.
After the closing host probe, the collector performs one final closing read of
Runner inventory, current-head run inventory, selected run/jobs and PR, and
requires it to equal the GitHub read immediately before that host probe. This
brackets the closing host evidence and prevents a short allocation from being
hidden by stale queued-job data.

Each workflow run must expose one unambiguous `pull_requests` entry matching the
requested pull number, current head and `main` base. Its workflow ID, name and
path must also match the fixed `test` or `test-backend` profile implied by its
exact job families. During the normal interval
between Runner registration and GitHub job assignment, the collector may derive
one awaiting allocation only from a unique online-idle Runner whose canonical
name, attempt, slot and exact label match one queued job family. The canonical
host evidence retains the allocated service detail; the evaluator requires one
active service cgroup with a positive PID inventory and dedicated UID 1005
membership. A matching Runner must remain online, and its busy state must match
awaiting versus running lifecycle state. Runner inventory retains every Runner
that carries an exact JIT label even when its name is noncanonical, so a renamed
or persistent competitor cannot disappear from admission evidence.

The global selector treats `shadow-teardown-verified` runs as completed
non-candidates and ignores them as peers while another allocation is active, so
they remain audited without blocking serial progression. A
terminal-only inventory reports `shadow-global-idle`. Each persisted soak event
stores its canonical snapshot and decision; journal reload recomputes the
evaluator result, both digests, event id, binding and summary before any event is
counted toward the 20-job gate.

A terminal peer is ignored beside an active allocation only when its
observation is not newer. A newer clean terminal observation invalidates the
older active view and forces a fresh cycle instead of reporting stale running
state with the newer timestamp.

Allocated jobs must belong to the run's latest attempt; the evaluator never
re-stamps an older job as current. Host load must be a finite non-negative
number, so JSON `NaN` or infinity cannot bypass cooldown admission.
Older jobs completed as `cancelled`, `skipped` or `stale` before acquiring a
Runner may carry null Runner identity and remain valid terminal evidence; a
successful or failed executed job still requires an exact Runner binding.
