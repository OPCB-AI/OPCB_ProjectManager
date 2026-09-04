# SIXLAB JIT serial scheduler and actuator boundary

Status: local implementation and test contract only. It does not authorize a
Runner registration, label mutation, token minting, host/service command,
workflow rerun, merge, deployment, migration, or Provider call.

The R1 components imported from `Steven-ZYH/sixlab-pr-control` PR #65 remain
the only source for per-run evidence normalization, head-stability, exact job
labeling, clean-host cooldown, allocation/runner/service binding, terminal
receipt validation, immutable launcher rendering, and all-host global
inventory selection. `sixlab_jit_serial_scheduler.py` adds no second
controller: it requires an externally collected bounded cycle of every open
SIXLAB PR and delegates candidate selection to the R1 global inventory.

The serial scheduler emits exactly one of:

- `shadow-serial-ready`: one earliest R1-admitted exact job is waiting for the
  actuator boundary.
- `shadow-serial-await-terminal-teardown`: an actual bound job still owns the
  single global slot; no successor is selected.
- `shadow-serial-idle`: the complete bounded cycle has no eligible work.
- `CHECK-INCOMPLETE`: missing PR, stale/inconsistent inventory, head/attempt
  drift, resource cooldown, residue, orphan Runner, or any R1 blocker.

The scheduler input explicitly lists all open PR numbers and contains one
latest-attempt snapshot per number. A missing or duplicate PR is rejected;
there is no static PR allowlist. R1's SPA `any-one-same-label` behavior stays
intact: a shard becomes actual only after GitHub's binding and a second shard
cannot proceed before terminal teardown is independently observed.

The production ProjectManager bridge directly invokes its checked-in copy of
SIXLAB PR #1201 at exact head `1efdfd2d754822d29d4f0a4f93b48117a663116f`:
`vendor/sixlab-pr1201/scripts/ci/collect-pr-runner-correlation.mjs`. The
vendor provenance manifest binds the B repository, PR, head, original paths,
and SHA-256 values for the collector, validator, and contract; the bridge also
pins the manifest digest in code. Replaced paths, manifest bytes, or vendor
files therefore fail closed. The collector paginates every open, non-draft
`main` PR and every required workflow, then closes with PR/run/job readbacks.
Its adjacent fixed `pr-runner-contract.mjs` validates the result before the
bridge can select a one-run R1 snapshot. The fixed live collector and contract,
not ProjectManager caller JSON, derive the PR universe and
workflow-to-family/job-instance map.

The bridge resolves a trusted system Node executable from fixed locations,
realpaths it, and requires a regular executable owned by root or the current
user with no group/world write permission. It never resolves `node` through
`PATH`. Before spawning Node it strips inherited `NODE_OPTIONS`, `NODE_PATH`,
all other `NODE_*` values except `NODE_EXTRA_CA_CERTS`, and dynamic-loader
variables. The child receives only `GITHUB_TOKEN` plus an explicit proxy/CA
allowlist; no module, loader, require, inspector, or test-seam environment is
passed. A collector failure, incomplete page, closing drift, unsafe executable,
vendor drift, or missing token fails closed. Fixture paths are
explicit test-only validation and return `CHECK-INCOMPLETE` with
`live_mutation_allowed=false` and `token_allowed=false`; they cannot emit a
schedulable cycle or reach the actuator.
The bridge still requires one explicit workflow selection for every PR; it
never silently prefers SPA/backend or combines two run attempts. ProjectManager
supplies the separate head-history and host/service/receipt evidence, which R1
verifies against the selected binding.

`sixlab_jit_actuator_admission.py` is intentionally a zero-command boundary.
It re-runs the scheduler on a fresh bounded cycle and compares the complete
repository/PR/head/run/attempt/job/family/label binding to the previous
decision. It also requires a non-authorized immutable launcher manifest plus a
regular, non-symlink launcher file whose SHA-256 equals the manifest's rendered
digest and whose source digest binds the same exact job. It produces only
`actuator-token-pending`; the output specifies `stdin-short-lived-only` but
does not accept, read, print, or persist a token.

Any future live actuator must be separately authorized and must perform fresh
readbacks for the open-PR inventory, PR head, latest attempt/job, clean host,
and Runner/service/terminal-receipt binding. A failed readback, digest drift,
host residue, orphan/offline Runner, head change, or attempt change is a
terminal fail-closed hold rather than a retry or fallback to a shared Runner.
