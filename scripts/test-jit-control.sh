#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHONPYCACHEPREFIX="${PYTHONPYCACHEPREFIX:-/tmp/opcb-projectmanager-pycache}"
export PYTHONPYCACHEPREFIX

for test in \
  SIXLABJITLauncherGeneratorSmoke.py \
  SIXLABJITShadowControllerSmoke.py \
  SIXLABJITShadowCollectorSmoke.py \
  SIXLABJITShadowInventorySmoke.py \
  SIXLABJITShadowSoakSmoke.py \
  SIXLABJITSerialSchedulerSmoke.py \
  SIXLABJITProjectManagerBridgeSmoke.py \
  SIXLABJITProjectManagerBridgePairSmoke.py \
  SIXLABJITProjectManagerBridgeVendorSmoke.py \
  SIXLABJITProjectManagerBridgeProductionCollectorSmoke.py; do
  python3 "$ROOT/tests/$test"
done

# The B collector's own reviewed tests establish collector success.  A's
# production tests cover only its fail-closed boundary and never use a loader
# or fetch-preload seam.  The vendored layout is intentionally B-relative.
(
  cd "$ROOT/vendor/sixlab-pr1201"
  node --test scripts/ci/collect-pr-runner-correlation.test.mjs
)
