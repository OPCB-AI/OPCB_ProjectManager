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
  SIXLABJITProjectManagerBridgeProductionCollectorSmoke.py; do
  python3 "$ROOT/tests/$test"
done
