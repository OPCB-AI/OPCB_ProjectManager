#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

readonly EXPECTED_HOST='VM-0-10-ubuntu'
readonly ROOT='/var/lib/sixlab-ephemeral-v1'
readonly USER_NAME='sixlabephem'
readonly USER_ID='1005'
readonly RUNNER_GOLDEN="$ROOT/golden/actions-runner-2.336.0"
readonly ROOTLESS="$ROOT/golden/rootless-29.1.3/dockerd-rootless.sh"
readonly STATIC_DOCKER="$ROOT/golden/docker-29.1.3"
readonly GOLDEN_IMAGES="$ROOT/golden/sixlab-test-images-20260824.tar"
readonly GOLDEN_IMAGES_SHA='f064a7844010dfb9d99e05bed5f9ab8655d5cbc260a87338b4eccd42bb369487'
readonly REPO_URL='https://github.com/Steven-ZYH/sixlab'
readonly PULL_NUMBER='1173'
readonly EXPECTED_HEAD='fcca0a92d8882f01b8e203f6ed661358882c5339'
readonly ATTEMPT='1'
readonly PREFIX='fcca0r1'
readonly LAUNCHER_PREFIX='fcca0-r1-usproxy5-scopefd1-exitmemv5'
readonly ALLOWED_SLOT='07'
readonly ALLOWED_FAMILY='spa-checks'
readonly NODE_HOME='/opt/sixlab-node-v22.23.2/bin'
readonly NODE_SHA='3517c2df0b2f8cd7f422b4b8450ef81c6889f08eb03e281d6de9079b15e6a327'
readonly NODE_DEVICE_INODE='64770:669682'
readonly LOCK_FILE='/run/lock/sixlab-pr-ephemeral-one-job.lock'
readonly UPSTREAM_PROXY_HOST='47.88.16.146'
readonly UPSTREAM_PROXY_PORT='8443'
readonly LOCAL_PROXY_HOST='127.0.0.1'
readonly LOCAL_PROXY_PORT='18080'
readonly LOCAL_DNS_PORT='15353'
readonly PROXY_URL="http://$LOCAL_PROXY_HOST:$LOCAL_PROXY_PORT"
readonly NO_PROXY_VALUE='localhost,127.0.0.1,::1'
readonly SELF="$ROOT/bin/pr${PULL_NUMBER}-one-job-launcher-${LAUNCHER_PREFIX}-slot${ALLOWED_SLOT}-${ALLOWED_FAMILY}.sh"

die() { printf 'P2-R2E one-job FAIL: %s\n' "$*" >&2; exit 64; }
valid_slot() {
  [[ "${1:-}" == "$ALLOWED_SLOT" ]]
}
label_for() {
  valid_slot "$1" || die 'invalid slot for label'
  printf 'sixlab-pr-job-%s-%s' "$EXPECTED_HEAD" "$ALLOWED_FAMILY"
}
unit_name() { printf 'sixlab-pr%s-%s-ephemeral-%s' "$PULL_NUMBER" "$PREFIX" "$1"; }
runner_name() { printf 'sixlab-pr%s-%s-%s' "$PULL_NUMBER" "$PREFIX" "$1"; }
receipt_path() { printf '%s/receipts/sixlab-pr%s-%s-ephemeral-%s.receipt' "$ROOT" "$PULL_NUMBER" "$PREFIX" "$1"; }
evidence_path() { printf '%s.evidence-v5.json' "$(receipt_path "$1")"; }
collect_scope_memory() {
  python3 - "$@" <<'SIXLAB_SCOPE_MEMORY_COLLECTOR'
# SIXLAB_SCOPE_MEMORY_COLLECTOR_BEGIN
import datetime
import json
import os
from pathlib import Path
import re
import stat
import sys
import time


(
    output_name,
    stop_name,
    expected_uid_text,
    scope_unit,
    proc_root_name,
    cgroup_root_name,
    expected_runner_device_text,
    expected_runner_inode_text,
    max_samples_text,
    interval_ms_text,
) = sys.argv[1:]
expected_uid = int(expected_uid_text)
expected_runner_identity = (
    int(expected_runner_device_text),
    int(expected_runner_inode_text),
)
max_samples = int(max_samples_text)
interval_ms = int(interval_ms_text)
output = Path(output_name)
stop = Path(stop_name)
proc_root = Path(proc_root_name)
cgroup_root = Path(cgroup_root_name)
scope_pattern = re.compile(r"^[A-Za-z0-9_.@:-]{1,128}\.scope$")
safe_cgroup_pattern = re.compile(r"^/[A-Za-z0-9_.@:/-]{1,512}$")
event_keys = ("low", "high", "max", "oom", "oom_kill", "oom_group_kill")
pressure_keys = ("avg10", "avg60", "avg300", "total")


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def read_bounded(path, limit=4096):
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError("unsafe_file")
    descriptor = os.open(path, flags)
    try:
        current = os.fstat(descriptor)
        if (
            not stat.S_ISREG(current.st_mode)
            or (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise ValueError("file_identity_drift")
        raw = os.read(descriptor, limit + 1)
        if len(raw) > limit:
            raise ValueError("file_too_large")
    finally:
        os.close(descriptor)
    return raw.decode("ascii")


def uid_for(pid_path):
    text = read_bounded(pid_path / "status")
    for line in text.splitlines():
        if line.startswith("Uid:"):
            values = line.split()[1:]
            if len(values) != 4 or any(not value.isdigit() for value in values):
                raise ValueError("invalid_uid")
            uids = tuple(int(value) for value in values)
            return uids
    raise ValueError("missing_uid")


def cgroup_for(pid_path):
    text = read_bounded(pid_path / "cgroup")
    rows = [line for line in text.splitlines() if line.startswith("0::")]
    if len(rows) != 1:
        raise ValueError("invalid_cgroup_membership")
    value = rows[0][3:]
    if safe_cgroup_pattern.fullmatch(value) is None or "//" in value:
        raise ValueError("unsafe_cgroup_path")
    parts = value.split("/")
    if any(part in (".", "..") for part in parts):
        raise ValueError("unsafe_cgroup_path")
    return value


def scope_root_from_memberships():
    matches = {}
    process_entries = 0
    for pid_path in sorted(proc_root.iterdir(), key=lambda item: item.name):
        if not pid_path.name.isdigit():
            continue
        process_entries += 1
        if process_entries > 32768:
            raise ValueError("process_inventory_too_large")
        try:
            uids = uid_for(pid_path)
            if any(value != expected_uid for value in uids):
                continue
            membership = cgroup_for(pid_path)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (OSError, UnicodeError, ValueError):
            continue
        components = membership.split("/")
        if scope_unit not in components:
            continue
        position = components.index(scope_unit)
        scope_path = "/".join(components[: position + 1])
        if not scope_path.startswith("/"):
            scope_path = "/" + scope_path
        matches.setdefault(scope_path, []).append(int(pid_path.name))
    if not matches:
        return None
    if len(matches) != 1:
        raise ValueError("ambiguous_scope_binding")
    scope_path, pids = next(iter(matches.items()))
    unique_pids = sorted(set(pids))
    if len(unique_pids) > 64:
        raise ValueError("scope_pid_inventory_too_large")
    return scope_path, unique_pids


def safe_scope_dir(scope_path):
    candidate = cgroup_root / scope_path.lstrip("/")
    root_real = cgroup_root.resolve(strict=True)
    candidate_real = candidate.resolve(strict=True)
    expected_real = root_real / scope_path.lstrip("/")
    if candidate_real.parent != root_real and root_real not in candidate_real.parents:
        raise ValueError("scope_outside_cgroup_root")
    if candidate_real != expected_real:
        raise ValueError("scope_symlink")
    current = root_real
    for component in Path(scope_path.lstrip("/")).parts:
        current = current / component
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("unsafe_scope_component")
    return candidate_real


def nonnegative_integer(text):
    value = text.strip()
    if not value.isdigit():
        raise ValueError("invalid_integer")
    parsed = int(value)
    if parsed > 2**63 - 1:
        raise ValueError("integer_too_large")
    return parsed


def parse_events(text):
    parsed = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 2 or not fields[0].replace("_", "").isalnum():
            raise ValueError("invalid_events")
        if fields[0] in event_keys:
            parsed[fields[0]] = nonnegative_integer(fields[1])
    if any(key not in parsed for key in event_keys):
        raise ValueError("incomplete_events")
    return {key: parsed[key] for key in event_keys}


def parse_pressure(text):
    parsed = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 5 or fields[0] not in ("some", "full"):
            raise ValueError("invalid_pressure")
        values = {}
        for field in fields[1:]:
            key, separator, raw = field.partition("=")
            if separator != "=" or key not in pressure_keys:
                raise ValueError("invalid_pressure")
            if key == "total":
                values[key] = nonnegative_integer(raw)
            elif re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", raw) is None:
                raise ValueError("invalid_pressure")
            else:
                values[key] = raw
        if set(values) != set(pressure_keys):
            raise ValueError("incomplete_pressure")
        parsed[fields[0]] = {key: values[key] for key in pressure_keys}
    if set(parsed) != {"some", "full"}:
        raise ValueError("incomplete_pressure")
    return parsed


def listener_pids(pids):
    observed = []
    for pid in pids:
        try:
            executable = os.stat(proc_root / str(pid) / "exe")
        except OSError:
            continue
        if (executable.st_dev, executable.st_ino) == expected_runner_identity:
            observed.append(pid)
    return observed


def snapshot(scope_path, pids):
    directory = safe_scope_dir(scope_path)
    return {
        "captured_at": utc_now(),
        "cgroup_path": scope_path,
        "pids": pids,
        "runner_listener_pids": listener_pids(pids),
        "memory_current_bytes": nonnegative_integer(read_bounded(directory / "memory.current")),
        "memory_peak_bytes": nonnegative_integer(read_bounded(directory / "memory.peak")),
        "memory_events": parse_events(read_bounded(directory / "memory.events")),
        "memory_events_local": parse_events(read_bounded(directory / "memory.events.local")),
        "memory_pressure": parse_pressure(read_bounded(directory / "memory.pressure")),
    }


def write_result(result):
    raw = (json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
    if len(raw) > 16384:
        raise ValueError("result_too_large")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(output, flags, 0o400)
    try:
        os.fchmod(descriptor, 0o400)
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short_write")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


result = {
    "schema": "sixlab-jit-scope-memory-evidence-v5",
    "collection_status": "unknown",
    "reason": "scope_not_observed",
    "expected_uid": expected_uid,
    "scope_unit": scope_unit,
    "sample_count": 0,
    "runner_listener_observed": False,
    "last_sample_age_ms": None,
    "sample": None,
}
last_sample_ns = None
try:
    if scope_pattern.fullmatch(scope_unit) is None:
        raise ValueError("unsafe_scope_unit")
    if any(value <= 0 for value in expected_runner_identity):
        raise ValueError("unsafe_runner_listener_identity")
    if not 1 <= max_samples <= 57600 or not 10 <= interval_ms <= 1000:
        raise ValueError("unsafe_sampling_bounds")
    observed_listener = False
    for _ in range(max_samples):
        binding = scope_root_from_memberships()
        if binding is not None:
            scope_path, pids = binding
            current = snapshot(scope_path, pids)
            observed_listener = observed_listener or bool(current["runner_listener_pids"])
            result.update({
                "collection_status": "observed",
                "reason": "sampling",
                "sample_count": result["sample_count"] + 1,
                "runner_listener_observed": observed_listener,
                "sample": current,
            })
            last_sample_ns = time.monotonic_ns()
        elif result["sample_count"]:
            result["reason"] = "scope_disappeared_after_observation"
            break
        if stop.exists():
            result["reason"] = "stop_requested" if result["sample_count"] else "scope_not_observed"
            break
        time.sleep(interval_ms / 1000)
    else:
        result["reason"] = "sample_limit_reached"
except Exception:
    result.update({
        "collection_status": "unknown",
        "reason": "collector_error",
        "sample": None,
    })
if last_sample_ns is not None:
    result["last_sample_age_ms"] = min(
        2**31 - 1, max(0, (time.monotonic_ns() - last_sample_ns) // 1_000_000)
    )
fresh = result["last_sample_age_ms"] is not None and result["last_sample_age_ms"] <= 2000
if result["collection_status"] == "observed" and not fresh:
    result.update({
        "collection_status": "unknown",
        "reason": "stale_sample",
        "runner_listener_observed": False,
        "sample": None,
    })
if result["collection_status"] == "observed" and not result["runner_listener_observed"]:
    result.update({
        "collection_status": "unknown",
        "reason": "runner_listener_not_observed",
        "sample": None,
    })
write_result(result)
raise SystemExit(0 if result["collection_status"] == "observed" else 75)
# SIXLAB_SCOPE_MEMORY_COLLECTOR_END
SIXLAB_SCOPE_MEMORY_COLLECTOR
}
stop_dedicated_runtime() {
  local state=''
  systemctl stop user@1005.service 2>/dev/null || true
  if pgrep -u "$USER_ID" >/dev/null 2>&1; then
    pkill -TERM -u "$USER_ID" 2>/dev/null || true
    for _ in $(seq 1 20); do
      pgrep -u "$USER_ID" >/dev/null 2>&1 || break
      sleep 0.25
    done
  fi
  if pgrep -u "$USER_ID" >/dev/null 2>&1; then
    pkill -KILL -u "$USER_ID" 2>/dev/null || true
    for _ in $(seq 1 20); do
      pgrep -u "$USER_ID" >/dev/null 2>&1 || break
      sleep 0.25
    done
  fi
  state="$(systemctl is-active user@1005.service 2>/dev/null || true)"
  [[ "$state" == inactive ]] && ! pgrep -u "$USER_ID" >/dev/null 2>&1
}

proxy_canary() {
  local chain="SLPR${PULL_NUMBER}C" dns_chain="SLPD${PULL_NUMBER}C" nft_table="s${PULL_NUMBER}pc1" comment="sixlab-pr${PULL_NUMBER}-us-proxy-canary" dns_comment="sixlab-pr${PULL_NUMBER}-dns-canary"
  local proxy_script="$ROOT/transient/pr${PULL_NUMBER}-us-proxy-canary.py"
  local proxy_log="$ROOT/transient/pr${PULL_NUMBER}-us-proxy-canary.log"
  local proxy_pid='' chain_created=0 jump_created=0 dns_chain_created=0 dns_jump_created=0 nft_created=0 proxy_started=0 status=0

  exec 9>"$LOCK_FILE"
  flock -n 9 || die 'another ephemeral job controller is active'
  cleanup_canary() {
    status=$?
    local signal_status="${1:-0}" cleanup_failed=0 iptables_state='' nft_state='' listeners=''
    if (( signal_status != 0 )); then status="$signal_status"; fi
    trap - EXIT INT TERM HUP
    if [[ "$proxy_started" == 1 && -n "${proxy_pid:-}" ]]; then
      if kill -0 "$proxy_pid" 2>/dev/null; then
        kill "$proxy_pid" 2>/dev/null || cleanup_failed=1
      fi
      wait "$proxy_pid" 2>/dev/null || true
    fi
    rm -f -- "$proxy_script" "$proxy_log" || cleanup_failed=1
    if stop_dedicated_runtime; then
      if [[ "$jump_created" == 1 ]] && ! iptables -w -D OUTPUT -m owner --uid-owner "$USER_ID" -m comment --comment "$comment" -j "$chain" 2>/dev/null; then cleanup_failed=1; fi
      if [[ "$chain_created" == 1 ]]; then
        iptables -w -F "$chain" 2>/dev/null || cleanup_failed=1
        iptables -w -X "$chain" 2>/dev/null || cleanup_failed=1
      fi
      if [[ "$dns_jump_created" == 1 ]] && ! iptables -w -t nat -D OUTPUT -m owner --uid-owner "$USER_ID" -m comment --comment "$dns_comment" -j "$dns_chain" 2>/dev/null; then cleanup_failed=1; fi
      if [[ "$dns_chain_created" == 1 ]]; then
        iptables -w -t nat -F "$dns_chain" 2>/dev/null || cleanup_failed=1
        iptables -w -t nat -X "$dns_chain" 2>/dev/null || cleanup_failed=1
      fi
      if [[ "$nft_created" == 1 ]] && ! nft delete table inet "$nft_table" 2>/dev/null; then cleanup_failed=1; fi
    else
      cleanup_failed=1
      printf 'P2-R2E egress fence retained: dedicated runtime remains\n' >&2
    fi
    if [[ -n "${proxy_pid:-}" ]] && kill -0 "$proxy_pid" 2>/dev/null; then cleanup_failed=1; fi
    if ! iptables_state="$(iptables-save 2>/dev/null)"; then
      cleanup_failed=1
    elif grep -Fq "$comment" <<<"$iptables_state" || grep -Fq "$dns_comment" <<<"$iptables_state" || grep -Fq ":$chain " <<<"$iptables_state" || grep -Fq ":$dns_chain " <<<"$iptables_state" || grep -Fq -- "-j $chain" <<<"$iptables_state" || grep -Fq -- "-j $dns_chain" <<<"$iptables_state"; then
      cleanup_failed=1
    fi
    if ! nft_state="$(nft list tables 2>/dev/null)"; then
      cleanup_failed=1
    elif grep -Fxq "table inet $nft_table" <<<"$nft_state"; then
      cleanup_failed=1
    fi
    if ! listeners="$(ss -H -ltn "( sport = :$LOCAL_PROXY_PORT or sport = :$LOCAL_DNS_PORT )" 2>/dev/null)" || [[ -n "$listeners" ]]; then cleanup_failed=1; fi
    if ! listeners="$(ss -H -lun "( sport = :$LOCAL_DNS_PORT )" 2>/dev/null)" || [[ -n "$listeners" ]]; then cleanup_failed=1; fi
    if [[ -e "$proxy_script" || -e "$proxy_log" ]]; then cleanup_failed=1; fi
    if (( cleanup_failed != 0 )); then
      (( status != 0 )) || status=70
      printf 'P2-R2E proxy canary teardown verification failed\n' >&2
    fi
    exit "$status"
  }
  trap cleanup_canary EXIT
  trap 'cleanup_canary 129' HUP
  trap 'cleanup_canary 130' INT
  trap 'cleanup_canary 143' TERM

  [[ "$(id -u)" == 0 && "$(hostname)" == "$EXPECTED_HOST" ]] || die 'root or host identity mismatch'
  [[ "$(id -u "$USER_NAME")" == "$USER_ID" ]] || die 'dedicated user identity drift'
  ! pgrep -u "$USER_ID" >/dev/null || die 'dedicated process exists before proxy canary'
  command -v getent >/dev/null && command -v pkill >/dev/null && command -v timeout >/dev/null || die 'getent, pkill or timeout missing for canary'
  [[ "$(systemctl is-active user@1005.service 2>/dev/null || true)" == inactive ]] || die 'dedicated user manager active before proxy canary'
  ! ss -H -ltn "( sport = :$LOCAL_PROXY_PORT )" | grep -q . || die 'local proxy port occupied'
  ! ss -H -ltn "( sport = :$LOCAL_DNS_PORT )" | grep -q . || die 'local DNS TCP port occupied'
  ! ss -H -lun "( sport = :$LOCAL_DNS_PORT )" | grep -q . || die 'local DNS UDP port occupied'
  iptables_state="$(iptables-save)" || die 'proxy canary iptables enumeration failed'
  nft_state="$(nft -a list ruleset)" || die 'proxy canary nftables enumeration failed'
  ! grep -Fq "$comment" <<<"$iptables_state" || die 'proxy canary firewall residue exists'
  ! grep -Fq "table inet $nft_table" <<<"$nft_state" || die 'proxy canary nft residue exists'
  ! grep -q "meta skuid $USER_ID" <<<"$nft_state" || die 'foreign nftables owner policy exists'
  install -d -m 0755 -o root -g root "$ROOT/transient"
  [[ ! -e "$proxy_script" && ! -e "$proxy_log" ]] || die 'proxy canary file residue exists'
  awk '
    $0 == "# SIXLAB_US_PROXY_RELAY_BEGIN" { capture = 1; next }
    $0 == "# SIXLAB_US_PROXY_RELAY_END" { exit }
    capture { print }
  ' "$SELF" | install -m 0500 -o root -g root /dev/stdin "$proxy_script"
  [[ "$(head -1 "$proxy_script")" == '#!/usr/bin/env python3' ]] || die 'embedded proxy relay extraction failed'

  nft -f - <<NFT
add table inet $nft_table
add chain inet $nft_table output { type filter hook output priority filter + 10; policy accept; }
add rule inet $nft_table output meta skuid $USER_ID ip daddr $LOCAL_PROXY_HOST tcp dport $LOCAL_PROXY_PORT accept
add rule inet $nft_table output meta skuid $USER_ID ip daddr 127.0.0.1 udp dport $LOCAL_DNS_PORT accept
add rule inet $nft_table output meta skuid $USER_ID ip daddr 127.0.0.1 tcp dport $LOCAL_DNS_PORT accept
add rule inet $nft_table output meta skuid $USER_ID drop
NFT
  nft_created=1
  iptables -w -N "$chain"
  chain_created=1
  iptables -w -A "$chain" -d "$LOCAL_PROXY_HOST/32" -p tcp --dport "$LOCAL_PROXY_PORT" -m comment --comment "$comment" -j ACCEPT
  iptables -w -A "$chain" -d 127.0.0.1/32 -p udp --dport "$LOCAL_DNS_PORT" -m comment --comment "$comment" -j ACCEPT
  iptables -w -A "$chain" -d 127.0.0.1/32 -p tcp --dport "$LOCAL_DNS_PORT" -m comment --comment "$comment" -j ACCEPT
  iptables -w -A "$chain" -m comment --comment "$comment" -j DROP
  iptables -w -I OUTPUT 1 -m owner --uid-owner "$USER_ID" -m comment --comment "$comment" -j "$chain"
  jump_created=1
  iptables -w -t nat -N "$dns_chain"
  dns_chain_created=1
  iptables -w -t nat -A "$dns_chain" -p udp --dport 53 -j REDIRECT --to-ports "$LOCAL_DNS_PORT"
  iptables -w -t nat -A "$dns_chain" -p tcp --dport 53 -j REDIRECT --to-ports "$LOCAL_DNS_PORT"
  iptables -w -t nat -I OUTPUT 1 -m owner --uid-owner "$USER_ID" -m comment --comment "$dns_comment" -j "$dns_chain"
  dns_jump_created=1

  python3 "$proxy_script" >"$proxy_log" 2>&1 &
  proxy_pid=$!
  proxy_started=1
  proxy_ready=0
  for _ in $(seq 1 40); do
    if nc -z "$LOCAL_PROXY_HOST" "$LOCAL_PROXY_PORT" >/dev/null 2>&1; then proxy_ready=1; break; fi
    kill -0 "$proxy_pid" 2>/dev/null || break
    sleep 0.25
  done
  [[ "$proxy_ready" == 1 ]] || die 'local US proxy relay failed to start'
  ss -H -lun "( sport = :$LOCAL_DNS_PORT )" | grep -q . || die 'local allowlist DNS relay failed to start'

  proxy_environment=(
    "HTTP_PROXY=$PROXY_URL" "HTTPS_PROXY=$PROXY_URL"
    "http_proxy=$PROXY_URL" "https_proxy=$PROXY_URL"
    "NO_PROXY=$NO_PROXY_VALUE" "no_proxy=$NO_PROXY_VALUE"
  )
  for proxy_target in https://github.com/ https://api.github.com/ https://registry.npmjs.org/; do
    runuser -u "$USER_NAME" -- env "${proxy_environment[@]}" \
      curl -4 -fsSI -o /dev/null --connect-timeout 8 --max-time 20 "$proxy_target" \
      || die "US proxy canary failed: $proxy_target"
  done
  runuser -u "$USER_NAME" -- getent ahostsv4 github.com >/dev/null || die 'allowlist DNS relay positive query failed'
  if runuser -u "$USER_NAME" -- getent ahostsv4 example.com >/dev/null 2>&1; then die 'allowlist DNS relay accepted forbidden query'; fi
  private_probe="$({ printf 'CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n'; } \
    | runuser -u "$USER_NAME" -- nc -w 3 "$LOCAL_PROXY_HOST" "$LOCAL_PROXY_PORT" 2>/dev/null \
    | tr -d '\r' | head -1 || true)"
  [[ "$private_probe" == 'HTTP/1.1 403 Forbidden' ]] || die 'local relay private-target rejection failed'
  if timeout 8 runuser -u "$USER_NAME" -- env \
    -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy -u ALL_PROXY -u all_proxy \
    curl -4 -fsS -o /dev/null --connect-timeout 3 --max-time 6 https://api.github.com/; then
    die 'direct external HTTPS unexpectedly reachable'
  fi
  printf 'P2-R2E US proxy canary PASS upstream=%s:%s local=%s:%s uid=%s\n' \
    "$UPSTREAM_PROXY_HOST" "$UPSTREAM_PROXY_PORT" "$LOCAL_PROXY_HOST" "$LOCAL_PROXY_PORT" "$USER_ID"
  cleanup_canary
}

run_job() {
  slot="$1"
  valid_slot "$slot" || die 'invalid slot'
  unit="$(unit_name "$slot")"
  runner="$(runner_name "$slot")"
  image_file="$ROOT/transient/$unit.ext4"
  proxy_script="$ROOT/transient/$unit-us-proxy-relay.py"
  proxy_log="$ROOT/transient/$unit-us-proxy-relay.log"
  # Keep containerd's derived Unix socket paths below Linux's 104-byte limit.
  # The backing image remains under ROOT; only its disposable mountpoint is short.
  job_root="/run/sj$slot"
  receipt="$(receipt_path "$slot")"
  evidence="$(evidence_path "$slot")"
  label="$(label_for "$slot")"
  scope_unit="${unit}-scope.scope"
  telemetry_work="$ROOT/transient/$unit.memory-evidence.json"
  telemetry_stop="$ROOT/transient/$unit.memory-evidence.stop"
  chain="SLPR${PULL_NUMBER}${slot}"
  dns_chain="SLPD${PULL_NUMBER}${slot}"
  nft_table="s${PULL_NUMBER}26${slot}"
  comment="sixlab-pr${PULL_NUMBER}-ephemeral-$slot"
  dns_comment="sixlab-pr${PULL_NUMBER}-dns-$slot"
  status=0
  user_manager_started=0
  mounted=0
  chain_created=0
  jump_created=0
  dns_chain_created=0
  dns_jump_created=0
  nft_created=0
  proxy_started=0
  proxy_pid=''
  telemetry_started=0
  telemetry_pid=''
  telemetry_collector_exit=75
  controller_status='not_started'
  controller_exit=''
  teardown_exit=0

  [[ ! -e "$receipt" && ! -L "$receipt" ]] || die 'receipt path already exists; archive explicitly before run'
  [[ ! -e "$evidence" && ! -L "$evidence" ]] || die 'evidence path already exists; archive explicitly before run'
  [[ ! -e "$telemetry_work" && ! -L "$telemetry_work" && ! -e "$telemetry_stop" && ! -L "$telemetry_stop" ]] \
    || die 'scope telemetry residue exists'

  exec 9>"$LOCK_FILE"
  flock -n 9 || die 'another ephemeral job controller is active'
  cleanup() {
    status=$?
    local signal_status="${1:-0}" cleanup_failed=0 iptables_state='' nft_state='' listeners=''
    if (( signal_status != 0 )); then
      status="$signal_status"
      controller_status='interrupted'
      controller_exit="$signal_status"
    fi
    trap - EXIT INT TERM HUP
    if [[ "$telemetry_started" == 1 && -n "${telemetry_pid:-}" ]]; then
      : >"$telemetry_stop"
      if wait "$telemetry_pid"; then telemetry_collector_exit=0; else telemetry_collector_exit=$?; fi
      telemetry_started=0
    fi
    if [[ "$proxy_started" == 1 && -n "${proxy_pid:-}" ]]; then
      if kill -0 "$proxy_pid" 2>/dev/null; then
        kill "$proxy_pid" 2>/dev/null || cleanup_failed=1
      fi
      wait "$proxy_pid" 2>/dev/null || true
    fi
    if stop_dedicated_runtime; then
      if [[ "$mounted" == 1 ]] && ! umount "$job_root" 2>/dev/null; then cleanup_failed=1; fi
      if [[ -d "$job_root" ]] && ! rmdir "$job_root" 2>/dev/null; then cleanup_failed=1; fi
      rm -f -- "$image_file" "$proxy_script" "$proxy_log" || cleanup_failed=1
      if [[ "$jump_created" == 1 ]] && ! iptables -w -D OUTPUT -m owner --uid-owner "$USER_ID" -m comment --comment "$comment" -j "$chain" 2>/dev/null; then cleanup_failed=1; fi
      if [[ "$chain_created" == 1 ]]; then
        iptables -w -F "$chain" 2>/dev/null || cleanup_failed=1
        iptables -w -X "$chain" 2>/dev/null || cleanup_failed=1
      fi
      if [[ "$dns_jump_created" == 1 ]] && ! iptables -w -t nat -D OUTPUT -m owner --uid-owner "$USER_ID" -m comment --comment "$dns_comment" -j "$dns_chain" 2>/dev/null; then cleanup_failed=1; fi
      if [[ "$dns_chain_created" == 1 ]]; then
        iptables -w -t nat -F "$dns_chain" 2>/dev/null || cleanup_failed=1
        iptables -w -t nat -X "$dns_chain" 2>/dev/null || cleanup_failed=1
      fi
      if [[ "$nft_created" == 1 ]] && ! nft delete table inet "$nft_table" 2>/dev/null; then cleanup_failed=1; fi
    else
      cleanup_failed=1
      printf 'P2-R2E egress fence retained: dedicated runtime remains\n' >&2
    fi
    if [[ -n "${proxy_pid:-}" ]] && kill -0 "$proxy_pid" 2>/dev/null; then cleanup_failed=1; fi
    if pgrep -u "$USER_ID" >/dev/null 2>&1; then cleanup_failed=1; fi
    if [[ "$(systemctl is-active user@1005.service 2>/dev/null || true)" != inactive ]]; then cleanup_failed=1; fi
    if findmnt -rn "$job_root" >/dev/null 2>&1; then cleanup_failed=1; fi
    if [[ -e "$job_root" || -e "$image_file" || -e "$proxy_script" || -e "$proxy_log" ]]; then cleanup_failed=1; fi
    if ! iptables_state="$(iptables-save 2>/dev/null)"; then
      cleanup_failed=1
    elif grep -Fq "$comment" <<<"$iptables_state" || grep -Fq "$dns_comment" <<<"$iptables_state" || grep -Fq ":$chain " <<<"$iptables_state" || grep -Fq ":$dns_chain " <<<"$iptables_state" || grep -Fq -- "-j $chain" <<<"$iptables_state" || grep -Fq -- "-j $dns_chain" <<<"$iptables_state"; then
      cleanup_failed=1
    fi
    if ! nft_state="$(nft list tables 2>/dev/null)"; then
      cleanup_failed=1
    elif grep -Fxq "table inet $nft_table" <<<"$nft_state"; then
      cleanup_failed=1
    fi
    if ! listeners="$(ss -H -ltn "( sport = :$LOCAL_PROXY_PORT or sport = :$LOCAL_DNS_PORT )" 2>/dev/null)" || [[ -n "$listeners" ]]; then cleanup_failed=1; fi
    if ! listeners="$(ss -H -lun "( sport = :$LOCAL_DNS_PORT )" 2>/dev/null)" || [[ -n "$listeners" ]]; then cleanup_failed=1; fi
    if (( cleanup_failed != 0 )); then
      teardown_exit=70
      (( status != 0 )) || status=70
      printf 'P2-R2E launcher teardown verification failed\n' >&2
    fi
    if (( telemetry_collector_exit != 0 )); then
      (( status != 0 )) || status=75
      printf 'P2-R2E scope memory evidence unavailable or stale\n' >&2
    fi
    install -d -m 0755 -o root -g root "$ROOT/receipts"
    writer_exit=0
    python3 - "$receipt" "$evidence" "$telemetry_work" "$telemetry_stop" "$slot" "$runner" "$EXPECTED_HEAD" "$label" \
      "$scope_unit" "$controller_status" "${controller_exit:--}" "$teardown_exit" "$status" \
      "$(date --iso-8601=seconds)" <<'RECEIPT_PY' || writer_exit=$?
import os
import datetime
import json
from pathlib import Path
import re
import stat
import sys
import tempfile

(
    receipt_path,
    evidence_path,
    telemetry_path,
    telemetry_stop_path,
    slot,
    runner,
    head,
    label,
    scope_unit,
    controller_status,
    controller_exit_text,
    teardown_exit_text,
    final_exit_text,
    finished,
) = sys.argv[1:]


def read_telemetry(path):
    source = Path(path)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    before = source.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_size > 16384
    ):
        raise ValueError("unsafe telemetry result")
    descriptor = os.open(source, flags)
    try:
        current = os.fstat(descriptor)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_uid != os.geteuid()
            or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise ValueError("telemetry identity drift")
        raw = os.read(descriptor, 16385)
        if len(raw) > 16384:
            raise ValueError("telemetry result too large")
    finally:
        os.close(descriptor)
    value = json.loads(raw.decode("ascii"))
    top_fields = {
        "schema", "collection_status", "reason", "expected_uid", "scope_unit",
        "sample_count", "runner_listener_observed", "last_sample_age_ms", "sample",
    }
    if (
        not isinstance(value, dict)
        or set(value) != top_fields
        or value.get("schema") != "sixlab-jit-scope-memory-evidence-v5"
        or value.get("expected_uid") != 1005
        or value.get("scope_unit") != scope_unit
        or value.get("collection_status") not in ("observed", "unknown")
        or type(value.get("sample_count")) is not int
        or not 0 <= value["sample_count"] <= 57600
        or type(value.get("runner_listener_observed")) is not bool
        or (
            value.get("last_sample_age_ms") is not None
            and (
                type(value["last_sample_age_ms"]) is not int
                or not 0 <= value["last_sample_age_ms"] <= 2**31 - 1
            )
        )
    ):
        raise ValueError("telemetry result binding drift")
    allowed_reasons = {
        "sampling", "stop_requested", "scope_not_observed",
        "scope_disappeared_after_observation", "sample_limit_reached", "collector_error",
        "stale_sample", "runner_listener_not_observed",
    }
    if value.get("reason") not in allowed_reasons:
        raise ValueError("telemetry result reason drift")
    if value["collection_status"] == "unknown":
        if value["sample"] is not None or value["runner_listener_observed"]:
            raise ValueError("unknown telemetry carries a sample")
        return value
    if value["runner_listener_observed"] is not True:
        raise ValueError("observed telemetry lacks verified Runner.Listener")
    if value["sample_count"] < 1 or type(value["last_sample_age_ms"]) is not int:
        raise ValueError("telemetry result sample count drift")
    sample = value.get("sample")
    sample_fields = {
        "captured_at", "cgroup_path", "pids", "runner_listener_pids",
        "memory_current_bytes", "memory_peak_bytes", "memory_events",
        "memory_events_local", "memory_pressure",
    }
    if not isinstance(sample, dict) or set(sample) != sample_fields:
        raise ValueError("telemetry sample fields drift")
    if (
        not isinstance(sample["captured_at"], str)
        or len(sample["captured_at"]) > 40
        or not isinstance(sample["cgroup_path"], str)
        or len(sample["cgroup_path"]) > 512
        or not sample["cgroup_path"].endswith("/" + scope_unit)
        or re.fullmatch(r"/[A-Za-z0-9_.@:/-]+", sample["cgroup_path"]) is None
    ):
        raise ValueError("telemetry sample binding drift")
    pids = sample["pids"]
    listener_pids = sample["runner_listener_pids"]
    if (
        not isinstance(pids, list)
        or not 1 <= len(pids) <= 64
        or any(type(pid) is not int or pid <= 0 for pid in pids)
        or pids != sorted(set(pids))
        or not isinstance(listener_pids, list)
        or any(pid not in pids for pid in listener_pids)
        or listener_pids != sorted(set(listener_pids))
    ):
        raise ValueError("telemetry PID binding drift")
    for scalar_name in ("memory_current_bytes", "memory_peak_bytes"):
        scalar = sample[scalar_name]
        if type(scalar) is not int or not 0 <= scalar <= 2**63 - 1:
            raise ValueError("telemetry scalar drift")
    event_fields = {"low", "high", "max", "oom", "oom_kill", "oom_group_kill"}
    for event_name in ("memory_events", "memory_events_local"):
        events = sample[event_name]
        if (
            not isinstance(events, dict)
            or set(events) != event_fields
            or any(type(item) is not int or not 0 <= item <= 2**63 - 1 for item in events.values())
        ):
            raise ValueError("telemetry events drift")
    pressure = sample["memory_pressure"]
    if not isinstance(pressure, dict) or set(pressure) != {"some", "full"}:
        raise ValueError("telemetry pressure drift")
    for values in pressure.values():
        if not isinstance(values, dict) or set(values) != {"avg10", "avg60", "avg300", "total"}:
            raise ValueError("telemetry pressure fields drift")
        if (
            type(values["total"]) is not int
            or not 0 <= values["total"] <= 2**63 - 1
            or any(
                not isinstance(values[key], str)
                or re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", values[key]) is None
                for key in ("avg10", "avg60", "avg300")
            )
        ):
            raise ValueError("telemetry pressure value drift")
    return value


def normalize_publication_freshness(value, publication_time):
    if value["collection_status"] != "observed":
        return value
    captured_text = value["sample"]["captured_at"]
    try:
        captured = datetime.datetime.fromisoformat(captured_text.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("telemetry capture time drift") from error
    if captured.utcoffset() != datetime.timedelta(0):
        raise ValueError("telemetry capture timezone drift")
    wall_age_ms = int((publication_time - captured).total_seconds() * 1000)
    if not 0 <= wall_age_ms <= 2**31 - 1:
        raise ValueError("telemetry capture time drift")
    effective_age_ms = max(value["last_sample_age_ms"], wall_age_ms)
    value["last_sample_age_ms"] = effective_age_ms
    if effective_age_ms > 2000:
        value.update({
            "collection_status": "unknown",
            "reason": "stale_sample",
            "runner_listener_observed": False,
            "sample": None,
        })
    return value


def temporary_file(directory, raw, mode):
    descriptor, name = tempfile.mkstemp(prefix=".sixlab-jit-evidence.", dir=directory)
    try:
        os.fchmod(descriptor, mode)
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short evidence write")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return name


controller_exit = None if controller_exit_text == "-" else int(controller_exit_text)
teardown_exit = int(teardown_exit_text)
final_exit = int(final_exit_text)
telemetry_valid = True
try:
    telemetry = read_telemetry(telemetry_path)
except (FileNotFoundError, OSError, UnicodeError, ValueError, json.JSONDecodeError):
    telemetry_valid = False
    telemetry = {
        "schema": "sixlab-jit-scope-memory-evidence-v5",
        "collection_status": "unknown",
        "reason": "collector_result_missing_or_invalid",
        "expected_uid": 1005,
        "scope_unit": scope_unit,
        "sample_count": 0,
        "runner_listener_observed": False,
        "last_sample_age_ms": None,
        "sample": None,
    }
def remove_transient(path):
    target = Path(path)
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise ValueError("unsafe telemetry transient")
    target.unlink()


telemetry_cleanup_ok = True
for transient_path in (telemetry_stop_path, telemetry_path):
    try:
        remove_transient(transient_path)
    except (OSError, ValueError):
        telemetry_cleanup_ok = False
if not telemetry_cleanup_ok and final_exit == 0:
    final_exit = 74
publication_time = datetime.datetime.now(datetime.timezone.utc)
try:
    telemetry = normalize_publication_freshness(telemetry, publication_time)
except (TypeError, ValueError):
    telemetry_valid = False
    telemetry = {
        "schema": "sixlab-jit-scope-memory-evidence-v5",
        "collection_status": "unknown",
        "reason": "collector_result_missing_or_invalid",
        "expected_uid": 1005,
        "scope_unit": scope_unit,
        "sample_count": 0,
        "runner_listener_observed": False,
        "last_sample_age_ms": None,
        "sample": None,
    }
if telemetry["collection_status"] != "observed" and final_exit == 0:
    final_exit = 75
finished = publication_time.isoformat()
runner_observed = (
    telemetry.get("collection_status") == "observed"
    and telemetry.get("runner_listener_observed") is True
)
runner_exit = None
runner_status = (
    "interrupted_unknown" if controller_status == "interrupted"
    else "listener_observed_exit_unknown" if runner_observed
    else "not_observed"
)
evidence = {
    "schema": "sixlab-jit-launcher-evidence-v5",
    "binding": {
        "slot": slot,
        "runner": runner,
        "expected_head": head,
        "label": label,
        "scope_unit": scope_unit,
    },
    "runner": {"status": runner_status, "exit_code": runner_exit},
    "controller": {"status": controller_status, "exit_code": controller_exit},
    "teardown": {"status": "ok" if teardown_exit == 0 else "failed", "exit_code": teardown_exit},
    "telemetry_cleanup": {
        "status": "ok" if telemetry_cleanup_ok else "failed",
        "exit_code": 0 if telemetry_cleanup_ok else 74,
    },
    "memory": telemetry,
    "final_exit_code": final_exit,
    "finished_at": finished,
    "legacy_receipt_schema": "sixlab-jit-teardown-receipt-v1",
}
receipt_raw = (
    f"slot={slot} runner={runner} expected_head={head} label={label} "
    f"exit={final_exit} finished={finished}\n"
).encode("utf-8")
evidence_raw = (json.dumps(evidence, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
directory = os.path.dirname(receipt_path)
receipt_temporary = None
evidence_temporary = None
linked_evidence = False
linked_receipt = False
try:
    receipt_temporary = temporary_file(directory, receipt_raw, 0o444)
    evidence_temporary = temporary_file(directory, evidence_raw, 0o444)
    if telemetry["collection_status"] == "observed":
        publication_recheck_time = datetime.datetime.now(datetime.timezone.utc)
        rechecked_telemetry = normalize_publication_freshness(
            json.loads(json.dumps(telemetry)), publication_recheck_time
        )
        if rechecked_telemetry["collection_status"] != "observed":
            os.unlink(receipt_temporary)
            os.unlink(evidence_temporary)
            receipt_temporary = None
            evidence_temporary = None
            telemetry = rechecked_telemetry
            if final_exit == 0:
                final_exit = 75
            finished = publication_recheck_time.isoformat()
            evidence["runner"] = {"status": "not_observed", "exit_code": None}
            evidence["memory"] = telemetry
            evidence["final_exit_code"] = final_exit
            evidence["finished_at"] = finished
            receipt_raw = (
                f"slot={slot} runner={runner} expected_head={head} label={label} "
                f"exit={final_exit} finished={finished}\n"
            ).encode("utf-8")
            evidence_raw = (
                json.dumps(evidence, separators=(",", ":"), sort_keys=True) + "\n"
            ).encode("ascii")
            receipt_temporary = temporary_file(directory, receipt_raw, 0o444)
            evidence_temporary = temporary_file(directory, evidence_raw, 0o444)
    os.link(evidence_temporary, evidence_path)
    linked_evidence = True
    os.link(receipt_temporary, receipt_path)
    linked_receipt = True
    for temporary_name in (receipt_temporary, evidence_temporary):
        os.unlink(temporary_name)
    receipt_temporary = None
    evidence_temporary = None
    directory_descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
except Exception:
    if linked_receipt:
        try:
            os.unlink(receipt_path)
        except FileNotFoundError:
            pass
    if linked_evidence:
        try:
            os.unlink(evidence_path)
        except FileNotFoundError:
            pass
    raise
finally:
    for temporary_name in (receipt_temporary, evidence_temporary):
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
raise SystemExit(final_exit)
RECEIPT_PY
    if [[ -f "$receipt" && ! -L "$receipt" && -f "$evidence" && ! -L "$evidence" ]]; then
      status="$writer_exit"
    else
      printf 'P2-R2E exclusive receipt creation failed\n' >&2
      (( status != 0 )) || status=74
    fi
    exit "$status"
  }
  trap cleanup EXIT
  trap 'cleanup 129' HUP
  trap 'cleanup 130' INT
  trap 'cleanup 143' TERM

  [[ "$(id -u)" == 0 && "$(hostname)" == "$EXPECTED_HOST" ]] || die 'root or host identity mismatch'
  [[ "$(id -u "$USER_NAME")" == "$USER_ID" ]] || die 'dedicated user identity drift'
  [[ "$(stat -fc %T /sys/fs/cgroup)" == cgroup2fs ]] || die 'cgroup v2 required'
  [[ -d "$RUNNER_GOLDEN" && -x "$ROOTLESS" && -x "$STATIC_DOCKER/docker" ]] || die 'golden runtime missing'
  [[ "$(sha256sum "$GOLDEN_IMAGES" | awk '{print $1}')" == "$GOLDEN_IMAGES_SHA" ]] || die 'golden images SHA mismatch'
  ! pgrep -u "$USER_ID" >/dev/null || die 'dedicated process exists before job admission'
  [[ "$(systemctl is-active user@1005.service 2>/dev/null || true)" == inactive ]] || die 'dedicated user manager unexpectedly active'
  iptables_state="$(iptables-save)" || die 'iptables enumeration failed'
  nft_state="$(nft -a list ruleset)" || die 'nftables enumeration failed'
  if grep -Fq "$comment" <<<"$iptables_state" || grep -Fq "$dns_comment" <<<"$iptables_state" || grep -Fq ":$chain " <<<"$iptables_state" || grep -Fq ":$dns_chain " <<<"$iptables_state"; then die 'firewall residue exists'; fi
  ! grep -Fq "table inet $nft_table" <<<"$nft_state" || die 'nftables table residue exists'
  ! grep -q "meta skuid $USER_ID" <<<"$nft_state" || die 'foreign nftables owner policy exists'
  ! ss -H -ltn '( sport = :3306 or sport = :6379 )' | grep -q . || die 'host DB/cache port occupied'
  ! ss -H -ltn "( sport = :$LOCAL_PROXY_PORT )" | grep -q . || die 'local proxy port occupied'
  ! ss -H -ltn "( sport = :$LOCAL_DNS_PORT )" | grep -q . || die 'local DNS TCP port occupied'
  ! ss -H -lun "( sport = :$LOCAL_DNS_PORT )" | grep -q . || die 'local DNS UDP port occupied'

  read -r ephemeral_port_min ephemeral_port_max < /proc/sys/net/ipv4/ip_local_port_range
  [[ "$ephemeral_port_min" =~ ^[0-9]+$ && "$ephemeral_port_max" =~ ^[0-9]+$ ]] || die 'invalid host ephemeral port range'
  (( ephemeral_port_min >= 1024 && ephemeral_port_min <= ephemeral_port_max && ephemeral_port_max <= 65535 )) || die 'unsafe host ephemeral port range'
  if ss -H -ltn4 | awk -v lower="$ephemeral_port_min" -v upper="$ephemeral_port_max" '
    {
      local_address = $4
      sub(/^.*:/, "", local_address)
      port = local_address + 0
      if (port >= lower && port <= upper) found = 1
    }
    END { exit found ? 0 : 1 }
  '; then
    die 'host listener occupies ephemeral loopback allowance'
  fi

  root_available="$(df -B1 --output=avail / | tail -1 | tr -d ' ')"
  memory_available="$(awk '/MemAvailable:/ {print $2 * 1024}' /proc/meminfo | cut -d. -f1)"
  swap_free="$(awk '/SwapFree:/ {print $2 * 1024}' /proc/meminfo | cut -d. -f1)"
  load5="$(awk '{print $2}' /proc/loadavg)"
  (( root_available >= 32 * 1024 * 1024 * 1024 )) || die 'disk gate below 32 GiB'
  (( memory_available + swap_free >= 4 * 1024 * 1024 * 1024 )) || die 'memory plus swap below 4 GiB'
  awk -v value="$load5" 'BEGIN { exit !(value <= 1.5) }' || die 'load5 above 1.5'
  [[ -x "$NODE_HOME/node" && ! -L "$NODE_HOME/node" ]] || die 'system node missing or unsafe'
  [[ "$(sha256sum "$NODE_HOME/node" | awk '{print $1}')" == "$NODE_SHA" ]] || die 'system node SHA drift'
  [[ "$(stat -c '%d:%i' "$NODE_HOME/node")" == "$NODE_DEVICE_INODE" ]] || die 'system node inode drift'
  export PATH="$NODE_HOME:/usr/bin:/bin:/usr/sbin:/sbin"
  for required_command in node npm git curl jq mkfs.ext4 mount flock python3 nc getent pkill timeout; do command -v "$required_command" >/dev/null || die "required host command missing: $required_command"; done
  node_major="$(node -p 'Number(process.versions.node.split(".")[0])')"
  (( node_major >= 20 )) || die 'system node below 20'

  install -d -m 0755 -o root -g root "$ROOT/transient" "$ROOT/jobs" "$ROOT/receipts"
  [[ ! -e "$image_file" && ! -e "$job_root" ]] || die 'job disk residue exists'
  if [[ "$slot" == 05 ]]; then
    truncate -s 35G "$image_file"
    memory_high=5G
    memory_max=6500M
  else
    truncate -s 20G "$image_file"
    memory_high=3G
    memory_max=4G
  fi
  mkfs.ext4 -q -F -m 0 "$image_file"
  install -d -m 0755 -o root -g root "$job_root"
  mount -o loop,nosuid,nodev "$image_file" "$job_root"
  mounted=1
  install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" "$job_root/home" "$job_root/run" "$job_root/docker-data" "$job_root/docker-exec" "$job_root/work" "$job_root/runner"
  cp -a "$RUNNER_GOLDEN/." "$job_root/runner/"
  chown -R "$USER_NAME:$USER_NAME" "$job_root"
  install -m 0500 -o root -g root /dev/stdin "$proxy_script" <<'PY'
# SIXLAB_US_PROXY_RELAY_BEGIN
#!/usr/bin/env python3
import select
import socket
import socketserver
import struct
import sys
import threading

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 18080
UPSTREAM_HOST = "47.88.16.146"
UPSTREAM_PORT = 8443
DNS_LISTEN_HOST = "127.0.0.1"
DNS_LISTEN_PORT = 15353
DNS_RESOLVERS = ("183.60.83.19", "183.60.82.98")
DNS_UPSTREAM_PORT = 53
DNS_MAX_QUERY = 4096
MAX_HEADER = 65536
MAX_CLIENTS = 64
ALLOWED_BASES = (
    "github.com",
    "githubusercontent.com",
    "actions.githubusercontent.com",
    "githubassets.com",
    "npmjs.org",
    "docker.io",
    "docker.com",
)


def allowed_host(value):
    host = value.rstrip(".").lower()
    try:
        host.encode("ascii")
    except UnicodeError:
        return False
    if not host or ":" in host or host.replace(".", "").isdigit():
        return False
    return any(host == base or host.endswith("." + base) for base in ALLOWED_BASES)


def dns_query_allowed(packet):
    if len(packet) < 17 or len(packet) > DNS_MAX_QUERY:
        return False
    try:
        _, flags, questions, answers, authorities, _ = struct.unpack("!HHHHHH", packet[:12])
    except struct.error:
        return False
    if flags & 0x8000 or flags & 0x7800 or questions != 1 or answers != 0 or authorities != 0:
        return False
    labels = []
    offset = 12
    while offset < len(packet):
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length > 63 or length & 0xC0 or offset + length > len(packet):
            return False
        try:
            label = packet[offset:offset + length].decode("ascii").lower()
        except UnicodeError:
            return False
        if not label or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for character in label):
            return False
        labels.append(label)
        offset += length
    if not labels or offset + 4 > len(packet):
        return False
    query_type, query_class = struct.unpack("!HH", packet[offset:offset + 4])
    return query_class == 1 and query_type in {1, 28} and allowed_host(".".join(labels))


def dns_error(packet, code):
    if len(packet) < 12:
        return b""
    request_flags = struct.unpack("!H", packet[2:4])[0]
    flags = 0x8000 | (request_flags & 0x0100) | code
    questions = 1 if dns_query_allowed(packet) else 0
    body = packet[12:] if questions else b""
    return packet[:2] + struct.pack("!HHHHH", flags, questions, 0, 0, 0) + body


def recv_exact(stream, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise OSError("short DNS response")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def forward_dns_udp(packet):
    for resolver in DNS_RESOLVERS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
                upstream.settimeout(5)
                upstream.sendto(packet, (resolver, DNS_UPSTREAM_PORT))
                response_packet, _ = upstream.recvfrom(65535)
                if response_packet[:2] == packet[:2]:
                    return response_packet
        except OSError:
            continue
    return dns_error(packet, 2)


def forward_dns_tcp(packet):
    for resolver in DNS_RESOLVERS:
        try:
            with socket.create_connection((resolver, DNS_UPSTREAM_PORT), timeout=5) as upstream:
                upstream.settimeout(5)
                upstream.sendall(struct.pack("!H", len(packet)) + packet)
                size = struct.unpack("!H", recv_exact(upstream, 2))[0]
                if size > 65535:
                    continue
                response_packet = recv_exact(upstream, size)
                if response_packet[:2] == packet[:2]:
                    return response_packet
        except OSError:
            continue
    return dns_error(packet, 2)


def response(stream, status):
    stream.sendall(
        (f"HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").encode("ascii")
    )


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        client.settimeout(15)
        raw = b""
        while b"\r\n\r\n" not in raw and len(raw) <= MAX_HEADER:
            chunk = client.recv(4096)
            if not chunk:
                return
            raw += chunk
        if b"\r\n\r\n" not in raw or len(raw) > MAX_HEADER:
            response(client, "431 Request Header Fields Too Large")
            return
        header, remainder = raw.split(b"\r\n\r\n", 1)
        try:
            first = header.split(b"\r\n", 1)[0].decode("ascii")
            method, authority, version = first.split(" ", 2)
            host, port_text = authority.rsplit(":", 1)
            port = int(port_text)
        except (UnicodeError, ValueError):
            response(client, "400 Bad Request")
            return
        if method != "CONNECT" or version not in {"HTTP/1.0", "HTTP/1.1"} or port != 443 or not allowed_host(host):
            response(client, "403 Forbidden")
            return
        try:
            upstream = socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT), timeout=10)
        except OSError:
            response(client, "502 Bad Gateway")
            return
        with upstream:
            upstream.sendall(header + b"\r\n\r\n" + remainder)
            client.settimeout(None)
            upstream.settimeout(None)
            peers = {client: upstream, upstream: client}
            while True:
                readable, _, _ = select.select(tuple(peers), (), (), 600)
                if not readable:
                    return
                for source in readable:
                    try:
                        data = source.recv(65536)
                    except OSError:
                        return
                    if not data:
                        return
                    try:
                        peers[source].sendall(data)
                    except OSError:
                        return


class DNSUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet, stream = self.request
        response_packet = (
            forward_dns_udp(packet) if dns_query_allowed(packet) else dns_error(packet, 5)
        )
        if response_packet:
            stream.sendto(response_packet, self.client_address)


class DNSTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            size = struct.unpack("!H", recv_exact(self.request, 2))[0]
            if size > DNS_MAX_QUERY:
                return
            packet = recv_exact(self.request, size)
            response_packet = (
                forward_dns_tcp(packet) if dns_query_allowed(packet) else dns_error(packet, 5)
            )
            if response_packet:
                self.request.sendall(struct.pack("!H", len(response_packet)) + response_packet)
        except (OSError, struct.error):
            return


CLIENT_GATE = threading.BoundedSemaphore(MAX_CLIENTS)


class BoundedThreadingMixIn(socketserver.ThreadingMixIn):
    daemon_threads = True

    def process_request(self, request, client_address):
        if not CLIENT_GATE.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            CLIENT_GATE.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            CLIENT_GATE.release()


class Server(BoundedThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    request_queue_size = MAX_CLIENTS

    def handle_error(self, request, client_address):
        return


class DNSUDPServer(BoundedThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True


class DNSTCPServer(BoundedThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit(64)
    with Server((LISTEN_HOST, LISTEN_PORT), Handler) as server, \
            DNSUDPServer((DNS_LISTEN_HOST, DNS_LISTEN_PORT), DNSUDPHandler) as dns_udp, \
            DNSTCPServer((DNS_LISTEN_HOST, DNS_LISTEN_PORT), DNSTCPHandler) as dns_tcp:
        udp_thread = threading.Thread(target=dns_udp.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
        tcp_thread = threading.Thread(target=dns_tcp.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
        udp_thread.start()
        tcp_thread.start()
        try:
            server.serve_forever(poll_interval=0.2)
        finally:
            dns_udp.shutdown()
            dns_tcp.shutdown()
            udp_thread.join(timeout=3)
            tcp_thread.join(timeout=3)
# SIXLAB_US_PROXY_RELAY_END
PY

  nft -f - <<NFT
add table inet $nft_table
add chain inet $nft_table output { type filter hook output priority filter + 10; policy accept; }
add rule inet $nft_table output meta skuid $USER_ID ip daddr 127.0.0.1 tcp dport { 3306, 6379 } accept
add rule inet $nft_table output meta skuid $USER_ID ip daddr $LOCAL_PROXY_HOST tcp dport $LOCAL_PROXY_PORT accept
add rule inet $nft_table output meta skuid $USER_ID ip daddr 127.0.0.1 udp dport $LOCAL_DNS_PORT accept
add rule inet $nft_table output meta skuid $USER_ID ip daddr 127.0.0.1 tcp dport $LOCAL_DNS_PORT accept
add rule inet $nft_table output meta skuid $USER_ID ip daddr 127.0.0.1 tcp dport $ephemeral_port_min-$ephemeral_port_max accept
add rule inet $nft_table output meta skuid $USER_ID ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/3 } drop
add rule inet $nft_table output meta skuid $USER_ID ip6 daddr { ::/127, ::ffff:0.0.0.0/96, 64:ff9b::/96, 64:ff9b:1::/48, 100::/64, 2001::/23, 2001:db8::/32, 2002::/16, 2620:4f:8000::/48, 3fff::/20, 5f00::/16, fc00::/7, fe80::/10, ff00::/8 } drop
add rule inet $nft_table output meta skuid $USER_ID ip daddr 10.0.0.10 drop
add rule inet $nft_table output meta skuid $USER_ID ip6 daddr 2402:4e00:c032:2e00:48a4:2b84:989c:0 drop
add rule inet $nft_table output meta skuid $USER_ID drop
NFT
  nft_created=1

  iptables -w -N "$chain"
  chain_created=1
  for port in 3306 6379; do iptables -w -A "$chain" -d 127.0.0.1/32 -p tcp --dport "$port" -m comment --comment "$comment" -j ACCEPT; done
  iptables -w -A "$chain" -d "$LOCAL_PROXY_HOST/32" -p tcp --dport "$LOCAL_PROXY_PORT" -m comment --comment "$comment" -j ACCEPT
  iptables -w -A "$chain" -d 127.0.0.1/32 -p udp --dport "$LOCAL_DNS_PORT" -m comment --comment "$comment" -j ACCEPT
  iptables -w -A "$chain" -d 127.0.0.1/32 -p tcp --dport "$LOCAL_DNS_PORT" -m comment --comment "$comment" -j ACCEPT
  # Supertest and similar in-process HTTP harnesses bind a random loopback port.
  # Permit only the kernel's ephemeral range, after the fail-closed host-listener
  # preflight above, instead of exposing every host-local service to the runner.
  iptables -w -A "$chain" -d 127.0.0.1/32 -p tcp --dport "$ephemeral_port_min:$ephemeral_port_max" -m comment --comment "$comment" -j ACCEPT
  for destination in 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 120.55.125.230/32 47.96.91.169/32 124.221.116.56/32; do
    iptables -w -A "$chain" -d "$destination" -m comment --comment "$comment" -j DROP
  done
  iptables -w -A "$chain" -m comment --comment "$comment" -j DROP
  iptables -w -I OUTPUT 1 -m owner --uid-owner "$USER_ID" -m comment --comment "$comment" -j "$chain"
  jump_created=1
  iptables -w -t nat -N "$dns_chain"
  dns_chain_created=1
  iptables -w -t nat -A "$dns_chain" -p udp --dport 53 -j REDIRECT --to-ports "$LOCAL_DNS_PORT"
  iptables -w -t nat -A "$dns_chain" -p tcp --dport 53 -j REDIRECT --to-ports "$LOCAL_DNS_PORT"
  iptables -w -t nat -I OUTPUT 1 -m owner --uid-owner "$USER_ID" -m comment --comment "$dns_comment" -j "$dns_chain"
  dns_jump_created=1

  python3 "$proxy_script" >"$proxy_log" 2>&1 &
  proxy_pid=$!
  proxy_started=1
  proxy_ready=0
  for _ in $(seq 1 40); do
    if nc -z "$LOCAL_PROXY_HOST" "$LOCAL_PROXY_PORT" >/dev/null 2>&1; then proxy_ready=1; break; fi
    kill -0 "$proxy_pid" 2>/dev/null || break
    sleep 0.25
  done
  [[ "$proxy_ready" == 1 ]] || die 'local US proxy relay failed to start'
  ss -H -lun "( sport = :$LOCAL_DNS_PORT )" | grep -q . || die 'local allowlist DNS relay failed to start'

  proxy_environment=(
    "HTTP_PROXY=$PROXY_URL" "HTTPS_PROXY=$PROXY_URL"
    "http_proxy=$PROXY_URL" "https_proxy=$PROXY_URL"
    "NO_PROXY=$NO_PROXY_VALUE" "no_proxy=$NO_PROXY_VALUE"
  )
  for proxy_canary in https://github.com/ https://api.github.com/ https://registry.npmjs.org/; do
    runuser -u "$USER_NAME" -- env "${proxy_environment[@]}" \
      curl -4 -fsSI -o /dev/null --connect-timeout 8 --max-time 20 "$proxy_canary" \
      || die "US proxy canary failed: $proxy_canary"
  done
  runuser -u "$USER_NAME" -- getent ahostsv4 github.com >/dev/null || die 'allowlist DNS relay positive query failed'
  if runuser -u "$USER_NAME" -- getent ahostsv4 example.com >/dev/null 2>&1; then die 'allowlist DNS relay accepted forbidden query'; fi
  private_probe="$({ printf 'CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n'; } \
    | runuser -u "$USER_NAME" -- nc -w 3 "$LOCAL_PROXY_HOST" "$LOCAL_PROXY_PORT" 2>/dev/null \
    | tr -d '\r' | head -1 || true)"
  [[ "$private_probe" == 'HTTP/1.1 403 Forbidden' ]] || die 'local relay private-target rejection failed'
  if timeout 8 runuser -u "$USER_NAME" -- env \
    -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy -u ALL_PROXY -u all_proxy \
    curl -4 -fsS -o /dev/null --connect-timeout 3 --max-time 6 https://api.github.com/; then
    die 'direct external HTTPS unexpectedly reachable'
  fi

  ! pgrep -u "$USER_ID" >/dev/null || die 'dedicated process exists before token exposure'

  systemctl start user@1005.service
  user_manager_started=1
  [[ "$(systemctl show user@1005.service -p Delegate --value)" == yes ]] || die 'user delegation missing'

  runner_listener="$job_root/runner/bin/Runner.Listener"
  [[ -x "$runner_listener" && ! -L "$runner_listener" ]] || die 'copied Runner.Listener missing or unsafe'
  runner_listener_device="$(stat -c '%d' "$runner_listener")"
  runner_listener_inode="$(stat -c '%i' "$runner_listener")"
  [[ "$runner_listener_device" =~ ^[1-9][0-9]*$ && "$runner_listener_inode" =~ ^[1-9][0-9]*$ ]] \
    || die 'copied Runner.Listener identity invalid'
  collect_scope_memory "$telemetry_work" "$telemetry_stop" "$USER_ID" "$scope_unit" \
    /proc /sys/fs/cgroup "$runner_listener_device" "$runner_listener_inode" 57600 100 &
  telemetry_pid=$!
  telemetry_started=1
  set +e
  runuser -u "$USER_NAME" -- env XDG_RUNTIME_DIR=/run/user/1005 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1005/bus \
    systemd-run --user --scope --quiet --unit="$scope_unit" --property=Delegate=yes \
      --property=CPUQuota=190% --property=MemoryHigh="$memory_high" --property=MemoryMax="$memory_max" --property=MemorySwapMax=2G \
      env HOME="$job_root/home" XDG_RUNTIME_DIR="$job_root/run" \
      PATH="$NODE_HOME:/usr/bin:/bin:/usr/sbin:/sbin:$STATIC_DOCKER:$ROOT/golden/rootless-29.1.3" \
      DOCKER_HOST="unix://$job_root/run/docker.sock" \
      DOCKERD_ROOTLESS_ROOTLESSKIT_NET=slirp4netns \
      DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER=slirp4netns \
      DOCKERD_ROOTLESS_ROOTLESSKIT_FLAGS=--disable-host-loopback \
      HTTP_PROXY="$PROXY_URL" HTTPS_PROXY="$PROXY_URL" http_proxy="$PROXY_URL" https_proxy="$PROXY_URL" \
      NO_PROXY="$NO_PROXY_VALUE" no_proxy="$NO_PROXY_VALUE" \
      JOB_ROOT="$job_root" RUNNER_NAME="$runner" LABEL="$label" REPO_URL="$REPO_URL" ROOTLESS="$ROOTLESS" GOLDEN_IMAGES="$GOLDEN_IMAGES" \
      bash -c '
set -Eeuo pipefail
cd "$JOB_ROOT/runner"
"$ROOTLESS" --data-root="$JOB_ROOT/docker-data" --exec-root="$JOB_ROOT/docker-exec" \
  --pidfile="$JOB_ROOT/run/dockerd.pid" --host="$DOCKER_HOST" --storage-driver=fuse-overlayfs \
  >"$JOB_ROOT/dockerd.log" 2>&1 &
dockerd_pid=$!
cleanup_inner() {
  local rc=$? signal_status="${1:-0}"
  if (( signal_status != 0 )); then rc="$signal_status"; fi
  trap - EXIT INT TERM HUP
  if (( rc != 0 )); then tail -160 "$JOB_ROOT/dockerd.log" >&2 2>/dev/null || true; fi
  kill "$dockerd_pid" 2>/dev/null || true
  wait "$dockerd_pid" 2>/dev/null || true
  exit "$rc"
}
trap cleanup_inner EXIT
trap "cleanup_inner 129" HUP
trap "cleanup_inner 130" INT
trap "cleanup_inner 143" TERM
ready=0
for _ in $(seq 1 60); do
  if docker info >/dev/null 2>&1; then ready=1; break; fi
  kill -0 "$dockerd_pid" 2>/dev/null || break
  sleep 1
done
[[ "$ready" == 1 ]]
docker info --format "{{json .SecurityOptions}}" | grep -q rootless
docker load --input "$GOLDEN_IMAGES" >/dev/null
[[ "$(docker image inspect mysql:8.0 --format "{{.Id}}")" == "sha256:6cd09145362dfe6831b14545de3d5fd6cc75c37cfd6ef8561429c1fc73518b39" ]]
[[ "$(docker image inspect redis:7 --format "{{.Id}}")" == "sha256:c6b72caa91cd332d62859e1712fb4860522ca34e3df364adaf29a37eeb9965c9" ]]
IFS= read -r token
[[ "$token" =~ ^[A-Z0-9]{20,80}$ ]]
./config.sh --url "$REPO_URL" --token "$token" --name "$RUNNER_NAME" --labels "$LABEL" \
  --work "$JOB_ROOT/work" --ephemeral --disableupdate --no-default-labels --unattended
unset token
RUNNER_MANUALLY_TRAP_SIG=1 ./run.sh
'
  controller_exit=$?
  controller_status='exited'
  set -e
  : >"$telemetry_stop"
  if wait "$telemetry_pid"; then telemetry_collector_exit=0; else telemetry_collector_exit=$?; fi
  telemetry_started=0
  return "$controller_exit"
}

case "${1:-}" in
  --proxy-canary) [[ $# == 1 ]] || die 'proxy-canary takes no arguments'; proxy_canary ;;
  --run) [[ $# == 2 ]] || die 'run requires slot'; run_job "$2" ;;
  *) die 'usage: --proxy-canary | --run SLOT (registration token: one stdin line)' ;;
esac
