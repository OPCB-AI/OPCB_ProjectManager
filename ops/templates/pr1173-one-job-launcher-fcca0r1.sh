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
readonly LAUNCHER_PREFIX='fcca0-r1-usproxy5'
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
  label="$(label_for "$slot")"
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

  [[ ! -e "$receipt" && ! -L "$receipt" ]] || die 'receipt path already exists; archive explicitly before run'

  exec 9>"$LOCK_FILE"
  flock -n 9 || die 'another ephemeral job controller is active'
  cleanup() {
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
      status=70
      printf 'P2-R2E launcher teardown verification failed\n' >&2
    fi
    install -d -m 0755 -o root -g root "$ROOT/receipts"
    if ! python3 - "$receipt" "$slot" "$runner" "$EXPECTED_HEAD" "$label" "$status" "$(date --iso-8601=seconds)" <<'RECEIPT_PY'
import os
import sys

path, slot, runner, head, label, status, finished = sys.argv[1:]
raw = (
    f"slot={slot} runner={runner} expected_head={head} label={label} "
    f"exit={status} finished={finished}\n"
).encode("utf-8")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags, 0o400)
try:
    os.fchmod(descriptor, 0o444)
    remaining = memoryview(raw)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("short receipt write")
        remaining = remaining[written:]
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
RECEIPT_PY
    then
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

  runuser -u "$USER_NAME" -- env XDG_RUNTIME_DIR=/run/user/1005 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1005/bus \
    systemd-run --user --scope --quiet --pipe --property=Delegate=yes \
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
./run.sh
'
}

case "${1:-}" in
  --proxy-canary) [[ $# == 1 ]] || die 'proxy-canary takes no arguments'; proxy_canary ;;
  --run) [[ $# == 2 ]] || die 'run requires slot'; run_job "$2" ;;
  *) die 'usage: --proxy-canary | --run SLOT (registration token: one stdin line)' ;;
esac
