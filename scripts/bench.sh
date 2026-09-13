#!/usr/bin/env bash
set -uo pipefail

usage() {
  cat >&2 <<'EOF'
usage: bench.sh [--out PATH] [--runs N] [--binary PATH] [SECTION ...]

Measure what the site publishes about this store, and write it as JSON the page
reads at load time. Nothing is typed into the page by hand: a number that was
not measured here stays absent, and the page renders it as a dash.

Sections (default: all of them)
  binary     size of the single binary
  deps       direct and total module count, the dependency surface
  coldstart  server start to a serving /v1/sys/health, sealed, fresh data dir
  unseal     initialise with Shamir shares and reach unsealed with a quorum
  secret     write and read latency on the hot path
  param      read latency for a parameter, which is not encrypted
  audit      verifying the hash chain, and how many records that covered
  limits     the per-caller request rate this build ships as its default

Environment
  SHARES      shares to split the key into, default 5
  THRESHOLD   shares needed to unseal, default 3
  SECRETS     secrets written before the read measurement, default 200
  PORT        loopback port the probe server binds, default 18200
  TENANT      tenant used for the probe data, default bench

The latency sections raise MARSEC_REQUEST_RATE_PER_MINUTE so they measure the
store rather than its rate limiter, which the limits section reports separately.

This runs an entire store of its own on loopback, in a temporary data directory
it deletes afterwards. It never touches a store you are already running, and it
sets MARSEC_ALLOW_INSECURE_HTTP because it only ever talks to itself.

Requires: python3, curl, and the marsec binary.
EOF
  exit 2
}

OUT=""
RUNS=5
BINARY=""
SECTIONS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="${2:-}"; shift 2 || usage ;;
    --runs) RUNS="${2:-}"; shift 2 || usage ;;
    --binary) BINARY="${2:-}"; shift 2 || usage ;;
    -h|--help) usage ;;
    -*) usage ;;
    *) SECTIONS+=("$1"); shift ;;
  esac
done

[ ${#SECTIONS[@]} -eq 0 ] && SECTIONS=(binary deps limits coldstart unseal secret param audit)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -n "$BINARY" ] || BINARY="$ROOT/bin/marsec"
SHARES="${SHARES:-5}"
THRESHOLD="${THRESHOLD:-3}"
SECRETS="${SECRETS:-200}"
PORT="${PORT:-18200}"
TENANT="${TENANT:-bench}"
BASE="http://127.0.0.1:$PORT"
WORK="$(mktemp -d)"
SERVER_PID=""

cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  wait "$SERVER_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

export MARSEC_ALLOW_INSECURE_HTTP=true
export MARSEC_ALLOW_UNPROTECTED_MEMORY=true
export MARSEC_LOG_LEVEL=error
export MARSEC_REQUEST_RATE_PER_MINUTE="${MARSEC_REQUEST_RATE_PER_MINUTE:-600000}"

has() { for s in "${SECTIONS[@]}"; do [ "$s" = "$1" ] && return 0; done; return 1; }
now_ms() { python3 -c 'import time;print(int(time.time()*1000))'; }
mono_ms() { python3 -c 'import time;print(time.perf_counter()*1000)'; }
note() { printf '%s\n' "$*" >&2; }
emit() { printf '%s\t%s\n' "$1" "$2" >> "$WORK/pairs"; }

collect() {
  local line
  COLLECTED=()
  while IFS= read -r line; do
    [ -n "$line" ] && COLLECTED+=("$line")
  done
}

stat_percentile() {
  python3 - "$@" <<'PY'
import sys, statistics
vals = sorted(float(v) for v in sys.argv[2:])
if not vals:
    print("null"); sys.exit()
q = float(sys.argv[1])
if q == 50:
    print(round(statistics.median(vals), 2)); sys.exit()
k = (len(vals) - 1) * q / 100
lo, hi = int(k), min(int(k) + 1, len(vals) - 1)
print(round(vals[lo] + (vals[hi] - vals[lo]) * (k - lo), 2))
PY
}

jq_get() { python3 -c "import json,sys;print(json.load(sys.stdin).get('$1',''))" 2>/dev/null; }

to_ms() {
  python3 - "$@" <<'PY'
import sys
for value in sys.argv[1:]:
    print(round(float(value) * 1000, 3))
PY
}

start_server() {
  local dir="$1"
  MARSEC_DATA_DIR="$dir" MARSEC_LISTEN_ADDR="127.0.0.1:$PORT" "$BINARY" server \
    > "$WORK/server.log" 2>&1 &
  SERVER_PID=$!
}

wait_health() {
  local deadline
  deadline=$(( $(now_ms) + 30000 ))
  while true; do
    curl -sf -o /dev/null --max-time 1 "$BASE/v1/sys/health" && return 0
    kill -0 "$SERVER_PID" 2>/dev/null || return 1
    [ "$(now_ms)" -gt "$deadline" ] && return 1
  done
}

stop_server() {
  [ -n "$SERVER_PID" ] || return 0
  kill "$SERVER_PID" 2>/dev/null
  wait "$SERVER_PID" 2>/dev/null
  SERVER_PID=""
}

measure_binary() {
  if [ ! -x "$BINARY" ]; then
    note "binary: $BINARY is not there, run make build first"
    return
  fi
  local bytes
  bytes="$(python3 -c 'import os,sys;print(os.path.getsize(sys.argv[1]))' "$BINARY")"
  emit binary_bytes "$bytes"
  note "binary: $bytes bytes"
}

measure_deps() {
  local direct total
  direct="$(python3 - "$ROOT/go.mod" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
count = 0
for block in re.findall(r"require\s*\((.*?)\)", text, re.S):
    count += sum(1 for line in block.splitlines()
                 if line.strip() and "// indirect" not in line)
for line in text.splitlines():
    m = re.match(r"require\s+\S+\s+\S+\s*$", line.strip())
    if m and "// indirect" not in line:
        count += 1
print(count)
PY
)"
  total="$(cd "$ROOT" && go list -m all 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')"
  [ -n "$direct" ] && emit deps_direct "$direct"
  [ -n "$total" ] && [ "$total" != 0 ] && emit deps_total "$total"
  note "deps: $direct direct, $total in the module graph"
}

measure_coldstart() {
  if [ ! -x "$BINARY" ]; then
    note "coldstart: $BINARY is not there, skipping"
    return
  fi
  local samples=() i dir t0 t1
  for i in $(seq 1 "$RUNS"); do
    dir="$WORK/cold-$i"
    mkdir -p "$dir"
    t0="$(now_ms)"
    start_server "$dir"
    if ! wait_health; then
      note "coldstart run $i: the server never answered, $(tail -1 "$WORK/server.log")"
      stop_server
      continue
    fi
    t1="$(now_ms)"
    stop_server
    samples+=("$((t1 - t0))")
    note "coldstart run $i: $((t1 - t0)) ms"
  done
  [ ${#samples[@]} -eq 0 ] && return
  emit coldstart_ms "$(stat_percentile 50 "${samples[@]}")"
}

initialise() {
  local dir="$1" body
  body="$(curl -sf --max-time 10 -X POST "$BASE/v1/sys/init" \
    -d "{\"shares\":$SHARES,\"threshold\":$THRESHOLD}")" || return 1
  printf '%s' "$body" > "$WORK/init.json"
  python3 -c "
import json
print('\n'.join(json.load(open('$WORK/init.json'))['shares']))" > "$WORK/shares" 2>/dev/null
  [ -s "$WORK/shares" ]
}

unseal_quorum() {
  local share n=0
  while read -r share; do
    n=$((n + 1))
    curl -sf -o /dev/null --max-time 10 -X POST "$BASE/v1/sys/unseal" \
      -d "{\"share\":\"$share\"}" || return 1
    [ "$n" -ge "$THRESHOLD" ] && break
  done < "$WORK/shares"
  [ "$(curl -sf "$BASE/v1/sys/seal-status" | jq_get state)" = unsealed ]
}

measure_unseal() {
  local samples=() i dir t0 t1
  for i in $(seq 1 "$RUNS"); do
    dir="$WORK/unseal-$i"
    mkdir -p "$dir"
    start_server "$dir"
    if ! wait_health; then stop_server; continue; fi
    if ! initialise "$dir"; then
      note "unseal run $i: init failed, $(tail -1 "$WORK/server.log")"
      stop_server
      continue
    fi
    t0="$(now_ms)"
    if ! unseal_quorum; then
      note "unseal run $i: the store did not reach unsealed"
      stop_server
      continue
    fi
    t1="$(now_ms)"
    stop_server
    samples+=("$((t1 - t0))")
    note "unseal run $i: $((t1 - t0)) ms for a quorum of $THRESHOLD"
  done
  [ ${#samples[@]} -eq 0 ] && return
  emit unseal_ms "$(stat_percentile 50 "${samples[@]}")"
  emit unseal_shares "$SHARES"
  emit unseal_threshold "$THRESHOLD"
}

bring_up_ready_store() {
  DATA="$WORK/live"
  mkdir -p "$DATA"

  cat > "$WORK/rules.json" <<'EOF'
[{"Path":"*","Capabilities":["read","write","list","delete"]}]
EOF

  MARSEC_DATA_DIR="$DATA" "$BINARY" operator identity add "service/bench" \
    --tenant "$TENANT" >/dev/null 2>"$WORK/err" || {
    note "setup: identity add failed, $(tr -d '\n' < "$WORK/err")"; return 1; }
  MARSEC_DATA_DIR="$DATA" "$BINARY" operator policy put bench \
    --tenant "$TENANT" --rules "$WORK/rules.json" >/dev/null 2>"$WORK/err" || {
    note "setup: policy put failed, $(tr -d '\n' < "$WORK/err")"; return 1; }
  MARSEC_DATA_DIR="$DATA" "$BINARY" operator policy bind "service/bench" \
    --tenant "$TENANT" --policy bench >/dev/null 2>"$WORK/err" || {
    note "setup: policy bind failed, $(tr -d '\n' < "$WORK/err")"; return 1; }
  BOOTSTRAP="$(MARSEC_DATA_DIR="$DATA" "$BINARY" operator bootstrap "service/bench" \
    --ttl 30m 2>"$WORK/err" | head -1)"
  [ -n "$BOOTSTRAP" ] || {
    note "setup: bootstrap failed, $(tr -d '\n' < "$WORK/err")"; return 1; }

  start_server "$DATA"
  wait_health || { note "setup: the server never answered"; return 1; }
  initialise "$DATA" || { note "setup: init failed"; return 1; }
  unseal_quorum || { note "setup: unseal failed"; return 1; }

  TOKEN="$(curl -sf --max-time 10 -X POST "$BASE/v1/auth/bootstrap/login" \
    -d "{\"token\":\"$BOOTSTRAP\"}" | jq_get token)"
  [ -n "$TOKEN" ] || { note "setup: trading the bootstrap token failed"; return 1; }
}

auth_curl() { curl -sf --max-time 15 -H "Authorization: Bearer $TOKEN" "$@"; }

timed_batch() {
  local method="$1" body="$2"
  shift 2
  local args=(-sS -o /dev/null -w '%{time_total}\n'
    -H "Authorization: Bearer $TOKEN" -X "$method")
  [ -n "$body" ] && args+=(-d "$body" -H 'Content-Type: application/json')
  curl "${args[@]}" "$@" 2>"$WORK/curl.err" | grep -E '^[0-9.]+$'
}

measure_secret() {
  local urls=() i writes=() reads=()
  for i in $(seq 1 "$SECRETS"); do
    urls+=("$BASE/v1/secret/data/$TENANT/probe-$i")
  done

  collect < <(timed_batch PUT '{"value":"benchmark"}' "${urls[@]}")
  writes=("${COLLECTED[@]}")
  if [ ${#writes[@]} -eq 0 ]; then
    note "secret: no write succeeded, $(tail -2 "$WORK/curl.err" | tr -d '\n')"
    return
  fi

  collect < <(timed_batch GET '' "${urls[@]}")
  reads=("${COLLECTED[@]}")
  [ ${#reads[@]} -eq 0 ] && return

  local w r
  collect < <(to_ms "${writes[@]}")
  w=("${COLLECTED[@]}")
  collect < <(to_ms "${reads[@]}")
  r=("${COLLECTED[@]}")

  emit secret_write_p50_ms "$(stat_percentile 50 "${w[@]}")"
  emit secret_write_p99_ms "$(stat_percentile 99 "${w[@]}")"
  emit secret_read_p50_ms "$(stat_percentile 50 "${r[@]}")"
  emit secret_read_p99_ms "$(stat_percentile 99 "${r[@]}")"
  emit secret_count "${#r[@]}"
  note "secret: read p50 $(stat_percentile 50 "${r[@]}") ms over ${#r[@]} reads, ${#w[@]} writes"
}

measure_param() {
  local urls=() i reads=() r
  auth_curl -o /dev/null -X PUT "$BASE/v1/param/data/$TENANT/log_level" \
    -H 'Content-Type: application/json' \
    -d '{"kind":"string","value":"info"}' 2>"$WORK/curl.err" || {
    note "param: the write failed, $(tail -2 "$WORK/curl.err" | tr -d '\n')"; return; }
  for i in $(seq 1 "$SECRETS"); do
    urls+=("$BASE/v1/param/data/$TENANT/log_level")
  done
  collect < <(timed_batch GET '' "${urls[@]}")
  reads=("${COLLECTED[@]}")
  [ ${#reads[@]} -eq 0 ] && return
  collect < <(to_ms "${reads[@]}")
  r=("${COLLECTED[@]}")
  emit param_read_p50_ms "$(stat_percentile 50 "${r[@]}")"
  note "param: read p50 $(stat_percentile 50 "${r[@]}") ms"
}

measure_limits() {
  local rate
  rate="$(grep -oE 'RequestRatePerMinute: *[0-9.]+' \
    "$ROOT/internal/platform/config/config.go" | grep -oE '[0-9.]+' | head -1)"
  [ -z "$rate" ] && return
  emit request_rate_per_minute "$rate"
  note "limits: $rate requests per minute per caller by default"
}

measure_audit() {
  local t0 t1 output records
  stop_server
  t0="$(mono_ms)"
  output="$(MARSEC_DATA_DIR="$DATA" "$BINARY" operator audit verify 2>&1)"
  t1="$(mono_ms)"
  records="$(printf '%s' "$output" | grep -oE '[0-9]+ record' | grep -oE '[0-9]+')"
  emit audit_verify_ms "$(python3 -c "print(round($t1-$t0,1))")"
  [ -n "$records" ] && emit audit_records "$records"
  note "audit: verified in $(python3 -c "print(round($t1-$t0,1))") ms, $output"
}

: > "$WORK/pairs"
has binary && measure_binary
has deps && measure_deps
has limits && measure_limits
has coldstart && measure_coldstart
has unseal && measure_unseal

if has secret || has param || has audit; then
  if bring_up_ready_store; then
    has secret && measure_secret
    has param && measure_param
    has audit && measure_audit
  else
    note "the probe store could not be brought up, skipping the sections that need it"
  fi
fi

HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"
HOST_KERNEL="$(uname -r)"
HOST_CPU="$(sysctl -n machdep.cpu.brand_string 2>/dev/null)"
[ -n "$HOST_CPU" ] || HOST_CPU="$(awk -F': ' '/model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null)"
[ -n "$HOST_CPU" ] || {
  VIRT="$(systemd-detect-virt 2>/dev/null)"
  [ -n "$VIRT" ] && [ "$VIRT" != none ] && HOST_CPU="$HOST_ARCH guest under $VIRT"
}
[ -n "$HOST_CPU" ] || HOST_CPU="unknown"
HOST_CORES="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo '?')"
HOST_CPU="$HOST_CPU, $HOST_CORES cores"
VERSION="$("$BINARY" version 2>/dev/null | head -1 || echo unknown)"

JSON="$(python3 - "$WORK/pairs" <<PY
import json, sys, datetime
values = {}
with open(sys.argv[1]) as fh:
    for line in fh:
        if not line.strip():
            continue
        k, v = line.rstrip("\n").split("\t", 1)
        try:
            values[k] = int(v) if v.isdigit() else float(v)
        except ValueError:
            values[k] = v
doc = {
    "measured_at": datetime.datetime.now().astimezone().strftime("%Y-%m-%d"),
    "method": {
        "host": "$HOST_CPU".strip(),
        "os": "$HOST_OS $HOST_KERNEL ($HOST_ARCH)",
        "version": "$VERSION".strip(),
        "runs": $RUNS,
        "statistic": "median, on loopback against a store with nothing else running",
    },
    "values": values,
}
print(json.dumps(doc, indent=2))
PY
)"

if [ -n "$OUT" ]; then
  printf '%s\n' "$JSON" > "$OUT"
  note "wrote $OUT"
else
  printf '%s\n' "$JSON"
fi
