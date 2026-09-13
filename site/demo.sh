#!/usr/bin/env bash
set -uo pipefail

PROMPT="${PROMPT:-\$ }"
SPEED="${SPEED:-0.035}"
PAUSE="${PAUSE:-1.2}"
PORT="${PORT:-18300}"
BASE="http://127.0.0.1:$PORT"
BINARY="${BINARY:-./bin/marsec}"
DATA="$(mktemp -d)"
SERVER_PID=""

export MARSEC_ALLOW_INSECURE_HTTP=true
export MARSEC_ALLOW_UNPROTECTED_MEMORY=true
export MARSEC_LOG_LEVEL=error
export MARSEC_DATA_DIR="$DATA"
export MARSEC_LISTEN_ADDR="127.0.0.1:$PORT"

cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  rm -rf "$DATA"
}
trap cleanup EXIT

type_out() {
  local text="$1" i
  printf '%s' "$PROMPT"
  for ((i = 0; i < ${#text}; i++)); do
    printf '%s' "${text:i:1}"
    sleep "$SPEED"
  done
  printf '\n'
}

say() {
  type_out "$*"
  sleep 0.4
  eval "$*"
  printf '\n'
  sleep "$PAUSE"
}

show_run() {
  local shown="$1"
  shift
  type_out "$shown"
  sleep 0.4
  "$@"
  printf '\n'
  sleep "$PAUSE"
}

if [ ! -x "$BINARY" ]; then
  echo "$BINARY is not there, run make build first" >&2
  exit 1
fi

"$BINARY" operator identity add service/payments --tenant prod >/dev/null 2>&1
printf '%s' '[{"Path":"*","Capabilities":["read","write","list"]}]' > "$DATA/rules.json"
"$BINARY" operator policy put app --tenant prod --rules "$DATA/rules.json" >/dev/null 2>&1
"$BINARY" operator policy bind service/payments --tenant prod --policy app >/dev/null 2>&1
BOOTSTRAP="$("$BINARY" operator bootstrap service/payments --ttl 10m 2>/dev/null | head -1)"

"$BINARY" server > "$DATA/server.log" 2>&1 &
SERVER_PID=$!
until curl -sf -o /dev/null "$BASE/v1/sys/health" 2>/dev/null; do sleep 0.1; done

clear

say "curl -s $BASE/v1/sys/seal-status"

type_out "curl -s -X POST $BASE/v1/sys/init -d '{\"shares\":5,\"threshold\":3}'"
sleep 0.4
curl -s -X POST "$BASE/v1/sys/init" -d '{"shares":5,"threshold":3}' > "$DATA/init.json"
python3 -c "
import json
shares = json.load(open('$DATA/init.json'))['shares']
print(json.dumps({'shares': [s[:18] + '...' for s in shares], 'threshold': 3}, indent=0))
"
printf '\n'
sleep "$PAUSE"

python3 -c "
import json
print('\n'.join(json.load(open('$DATA/init.json'))['shares'][:3]))" > "$DATA/quorum"

say "curl -s $BASE/v1/sys/seal-status"

type_out "kill \$SERVER_PID && marsec server &"
sleep 0.4
kill "$SERVER_PID" 2>/dev/null
wait "$SERVER_PID" 2>/dev/null
"$BINARY" server > "$DATA/server.log" 2>&1 &
SERVER_PID=$!
until curl -sf -o /dev/null "$BASE/v1/sys/health" 2>/dev/null; do sleep 0.1; done
printf '\n'
sleep "$PAUSE"

say "curl -s $BASE/v1/sys/seal-status"

while read -r share; do
  type_out "curl -s -X POST $BASE/v1/sys/unseal -d '{\"share\":\"${share:0:18}...\"}'"
  sleep 0.2
  curl -s -X POST "$BASE/v1/sys/unseal" -d "{\"share\":\"$share\"}"
  printf '\n'
  sleep 0.6
done < "$DATA/quorum"

printf '\n'
sleep 0.6

TOKEN="$(curl -s -X POST "$BASE/v1/auth/bootstrap/login" \
  -d "{\"token\":\"$BOOTSTRAP\"}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')"

show_run "curl -s -X PUT $BASE/v1/secret/data/prod/payment-api \\
  -H 'Authorization: Bearer \$TOKEN' -d '{\"value\":\"hunter2-the-real-one\"}'" \
  curl -s -X PUT "$BASE/v1/secret/data/prod/payment-api" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"value":"hunter2-the-real-one"}'

show_run "curl -s $BASE/v1/secret/data/prod/payment-api -H 'Authorization: Bearer \$TOKEN'" \
  curl -s "$BASE/v1/secret/data/prod/payment-api" \
    -H "Authorization: Bearer $TOKEN"

STORED="$(curl -s "$BASE/v1/secret/data/prod/payment-api" \
  -H "Authorization: Bearer $TOKEN" | grep -c 'hunter2-the-real-one')"
if [ "$STORED" != 1 ]; then
  echo "the secret never made it into the store, so the next step would prove nothing" >&2
  exit 1
fi

say "ls $DATA"

say "grep -ra 'hunter2-the-real-one' $DATA/ || echo 'the value is in none of those files'"

say "$BINARY operator audit verify"

sleep 2
