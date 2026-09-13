#!/usr/bin/env bash
set -uo pipefail

PORT="${PORT:-18400}"
BASE="http://127.0.0.1:$PORT"
BINARY="${BINARY:-./bin/marsec}"
ROOT="${ROOT:-/tmp/marsec-ui}"
DATA="$ROOT/store"
VIDEO_DIR="$ROOT/video"
OUT_GIF="${OUT_GIF:-site/ui-demo.gif}"
TENANT="${TENANT:-prod}"
SERVER_PID=""

cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
}
trap cleanup EXIT

command -v node >/dev/null || { echo "node is required" >&2; exit 1; }
command -v ffmpeg >/dev/null || { echo "ffmpeg is required to make the gif" >&2; exit 1; }
node -e "import(process.env.PLAYWRIGHT_MODULE || 'playwright')" 2>/dev/null || {
  echo "playwright is not resolvable; npm install playwright, or point" >&2
  echo "PLAYWRIGHT_MODULE at an installed copy" >&2
  exit 1
}
[ -x "$BINARY" ] || { echo "$BINARY is not there, run make build first" >&2; exit 1; }

rm -rf "$ROOT"
mkdir -p "$DATA" "$VIDEO_DIR"

export MARSEC_ALLOW_INSECURE_HTTP=true
export MARSEC_ALLOW_UNPROTECTED_MEMORY=true
export MARSEC_LOG_LEVEL=error
export MARSEC_UI_ENABLED=true
export MARSEC_DATA_DIR="$DATA"
export MARSEC_LISTEN_ADDR="127.0.0.1:$PORT"

printf '%s' '[{"Path":"*","Capabilities":["read","write","list","delete"]}]' > "$ROOT/rules.json"
"$BINARY" operator identity add service/payments --tenant "$TENANT" >/dev/null
"$BINARY" operator policy put app --tenant "$TENANT" --rules "$ROOT/rules.json" >/dev/null
"$BINARY" operator policy bind service/payments --tenant "$TENANT" --policy app >/dev/null
BOOTSTRAP="$("$BINARY" operator bootstrap service/payments --ttl 30m 2>/dev/null | head -1)"
[ -n "$BOOTSTRAP" ] || { echo "no bootstrap token was issued" >&2; exit 1; }

"$BINARY" server > "$ROOT/server.log" 2>&1 &
SERVER_PID=$!
until curl -sf -o /dev/null "$BASE/v1/sys/health" 2>/dev/null; do sleep 0.2; done

SIGNALS="$ROOT/signals"
mkdir -p "$SIGNALS"

(
  while [ ! -f "$SIGNALS/restart-please" ]; do
    sleep 0.2
    [ -f "$SIGNALS/give-up" ] && exit 0
  done
  kill "$SERVER_PID" 2>/dev/null
  wait "$SERVER_PID" 2>/dev/null
  "$BINARY" server > "$ROOT/server2.log" 2>&1 &
  echo $! > "$SIGNALS/pid"
  until curl -sf -o /dev/null "$BASE/v1/sys/health" 2>/dev/null; do sleep 0.2; done
  touch "$SIGNALS/restart-done"
) &
RESTARTER=$!

BASE="$BASE" BOOTSTRAP="$BOOTSTRAP" VIDEO_DIR="$VIDEO_DIR" \
  SIGNAL_DIR="$SIGNALS" node site/ui-demo.mjs
STATUS=$?

touch "$SIGNALS/give-up"
wait "$RESTARTER" 2>/dev/null
[ -f "$SIGNALS/pid" ] && SERVER_PID="$(cat "$SIGNALS/pid")"
[ "$STATUS" -eq 0 ] || exit 1

WEBM="$(find "$VIDEO_DIR" -name '*.webm' | head -1)"
[ -n "$WEBM" ] || { echo "playwright wrote no video" >&2; exit 1; }

ffmpeg -hide_banner -loglevel error -y -i "$WEBM" \
  -vf "fps=6,scale=900:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=64[p];[b][p]paletteuse=dither=bayer:bayer_scale=4" \
  "$OUT_GIF"

echo "wrote $OUT_GIF"
