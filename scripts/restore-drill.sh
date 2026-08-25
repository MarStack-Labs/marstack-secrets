#!/bin/sh
set -eu

binary=${1:-bin/marsec}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

origin="$work/origin"
snapshot="$work/marsec.snap"
restored="$work/restored"

mkdir -p "$origin" "$restored"

cat > "$work/policy.json" <<'RULES'
[{"Path":"secret/prod/*","Capabilities":["read","write"]}]
RULES

"$binary" operator identity add service/drill --tenant prod --kind bootstrap --data-dir "$origin" >/dev/null
"$binary" operator policy put drill --tenant prod --rules "$work/policy.json" --data-dir "$origin" >/dev/null
"$binary" operator policy bind service/drill --tenant prod --policy drill --data-dir "$origin" >/dev/null

"$binary" operator snapshot save "$snapshot" --data-dir "$origin" >/dev/null
"$binary" operator snapshot verify "$snapshot" >/dev/null
"$binary" operator snapshot restore "$snapshot" --data-dir "$restored" >/dev/null

before=$("$binary" operator policy list --tenant prod --data-dir "$origin")
after=$("$binary" operator policy list --tenant prod --data-dir "$restored")

if [ "$before" != "$after" ]; then
	echo "restore drill failed: the restored store does not match" >&2
	echo "before: $before" >&2
	echo "after:  $after" >&2
	exit 1
fi

if [ -z "$after" ]; then
	echo "restore drill failed: the restored store is empty" >&2
	exit 1
fi

if "$binary" operator snapshot restore "$snapshot" --data-dir "$restored" >/dev/null 2>&1; then
	echo "restore drill failed: restoring over an existing database was allowed" >&2
	exit 1
fi

echo "restore drill passed: $(echo "$after" | tr '\n' ' ')restored and verified"
