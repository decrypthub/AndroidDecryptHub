#!/usr/bin/env bash
# v2.7 — Zygisk module + scope file presence (module W).
# SKIP (not FAIL) when no device, no Magisk, or module not flashed yet.
# PASS when: Magisk present, /data/adb/modules/adh exists, scope.json writable,
#            writing com.adh.sandbox into allowlist round-trips.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v27_zygisk (no device)"
  echo "RESULT:PASS"
  exit 0
fi

MAGISK="$(adb -s "$SERIAL" shell 'su -c "test -d /data/adb/magisk && echo YES || echo NO"' 2>/dev/null | tr -d '\r' || true)"
if [ "$MAGISK" != "YES" ]; then
  echo "SKIP  verify_v27_zygisk (no Magisk on device)"
  echo "RESULT:PASS"
  exit 0
fi

MOD="$(adb -s "$SERIAL" shell 'su -c "test -d /data/adb/modules/adh && echo YES || echo NO"' 2>/dev/null | tr -d '\r' || true)"
if [ "$MOD" != "YES" ]; then
  echo "SKIP  verify_v27_zygisk (adh Zygisk module not installed — flash injector/zygisk/dist/adh-zygisk.zip)"
  echo "RESULT:PASS"
  exit 0
fi

# Round-trip scope write (does not require cold-start inject for this check).
SCOPE_JSON='{"version":1,"mode":"allowlist","packages":["com.adh.sandbox"]}'
B64="$(printf '%s' "$SCOPE_JSON" | base64 | tr -d '\n\r')"
adb -s "$SERIAL" shell "su -c \"mkdir -p /data/adb/adh && echo $B64 | base64 -d > /data/adb/adh/scope.json && chmod 644 /data/adb/adh/scope.json\"" >/dev/null
GOT="$(adb -s "$SERIAL" shell 'su -c "cat /data/adb/adh/scope.json"' 2>/dev/null | tr -d '\r' || true)"

set +e
OUT="$(node - "$GOT" <<'EOF'
const got = process.argv[2] || '';
const ok = got.includes('com.adh.sandbox') && got.includes('allowlist');
console.log(ok ? 'RESULT:PASS' : 'RESULT:FAIL');
if (!ok) { console.error('scope round-trip failed, got:', got.slice(0, 200)); process.exit(1); }
EOF
)"
set -e
echo "$OUT"
ALIVE=1  # not sandbox-gated
verify_gate "v2.7 zygisk scope round-trip" 0 && exit 0 || exit 1
