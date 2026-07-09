#!/usr/bin/env bash
# Master regression runner — runs every version acceptance script and reports a summary.
# Ensures idhd + adb reverse are up first. Device-only scripts are skipped (not failed)
# when no device is attached. Exit 0 only if all RUN scripts passed.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
bash tools/dev_up.sh >/dev/null 2>&1
STATE="$(adb get-state 2>/dev/null | tr -d '\r')"

# name:needs_device
SCRIPTS=(
  "verify_v01.sh:device"
  "verify_v02.sh:device"
  "verify_v02_dump.sh:device"
  "verify_v02_so.sh:device"
  "verify_v02_dexrepair.sh:host"
  "verify_v03.sh:device"
  "verify_v04_dexparse.sh:host"
  "verify_v04_gothook.sh:device"
  "verify_v04_crypto.sh:device"
  "verify_v05_detect.sh:device"
  "verify_v06.sh:device"
  "verify_v07.sh:device"
  "verify_v07_flow.sh:device"
  "verify_v08_dexsearch.sh:host"
  "verify_v08_disasm.sh:host"
  "verify_v08_analyze.sh:host"
  "verify_v08_xref.sh:host"
  "verify_v09_cryptoconst.sh:host"
  "verify_v09_syscall.sh:host"
  "verify_v09_methodcode.sh:host"
  "verify_v10_mcp.sh:host"
  "verify_v10_webui.sh:host"
  "verify_v10_trace.sh:device"
  "verify_v10_export.sh:host"
)

pass=0; fail=0; skip=0; FAILED=""
for entry in "${SCRIPTS[@]}"; do
  name="${entry%%:*}"; needs="${entry##*:}"
  [ -f "tools/$name" ] || continue
  if [ "$needs" = "device" ] && [ "$STATE" != "device" ]; then
    echo "SKIP  $name (no device)"; skip=$((skip+1)); continue
  fi
  # device scripts need the sandbox running + agent connected; (re)launch first
  if [ "$needs" = "device" ]; then
    adb shell am force-stop com.idh.sandbox >/dev/null 2>&1
    adb shell am start -n com.idh.sandbox/.MainActivity >/dev/null 2>&1; sleep 4
  fi
  if bash "tools/$name" >/tmp/vr.log 2>&1; then
    echo "PASS  $name"; pass=$((pass+1))
  else
    echo "FAIL  $name"; fail=$((fail+1)); FAILED="$FAILED $name"
    tail -6 /tmp/vr.log | sed 's/^/        /'
  fi
done
echo "----"
echo "pass=$pass fail=$fail skip=$skip${FAILED:+  failed:$FAILED}"
[ "$fail" -eq 0 ] && exit 0 || exit 1
