#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
SERIAL="${ANDROID_SERIAL:-${ADH_SERIAL:-}}"
[ "$SERIAL" != a22fecdd ] || { echo 'daily device refused before fixture setup' >&2; exit 2; }
if [ -z "$SERIAL" ] || [ ! -f "$ROOT/agent/build/adh-qbdi-stack" ] || [ ! -f "$ROOT/agent/third_party/qbdi/lib/libQBDI.so" ]; then
  echo 'RESULT:SKIP explicit test serial and built QBDI stack fixture required'
  exit 0
fi
REPORT_PARENT="$(mktemp -d "${TMPDIR:-/tmp}/adh-qbdi-stack.XXXXXX")"
echo "evidence=$REPORT_PARENT/result"
if node "$ROOT/tools/verify_qbdi_stack.ts" "$SERIAL" "$ROOT/agent/build/adh-qbdi-stack" "$ROOT/agent/third_party/qbdi/lib/libQBDI.so" "$REPORT_PARENT/result"; then
  echo 'RESULT:PASS'
else
  echo 'RESULT:FAIL'
  exit 1
fi
