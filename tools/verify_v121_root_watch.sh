#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env
verify_unit_pass "root watch bounds and kernel stack projection" root_watch.test.ts 2 || exit 1
if [ -z "$SERIAL" ]; then
  echo 'SKIP verify_v121_root_watch (no online ADB device)'; exit 0
fi
if [ "$(adb -s "$SERIAL" shell su -c 'id -u' 2>/dev/null | tr -d '\r\n')" != '0' ]; then
  echo 'SKIP verify_v121_root_watch (root required; device apps were not touched)'; exit 0
fi
if [ ! -f "$ROOT/agent/build/adh-root-watch" ]; then
  echo 'SKIP verify_v121_root_watch (build optional root helper with tools/build_root_watch.sh)'; exit 0
fi
verify_restart_sandbox
if ! SID="$(cd "$ROOT/daemon" && node src/cli.ts target --package com.adh.sandbox --quiet)"; then
  echo 'SKIP verify_v121_root_watch (no online sandbox agent)'; exit 0
fi
cd "$ROOT"
set +e
OUT="$(node --input-type=module - "$BASE" "$SERIAL" <<'EOF'
import { runRootWatchAcceptance } from './daemon/test/root_watch.device.ts';
try { await runRootWatchAcceptance(process.argv[2], process.argv[3]); process.exit(0); }
catch (e) { console.error(e); console.log('RESULT:FAIL'); process.exit(1); }
EOF
)"
RC=$?
set -e
echo "$OUT"
if [ "$RC" != 0 ]; then exit "$RC"; fi
verify_gate 'root-side hardware observation' 0
