#!/usr/bin/env bash
# v129 — QBDI payload delivery on a REAL target (product path, not the sandbox APK).
#
# Why this exists: the sandbox APK used to carry libQBDI.so inside jniLibs, so a sandbox-only test
# passed no matter what the injection path did. Real apps never ship our tracer. This script asserts
# the product behaviour end to end:
#   A. flag off  -> the trace is refused with an actionable "delivery is off" error, and the target
#                   has no QBDI fd (default injection surface is unchanged);
#   B. flag on   -> the companion hands an fd to the allowlisted process, the agent loads lazily,
#                   the trace runs, and the library is released again after a standalone trace.
#
# Needs: adhd running, root device, one allowlisted third-party app installed.
# Target package: ADH_QBDI_TEST_PKG (default com.uxin.kilaaudio). Missing target => SKIP, not FAIL.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

PKG="${ADH_QBDI_TEST_PKG:-com.uxin.kilaaudio}"
FLAG="/data/adb/adh/qbdi.enabled"

fail() { echo "❌ v129 QBDI delivery FAIL: $*"; echo "RESULT:FAIL"; exit 1; }
skip() { echo "⏭  SKIP: $*"; echo "RESULT:SKIP"; exit 0; }

adb -s "$SERIAL" get-state >/dev/null 2>&1 || skip "no device ($SERIAL)"

dev_root() { adb -s "$SERIAL" shell "su -c '$1'" | tr -d '\r'; }
flag_state() { dev_root "test -f $FLAG && echo on || echo off" | tail -n 1; }

adb -s "$SERIAL" shell "pm path $PKG" | tr -d '\r' | grep -q '^package:' || skip "$PKG not installed (set ADH_QBDI_TEST_PKG)"
[ "$(dev_root 'id -u' | tail -n 1)" = "0" ] || skip "no root (su)"
curl -s -m 3 "http://127.0.0.1:$HTTP/health" | grep -q '"ok": *true' || skip "adhd not running on :$HTTP"

ORIGINAL_FLAG="$(flag_state)"

cold_start() {
  adb -s "$SERIAL" shell am force-stop "$PKG" >/dev/null 2>&1
  sleep 1
  adb -s "$SERIAL" shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
}

# Newest online agent for the package's MAIN process (companions have a ':' in the name).
wait_agent() {
  node - "$HTTP" "$PKG" <<'EOF'
const [http, pkg] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const deadline = Date.now() + 30000;
for (;;) {
  try {
    const agents = await (await fetch(`${base}/api/agents`)).json();
    const a = agents.filter(x => x.package === pkg && x.process === pkg && x.online)
                    .sort((x, y) => y.connectedAt - x.connectedAt)[0];
    if (a) { console.log(`${a.sessionId} ${a.pid}`); process.exit(0); }
  } catch {}
  if (Date.now() > deadline) { console.log('NO_AGENT'); process.exit(0); }
  await new Promise(r => setTimeout(r, 500));
}
EOF
}

trace() {
  node - "$HTTP" "$1" <<'EOF'
const [http, session] = process.argv.slice(2);
const url = `http://127.0.0.1:${http}/api/trace/qbdi?session=${session}&symLib=libc.so&symbol=getpid`;
try {
  const r = await fetch(url);
  const j = await r.json();
  console.log(JSON.stringify(j));
} catch (e) { console.log(JSON.stringify({ ok: false, error: String(e) })); }
EOF
}

restore() {
  if [ "$ORIGINAL_FLAG" = "on" ]; then dev_root "touch $FLAG"; else dev_root "rm -f $FLAG"; fi
  adb -s "$SERIAL" shell am force-stop "$PKG" >/dev/null 2>&1
}
trap restore EXIT

# --- A. default (off): refused with an actionable error, no fd delivered -------------------------
dev_root "rm -f $FLAG"
cold_start
read -r SESSION PID <<<"$(wait_agent)"
[ "$SESSION" != "NO_AGENT" ] || fail "no agent connected for $PKG (off phase)"
echo "A. flag off: session=$SESSION pid=$PID"
A_OUT="$(trace "$SESSION")"
echo "A. trace reply: $(echo "$A_OUT" | cut -c1-260)"
echo "$A_OUT" | grep -q 'delivery is off' || fail "flag off must refuse with 'delivery is off', got: $A_OUT"
FDS="$(dev_root "ls -l /proc/$PID/fd" 2>/dev/null)"
echo "$FDS" | grep -q 'libQBDI.so' && fail "flag off still delivered a QBDI fd"
echo "A. PASS (refused, no fd)"

# --- B. opt-in (on): fd delivered, trace works, library released after ---------------------------
dev_root "mkdir -p /data/adb/adh && touch $FLAG"
cold_start
read -r SESSION PID <<<"$(wait_agent)"
[ "$SESSION" != "NO_AGENT" ] || fail "no agent connected for $PKG (on phase)"
echo "B. flag on: session=$SESSION pid=$PID"
FDS="$(dev_root "ls -l /proc/$PID/fd" 2>/dev/null)"
echo "$FDS" | grep -q 'libQBDI.so' || fail "flag on but no QBDI fd was delivered to pid $PID"
echo "B. delivered: $(echo "$FDS" | grep 'libQBDI.so' | head -n1 | sed 's/^ *//')"
B_OUT="$(trace "$SESSION")"
echo "B. trace reply: $(echo "$B_OUT" | cut -c1-260)"
echo "$B_OUT" | grep -q '"ok":true' || fail "trace failed with the payload enabled: $B_OUT"
RET="$(echo "$B_OUT" | sed -n 's/.*"retval":\([0-9]*\).*/\1/p')"
[ "$RET" = "$PID" ] || fail "libc getpid should return the target pid ($PID), got '$RET'"
MAPS="$(dev_root "cat /proc/$PID/maps" 2>/dev/null)"
echo "$MAPS" | grep -q 'libQBDI' && fail "standalone trace must dlclose the tracer, but it is still mapped"
echo "B. PASS (trace retval=$RET, library released)"

echo "✅ v129 QBDI delivery PASS (default refused; opt-in delivered, traced, released)"
echo "RESULT:PASS"
exit 0
