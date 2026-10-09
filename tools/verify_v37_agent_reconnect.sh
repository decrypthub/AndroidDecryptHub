#!/usr/bin/env bash
# v3.7 acceptance: an injected agent survives a Host ADH Daemon restart.
#
# Historically the agent dialled exactly once, so restarting the daemon (which happens on every
# upgrade) orphaned every target until its app was restarted — no captures, no events, and
# phone_wait signal filters went blind. This proves the reconnect loop end to end:
#   same app process afterwards (pid unchanged) + fresh session id + the channel answers a command.
#
# SKIPs cleanly when there is no device, no daemon process to restart, or no online sandbox
# session. Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

STATE="$(adb -s "$SERIAL" get-state 2>/dev/null | tr -d '\r')"
if [ "$STATE" != "device" ]; then
  echo "RESULT:SKIP"
  echo "⏭ v3.7 agent reconnect SKIP (no device)"
  exit 0
fi

# The target host app must be running for this to mean anything (same setup as other scripts).
adb -s "$SERIAL" shell am start -n com.adh.sandbox/.MainActivity >/dev/null 2>&1
sleep 3

BEFORE="$(node - "$BASE" <<'EOF'
const base = process.argv[2];
const agents = await (await fetch(`${base}/api/agents`)).json();
const a = agents.filter((x) => x.package === 'com.adh.sandbox' && x.online).sort((x, y) => y.connectedAt - x.connectedAt)[0];
console.log(a ? `${a.sessionId} ${a.pid}` : '');
EOF
)"
if [ -z "$BEFORE" ]; then
  echo "RESULT:SKIP"
  echo "⏭ v3.7 agent reconnect SKIP (no online com.adh.sandbox session)"
  exit 0
fi
BEFORE_SID="${BEFORE%% *}"
BEFORE_PID="${BEFORE##* }"
echo "before: session=$BEFORE_SID pid=$BEFORE_PID"

DAEMON_PID="$(daemon_pid_on_port "$HTTP")"   # ss/lsof on Linux, netstat on Windows
if [ -z "$DAEMON_PID" ]; then
  echo "RESULT:SKIP"
  echo "⏭ v3.7 agent reconnect SKIP (could not find the daemon process listening on $HTTP — start it with tools/dev_up.sh)"
  exit 0
fi
echo ">> restarting adhd (pid $DAEMON_PID)"
verify_stop_pid "$DAEMON_PID"
STOPPED=""
for _ in $(seq 1 12); do
  if [ -z "$(daemon_pid_on_port "$HTTP")" ]; then STOPPED=1; break; fi
  sleep 0.5
done
if [ -z "$STOPPED" ]; then
  echo "RESULT:FAIL"
  echo "❌ v3.7 agent reconnect FAIL (daemon pid $DAEMON_PID did not stop)"
  exit 1
fi
if ! verify_start_daemon "$HTTP"; then
  echo "RESULT:FAIL"
  echo "❌ v3.7 agent reconnect FAIL (daemon did not come back within the cold-start budget)"
  exit 1
fi

OUT="$(node - "$BASE" "$BEFORE_PID" "$BEFORE_SID" <<'EOF'
const [base, beforePid, beforeSid] = process.argv.slice(2);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const expected = Number(beforePid);
let session = null;
const deadline = Date.now() + 25_000;
while (Date.now() < deadline) {
  try {
    const agents = await (await fetch(`${base}/api/agents`)).json();
    const a = agents
      .filter((x) => x.package === 'com.adh.sandbox' && x.online)
      .sort((x, y) => y.connectedAt - x.connectedAt)[0];
    if (a && a.pid === expected) { session = a; break; }
  } catch { /* daemon may still be starting */ }
  await sleep(500);
}
if (!session) {
  console.log(`no reconnect within 25s for pid ${expected}`);
  console.log('RESULT:FAIL');
  process.exit(0);
}
console.log(`after: session=${session.sessionId} pid=${session.pid} entry=${session.entry} ver=${session.agentVer}`);
const sameProcess = session.pid === expected;
const freshSession = session.sessionId !== beforeSid;
let answers = false;
let modules = 'n/a';
try {
  const mods = await (await fetch(`${base}/api/modules?session=${session.sessionId}`)).json();
  answers = Array.isArray(mods);
  modules = answers ? mods.length : 'n/a';
} catch { answers = false; }
console.log(`same-process=${sameProcess} fresh-session=${freshSession} answers-command=${answers} modules=${modules}`);
console.log(sameProcess && freshSession && answers ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if grep -q 'RESULT:PASS' <<<"$OUT"; then
  echo "✅ v3.7 agent reconnect PASS"
  exit 0
else
  echo "❌ v3.7 agent reconnect FAIL"
  exit 1
fi
