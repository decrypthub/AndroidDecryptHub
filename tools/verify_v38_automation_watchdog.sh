#!/usr/bin/env bash
# v3.8 acceptance: a stuck device command must not kill the automation channel.
#
# History: the device watchdog used to release its "busy" gate without ever answering the host, so
# one blocked Accessibility traversal turned into a permanently dead channel (every later command
# timed out too). The bridge now enforces a hard per-command deadline, always answers, and only
# recycles the socket when several commands pile up.
#
# Fault injection: the device exposes `selftest_sleep` (inert; sleeps N ms) purely so this can be
# proven. SKIPs when there is no device or no connected bridge. Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

STATE="$(adb -s "$SERIAL" get-state 2>/dev/null | tr -d '\r')"
if [ "$STATE" != "device" ]; then
  echo "RESULT:SKIP"
  echo "⏭ v3.8 automation watchdog SKIP (no device)"
  exit 0
fi

BRIDGE="$(node - "$BASE" <<'EOF'
const base = process.argv[2];
try {
  const r = await (await fetch(`${base}/api/automation/status`)).json();
  console.log(r.bridge?.connected ? 'connected' : 'offline');
} catch { console.log('offline'); }
EOF
)"
if [ "$BRIDGE" != "connected" ]; then
  echo "RESULT:SKIP"
  echo "⏭ v3.8 automation watchdog SKIP (bridge not connected)"
  exit 0
fi

OUT="$(node - "$BASE" <<'EOF'
const base = process.argv[2];
const checks = [];
function chk(label, ok, detail = '') {
  checks.push([label, !!ok]);
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ' — ' + detail : ''}`);
}
const post = async (path) => (await (await fetch(base + path, { method: 'POST' })).json());
async function tool(name, args) {
  const body = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } };
  const r = await (await fetch(base + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).json();
  if (r.error) throw new Error(r.error.message || JSON.stringify(r.error));
  if (r.result?.isError) throw new Error(r.result.content?.[0]?.text ?? `${name} failed`);
  return (r.result.content ?? []).find((item) => item.type === 'text')?.text ?? '';
}

try {
  const started = Date.now();
  const injected = await post('/api/automation/selftest?op=selftest_sleep&ms=20000');
  const elapsed = Date.now() - started;
  chk('a command that outruns the deadline is answered, not swallowed', injected.ok === false && injected.code === 'command_timeout', `code=${injected.code} elapsed=${elapsed}ms`);
  chk('the answer arrives at the device deadline, before the host gives up', elapsed >= 8000 && elapsed <= 16000, `elapsed=${elapsed}ms`);

  // The channel must still serve: any answer counts (a tree, or a policy refusal naming the
  // foreground package) — what must NOT happen is another timeout.
  let followUp = 'no answer';
  try {
    const text = await tool('phone_observe', { mode: 'text', maxNodes: 10 });
    followUp = text.split('\n')[0] || 'text view';
  } catch (error) {
    followUp = error.message || String(error);
  }
  const stalled = /timed out|no automation device connected/i.test(followUp);
  chk('the next command is served on the surviving channel', !stalled, followUp.slice(0, 90));

  const status = await post('/api/automation/selftest?op=status');
  const stats = status.result?.bridge ?? {};
  chk('the device reports the timeout in its own stats', Number(stats.timeouts ?? 0) >= 1, `timeouts=${stats.timeouts} inFlight=${stats.inFlight}`);
} catch (error) {
  chk('watchdog acceptance path completed', false, error.message || String(error));
}

console.log(checks.every(([, ok]) => ok) ? 'RESULT:PASS' : 'RESULT:FAIL');
process.exit(checks.every(([, ok]) => ok) ? 0 : 1);
EOF
)"
echo "$OUT"
if grep -q 'RESULT:PASS' <<<"$OUT"; then
  echo "✅ v3.8 automation watchdog PASS"
  exit 0
else
  echo "❌ v3.8 automation watchdog FAIL"
  exit 1
fi
