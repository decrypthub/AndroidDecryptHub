#!/usr/bin/env bash
# v4.9 native active-call acceptance.
# Calls libadhdetect.so:adh_add_target by symbol and by absolute address, checks the
# deterministic return value, and verifies the Host confirmation gate rejects an
# unconfirmed arbitrary call. SKIPs on an agent without native_call.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${ADH_HTTP_PORT:-8088}"

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const agents = await (await fetch(`${base}/api/agents`)).json();
const agent = agents.filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0];
if (!agent) { console.log('NO_AGENT'); console.log('RESULT:SKIP'); process.exit(0); }
async function post(path, body) {
  const r = await fetch(`${base}${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  return { status: r.status, body: await r.json() };
}
const session = agent.sessionId;
const bySymbol = await post('/api/native/call', {
  session, module: 'libadhdetect.so', symbol: 'adh_add_target', args: ['20', '22'], confirm: true,
});
const noArg = await post('/api/native/call', {
  session, module: 'libadhdetect.so', symbol: 'adh_trace_target', args: [], confirm: true,
});
if (!bySymbol.body.ok && /unsupported|unknown op/i.test(String(bySymbol.body.error ?? ''))) {
  console.log(`old payload / no native_call: ${bySymbol.body.error}`);
  console.log('RESULT:SKIP');
  process.exit(0);
}
const unconfirmed = await post('/api/native/call', {
  session, module: 'libadhdetect.so', symbol: 'adh_add_target', args: ['1', '2'],
});
const hook = await post('/api/native/hook', {
  session, action: 'hook', mode: 'inline', module: 'libadhdetect.so', symbol: 'adh_add_target',
});
const hookId = Number(hook.body.hookId ?? 0);
const addr = hook.body.status?.hooks?.[0]?.target ?? hook.body.status?.hooks?.[0]?.address;
const unhook = hookId > 0
  ? await post('/api/native/hook', { session, action: 'unhook', hookId })
  : { body: { ok: false } };
const byAddress = addr
  ? await post('/api/native/call', { session, addr, args: ['0x7', '8'], confirm: true })
  : { body: { ok: false, error: 'no resolved address' } };
// v4.95: a call that does not return must not freeze the session. adh_slow_leaf sleeps 30s, the
// agent's 15s watchdog has to answer timedOut:true (before the host's own 20s gives up), and the
// very next command must still work - that second half is the whole point of the watchdog.
const slowStart = Date.now();
const slow = await post('/api/native/call', {
  session, module: 'libadhdetect.so', symbol: 'adh_slow_leaf', args: [], confirm: true,
});
const slowMs = Date.now() - slowStart;
const pingAfter = await (await fetch(`${base}/api/agent/ping?session=${encodeURIComponent(session)}`)).json().catch(() => ({}));
const watchdogPass = slow.body?.timedOut === true && slow.body?.ok === false
  && slowMs >= 14000 && slowMs < 19000 && pingAfter.ok === true;
console.log(`watchdog: timedOut=${slow.body?.timedOut} after ${slowMs}ms pingAfter=${pingAfter.ok} (${String(slow.body?.error ?? '').slice(0, 60)})`);

const pass = watchdogPass && bySymbol.body.ok === true && Number(bySymbol.body.resultDecimal) === 84 &&
  noArg.body.ok === true && Number(noArg.body.resultDecimal) === 30 &&
  byAddress.body.ok === true && Number(byAddress.body.resultDecimal) === 30 &&
  unconfirmed.status === 400 && /confirm:true/i.test(String(unconfirmed.body.error ?? '')) &&
  unhook.body.ok === true;
console.log(JSON.stringify({
  bySymbol: bySymbol.body, noArg: noArg.body, byAddress: byAddress.body,
  unconfirmed: { status: unconfirmed.status, error: unconfirmed.body.error },
  addr, unhook: unhook.body.ok === true,
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.9 native active call PASS (symbol + address + confirmation gate)"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.9 native active call SKIP (agent not deployed)"
  exit 0
else
  echo "❌ v4.9 native active call FAIL"
  exit 1
fi