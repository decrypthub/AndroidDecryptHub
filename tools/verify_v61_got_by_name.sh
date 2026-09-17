#!/usr/bin/env bash
# v4.21 by-name GOT hook acceptance (native_hook mode=got).
# Regression guard: the by-name GOT replacement used to match nothing because the relocation
# scan fed a full /proc/self/maps path into a basename comparison, so install reported
# "hooked:0"/"symbol not found" while other (inline) paths stayed green. This script requires a
# real by-name replacement to install, fire a NATIVE_HOOK event and unhook cleanly.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${ADH_HTTP_PORT:-8088}"
set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const MODULE = 'libadhdetect.so';
const SYMBOL = 'adh_trace_target';       // called by nativeHookProbe(), reached through the PLT
const EXPECT_CALL = 30;                  // adh_trace_target(): sum i*3 for i in 0..4
const agents = await (await fetch(`${base}/api/agents`)).json();
const agent = agents.filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0];
if (!agent) { console.log('NO_AGENT'); console.log('RESULT:SKIP'); process.exit(0); }
async function post(path, body) {
  const r = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
}
async function callProbe(session) {
  const r = await post('/api/java/call', { session, className: 'com.adh.sandbox.Detection', method: 'nativeHookProbe', params: '', args: [] });
  return { ok: r.body.ok === true, value: r.body?.result?.result, error: r.body.error };
}
const session = agent.sessionId;
const status0 = await post('/api/native/hook', { session, action: 'status' });
if (status0.status === 404 || /unsupported|unknown op/i.test(String(status0.body.error ?? ''))) {
  console.log('old payload / no native_hook');
  console.log('RESULT:SKIP');
  process.exit(0);
}
const hook = await post('/api/native/hook', { session, action: 'hook', hookId: 0, mode: 'got', module: MODULE, symbol: SYMBOL });
if (hook.body.ok !== true) {
  console.log('by-name GOT install failed (this is the regression this script guards):');
  console.log(JSON.stringify(hook.body));
  console.log('RESULT:FAIL');
  process.exit(0);
}
const hookId = Number(hook.body.hookId);
const installed = (hook.body.status?.hooks ?? []).find((h) => h.id === hookId);
const installOk = hook.body.status?.count === 1 && installed?.mode === 'got' &&
  installed?.symbol === SYMBOL && Number(installed?.target) !== 0 && Number(installed?.original) !== 0;
const call1 = await callProbe(session);
let event = null;
for (let i = 0; i < 20 && !event; i++) {
  const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=400`)).json();
  for (const c of (list.captures ?? []).filter((x) => x.func === 'NATIVE_HOOK')) {
    const detail = await (await fetch(`${base}/api/captures/${c.id}`)).json();
    if (String(detail.text ?? '').includes(`"hookId":${hookId}`)) { event = { id: c.id, preview: detail.preview }; break; }
  }
  if (event) break;
  await sleep(120);
}
const status1 = await post('/api/native/hook', { session, action: 'status' });
const hits1 = Number((status1.body.status?.hooks ?? []).find((h) => h.id === hookId)?.hits ?? -1);
// Soft unhook keeps the slot patched but inactive: the trigger must still work and must NOT
// produce a new event. Compare the newest matching capture id instead of a count, because the
// capture list is a bounded window that scrolls.
async function newestMatching() {
  const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=400`)).json();
  const ids = (list.captures ?? []).filter((c) => c.func === 'NATIVE_HOOK' && String(c.preview ?? '').includes(`"hookId":${hookId}`)).map((c) => Number(c.id));
  return ids.length ? Math.max(...ids) : 0;
}
const unhook = await post('/api/native/hook', { session, action: 'unhook', hookId });
const status2 = await post('/api/native/hook', { session, action: 'status' });
const idBefore = await newestMatching();
const call2 = await callProbe(session);
await sleep(400);
const idAfter = await newestMatching();
const events2 = idAfter - idBefore;
const alive = (await (await fetch(`${base}/api/agents`)).json()).some((x) => x.online && x.package === 'com.adh.sandbox');
const callOk = Number(call1.value) === EXPECT_CALL && Number(call2.value) === EXPECT_CALL;
const pass = installOk && call1.ok === true && event != null && hits1 >= 1 &&
  unhook.body.ok === true && Number(status2.body.status?.count) === 0 && callOk && events2 === 0 && alive;
console.log(JSON.stringify({
  hookId, installOk, installed: installed ? { mode: installed.mode, target: installed.target, original: installed.original } : null,
  call1: call1.value, event, hits1, unhook: unhook.body.ok, activeAfterUnhook: status2.body.status?.count,
  call2: call2.value, matchingEventsAfterUnhook: events2, newestMatchingId: [idBefore, idAfter], alive,
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.21 by-name GOT hook (native_hook mode=got) PASS"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.21 by-name GOT hook SKIP (new agent not deployed)"
  exit 0
else
  echo "❌ v4.21 by-name GOT hook (native_hook mode=got) FAIL"
  exit 1
fi