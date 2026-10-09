#!/usr/bin/env bash
# v4.17 JNI_OnLoad discovery/hook/manual-call acceptance.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${ADH_HTTP_PORT:-8088}"
set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const agents = await (await fetch(`${base}/api/agents`)).json();
const agent = agents.filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0];
if (!agent) { console.log('NO_AGENT'); console.log('RESULT:SKIP'); process.exit(0); }
async function post(path, body) {
  const r = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
}
const session = agent.sessionId;
const list = await post('/api/jni/onload', { session, action: 'list' });
if (list.status === 404 || /unsupported|unknown op/i.test(String(list.body.error ?? ''))) { console.log('old payload / no jni_onload'); console.log('RESULT:SKIP'); process.exit(0); }
const moduleEntry = (list.body.modules ?? []).find((m) => m.module === 'libadhdetect.so');
const hook = await post('/api/jni/onload', { session, action: 'hook', module: 'libadhdetect.so' });
const noConfirm = await post('/api/jni/onload', { session, action: 'call', module: 'libadhdetect.so' });
const call1 = await post('/api/jni/onload', { session, action: 'call', module: 'libadhdetect.so', confirm: true });
let event = null;
for (let i = 0; i < 20; i++) {
  const caps = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=300`)).json();
  for (const found of (caps.captures ?? []).filter((c) => c.func === 'JNI_ONLOAD')) {
    const detail = await (await fetch(`${base}/api/captures/${found.id}`)).json();
    const text = String(detail.text ?? '');
    if (text.includes('libadhdetect.so') && text.includes('65542')) { event = detail; break; }
  }
  if (event) break; await sleep(100);
}
const status1 = await post('/api/jni/onload', { session, action: 'status' });
const unhook = await post('/api/jni/onload', { session, action: 'unhook', module: 'libadhdetect.so' });
const call2 = await post('/api/jni/onload', { session, action: 'call', module: 'libadhdetect.so', confirm: true });
const status2 = await post('/api/jni/onload', { session, action: 'status' });
const alive = (await (await fetch(`${base}/api/agents`)).json()).some((x) => x.online && x.package === 'com.adh.sandbox');
const pass = list.body.ok === true && moduleEntry && Number(moduleEntry.target) !== 0 && hook.body.ok === true && hook.body.installed === true &&
  noConfirm.status === 400 && call1.body.ok === true && Number(call1.body.retval) === 65542 && event != null &&
  status1.body.hits >= 1 && Number(status1.body.lastRet) === 65542 && unhook.body.ok === true && unhook.body.active === false &&
  call2.body.ok === true && Number(call2.body.retval) === 65542 && Number(status2.body.hits) === Number(status1.body.hits) && alive;
console.log(JSON.stringify({ listCount: list.body.found, moduleEntry, hook: hook.body, noConfirm: noConfirm.status, call1: call1.body.retval,
  status1: { hits: status1.body.hits, lastRet: status1.body.lastRet }, event: event ? { id: event.id, func: event.func, preview: event.preview } : null,
  unhook: unhook.body, call2: call2.body.retval, status2: { hits: status2.body.hits, lastRet: status2.body.lastRet }, alive }));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then echo "✅ v4.17 JNI_OnLoad list/hook/call/unhook PASS"; exit 0; elif echo "$OUT" | grep -q 'RESULT:SKIP'; then echo "⏭  v4.17 JNI_OnLoad SKIP (new daemon/agent not deployed)"; exit 0; else echo "❌ v4.17 JNI_OnLoad FAIL"; exit 1; fi