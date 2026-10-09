#!/usr/bin/env bash
# v4.16 hook lifecycle stress acceptance.
# Exercises repeated install/unhook on the same native and Java targets. Both managers
# soft-unhook by deactivating an already-installed stub and reactivating it on the next
# install, so this proves the slot is reusable and the target survives.
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
  return r.json();
}
const session = agent.sessionId;
let nativeCycles = 0, javaCycles = 0;
for (let i = 1; i <= 24; i++) {
  const h = await post('/api/native/hook', { session, action: 'hook', mode: 'inline', module: 'libadhdetect.so', symbol: 'adh_add_target', argIndex: 0, argValue: String(i) });
  if (!h.ok) { console.log(`native install ${i} failed: ${h.error}`); break; }
  const u = await post('/api/native/hook', { session, action: 'unhook', hookId: h.hookId });
  if (!u.ok) { console.log(`native unhook ${i} failed: ${u.error}`); break; }
  nativeCycles = i;
}
for (let i = 1; i <= 24; i++) {
  const h = await post('/api/java/hook', { session, action: 'hook', className: 'com.adh.sandbox.HookProbe', method: 'ping', params: 'java.lang.String', argIndex: 0, argValue: `STRESS_${i}` });
  if (!h.ok) { console.log(`java install ${i} failed: ${h.error}`); break; }
  const u = await post('/api/java/hook', { session, action: 'unhook', hookId: h.hookId });
  if (!u.ok) { console.log(`java unhook ${i} failed: ${u.error}`); break; }
  javaCycles = i;
}
const nativeStatus = await post('/api/native/hook', { session, action: 'status' });
const javaStatus = await post('/api/java/hook', { session, action: 'status' });
const nativeCall = await post('/api/native/call', { session, module: 'libadhdetect.so', symbol: 'adh_add_target', args: ['1', '2'], confirm: true });
const javaCall = await post('/api/java/call', { session, className: 'com.adh.sandbox.HookProbe', method: 'recordPing', params: 'java.lang.String', args: ['PLAIN'] });
const alive = (await (await fetch(`${base}/api/agents`)).json()).some((x) => x.online && x.package === 'com.adh.sandbox');
const pass = nativeCycles === 24 && javaCycles === 24 &&
  nativeStatus?.status?.patched >= 1 && javaStatus?.status?.patched >= 1 &&
  nativeCall.ok === true && Number(nativeCall.resultDecimal) === 6 &&
  javaCall.ok === true && javaCall.result?.result === 'REAL_HOOK:PLAIN' && alive;
console.log(JSON.stringify({ nativeCycles, javaCycles, nativePatched: nativeStatus?.status?.patched, javaPatched: javaStatus?.status?.patched,
  nativeResult: nativeCall.resultDecimal, javaResult: javaCall.result?.result, alive }));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.16 hook lifecycle stress PASS (24 native + 24 Java install/unhook)"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.16 hook lifecycle stress SKIP (new agent not deployed)"
  exit 0
else
  echo "❌ v4.16 hook lifecycle stress FAIL"
  exit 1
fi