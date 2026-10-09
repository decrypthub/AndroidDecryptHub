#!/usr/bin/env bash
# v4.13 Java hook argument rewrite acceptance.
# Rewrites HookProbe.ping's String argument before invoking the original and proves the
# caller-visible return uses the rewritten value while the original method still runs.
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
const initialStatus = await post('/api/java/hook', { session, action: 'status' });
if (initialStatus?.status?.argRewrite !== true) {
  console.log('old payload / java_hook has no argument rewrite capability');
  console.log('RESULT:SKIP');
  process.exit(0);
}
await post('/api/java/hook', { session, action: 'unhook', hookId: 0 }).catch(() => null);
const hook = await post('/api/java/hook', {
  session, action: 'hook', className: 'com.adh.sandbox.HookProbe', method: 'ping',
  params: 'java.lang.String', argIndex: 0, argValue: 'ADH_REWRITTEN',
});
const hookId = Number(hook.hookId ?? 0);
const call = await post('/api/java/call', {
  session, className: 'com.adh.sandbox.HookProbe', method: 'recordPing',
  params: 'java.lang.String', args: ['ADH_ORIGINAL'],
});
const readback = await post('/api/java/call', {
  session, className: 'com.adh.sandbox.HookProbe', method: 'lastPingResult', params: '', args: [],
});
const status = await post('/api/java/hook', { session, action: 'status' });
const st = (status?.status?.hooks ?? []).find((x) => Number(x.id) === hookId) ?? {};
const unhook = await post('/api/java/hook', { session, action: 'unhook', hookId });
const alive = (await (await fetch(`${base}/api/agents`)).json())
  .some((x) => x.online && x.package === 'com.adh.sandbox');
const callResult = call?.result?.result;
const readbackResult = readback?.result?.result;
const pass = hook.ok === true && hookId >= 1 &&
  call.ok === true && callResult === 'REAL_HOOK:ADH_REWRITTEN' &&
  readback.ok === true && readbackResult === 'REAL_HOOK:ADH_REWRITTEN' &&
  st.hits >= 1 && st.lastArg === 'ADH_REWRITTEN' &&
  st.lastReturn === 'REAL_HOOK:ADH_REWRITTEN' &&
  (st.lastError === '' || st.lastError == null) &&
  unhook.ok === true && alive;
console.log(JSON.stringify({ hook, call, readback, status, unhook, alive, callResult, readbackResult }));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.13 Java hook argument rewrite PASS"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.13 Java hook argument rewrite SKIP (new agent not deployed)"
  exit 0
else
  echo "❌ v4.13 Java hook argument rewrite FAIL"
  exit 1
fi