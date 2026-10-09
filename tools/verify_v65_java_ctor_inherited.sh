#!/usr/bin/env bash
# v4.28 java_hook completeness: constructor hooks + inherited members.
#   * hook JniCtorTarget."<init>"(int)  -> the callback must see the argument, the object must
#     still be constructed (total stays 42) and the ctor-hook must reject skipOriginal/returnValue;
#   * hook JniDerived.baseValue (declared by JniBase) -> resolution walks the superclass chain and
#     the signature reports the declaring class;
#   * both hooks are then removed and the behaviour is re-checked.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${ADH_HTTP_PORT:-8088}"
set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const CTOR_PROBE = 0xAD6000 | 1;
const agents = await (await fetch(`${base}/api/agents`)).json();
const agent = agents.filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0];
if (!agent) { console.log('NO_AGENT'); console.log('RESULT:SKIP'); process.exit(0); }
const session = agent.sessionId;
async function post(path, body) {
  const r = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
}
const hookStatus = () => post('/api/java/hook', { session, action: 'status' });
const callProbe = async (cls, method) => {
  const r = await post('/api/java/call', { session, className: cls, method, params: '', args: [] });
  return { ok: r.body.ok === true, value: r.body?.result?.result, error: r.body.error };
};
const ctorHook = await post('/api/java/hook', {
  session, action: 'hook', className: 'com.adh.sandbox.JniCtorTarget', method: '<init>', params: 'int',
});
const rejectSkip = await post('/api/java/hook', {
  session, action: 'hook', className: 'com.adh.sandbox.JniCtorTarget', method: '<init>', params: 'int',
  skipOriginal: true, returnValue: '1',
});
const inheritedHook = await post('/api/java/hook', {
  session, action: 'hook', className: 'com.adh.sandbox.JniDerived', method: 'baseValue', params: '',
});
const probe1 = await callProbe('com.adh.sandbox.Detection', 'jniCtorProbe');
const inherited1 = await callProbe('com.adh.sandbox.JniInheritStatics', 'derivedBaseValue');
await sleep(400);
const st = await hookStatus();
const hooks = (st.body.status && st.body.status.hooks) || [];
const ctorEntry = hooks.find((h) => h.id === ctorHook.body.hookId);
const inheritedEntry = hooks.find((h) => h.id === inheritedHook.body.hookId);
const ctorOk = ctorHook.body.ok === true && ctorEntry && /JniCtorTarget\.<init>\(int\)/.test(String(ctorEntry.target)) &&
  Number(ctorEntry.hits) >= 1 && String(ctorEntry.lastArg).includes('21');
const rejectOk = rejectSkip.body.ok === false && /constructor/i.test(String(rejectSkip.body.error));
const inheritedOk = inheritedHook.body.ok === true && inheritedEntry &&
  /com\.adh\.sandbox\.JniBase\.baseValue\(\)/.test(String(inheritedEntry.target)) &&
  Number(inheritedEntry.hits) >= 1;
const unhookCtor = await post('/api/java/hook', { session, action: 'unhook', hookId: ctorHook.body.hookId });
const unhookInherited = await post('/api/java/hook', { session, action: 'unhook', hookId: inheritedHook.body.hookId });
const probe2 = await callProbe('com.adh.sandbox.Detection', 'jniCtorProbe');
const inherited2 = await callProbe('com.adh.sandbox.JniInheritStatics', 'derivedBaseValue');
const stEnd = await hookStatus();
const hooksEnd = ((stEnd.body.status && stEnd.body.status.hooks) || []).filter((h) => h.active === true);
const alive = (await (await fetch(`${base}/api/agents`)).json()).some((x) => x.online && x.package === 'com.adh.sandbox');
const pass = ctorOk && rejectOk && inheritedOk &&
  probe1.ok === true && Number(probe1.value) === CTOR_PROBE &&
  inherited1.ok === true && Number(inherited1.value) === 7 &&
  unhookCtor.body.ok === true && unhookInherited.body.ok === true &&
  hooksEnd.length === 0 && probe2.ok === true && Number(probe2.value) === CTOR_PROBE &&
  inherited2.ok === true && Number(inherited2.value) === 7 && alive;
console.log(JSON.stringify({
  ctorHook: { ok: ctorHook.body.ok, error: ctorHook.body.error, target: ctorEntry && ctorEntry.target },
  rejectSkip: { ok: rejectSkip.body.ok, error: rejectSkip.body.error },
  inheritedHook: { ok: inheritedHook.body.ok, error: inheritedHook.body.error, target: inheritedEntry && inheritedEntry.target },
  ctorEntry: ctorEntry && { hits: ctorEntry.hits, lastArg: ctorEntry.lastArg, lastReturn: ctorEntry.lastReturn },
  inheritedEntry: inheritedEntry && { hits: inheritedEntry.hits, lastArg: inheritedEntry.lastArg, lastReturn: inheritedEntry.lastReturn },
  probes: { probe1: probe1.value, inherited1: inherited1.value, probe2: probe2.value, inherited2: inherited2.value },
  activeHooksAfterUnhook: hooksEnd.length, alive,
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.28 java_hook constructor + inherited member PASS"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.28 java_hook constructor + inherited member SKIP (new agent/sandbox not deployed)"
  exit 0
else
  echo "❌ v4.28 java_hook constructor + inherited member FAIL"
  exit 1
fi