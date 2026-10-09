#!/usr/bin/env bash
# v4.29 native hard-unhook acceptance (original bytes restored, no Dobby pool damage).
#
# Soft unhook keeps the Dobby stub/trampoline installed (re-activatable, but the patch and its
# pool page stay). Hard unhook writes the SAVED ORIGINAL PROLOGUE back over the patch after a
# quiesce window, frees the hook slot and deliberately does NOT call DobbyDestroy (on this Dobby
# build destroying frees the trampoline pool in a way that makes the next DobbyHook crash inside
# Dobby's memcpy - reproduced on device). Consequences asserted here:
#   * after hard unhook the target behaves exactly as before and no longer emits events;
#   * status shows the hook gone (count/patched 0) and the slot is reusable for a DIFFERENT target;
#   * re-hooking the SAME address is refused loudly (Dobby state is stale for it);
#   * no RWX page, and the anon-exec footprint stays stable (Dobby pool is retained, not leaked per hook).
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
const session = agent.sessionId;
async function post(path, body) {
  const r = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
}
const footprint = async () => {
  const r = await (await fetch(`${base}/api/compat/probe?session=${encodeURIComponent(session)}`)).json();
  return { ok: r.ok, rwx: r.rwxMappings, anon: r.anonExecMappings, exec: r.execMappings };
};
const traceProbe = async () => (await post('/api/java/call', { session, className: 'com.adh.sandbox.Detection', method: 'nativeHookProbe', params: '', args: [] })).body?.result?.result;
const callAdd = async () => (await post('/api/native/call', { session, module: 'libadhdetect.so', symbol: 'adh_add_target', args: ['20', '22'], confirm: true })).body;
const status = async () => {
  const b = (await post('/api/native/hook', { session, action: 'status' })).body;
  return b.status || { count: 0, patched: 0, hooks: [], error: b.error };
};
const hookCycle = async (symbol, expectCall) => {
  const hook = await post('/api/native/hook', { session, action: 'hook', hookId: 0, mode: 'inline', module: 'libadhdetect.so', symbol });
  const hookId = Number(hook.body.hookId);
  const call1 = await expectCall();
  await sleep(200);
  const st1 = await status();
  const hits = Number((st1.hooks ?? []).find((h) => h.id === hookId)?.hits ?? 0);
  const afterHook = await footprint();
  const unhook = await post('/api/native/hook', { session, action: 'unhook', hookId, hard: true });
  const st2 = await status();
  const call2 = await expectCall();
  const afterDestroy = await footprint();
  return { hookId, hookOk: hook.body.ok === true, call1, hits, afterHook, unhookOk: unhook.body.ok === true, unhookErr: unhook.body.error,
    count: st2.count, patched: st2.patched, call2, afterDestroy };
};
const baseline = await footprint();
const cycleTrace = await hookCycle('adh_trace_target', traceProbe);
const cycleAdd = await hookCycle('adh_add_target', async () => (await callAdd()).resultDecimal);
const reHook = await post('/api/native/hook', { session, action: 'hook', hookId: 0, mode: 'inline', module: 'libadhdetect.so', symbol: 'adh_trace_target' });
const stEnd = await status();
const alive = (await (await fetch(`${base}/api/agents`)).json()).some((x) => x.online && x.package === 'com.adh.sandbox');
const pass = cycleTrace.hookOk && Number(cycleTrace.call1) === 30 && cycleTrace.hits >= 1 && cycleTrace.unhookOk &&
  cycleTrace.count === 0 && cycleTrace.patched === 0 && Number(cycleTrace.call2) === 30 &&
  cycleAdd.hookOk && Number(cycleAdd.call1) === 84 && cycleAdd.hits >= 1 && cycleAdd.unhookOk &&
  cycleAdd.count === 0 && cycleAdd.patched === 0 && Number(cycleAdd.call2) === 84 &&
  cycleTrace.afterDestroy.rwx === baseline.rwx && cycleAdd.afterDestroy.rwx === baseline.rwx &&
  cycleAdd.afterDestroy.anon === cycleTrace.afterDestroy.anon && cycleAdd.afterDestroy.anon <= baseline.anon + 4 &&
  reHook.body.ok === false && /hard-unhooked earlier/.test(String(reHook.body.error)) &&
  stEnd.count === 0 && alive;
console.log(JSON.stringify({
  baseline, cycleTrace, cycleAdd,
  reHook: { ok: reHook.body.ok, error: reHook.body.error },
  finalStatus: { count: stEnd.count, patched: stEnd.patched }, alive,
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.29 native hard-unhook (original bytes restored) PASS"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.29 native hard-unhook SKIP (new agent/daemon not deployed)"
  exit 0
else
  echo "❌ v4.29 native hard-unhook FAIL"
  exit 1
fi