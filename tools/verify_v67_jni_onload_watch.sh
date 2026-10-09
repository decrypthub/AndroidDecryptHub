#!/usr/bin/env bash
# v4.30 load-time JNI_OnLoad watch acceptance.
#
# `jni_onload watch module=...` hooks the process dlopen entry and patches the module's
# JNI_OnLoad as soon as it is mapped, BEFORE the VM calls it. Two runtime-loaded plugin libs are
# used (libadhplugin_a/b.so - not loaded at app start):
#   * plugin A: observe the real load-time call (event phase=load, retval=JNI_VERSION_1_6) and the
#     plugin's own counter must be 1;
#   * plugin B: skipOriginal + returnValue -> the load-time call is REPLACED, so the plugin's
#     counter must stay 0 while System.loadLibrary still succeeds (ART sees a valid version).
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
const nativeCount = async (symbol) => (await post('/api/native/call', { session, module: symbol === 'adh_plugin_a_count' ? 'libadhplugin_a.so' : 'libadhplugin_b.so', symbol, args: [], confirm: true })).body;
const javaCall = async (method) => (await post('/api/java/call', { session, className: 'com.adh.sandbox.Detection', method, params: '', args: [] })).body;
const findEvent = async (module) => {
  for (let i = 0; i < 25; i++) {
    const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=400`)).json();
    for (const c of (list.captures ?? []).filter((x) => x.func === 'JNI_ONLOAD')) {
      const detail = await (await fetch(`${base}/api/captures/${c.id}`)).json();
      const text = String(detail.text ?? '');
      if (text.includes(`"module":"${module}"`)) return { id: c.id, text };
    }
    await sleep(120);
  }
  return null;
};
// --- plugin A: observe the real load-time call ------------------------------------------------
const watchA = await post('/api/jni/onload', { session, action: 'watch', module: 'libadhplugin_a.so' });
const loadA = await javaCall('loadPluginA');
const eventA = await findEvent('libadhplugin_a.so');
const countA = await nativeCount('adh_plugin_a_count');
// --- plugin B: replace the load-time call ------------------------------------------------------
// The onload hook slot is single by design: unhook A before arming the next watch.
const unhookA = await post('/api/jni/onload', { session, action: 'unhook', module: 'libadhplugin_a.so' });
const watchB = await post('/api/jni/onload', { session, action: 'watch', module: 'libadhplugin_b.so', skipOriginal: true, returnValue: 65542 });
const loadB = await javaCall('loadPluginB');
const eventB = await findEvent('libadhplugin_b.so');
const countB = await nativeCount('adh_plugin_b_count');
const status = await post('/api/jni/onload', { session, action: 'status' });
const unwatch = await post('/api/jni/onload', { session, action: 'unwatch' });
const alive = (await (await fetch(`${base}/api/agents`)).json()).some((x) => x.online && x.package === 'com.adh.sandbox');
const watchOk = (r) => r.body.ok === true && r.body.watch && r.body.watch.armed === true && Number(r.body.dlopenWatch) === 1;
const eventOk = (e, opts) => e && e.text.includes('"phase":"load"') &&
  e.text.includes(`"retval":${opts.retval}`) && e.text.includes(`"skipped":${opts.skipped ? 'true' : 'false'}`);
const pass = unhookA.body.ok === true && watchOk(watchA) && loadA.ok === true && eventOk(eventA, { retval: 65542, skipped: false }) &&
  Number(countA.resultDecimal) === 1 &&
  watchOk(watchB) && loadB.ok === true && eventOk(eventB, { retval: 65542, skipped: true }) &&
  Number(countB.resultDecimal) === 0 &&
  status.body.ok === true && unwatch.body.ok === true && unwatch.body.watch && unwatch.body.watch.armed === false && alive;
console.log(JSON.stringify({
  watchA: { ok: watchA.body.ok, watch: watchA.body.watch, dlopenWatch: watchA.body.dlopenWatch, error: watchA.body.error },
  loadA: { ok: loadA.ok, error: loadA.error }, eventA: eventA && eventA.text, countA: countA.resultDecimal,
  watchB: { ok: watchB.body.ok, watch: watchB.body.watch, error: watchB.body.error },
  loadB: { ok: loadB.ok, error: loadB.error }, eventB: eventB && eventB.text, countB: countB.resultDecimal,
  unhookA: unhookA.body.ok, unwatch: unwatch.body.watch, alive,
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.30 load-time JNI_OnLoad watch PASS"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.30 load-time JNI_OnLoad watch SKIP (new agent/sandbox not deployed)"
  exit 0
else
  echo "❌ v4.30 load-time JNI_OnLoad watch FAIL"
  exit 1
fi