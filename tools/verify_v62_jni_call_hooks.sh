#!/usr/bin/env bash
# v4.25 JNIEnv Call*Method / NewObject table hook acceptance.
# The NDK C++ JNIEnv_ wrappers call the "...V" entry, C callers use the varargs entry and
# generated code uses the "...A" entry, so this installs one of each (plus NewObjectA), runs
# Detection.jniCallProbe() (which drives all three forms on purpose) and asserts:
#   * one JNI_ENV event per installed slot with the resolved class#method(signature);
#   * rendered argument values for the String/int arguments;
#   * the probe's own bitmask (the calls really produced the expected values);
#   * uninstall puts the live table entry back (slotValue == original) and hits freeze.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${ADH_HTTP_PORT:-8088}"
set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// slot name -> substring that must appear inside that slot's event value
const EXPECT = {
  NewObjectA: 'com.adh.sandbox.JniCallTarget#<init>()V',
  CallObjectMethodA: 'com.adh.sandbox.JniCallTarget#combine(Ljava/lang/String;I)Ljava/lang/String; args("ADH_CALL",7)',
  CallIntMethodA: 'com.adh.sandbox.JniCallTarget#counterValue()I',
  CallVoidMethod: 'com.adh.sandbox.JniCallTarget#note(Ljava/lang/String;)V args("ADH_CALL")',
  CallStaticObjectMethod: 'com.adh.sandbox.JniCallStatics#staticCombine(Ljava/lang/String;I)Ljava/lang/String; args("ADH_CALL",9)',
};
const PROBE_VALUE = 0xAD3000 | 1 | 2 | 4 | 8;   // every fixture assertion inside the probe held
const FUNCS = Object.keys(EXPECT);
const agents = await (await fetch(`${base}/api/agents`)).json();
const agent = agents.filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0];
if (!agent) { console.log('NO_AGENT'); console.log('RESULT:SKIP'); process.exit(0); }
async function post(path, body) {
  const r = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
}
async function callProbe(session) {
  const r = await post('/api/java/call', { session, className: 'com.adh.sandbox.Detection', method: 'jniCallProbe', params: '', args: [] });
  return { ok: r.body.ok === true, value: r.body?.result?.result, error: r.body.error };
}
const relroOk = (body) => typeof body?.tablePerms === 'string' && body.tablePerms.startsWith('r') && body.tablePerms[1] !== 'w'
  && (body?.hooks ?? []).every((h) => h.installed !== true || (typeof h.perms === 'string' && h.perms.startsWith('r') && h.perms[1] !== 'w'));
const tablePatched = (body) => (body?.hooks ?? []).every((h) => h.installed !== true || (h.slotValue && h.slotValue !== h.original));
const tableRestored = (body) => (body?.hooks ?? []).every((h) => h.installed === true || !h.original || h.original === '0x0' || h.slotValue === h.original);
const session = agent.sessionId;
const initial = await post('/api/jni/env_hook', { session, action: 'status' });
if (initial.status === 404 || /unsupported|unknown op/i.test(String(initial.body.error ?? ''))) {
  console.log('old payload / no jni_env_hook');
  console.log('RESULT:SKIP');
  process.exit(0);
}
if (!(initial.body.hooks ?? []).some((h) => h.function === 'CallObjectMethodA')) {
  console.log('agent has no Call* family slots');
  console.log('RESULT:SKIP');
  process.exit(0);
}
const installs = {};
const installOk = [];
for (const f of FUNCS) {
  const r = await post('/api/jni/env_hook', { session, action: 'install', function: f });
  installs[f] = { ok: r.body.ok, error: r.body.error };
  installOk.push(r.body.ok === true && (r.body.hooks ?? []).some((h) => h.function === f && h.active === true && h.installed === true));
}
const probe1 = await callProbe(session);
const found = {};
for (let i = 0; i < 25 && Object.keys(found).length < FUNCS.length; i++) {
  const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=400`)).json();
  for (const c of (list.captures ?? []).filter((x) => x.func === 'JNI_ENV')) {
    const detail = await (await fetch(`${base}/api/captures/${c.id}`)).json();
    // capture text is the raw JSON payload, so string arguments appear as \"ADH_CALL\":
    // normalise the escaped quotes before matching the expected argument rendering.
    const text = String(detail.text ?? '').replace(/\\"/g, '"');
    for (const f of FUNCS) {
      if (!found[f] && text.includes(`"function":"${f}"`) && text.includes(EXPECT[f])) {
        found[f] = { id: c.id, preview: detail.preview ?? '' };
      }
    }
  }
  if (Object.keys(found).length >= FUNCS.length) break;
  await sleep(120);
}
const status1 = await post('/api/jni/env_hook', { session, action: 'status' });
const hitsOk = FUNCS.every((f) => Number((status1.body.hooks ?? []).find((h) => h.function === f)?.hits ?? 0) >= 1);
const relro1 = relroOk(status1.body);
const patched1 = tablePatched(status1.body);
const uninstalls = {};
const uninstallOk = [];
for (const f of FUNCS) {
  const r = await post('/api/jni/env_hook', { session, action: 'uninstall', function: f });
  uninstalls[f] = { ok: r.body.ok, error: r.body.error };
  uninstallOk.push(r.body.ok === true);
}
const status2 = await post('/api/jni/env_hook', { session, action: 'status' });
const restored = FUNCS.every((f) => (status2.body.hooks ?? []).some((h) => h.function === f && h.installed === false && h.active === false));
const restoredTable = tableRestored(status2.body);
const probe2 = await callProbe(session);
const status3 = await post('/api/jni/env_hook', { session, action: 'status' });
const hitsAfter = Object.fromEntries((status3.body.hooks ?? []).map((h) => [h.function, Number(h.hits)]));
const hitsBefore = Object.fromEntries((status1.body.hooks ?? []).map((h) => [h.function, Number(h.hits)]));
const frozen = FUNCS.every((f) => hitsAfter[f] === hitsBefore[f]);
const relro2 = relroOk(status3.body);
const alive = (await (await fetch(`${base}/api/agents`)).json()).some((x) => x.online && x.package === 'com.adh.sandbox');
const pass = installOk.every(Boolean) && probe1.ok === true && Number(probe1.value) === PROBE_VALUE &&
  Object.keys(found).length === FUNCS.length && hitsOk && patched1 && relro1 &&
  uninstallOk.every(Boolean) && restored && restoredTable &&
  probe2.ok === true && Number(probe2.value) === PROBE_VALUE && frozen && relro2 && alive;
console.log(JSON.stringify({
  installs, probe1: probe1.value, probeError: probe1.error ?? null,
  events: found, hitsBefore, hitsOk, patched1, relro1, uninstalls, restored, restoredTable,
  probe2: probe2.value, frozen, relro2, alive,
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.25 JNIEnv Call*Method / NewObject hooks PASS"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.25 JNIEnv Call*Method / NewObject hooks SKIP (new agent/sandbox not deployed)"
  exit 0
else
  echo "❌ v4.25 JNIEnv Call*Method / NewObject hooks FAIL"
  exit 1
fi