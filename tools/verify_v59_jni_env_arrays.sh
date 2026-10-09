#!/usr/bin/env bash
# v4.19 JNIEnv field-ID / byte-array table hook acceptance.
# Installs GetFieldID / GetStaticFieldID / SetByteArrayRegion / GetByteArrayElements hooks,
# drives Detection.jniEnvArrayProbe() once (the trigger performs all four lookups/copies),
# asserts one JNI_ENV event per entry with the probe's exact value, then unhooks and proves the
# table entries were restored (entries inactive, hit counts frozen, RELRO page still r--).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${ADH_HTTP_PORT:-8088}"
set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const ARRAY_HEX = '4144480203040506';   // 41 44 48 02 03 04 05 06 as written by the probe
const EXPECT = {
  GetFieldID: 'com.adh.sandbox.JniEnvHolder#marker:I',
  GetStaticFieldID: 'com.adh.sandbox.Detection#jniEnvStaticField:I',
  SetByteArrayRegion: `start=0 len=8 hex=${ARRAY_HEX}`,
  GetByteArrayElements: `len=8 hex=${ARRAY_HEX}`,
};
const FUNCS = Object.keys(EXPECT);
const PROBE_VALUE = 0xAD1000 + 8;   // the probe returns 0xAD1008 when all four paths worked
const agents = await (await fetch(`${base}/api/agents`)).json();
const agent = agents.filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0];
if (!agent) { console.log('NO_AGENT'); console.log('RESULT:SKIP'); process.exit(0); }
async function post(path, body) {
  const r = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
}
async function callProbe(session) {
  const r = await post('/api/java/call', { session, className: 'com.adh.sandbox.Detection', method: 'jniEnvArrayProbe', params: '', args: [] });
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
if (!(initial.body.hooks ?? []).some((h) => h.function === 'SetByteArrayRegion')) {
  console.log('agent has the base JNIEnv hooks only (no field/array entries)');
  console.log('RESULT:SKIP');
  process.exit(0);
}
const installs = {};
const installOk = [];
for (const f of FUNCS) {
  const r = await post('/api/jni/env_hook', { session, action: 'install', function: f });
  installs[f] = { ok: r.body.ok, error: r.body.error, entry: (r.body.hooks ?? []).find((h) => h.function === f)?.entry };
  installOk.push(r.body.ok === true && (r.body.hooks ?? []).some((h) => h.function === f && h.active === true && h.installed === true));
}
const probe1 = await callProbe(session);
const found = {};
for (let i = 0; i < 25 && Object.keys(found).length < FUNCS.length; i++) {
  const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=400`)).json();
  for (const c of (list.captures ?? []).filter((x) => x.func === 'JNI_ENV')) {
    const detail = await (await fetch(`${base}/api/captures/${c.id}`)).json();
    const text = String(detail.text ?? '');
    for (const f of FUNCS) {
      // "starts with": the two ID lookups report the resolved jfieldID AFTER the class#field label
      // ("...marker:I -> 0x21"), which is runtime-assigned and can never match a fixed string.
      if (!found[f] && text.includes(`"function":"${f}"`) && text.includes(`"value":"${EXPECT[f]}`)) {
        found[f] = { id: c.id, preview: detail.preview ?? '' };
      }
    }
  }
  if (Object.keys(found).length >= FUNCS.length) break;
  await sleep(120);
}
const status1 = await post('/api/jni/env_hook', { session, action: 'status' });
const hitsBefore = Object.fromEntries((status1.body.hooks ?? []).map((h) => [h.function, Number(h.hits)]));
const hitsOk = FUNCS.every((f) => hitsBefore[f] >= 1);
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
const probe2 = await callProbe(session);
const status3 = await post('/api/jni/env_hook', { session, action: 'status' });
const hitsAfter = Object.fromEntries((status3.body.hooks ?? []).map((h) => [h.function, Number(h.hits)]));
const frozen = FUNCS.every((f) => hitsAfter[f] === hitsBefore[f]);
const relro2 = relroOk(status3.body);
const restored2 = tableRestored(status2.body) && tableRestored(status3.body);
const alive = (await (await fetch(`${base}/api/agents`)).json()).some((x) => x.online && x.package === 'com.adh.sandbox');
const pass = installOk.every(Boolean) && probe1.ok === true && Number(probe1.value) === PROBE_VALUE &&
  Object.keys(found).length === FUNCS.length && hitsOk && uninstallOk.every(Boolean) && restored &&
  probe2.ok === true && Number(probe2.value) === PROBE_VALUE && frozen && relro1 && relro2 && patched1 && restored2 && alive;
if (!pass) {
  const flags = { installs: installOk.every(Boolean), probe1: probe1.ok === true && Number(probe1.value) === PROBE_VALUE,
    found: Object.keys(found).length === FUNCS.length, foundKeys: Object.keys(found).join('/'), hitsOk, uninstalls: uninstallOk.every(Boolean),
    restored, probe2: probe2.ok === true && Number(probe2.value) === PROBE_VALUE, frozen, relro1, relro2, patched1, restored2, alive };
  console.log('failed checks: ' + Object.entries(flags).filter(([, v]) => v !== true).map(([k, v]) => `${k}=${v}`).join(', '));
}
console.log(JSON.stringify({
  table: status1.body.table, tablePerms: [status1.body.tablePerms, status3.body.tablePerms],
  installs, probe1: probe1.value, probe1Error: probe1.error ?? null,
  events: Object.fromEntries(Object.entries(found).map(([k, v]) => [k, v.id])), hitsBefore, hitsOk,
  uninstalls, restored, probe2: probe2.value, hitsAfter, frozen, relro1, relro2, patched1, restored2, alive,
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.19 JNIEnv field-ID / byte-array hook PASS"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.19 JNIEnv field-ID / byte-array hook SKIP (new agent/sandbox not deployed)"
  exit 0
else
  echo "❌ v4.19 JNIEnv field-ID / byte-array hook FAIL"
  exit 1
fi