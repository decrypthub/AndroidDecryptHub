#!/usr/bin/env bash
# v4.26 byte-array writeback hook acceptance.
# Covers the in-place pattern that the read-side hooks miss: GetByteArrayElements ->
# ReleaseByteArrayElements(mode 0) and the Get/ReleasePrimitiveArrayCritical pair, plus
# GetByteArrayRegion for the read path. The fixture writes 0xA0.. / 0xB0.. in place and reads it
# back, so the events must show the rewritten payload and the probe must report it landed.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${ADH_HTTP_PORT:-8088}"
set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const FUNCS = ['SetByteArrayRegion', 'GetByteArrayElements', 'ReleaseByteArrayElements',
               'GetByteArrayRegion', 'GetPrimitiveArrayCritical', 'ReleasePrimitiveArrayCritical'];
const WANT = [
  { f: 'SetByteArrayRegion', v: 'start=0 len=8 hex=0102030405060708' },
  { f: 'GetByteArrayElements', v: 'len=8 hex=0102030405060708' },
  { f: 'ReleaseByteArrayElements', v: 'len=8 mode=0 writeback hex=a0a1a2a3a4a5a6a7' },
  { f: 'GetByteArrayRegion', v: 'start=0 len=8 hex=a0a1a2a3a4a5a6a7' },
  { f: 'GetPrimitiveArrayCritical', v: 'ptr=0x' },
  { f: 'ReleasePrimitiveArrayCritical', v: 'len=8 mode=0 writeback hex=b0b1b2b3b4b5b6b7' },
  { f: 'GetByteArrayRegion', v: 'start=0 len=8 hex=b0b1b2b3b4b5b6b7' },
];
const PROBE_VALUE = 0xAD4000 | 1 | 2;
const agents = await (await fetch(`${base}/api/agents`)).json();
const agent = agents.filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0];
if (!agent) { console.log('NO_AGENT'); console.log('RESULT:SKIP'); process.exit(0); }
async function post(path, body) {
  const r = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
}
async function callProbe(session) {
  const r = await post('/api/java/call', { session, className: 'com.adh.sandbox.Detection', method: 'jniArrayWriteProbe', params: '', args: [] });
  return { ok: r.body.ok === true, value: r.body?.result?.result, error: r.body.error };
}
const relroOk = (body) => typeof body?.tablePerms === 'string' && body.tablePerms.startsWith('r') && body.tablePerms[1] !== 'w'
  && (body?.hooks ?? []).every((h) => h.installed !== true || (typeof h.perms === 'string' && h.perms.startsWith('r') && h.perms[1] !== 'w'));
const tablePatched = (body) => (body?.hooks ?? []).every((h) => h.installed !== true || (h.slotValue && h.slotValue !== h.original));
const tableRestored = (body) => (body?.hooks ?? []).every((h) => h.installed === true || !h.original || h.original === '0x0' || h.slotValue === h.original);
const session = agent.sessionId;
const initial = await post('/api/jni/env_hook', { session, action: 'status' });
if (initial.status === 404 || /unsupported|unknown op/i.test(String(initial.body.error ?? ''))) {
  console.log('old payload / no jni_env_hook'); console.log('RESULT:SKIP'); process.exit(0);
}
if (!(initial.body.hooks ?? []).some((h) => h.function === 'ReleasePrimitiveArrayCritical')) {
  console.log('agent has no writeback/critical slots'); console.log('RESULT:SKIP'); process.exit(0);
}
const installs = [];
const installOk = [];
for (const f of FUNCS) {
  const r = await post('/api/jni/env_hook', { session, action: 'install', function: f });
  installs.push({ f, ok: r.body.ok, error: r.body.error });
  installOk.push(r.body.ok === true && (r.body.hooks ?? []).some((h) => h.function === f && h.active === true));
}
const probe1 = await callProbe(session);
const found = [];
for (let i = 0; i < 25 && found.length < WANT.length; i++) {
  const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=400`)).json();
  for (const c of (list.captures ?? []).filter((x) => x.func === 'JNI_ENV')) {
    const detail = await (await fetch(`${base}/api/captures/${c.id}`)).json();
    const text = String(detail.text ?? '').replace(/\\"/g, '"');
    for (let k = 0; k < WANT.length; k++) {
      if (found[k]) continue;
      if (text.includes(`"function":"${WANT[k].f}"`) && text.includes(WANT[k].v)) found[k] = c.id;
    }
  }
  if (found.filter(Boolean).length >= WANT.length) break;
  await sleep(120);
}
const missing = WANT.map((w, i) => found[i] ? null : `${w.f} ${w.v}`).filter(Boolean);
const status1 = await post('/api/jni/env_hook', { session, action: 'status' });
const hitsOk = FUNCS.every((f) => Number((status1.body.hooks ?? []).find((h) => h.function === f)?.hits ?? 0) >= 1);
const relro1 = relroOk(status1.body);
const patched1 = tablePatched(status1.body);
const uninstalls = [];
for (const f of FUNCS) {
  const r = await post('/api/jni/env_hook', { session, action: 'uninstall', function: f });
  uninstalls.push({ f, ok: r.body.ok, error: r.body.error });
}
const status2 = await post('/api/jni/env_hook', { session, action: 'status' });
const restored = FUNCS.every((f) => (status2.body.hooks ?? []).some((h) => h.function === f && h.installed === false && h.active === false));
const restoredTable = tableRestored(status2.body);
const probe2 = await callProbe(session);
const alive = (await (await fetch(`${base}/api/agents`)).json()).some((x) => x.online && x.package === 'com.adh.sandbox');
const pass = installOk.every(Boolean) && probe1.ok === true && Number(probe1.value) === PROBE_VALUE &&
  missing.length === 0 && hitsOk && relro1 && patched1 && uninstalls.every((u) => u.ok) && restored &&
  restoredTable && probe2.ok === true && Number(probe2.value) === PROBE_VALUE && alive;
console.log(JSON.stringify({
  installs, probe1: probe1.value, probeError: probe1.error ?? null, missingEvents: missing,
  hitsOk, relro1, patched1, uninstalls, restored, restoredTable, probe2: probe2.value, alive,
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.26 byte-array writeback hooks PASS"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.26 byte-array writeback hooks SKIP (new agent/sandbox not deployed)"
  exit 0
else
  echo "❌ v4.26 byte-array writeback hooks FAIL"
  exit 1
fi