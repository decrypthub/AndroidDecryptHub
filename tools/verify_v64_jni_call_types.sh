#!/usr/bin/env bash
# v4.27 full Call* family coverage acceptance (all return types + wildcard install).
# Phase 1 installs EVERY JNIEnv table slot in one wildcard call (function="*") and asserts the
# ABI guard accepted all of them (applied == slot count, failed == 0) and that every family the
# fixture uses registered its own hit; phase 2 hooks only those families and matches the resolved
# class#method(signature) events (a low-traffic window, since a full install also routes the
# agent's own reflection traffic through the hooks). Then everything is uninstalled and the table
# pointers are proven restored.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${ADH_HTTP_PORT:-8088}"
set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const WANT = [
  { f: 'CallBooleanMethodA', v: 'com.adh.sandbox.JniCallTarget#flag()Z' },
  { f: 'CallByteMethodA', v: 'com.adh.sandbox.JniCallTarget#byteValue()B' },
  { f: 'CallCharMethodA', v: 'com.adh.sandbox.JniCallTarget#charValue()C' },
  { f: 'CallShortMethodA', v: 'com.adh.sandbox.JniCallTarget#shortValue()S' },
  { f: 'CallLongMethodA', v: 'com.adh.sandbox.JniCallTarget#longValue()J' },
  { f: 'CallFloatMethodA', v: 'com.adh.sandbox.JniCallTarget#floatValue()F' },
  { f: 'CallDoubleMethodA', v: 'com.adh.sandbox.JniCallTarget#doubleValue()D' },
  { f: 'CallStaticBooleanMethod', v: 'com.adh.sandbox.JniCallStatics#staticFlag()Z' },
  { f: 'CallStaticByteMethod', v: 'com.adh.sandbox.JniCallStatics#staticByte()B' },
  { f: 'CallStaticCharMethod', v: 'com.adh.sandbox.JniCallStatics#staticChar()C' },
  { f: 'CallStaticShortMethod', v: 'com.adh.sandbox.JniCallStatics#staticShort()S' },
  { f: 'CallStaticLongMethod', v: 'com.adh.sandbox.JniCallStatics#staticLong()J' },
  { f: 'CallStaticFloatMethod', v: 'com.adh.sandbox.JniCallStatics#staticFloat()F' },
  { f: 'CallStaticDoubleMethod', v: 'com.adh.sandbox.JniCallStatics#staticDouble()D' },
];
// The fixture sets bits 0..6 (instance) and 8..14 (static); 0x7F7F is the full expected mask.
const PROBE_VALUE = 0xAD5000 | 0x7F7F;
const agents = await (await fetch(`${base}/api/agents`)).json();
const agent = agents.filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0];
if (!agent) { console.log('NO_AGENT'); console.log('RESULT:SKIP'); process.exit(0); }
async function post(path, body) {
  const r = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
}
async function probe(session) {
  const r = await post('/api/java/call', { session, className: 'com.adh.sandbox.Detection', method: 'jniCallTypesProbe', params: '', args: [] });
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
const slotCount = (initial.body.hooks ?? []).length;
if (!(initial.body.hooks ?? []).some((h) => h.function === 'CallStaticDoubleMethodA')) {
  console.log('agent has no full Call* coverage'); console.log('RESULT:SKIP'); process.exit(0);
}
// ---- phase 1: install everything, prove per-slot interception -------------------------------
const baseline = await probe(session);
const installAll = await post('/api/jni/env_hook', { session, action: 'install', function: '*' });
// The install reply's own list is clipped to the reply buffer; it now says so (total/emitted/
// truncated). Count from the status reply, which is allowed to carry the whole table.
const statusAfterInstall = await post('/api/jni/env_hook', { session, action: 'status' });
const installedCount = (statusAfterInstall.body.hooks ?? []).filter((h) => h.installed === true).length;
const statusHonest = statusAfterInstall.body?.truncated === false || Number(statusAfterInstall.body?.emitted ?? 0) === Number(statusAfterInstall.body?.matched ?? -1);
const installReplyHonest = installAll.body?.truncated === false || Number(installAll.body?.emitted ?? -1) < Number(installAll.body?.total ?? -2);
const probeAll = await probe(session);
const statusAll = await post('/api/jni/env_hook', { session, action: 'status' });
const hitsAll = Object.fromEntries((statusAll.body.hooks ?? []).map((h) => [h.function, Number(h.hits)]));
const hitOffenders = WANT.filter((w) => !(hitsAll[w.f] >= 1)).map((w) => `${w.f}=${hitsAll[w.f]}`);
const relro1 = relroOk(statusAll.body);
const patched1 = tablePatched(statusAll.body);
const uninstallAll = await post('/api/jni/env_hook', { session, action: 'uninstall', function: '*' });
const statusAfterAll = await post('/api/jni/env_hook', { session, action: 'status' });
const restoredAll = (statusAfterAll.body.hooks ?? []).every((h) => h.installed === false && h.active === false) && tableRestored(statusAfterAll.body);
// ---- phase 2: prove the resolved labels -----------------------------------------------------
// Labels are read from each slot's status "last" snapshot instead of the capture ring: a busy
// target (or a full 76-slot install) pushes far more records than the ring holds, so ring-based
// matching is a race. hits + last are authoritative and flood-proof.
const installNames = [];
for (const w of WANT) {
  const r = await post('/api/jni/env_hook', { session, action: 'install', function: w.f });
  installNames.push({ f: w.f, ok: r.body.ok });
}
const probe2 = await probe(session);
await sleep(400);
const status2 = await post('/api/jni/env_hook', { session, action: 'status' });
const missing = [];
const labels = {};
for (const w of WANT) {
  const h = (status2.body.hooks ?? []).find((x) => x.function === w.f);
  labels[w.f] = h ? h.last : null;
  if (!h || !String(h.last ?? '').includes(w.v)) missing.push(`${w.f} ${w.v}`);
}
const uninstalls = [];
for (const w of WANT) {
  const r = await post('/api/jni/env_hook', { session, action: 'uninstall', function: w.f });
  uninstalls.push({ f: w.f, ok: r.body.ok });
}
const statusEnd = await post('/api/jni/env_hook', { session, action: 'status' });
const restoredEnd = tableRestored(statusEnd.body);
const probe3 = await probe(session);
const alive = (await (await fetch(`${base}/api/agents`)).json()).some((x) => x.online && x.package === 'com.adh.sandbox');
const pass = baseline.ok === true && Number(baseline.value) === PROBE_VALUE &&
  installAll.body.ok === true && Number(installAll.body.applied) === slotCount && Number(installAll.body.failed) === 0 &&
  installedCount === slotCount && statusHonest && installReplyHonest && probeAll.ok === true && Number(probeAll.value) === PROBE_VALUE &&
  hitOffenders.length === 0 && relro1 && patched1 &&
  uninstallAll.body.ok === true && Number(uninstallAll.body.applied) === slotCount && restoredAll &&
  installNames.every((x) => x.ok) && probe2.ok === true && Number(probe2.value) === PROBE_VALUE &&
  missing.length === 0 && uninstalls.every((x) => x.ok) && restoredEnd &&
  probe3.ok === true && Number(probe3.value) === PROBE_VALUE && alive;
console.log(JSON.stringify({
  slotCount, baseline: baseline.value,
  installAll: { ok: installAll.body.ok, applied: installAll.body.applied, failed: installAll.body.failed, error: installAll.body.error },
  installedCount, probeAll: probeAll.value, hitOffenders, relro1, patched1,
  uninstallAll: { ok: uninstallAll.body.ok, applied: uninstallAll.body.applied, failed: uninstallAll.body.failed },
  restoredAll, installNames, probe2: probe2.value, missingEvents: missing,
  uninstalls, restoredEnd, probe3: probe3.value, alive,
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.27 full Call* family coverage (wildcard install) PASS"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.27 full Call* family coverage SKIP (new agent/sandbox not deployed)"
  exit 0
else
  echo "❌ v4.27 full Call* family coverage FAIL"
  exit 1
fi