#!/usr/bin/env bash
# v4.20 JNIEnv table hook behaviour-preservation acceptance.
# Hooking a member-ID lookup must not change what the target observes: a *failed* lookup must
# still leave its error pending (NoSuchMethodError / NoSuchFieldError) after our wrapper has run
# its own class-name reflection. The script compares Detection.jniEnvExceptionProbe() with the
# hooks installed against the same probe without them, and requires the failed-lookup bits.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${ADH_HTTP_PORT:-8088}"
set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const FUNCS = ['GetMethodID', 'GetStaticMethodID', 'GetFieldID', 'GetStaticFieldID'];
const MISSING_BITS = 1 | 4;   // failed GetMethodID + failed GetStaticFieldID both threw
const agents = await (await fetch(`${base}/api/agents`)).json();
const agent = agents.filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0];
if (!agent) { console.log('NO_AGENT'); console.log('RESULT:SKIP'); process.exit(0); }
async function post(path, body) {
  const r = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
}
async function probe(session) {
  const r = await post('/api/java/call', { session, className: 'com.adh.sandbox.Detection', method: 'jniEnvExceptionProbe', params: '', args: [] });
  return { ok: r.body.ok === true, value: r.body?.result?.result, error: r.body.error };
}
const session = agent.sessionId;
const initial = await post('/api/jni/env_hook', { session, action: 'status' });
if (initial.status === 404 || /unsupported|unknown op/i.test(String(initial.body.error ?? ''))) {
  console.log('old payload / no jni_env_hook');
  console.log('RESULT:SKIP');
  process.exit(0);
}
if (!(initial.body.hooks ?? []).some((h) => h.function === 'GetStaticFieldID')) {
  console.log('agent has the base JNIEnv hooks only (no field-ID entries)');
  console.log('RESULT:SKIP');
  process.exit(0);
}
const baseline = await probe(session);
const installs = {};
const installOk = [];
for (const f of FUNCS) {
  const r = await post('/api/jni/env_hook', { session, action: 'install', function: f });
  installs[f] = { ok: r.body.ok, error: r.body.error };
  installOk.push(r.body.ok === true && (r.body.hooks ?? []).some((h) => h.function === f && h.active === true));
}
const hooked = await probe(session);
// The failed lookups must still be visible as JNI_ENV events (captured even though they threw).
const found = {};
for (let i = 0; i < 20 && Object.keys(found).length < 2; i++) {
  const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=400`)).json();
  for (const c of (list.captures ?? []).filter((x) => x.func === 'JNI_ENV')) {
    const detail = await (await fetch(`${base}/api/captures/${c.id}`)).json();
    const text = String(detail.text ?? '');
    if (!found.GetMethodID && text.includes('"function":"GetMethodID"') && text.includes('adhNoSuchMethod')) found.GetMethodID = c.id;
    if (!found.GetStaticFieldID && text.includes('"function":"GetStaticFieldID"') && text.includes('adhNoSuchField')) found.GetStaticFieldID = c.id;
  }
  if (Object.keys(found).length >= 2) break;
  await sleep(120);
}
const status = await post('/api/jni/env_hook', { session, action: 'status' });
const relroOk = (body) => typeof body?.tablePerms === 'string' && body.tablePerms.startsWith('r') && body.tablePerms[1] !== 'w'
  && (body?.hooks ?? []).every((h) => h.installed !== true || (typeof h.perms === 'string' && h.perms.startsWith('r') && h.perms[1] !== 'w'));
const relro = relroOk(status.body);
const uninstalls = {};
const uninstallOk = [];
for (const f of FUNCS) {
  const r = await post('/api/jni/env_hook', { session, action: 'uninstall', function: f });
  uninstalls[f] = { ok: r.body.ok, error: r.body.error };
  uninstallOk.push(r.body.ok === true);
}
const after = await probe(session);
const alive = (await (await fetch(`${base}/api/agents`)).json()).some((x) => x.online && x.package === 'com.adh.sandbox');
const baseBits = Number(baseline.value), hookBits = Number(hooked.value), afterBits = Number(after.value);
const preserved = baseBits === hookBits && afterBits === baseBits && (baseBits & MISSING_BITS) === MISSING_BITS;
const pass = baseline.ok === true && installOk.every(Boolean) && hooked.ok === true && after.ok === true &&
  preserved && Object.keys(found).length === 2 && uninstallOk.every(Boolean) && relro && alive;
console.log(JSON.stringify({
  bits: { baseline: baseline.value, hooked: hooked.value, afterUnhook: after.value },
  probeErrors: [baseline.error, hooked.error, after.error].filter(Boolean),
  installs, failedLookupEvents: found, uninstalls, relro, alive,
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.20 JNIEnv hook behaviour preservation PASS"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.20 JNIEnv hook behaviour preservation SKIP (new agent/sandbox not deployed)"
  exit 0
else
  echo "❌ v4.20 JNIEnv hook behaviour preservation FAIL"
  exit 1
fi