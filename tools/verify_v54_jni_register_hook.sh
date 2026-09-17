#!/usr/bin/env bash
# v4.14 JNI RegisterNatives hook acceptance.
# Installs the global JNIEnv->RegisterNatives hook, triggers the sandbox's
# Detection.jniRegisterProbe(), and verifies both the JNI_NATIVE event and the newly
# registered method callable through normal JNI (0xAD11).
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
async function post(path, body) {
  const r = await fetch(`${base}${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  return { status: r.status, body: await r.json() };
}
const session = agent.sessionId;
const initial = await post('/api/jni/hook', { session, action: 'status' });
if (initial.status === 404 || /unsupported|unknown op/i.test(String(initial.body.error ?? ''))) {
  console.log('old payload / no jni_hook');
  console.log('RESULT:SKIP');
  process.exit(0);
}
await post('/api/jni/hook', { session, action: 'uninstall' }).catch(() => null);
const install = await post('/api/jni/hook', { session, action: 'install' });
if (!install.body.ok) {
  console.log(JSON.stringify({ install }));
  console.log('RESULT:FAIL');
  process.exit(0);
}
const register = await post('/api/java/call', {
  session, className: 'com.adh.sandbox.Detection', method: 'jniRegisterProbe', params: '', args: [],
});
const registered = await post('/api/java/call', {
  session, className: 'com.adh.sandbox.Detection', method: 'jniRegisteredProbe', params: '', args: [],
});
let event = null;
for (let i = 0; i < 20; i++) {
  const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=300`)).json();
  for (const found of (list.captures ?? []).filter((c) => c.func === 'JNI_NATIVE')) {
    const detail = await (await fetch(`${base}/api/captures/${found.id}`)).json();
    const text = String(detail.text ?? '');
    if (text.includes('"class":"com.adh.sandbox.Detection"') && text.includes('"method":"jniRegisteredProbe"') &&
        text.includes('"signature":"()I"')) { event = detail; break; }
  }
  if (event) break;
  await sleep(100);
}
const status = await post('/api/jni/hook', { session, action: 'status' });
const uninstall = await post('/api/jni/hook', { session, action: 'uninstall' });
const alive = (await (await fetch(`${base}/api/agents`)).json()).some((x) => x.online && x.package === 'com.adh.sandbox');
const registerResult = register?.body?.result?.result;
const registeredResult = registered?.body?.result?.result;
const pass = install.body.ok === true && install.body.installed === true &&
  register.body.ok === true && Number(registerResult) === 0 &&
  registered.body.ok === true && Number(registeredResult) === 0xAD11 &&
  event != null && status.body.hits >= 1 && status.body.lastCount === 1 &&
  uninstall.body.ok === true && uninstall.body.installed === false && alive;
console.log(JSON.stringify({
  install: install.body, register: register.body?.result?.result, registered: registered.body?.result?.result,
  status: status.body, event: event ? { id: event.id, func: event.func, preview: event.preview } : null,
  uninstall: uninstall.body, alive,
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.14 JNI RegisterNatives hook PASS"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.14 JNI RegisterNatives hook SKIP (new agent not deployed)"
  exit 0
else
  echo "❌ v4.14 JNI RegisterNatives hook FAIL"
  exit 1
fi