#!/usr/bin/env bash
# v4.3 LSPlant Java-method-hook acceptance.
#
# Deterministic path: install a hook on com.adh.sandbox.HookProbe.ping(String), trigger the
# exported HookProbeReceiver with an explicit broadcast, then assert the bridge captured the
# real argument and original return value while the target process stayed alive.
#
# SKIPs when the deployed agent predates java_hook or the sandbox is not running. Exit 0 = PASS/SKIP.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${ADH_HTTP_PORT:-8088}"
export ADH_ADB="${ADH_ADB:-$(command -v adb)}"

set +e
OUT="$(node - "$HTTP" <<'EOF'
import { spawnSync } from 'node:child_process';
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const adb = process.env.ADH_ADB || 'adb';

function adbArgs(args) {
  const serial = process.env.ANDROID_SERIAL || process.env.ADH_SERIAL || '';
  return serial ? ['-s', serial, ...args] : args;
}
async function post(path, body) {
  const r = await fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return r.json();
}
function result(name, pass) {
  console.log(name);
  console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
}
function skip(reason) {
  console.log(reason);
  console.log('RESULT:SKIP');
  process.exit(0);
}

const agents = await (await fetch(`${base}/api/agents`)).json();
const agent = agents.filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0];
const serialOut = spawnSync(adb, adbArgs(['devices']), { encoding: 'utf8' });
if (serialOut.status !== 0) skip(`adb unavailable: ${serialOut.stderr || serialOut.stdout}`);
const lines = String(serialOut.stdout || '').split(/\r?\n/).filter((x) => /\tdevice$/.test(x));
if (!lines.length) skip('no Android device');
const serial = (process.env.ANDROID_SERIAL || process.env.ADH_SERIAL || lines[0].split('\t')[0]);
const pidOut = spawnSync(adb, ['-s', serial, 'shell', 'pidof', 'com.adh.sandbox'], { encoding: 'utf8' });
if (!String(pidOut.stdout || '').trim()) skip('com.adh.sandbox is not running');
if (!agent) skip('no online com.adh.sandbox agent session');

await post('/api/java/hook', { session: agent.sessionId, action: 'unhook', hookId: 0 }).catch(() => null);
const hook = await post('/api/java/hook', {
  session: agent.sessionId,
  action: 'hook',
  className: 'com.adh.sandbox.HookProbe',
  method: 'ping',
  params: 'java.lang.String',
});
const hookError = String(hook.error ?? '');
if (!hook.ok && /lsplant not built|java hook backend not built|unsupported|unknown op/i.test(hookError)) {
  skip(`agent does not expose LSPlant java_hook: ${hookError}`);
}
if (!hook.ok) {
  console.log(JSON.stringify({ hook, hookError }));
  result('java_hook install', false);
  process.exit(0);
}

const bc = spawnSync(adb, ['-s', serial, 'shell', 'am', 'broadcast',
  '-a', 'com.adh.sandbox.HOOK_PROBE',
  '--es', 'value', 'ADH_HOOK_PING',
  '-n', 'com.adh.sandbox/.HookProbeReceiver'], { encoding: 'utf8' });
if (bc.status !== 0) {
  console.log(`broadcast failed: ${bc.stderr || bc.stdout}`);
  await post('/api/java/hook', { session: agent.sessionId, action: 'unhook', hookId: 0 }).catch(() => null);
  result('hook trigger broadcast', false);
  process.exit(0);
}

const hookId = Number(hook.hookId ?? 0);
let status = null;
for (let i = 0; i < 20; i++) {
  status = await post('/api/java/hook', { session: agent.sessionId, action: 'status' });
  const h = (status?.status?.hooks ?? []).find((x) => Number(x.id) === hookId);
  if (h?.hits >= 1) break;
  await sleep(100);
}
const st = (status?.status?.hooks ?? []).find((x) => Number(x.id) === hookId) ?? {};
let event = null;
for (let i = 0; i < 20; i++) {
  const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(agent.sessionId)}&limit=200`)).json();
  for (const found of (list.captures ?? []).filter((c) => c.func === 'JAVA_HOOK')) {
    const detail = await (await fetch(`${base}/api/captures/${found.id}`)).json();
    if (String(detail.text ?? '').includes('ADH_HOOK_PING') &&
        String(detail.text ?? '').includes('REAL_HOOK:ADH_HOOK_PING')) {
      event = detail;
      break;
    }
  }
  await sleep(100);
}
const instanceHook = await post('/api/java/hook', {
  session: agent.sessionId,
  action: 'hook',
  className: 'com.adh.sandbox.HookProbe',
  method: 'instancePing',
  params: 'java.lang.String',
  field: 'INSTANCE',
});
const instanceHookId = Number(instanceHook.hookId ?? 0);
let instanceStatus = null;
if (instanceHook.ok) {
  const ibc = spawnSync(adb, ['-s', serial, 'shell', 'am', 'broadcast',
    '-a', 'com.adh.sandbox.INSTANCE_HOOK_PROBE',
    '--es', 'value', 'ADH_INSTANCE_PING',
    '-n', 'com.adh.sandbox/.InstanceHookProbeReceiver'], { encoding: 'utf8' });
  if (ibc.status !== 0) console.log(`instance broadcast failed: ${ibc.stderr || ibc.stdout}`);
  for (let i = 0; i < 20; i++) {
    instanceStatus = await post('/api/java/hook', { session: agent.sessionId, action: 'status' });
    const h = (instanceStatus?.status?.hooks ?? []).find((x) => Number(x.id) === instanceHookId);
    if (h?.hits >= 1) break;
    await sleep(100);
  }
}
const ist = (instanceStatus?.status?.hooks ?? []).find((x) => Number(x.id) === instanceHookId) ?? {};
const alive = String(spawnSync(adb, ['-s', serial, 'shell', 'pidof', 'com.adh.sandbox'], { encoding: 'utf8' }).stdout || '').trim();
const unhookStatic = await post('/api/java/hook', { session: agent.sessionId, action: 'unhook', hookId: hookId }).catch(() => null);
const unhookInstance = instanceHookId > 0
  ? await post('/api/java/hook', { session: agent.sessionId, action: 'unhook', hookId: instanceHookId }).catch(() => null)
  : null;
const pass = hook.ok === true && hookId >= 1 &&
  st.hits >= 1 &&
  st.lastArg === 'ADH_HOOK_PING' &&
  st.lastReturn === 'REAL_HOOK:ADH_HOOK_PING' &&
  (st.lastError === '' || st.lastError == null) &&
  event != null &&
  instanceHook.ok === true && instanceHookId >= 1 &&
  ist.hits >= 1 &&
  ist.lastArg === 'ADH_INSTANCE_PING' &&
  ist.lastReturn === 'REAL_INSTANCE:ADH_INSTANCE_PING' &&
  (ist.lastError === '' || ist.lastError == null) &&
  unhookStatic?.ok === true &&
  unhookInstance?.ok === true &&
  alive.length > 0;
console.log(JSON.stringify({ hook, instanceHook, status, instanceStatus, event: event ? { id: event.id, func: event.func, algo: event.algo, op: event.op, preview: event.preview } : null, unhookStatic, unhookInstance, alive }));
result('java_hook static + instance + original + event stream + unhook', pass);
process.exit(0);
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.3 LSPlant java_hook PASS"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.3 LSPlant java_hook SKIP (new agent/sandbox not deployed yet)"
  exit 0
else
  echo "❌ v4.3 LSPlant java_hook FAIL"
  exit 1
fi