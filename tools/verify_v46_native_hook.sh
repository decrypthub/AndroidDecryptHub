#!/usr/bin/env bash
# v4.6 Native hook manager acceptance.
# Installs an inline hook on libadhdetect.so:adh_trace_target, triggers it through JNI,
# checks the register event and status hit count, then unhooks. SKIPs on old payloads.
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
function serialArgs(args) {
  const s = process.env.ANDROID_SERIAL || process.env.ADH_SERIAL || '';
  return s ? ['-s', s, ...args] : args;
}
async function post(path, body) {
  const r = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return r.json();
}
function skip(reason) { console.log(reason); console.log('RESULT:SKIP'); process.exit(0); }

const agents = await (await fetch(`${base}/api/agents`)).json();
const agent = agents.filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0];
if (!agent) skip('NO_AGENT');
const dev = spawnSync(adb, serialArgs(['devices']), { encoding: 'utf8' });
const line = String(dev.stdout || '').split(/\r?\n/).find((x) => /\tdevice$/.test(x));
if (!line) skip('no Android device');
const serial = process.env.ANDROID_SERIAL || process.env.ADH_SERIAL || line.split('\t')[0];
const pid = String(spawnSync(adb, ['-s', serial, 'shell', 'pidof', 'com.adh.sandbox'], { encoding: 'utf8' }).stdout || '').trim();
if (!pid) skip('com.adh.sandbox is not running');

await post('/api/native/hook', { session: agent.sessionId, action: 'unhook', hookId: 0 }).catch(() => null);
let hook;
try {
  hook = await post('/api/native/hook', {
    session: agent.sessionId, action: 'hook', mode: 'inline',
    module: 'libadhdetect.so', symbol: 'adh_trace_target',
  });
} catch (e) { skip(`old payload / no native_hook: ${e.message}`); }
const hookErr = String(hook.error ?? '');
if (!hook.ok && /unsupported|unknown op/i.test(hookErr)) skip(`old payload / no native_hook: ${hookErr}`);
if (!hook.ok) {
  if (/symbol not found|not found/i.test(hookErr)) skip(`libadhdetect target unavailable: ${hookErr}`);
  console.log(JSON.stringify({ hook }));
  console.log('RESULT:FAIL');
  process.exit(0);
}
const hookId = Number(hook.hookId ?? 0);
const bc = spawnSync(adb, ['-s', serial, 'shell', 'am', 'broadcast',
  '-a', 'com.adh.sandbox.NATIVE_HOOK_PROBE',
  '-n', 'com.adh.sandbox/.NativeHookProbeReceiver'], { encoding: 'utf8' });
if (bc.status !== 0) {
  await post('/api/native/hook', { session: agent.sessionId, action: 'unhook', hookId: hookId }).catch(() => null);
  console.log(`broadcast failed: ${bc.stderr || bc.stdout}`);
  console.log('RESULT:FAIL');
  process.exit(0);
}
let status = null;
let event = null;
for (let i = 0; i < 20; i++) {
  status = await post('/api/native/hook', { session: agent.sessionId, action: 'status' });
  const h = (status?.status?.hooks ?? []).find((x) => Number(x.id) === hookId);
  if (h?.hits >= 1) {
    const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(agent.sessionId)}&limit=300`)).json();
    for (const found of (list.captures ?? []).filter((c) => c.func === 'NATIVE_HOOK')) {
      const detail = await (await fetch(`${base}/api/captures/${found.id}`)).json();
      if (String(detail.text ?? '').includes(`"hookId":${hookId}`)) { event = detail; break; }
    }
  }
  if (event) break;
  await sleep(100);
}
const h = (status?.status?.hooks ?? []).find((x) => Number(x.id) === hookId) ?? {};
const alive = String(spawnSync(adb, ['-s', serial, 'shell', 'pidof', 'com.adh.sandbox'], { encoding: 'utf8' }).stdout || '').trim();
const unhook = await post('/api/native/hook', { session: agent.sessionId, action: 'unhook', hookId: hookId }).catch(() => null);
const pass = hook.ok === true && hookId >= 1 && h.hits >= 1 && event != null && unhook?.ok === true && alive.length > 0;
console.log(JSON.stringify({ hook, status, event: event ? { id: event.id, func: event.func, algo: event.algo, op: event.op, preview: event.preview } : null, unhook, alive }));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.6 native hook install/trigger/register-event/unhook PASS"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.6 native hook SKIP (new agent/sandbox not deployed yet)"
  exit 0
else
  echo "❌ v4.6 native hook FAIL"
  exit 1
fi