#!/usr/bin/env bash
# v4.45 device half: java_trace on a live class.
#
# start (hook the class method with stack:true) -> trigger through the sandbox call chain
# (stackOuter -> stackMiddle -> ping) -> digest: per-method counts, a caller histogram naming the app
# frames and a non-empty timeline - then stop and require the process to stay alive.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v83_device_java_trace (no device)"
  exit 0
fi

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const skip = (msg) => { console.log('SKIP  verify_v83_device_java_trace (' + msg + ')'); console.log('RESULT:SKIP'); process.exit(0); };
const fail = (msg, extra) => { if (extra !== undefined) console.log(JSON.stringify(extra)); console.log('FAIL ' + msg); console.log('RESULT:FAIL'); process.exit(0); };
async function post(path, body) {
  const r = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  let parsed = null; try { parsed = await r.json(); } catch { parsed = null; }
  return { status: r.status, body: parsed };
}
const agents = await (await fetch(`${base}/api/agents`)).json().catch(() => null);
const agent = (Array.isArray(agents) ? agents : []).filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((a, b) => (b.connectedAt ?? 0) - (a.connectedAt ?? 0))[0];
if (!agent) skip('no online sandbox agent');
const session = agent.sessionId;
// The sandbox fixture that issues uname(2) through libc; the positive control below proves symbol
// resolution works, so a missing fixture is an old APK rather than a resolver bug.
const unameProbe = () => post('/api/native/call', { session, module: 'libadhdetect.so', symbol: 'adh_libc_uname_probe', args: [], confirm: true });
const control = () => post('/api/native/call', { session, module: 'libadhdetect.so', symbol: 'adh_add_target', args: ['2', '3'], confirm: true });
const alive = async () => {
  const { spawnSync } = await import('node:child_process');
  const serial = process.env.ANDROID_SERIAL || process.env.ADH_SERIAL || '';
  return String(spawnSync('adb', ['-s', serial, 'shell', 'pidof', 'com.adh.sandbox'], { encoding: 'utf8' }).stdout || '').trim();
};
const CLASS = 'com.adh.sandbox.HookProbe';
const start = await post('/api/java/trace', { session, action: 'start', className: CLASS, method: 'ping', stack: true, limit: 4 });
if (start.status === 404 || /requires action/i.test(String(start.body?.error ?? ''))) skip('agent/daemon predates java_trace');
const startErr = String(start.body?.error ?? '');
if (/unsupported|unknown op/i.test(startErr)) skip('agent predates java_trace: ' + startErr);
if (!start.body?.hookIds?.length) {
  if (/not built|java hook backend/i.test(startErr)) skip('java hook backend not built: ' + startErr);
  fail('java_trace start installed no hooks: ' + startErr, start.body);
}
const ids = start.body.hookIds.map(Number).filter((n) => n > 0);

// stackOuter(input: String): the params spec is part of the request, otherwise the agent looks for
// a no-arg overload that does not exist ("target method not found: ...stackOuter()").
const call = await post('/api/java/call', { session, className: CLASS, method: 'stackOuter', params: 'java.lang.String', args: ['ADH_JT'] });
if (call.body?.ok !== true) fail('java_call of the fixture failed: ' + String(call.body?.error ?? call.status), call.body);
await sleep(500);

const digest = await post('/api/java/trace', { session, action: 'digest', hookIds: ids, sinceCaptureId: start.body.cursor });
const d = digest.body?.digest ?? {};
const methods = d.methods ?? [];
const callers = d.callers ?? [];
console.log(`samples=${d.samples} empty=${d.empty} complete=${d.complete} methods=${methods.length} timeline=${(d.timeline ?? []).length} callers=${callers.length} drainOk=${digest.body?.drain?.ok} ringComplete=${digest.body?.ring?.complete}`);
for (const m of methods.slice(0, 3)) console.log(`  ${m.target} x${m.count} lastArg=${m.lastArg} lastReturn=${m.lastReturn} errors=${m.errorCount}`);
for (const c of callers.slice(0, 3)) console.log(`  caller ${c.caller} x${c.count}`);

const stop = await post('/api/java/trace', { session, action: 'stop', hookIds: ids });
const callerText = JSON.stringify(callers);
const namedFrames = /stackMiddle|stackOuter/.test(callerText);
const pass = Number(d.samples) >= 1
  && d.complete !== false
  && methods.length >= 1
  && Number(methods[0]?.count ?? 0) >= 1
  && (d.timeline ?? []).length >= 1
  && namedFrames
  && stop.body?.ok === true
  && (await alive()).length > 0;
if (!namedFrames) console.log('the caller histogram does not name the app frames (stack:true should have captured them)');
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v4.45 java_trace on a device (per-method counts + caller chain + stop)" 0 && exit 0 || exit 1
