#!/usr/bin/env bash
# v4.48 device half: the per-hook event throttle must thin the stream WITHOUT changing behaviour.
#
# Two things are asserted together, because either one alone can look fine while the other is broken:
#   (1) the accounting identity hits = emitted events + throttled holds on a real hook, and
#   (2) a hook that rewrites the return value still rewrites EVERY hit, throttled or not (the
#       throttle may only suppress the EVENT, never the effect).
# Needs: a sandbox agent, the libadhdetect fixture (adh_trace_target), native_hook + native_call.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v86_device_throttle (no device)"
  exit 0
fi

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const skip = (msg) => { console.log('SKIP  verify_v86_device_throttle (' + msg + ')'); console.log('RESULT:SKIP'); process.exit(0); };
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

const MODULE = 'libadhdetect.so';
const SYMBOL = 'adh_trace_target';
const THROTTLE = 200;
const FORCED = 0x1234;   // 4660 decimal: what every call must return while the rewrite is installed

// A hook with a forced return AND a throttle: the rewrite must not be throttled.
const hook = await post('/api/native/hook', {
  session, action: 'hook', mode: 'inline', module: MODULE, symbol: SYMBOL,
  returnValue: `0x${FORCED.toString(16)}`, throttleMs: THROTTLE,
});
const hookErr = String(hook.body?.error ?? '');
if (!hook.body?.ok) {
  if (/unsupported|unknown op/i.test(hookErr)) skip('agent predates native_hook: ' + hookErr);
  if (/symbol not found|module not found|not found/i.test(hookErr)) skip('fixture unavailable: ' + hookErr);
  fail('hook install failed: ' + hookErr, hook.body);
}
const hookId = Number(hook.body.hookId ?? 0);
if (!(hookId >= 1)) fail('hook installed without a hookId', hook.body);

const N = 20;
let forcedOk = 0;
for (let i = 0; i < N; i++) {
  const r = await post('/api/native/call', { session, module: MODULE, symbol: SYMBOL, args: '', confirm: true });
  if (!r.body?.ok) fail('native_call failed at iteration ' + i + ': ' + String(r.body?.error ?? r.status));
  // Field-name agnostic on purpose: the forced value must appear in the reply whatever the agent
  // calls the return slot.
  if (JSON.stringify(r.body).includes(String(FORCED))) forcedOk++;
}
const st1 = await post('/api/native/hook', { session, action: 'status' });
const h1 = (st1.body?.status?.hooks ?? []).find((x) => Number(x.id) === hookId) ?? {};
await sleep(1800);   // let the daemon drain the ring so the emitted events are countable
const st2 = await post('/api/native/hook', { session, action: 'status' });
const h2 = (st2.body?.status?.hooks ?? []).find((x) => Number(x.id) === hookId) ?? {};

const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=500`)).json().catch(() => ({}));
let emitted = 0;
for (const c of (list.captures ?? []).filter((x) => x.func === 'NATIVE_HOOK')) {
  const d = await (await fetch(`${base}/api/captures/${c.id}`)).json().catch(() => null);
  if (String(d?.text ?? '').includes(`"hookId":${hookId}`)) emitted++;
}
const unhook = await post('/api/native/hook', { session, action: 'unhook', hookId });
const alive = String((await import('node:child_process')).spawnSync('adb', ['-s', process.env.ANDROID_SERIAL || process.env.ADH_SERIAL || '', 'shell', 'pidof', 'com.adh.sandbox'], { encoding: 'utf8' }).stdout || '').trim();

const hits = Number(h2.hits ?? 0);
const throttled = Number(h2.throttled ?? 0);
console.log(`hook=${hookId} throttleMs=${h2.throttleMs} hits=${hits} throttled=${throttled} emitted=${emitted} forcedReturn=${forcedOk}/${N}`);
console.log(`status reads: throttled ${Number(h1.throttled ?? 0)} -> ${throttled} (must not go backwards)`);
const identityOk = emitted >= 1 && emitted + throttled === hits;
const pass = Number(h2.throttleMs) === THROTTLE
  && hits >= N
  && throttled > 0
  && identityOk
  && throttled >= Number(h1.throttled ?? 0)
  && forcedOk === N
  && unhook.body?.ok === true
  && alive.length > 0;
if (!identityOk) console.log(`❌ identity violated: emitted(${emitted}) + throttled(${throttled}) != hits(${hits})`);
if (forcedOk !== N) console.log(`❌ the return rewrite was throttled: only ${forcedOk}/${N} calls returned 0x${FORCED.toString(16)}`);
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v4.48 native event throttle (hits = emitted + throttled, rewrite never throttled)" 0 && exit 0 || exit 1
