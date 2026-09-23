#!/usr/bin/env bash
# v4.47 device half: the one-shot syscall_trace chain (start -> trigger -> digest -> stop).
#
# Same evidence as v81, through the tool that threads the static attribution itself: if the expected
# {hookId: nr} map did not survive the round trip, the digest reports a mismatch instead of a label.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v85_device_syscall_trace (no device)"
  exit 0
fi
verify_restart_sandbox || { echo "FAIL  could not restart sandbox before syscall scan"; exit 1; }

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const skip = (msg) => { console.log('SKIP  verify_v85_device_syscall_trace (' + msg + ')'); console.log('RESULT:SKIP'); process.exit(0); };
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
const ctl = await control();
if (ctl.body?.ok !== true) fail('positive control failed: adh_add_target is not callable (' + String(ctl.body?.error ?? ctl.status) + ')', ctl.body);

const start = await post('/api/syscall/trace', { session, action: 'start', module: 'libc.so', syscalls: ['uname'], limit: 2 });
if (start.status === 404 || /action must be/i.test(String(start.body?.error ?? ''))) skip('daemon predates syscall_trace');
if (!start.body?.hookIds?.length) fail('syscall_trace start installed nothing: ' + String(start.body?.error ?? ''), start.body);
const ids = start.body.hookIds.map(Number);
const expected = start.body.expected ?? {};
console.log(`start: hookIds=${JSON.stringify(ids)} expected=${JSON.stringify(expected)} svcCount=${start.body.svcCount} unattributed=${(start.body.unattributed ?? []).length}`);

const call = await unameProbe();
if (!call.body?.ok) fail('uname probe call failed: ' + String(call.body?.error ?? call.status), call.body);
await sleep(1800);

const digest = await post('/api/syscall/trace', { session, action: 'digest', hookIds: ids, expected });
const d = digest.body?.digest ?? {};
const groups = d.groups ?? [];
console.log(`digest: samples=${d.samples} groups=${groups.length} observed=${JSON.stringify((d.observed ?? []).map((o) => o.nr))} mismatches=${(d.mismatches ?? []).length} ringComplete=${d.ring?.complete}`);
for (const g of groups.slice(0, 3)) console.log(`  nr=${g.nr}(${g.name}) x${g.count} caller=${g.caller}`);

const stop = await post('/api/syscall/trace', { session, action: 'stop', hookIds: ids });
const pass = Number(d.samples) >= 1
  && (d.mismatches ?? []).length === 0
  && /adh_libc_uname_probe/.test(JSON.stringify(groups))
  && d.ring?.complete !== false
  && stop.body?.ok === true
  && (await alive()).length > 0;
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v4.47 syscall_trace on a device (threaded attribution, caller outside libc, stop)" 0 && exit 0 || exit 1
