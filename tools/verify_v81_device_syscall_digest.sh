#!/usr/bin/env bash
# v4.43 device half: syscall_digest on a live libc uname site.
#
# The claim the whole watch exists for: given watched libc svc sites, name the code that ISSUED the
# syscall. The sandbox probe calls uname(2) through libc, so the digest must see samples, report the
# runtime x8 as 160 with no attribution mismatch, and put a caller outside libc (the fixture).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v81_device_syscall_digest (no device)"
  exit 0
fi
verify_restart_sandbox || { echo "FAIL  could not restart sandbox before syscall scan"; exit 1; }

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const skip = (msg) => { console.log('SKIP  verify_v81_device_syscall_digest (' + msg + ')'); console.log('RESULT:SKIP'); process.exit(0); };
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
if (ctl.body?.ok !== true) fail('positive control failed: adh_add_target is not callable (' + String(ctl.body?.error ?? ctl.status) + ') - resolver problem, not an old APK', ctl.body);

const watch = await post('/api/native/syscall_watch', { session, module: 'libc.so', syscalls: ['uname'], limit: 2 });
if (watch.status === 404 || /unknown|unsupported/i.test(String(watch.body?.error ?? ''))) skip('daemon predates syscall_watch');
if (Number(watch.body?.installedCount) < 1) fail('no uname svc site hooked in libc.so', watch.body);
const ids = (watch.body.hooks ?? []).map((h) => Number(h.hookId)).filter((n) => n > 0);
const expected = Object.fromEntries(ids.map((id) => [id, 160]));

const call = await unameProbe();
if (!call.body?.ok) fail('uname probe call failed: ' + String(call.body?.error ?? call.status), call.body);
await sleep(1800);   // let the capture loop drain the ring

const digest = await post('/api/syscall/digest', { session, hookIds: ids, expected, decode: true });
const d = digest.body ?? {};
const observedNr = (d.observed ?? []).map((o) => Number(o.nr));
const groups = d.groups ?? [];
console.log(`samples=${d.samples} groups=${groups.length} observed=${JSON.stringify(observedNr)} mismatches=${(d.mismatches ?? []).length} ringComplete=${d.ring?.complete} decoded=${d.decodedSamples}`);
for (const g of groups.slice(0, 3)) console.log(`  nr=${g.nr}(${g.name}) x${g.count} caller=${g.caller}`);

const namedCaller = /adh_libc_uname_probe/.test(JSON.stringify(groups));
const unhooked = [];
for (const id of ids) unhooked.push((await post('/api/native/hook', { session, action: 'unhook', hookId: id })).body?.ok === true);
const pass = Number(d.samples) >= 1
  && observedNr.includes(160)
  && (d.mismatches ?? []).length === 0
  && namedCaller
  && d.ring?.complete !== false
  && unhooked.every(Boolean)
  && (await alive()).length > 0;
if (!namedCaller) console.log('no group names the issuing fixture - the attribution never left libc');
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v4.43 syscall_digest on a device (caller outside libc, x8 vs attributed, no mismatch)" 0 && exit 0 || exit 1
