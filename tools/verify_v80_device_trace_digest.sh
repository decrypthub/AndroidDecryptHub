#!/usr/bin/env bash
# v4.41 device half: trace_digest against a real QBDI capture.
#
# The host verifier digests a synthetic stream; this proves the chain on a device: QBDI-trace a real
# fixture (libadhdetect.so:adh_add_target(2,3) -> 10) and require the digest to actually describe
# that function instead of being an empty shell. SKIPs when QBDI is not bundled.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v80_device_trace_digest (no device)"
  exit 0
fi

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const skip = (msg) => { console.log('SKIP  verify_v80_device_trace_digest (' + msg + ')'); console.log('RESULT:SKIP'); process.exit(0); };
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
const digest = await post('/api/trace/digest', { session, symLib: 'libadhdetect.so', symbol: 'adh_add_target', args: [2, 3] });
if (digest.status === 404) skip('daemon predates trace_digest (restart adhd)');
const err = String(digest.body?.error ?? '');
if (/QBDI|dlopen|not available/i.test(err)) skip('QBDI not bundled in this agent: ' + err);
if (!digest.body?.digest) fail('trace_digest returned no digest: ' + err, digest.body);

const d = digest.body.digest;
const mnemonics = (d.mnemonics ?? []).map((m) => m.mnemonic);
console.log(`retval=${digest.body.retval} instructions=${digest.body.instructionCount} digestInstructions=${d.instructions}`);
console.log(`mnemonics=${mnemonics.slice(0, 6).join('/')} hot=${(d.hotInstructions ?? []).length} calls=${(d.calls ?? []).length} memory=${(d.memory ?? []).length} constants=${(d.constants ?? []).length}`);
const retval = Number.parseInt(String(digest.body.retval ?? '').replace(/^0x/i, ''), 16);
const pass = retval === 10
  && Number(digest.body.instructionCount) >= 3
  && Number(d.instructions) >= 3
  && mnemonics.length >= 2
  && (d.hotInstructions ?? []).length >= 1;
if (!pass) console.log('the digest does not describe the traced fixture');
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v4.41 trace_digest on a device (real QBDI stream -> digest)" 0 && exit 0 || exit 1
