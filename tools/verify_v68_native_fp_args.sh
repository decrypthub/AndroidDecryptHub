#!/usr/bin/env bash
# v4.31 native FP/SIMD argument support acceptance.
#   * native_call with typed args f:<float> / d:<double> places them in the FP register bank
#     (AAPCS64 keeps x0-x7 and d0-d7 independent), reports the d0 / s0 return, and still refuses
#     unknown argument types;
#   * an inline hook on the same function reports the FP argument registers (s0=2.5, d1=4) next to
#     the integer registers in its NATIVE_HOOK event, so float/double arguments are visible in traces.
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
const session = agent.sessionId;
async function post(path, body) {
  const r = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
}
const call = async (symbol, args) => (await post('/api/native/call', {
  session, module: 'libadhdetect.so', symbol, args, confirm: true,
})).body;
// doubles: 11.0 = 0x4026000000000000, 6.0 = 0x4018000000000000; float 11.0f = 0x41300000.
const plain = await call('adh_fp_target', ['f:2.5', 'd:4', '1']);
const mixed = await call('adh_fp_target', ['f:1.5', 'd:2', '3']);   // typed to the signature: 1.5*2+3 = 6.0
const fret = await call('adh_fp_target_f', ['f:2.5', 'd:4', '1']);
const bad = await call('adh_fp_target', ['x:1.5']);
const intOnly = await call('adh_add_target', ['20', '22']);
// hook the same function and check the FP argument capture
const hook = await post('/api/native/hook', { session, action: 'hook', hookId: 0, mode: 'inline', module: 'libadhdetect.so', symbol: 'adh_fp_target' });
const hookId = Number(hook.body.hookId);
const hooked = await call('adh_fp_target', ['f:2.5', 'd:4', '1']);
let event = null;
for (let i = 0; i < 20 && !event; i++) {
  const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=400`)).json();
  for (const c of (list.captures ?? []).filter((x) => x.func === 'NATIVE_HOOK')) {
    const detail = await (await fetch(`${base}/api/captures/${c.id}`)).json();
    const text = String(detail.text ?? '');
    if (text.includes(`"hookId":${hookId}`) && text.includes('"s0":"2.5"') && text.includes('"d1":"4"') && text.includes('"x0":"0x1"')) {
      event = { id: c.id, text }; break;
    }
  }
  if (event) break;
  await sleep(120);
}
const unhook = await post('/api/native/hook', { session, action: 'unhook', hookId });
const afterUnhook = await call('adh_fp_target', ['f:2.5', 'd:4', '1']);
const alive = (await (await fetch(`${base}/api/agents`)).json()).some((x) => x.online && x.package === 'com.adh.sandbox');
const close = (a, b) => Math.abs(Number(a) - Number(b)) < 1e-9;
const pass = plain.ok === true && plain.fpSupported === true && Number(plain.fpArgCount) === 2 && Number(plain.intArgCount) === 1 &&
  plain.fpResult === '0x4026000000000000' && close(plain.fpResultDouble, 11.0) && plain.returnBank === 'd0' &&
  mixed.ok === true && mixed.fpResult === '0x4018000000000000' && close(mixed.fpResultDouble, 6.0) &&
  fret.ok === true && close(fret.fpResultFloat, 11.0) && String(fret.fpResult).endsWith('41300000') &&
  bad.ok === false && /unknown argument type/.test(String(bad.error)) &&
  intOnly.ok === true && Number(intOnly.resultDecimal) === 84 &&
  hook.body.ok === true && hooked.ok === true && close(hooked.fpResultDouble, 11.0) &&
  event != null && unhook.body.ok === true && close(afterUnhook.fpResultDouble, 11.0) && alive;
console.log(JSON.stringify({
  plain: { fpResult: plain.fpResult, fpResultDouble: plain.fpResultDouble, fpArgCount: plain.fpArgCount, intArgCount: plain.intArgCount, returnBank: plain.returnBank, error: plain.error },
  mixed: { fpResult: mixed.fpResult, fpResultDouble: mixed.fpResultDouble, error: mixed.error },
  floatReturn: { fpResult: fret.fpResult, fpResultFloat: fret.fpResultFloat, error: fret.error },
  badArg: { ok: bad.ok, error: bad.error },
  intOnly: { resultDecimal: intOnly.resultDecimal, error: intOnly.error },
  hookId, hooked: { fpResultDouble: hooked.fpResultDouble, error: hooked.error },
  event: event && event.text, unhook: unhook.body.ok, afterUnhook: afterUnhook.fpResultDouble, alive,
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.31 native FP/SIMD argument support PASS"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.31 native FP/SIMD argument support SKIP (new agent/sandbox not deployed)"
  exit 0
else
  echo "❌ v4.31 native FP/SIMD argument support FAIL"
  exit 1
fi