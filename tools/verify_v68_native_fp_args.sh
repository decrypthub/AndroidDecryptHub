#!/usr/bin/env bash
# v4.31 native FP/SIMD argument support acceptance.
#   * native_call with typed args f:<float> / d:<double> places them in the FP register bank
#     (AAPCS64 keeps x0-x7 and d0-d7 independent), reports the d0 / s0 return and still refuses
#     malformed input instead of guessing;
#   * a non-commutative fixture pair proves the FIRST typed argument really lands in the first FP
#     register in either order, and a float32-rounding probe proves the width of "f:";
#   * an inline hook on the same function reports the FP argument registers (s0=2.5, d1=4) next to
#     the integer registers in its NATIVE_HOOK event, and stops emitting events after unhook.
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
const hookEvents = async (id) => {
  const out = [];
  const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=400`)).json();
  for (const c of (list.captures ?? []).filter((x) => x.func === 'NATIVE_HOOK')) {
    const detail = await (await fetch(`${base}/api/captures/${c.id}`)).json();
    const text = String(detail.text ?? '');
    if (text.includes(`"hookId":${id}`)) out.push({ id: c.id, text });
  }
  return out;
};
// doubles: 11.0 = 0x4026000000000000, 6.0 = 0x4018000000000000, 291.0 = 0x4072300000000000;
// float 11.0f = 0x41300000; quiet NaN double = 0x7ff8000000000000.
const plain = await call('adh_fp_target', ['f:2.5', 'd:4', '1']);
const mixed = await call('adh_fp_target', ['f:1.5', 'd:2', '3']);   // typed to the signature: 1.5*2+3 = 6.0
const fret = await call('adh_fp_target_f', ['f:2.5', 'd:4', '1']);
const orderFd = await call('adh_fp_order_fd', ['f:2.5', 'd:4', '1']);
const orderDf = await call('adh_fp_order_df', ['d:2.5', 'f:4', '1']);
const mix = await call('adh_fp_mix', ['f:0.1', 'd:2']);
const nan = await call('adh_fp_nan', ['d:1']);
const intOnly = await call('adh_add_target', ['20', '22']);
const badType = await call('adh_fp_target', ['x:1.5']);
const badEmpty = await call('adh_fp_target', ['1', '', '2']);
const badIntRange = await call('adh_fp_target', ['99999999999999999999999']);
const badFloatRange = await call('adh_fp_target', ['d:1e9999']);
const tooManyFp = await call('adh_fp_target', ['f:1', 'f:2', 'f:3', 'f:4', 'f:5', 'f:6', 'f:7', 'f:8', 'f:9']);
const tooManyInt = await call('adh_fp_target', ['1', '2', '3', '4', '5', '6', '7', '8', '9']);
// hook the same function and check the FP argument capture
const hook = await post('/api/native/hook', { session, action: 'hook', hookId: 0, mode: 'inline', module: 'libadhdetect.so', symbol: 'adh_fp_target' });
const hookId = Number(hook.body.hookId);
const hooked = await call('adh_fp_target', ['f:2.5', 'd:4', '1']);
let event = null;
for (let i = 0; i < 20 && !event; i++) {
  for (const e of await hookEvents(hookId)) {
    if (e.text.includes('"s0":"2.5"') && e.text.includes('"d1":"4"') && e.text.includes('"x0":"0x1"')) { event = e; break; }
  }
  if (event) break;
  await sleep(120);
}
const unhook = await post('/api/native/hook', { session, action: 'unhook', hookId });
// A soft unhook deactivates the slot: the call must still work, but it must not add a NEW event.
// The capture ring keeps the earlier records, so compare the count around a fresh call.
const eventsAtUnhook = (await hookEvents(hookId)).length;
const afterUnhook = await call('adh_fp_target', ['f:2.5', 'd:4', '1']);
await sleep(400);
const eventsAfterUnhook = (await hookEvents(hookId)).length;
const alive = (await (await fetch(`${base}/api/agents`)).json()).some((x) => x.online && x.package === 'com.adh.sandbox');
const close = (a, b, eps = 1e-9) => Math.abs(Number(a) - Number(b)) < eps;
const pass = plain.ok === true && plain.fpSupported === true && Number(plain.fpArgCount) === 2 && Number(plain.intArgCount) === 1 &&
  plain.fpResult === '0x4026000000000000' && close(plain.fpResultDouble, 11.0) && plain.returnBank === 'd0' && plain.x0MayBeStale === true &&
  mixed.ok === true && mixed.fpResult === '0x4018000000000000' && close(mixed.fpResultDouble, 6.0) &&
  fret.ok === true && close(fret.fpResultFloat, 11.0) && String(fret.fpResult).endsWith('41300000') &&
  orderFd.ok === true && orderFd.fpResult === '0x4072300000000000' && close(orderFd.fpResultDouble, 291.0) &&
  orderDf.ok === true && orderDf.fpResult === '0x4072300000000000' && close(orderDf.fpResultDouble, 291.0) &&
  mix.ok === true && mix.fpResult === '0x4059800006400000' && close(mix.fpResultDouble, Math.fround(0.1) * 1000 + 2, 1e-12) &&
  nan.ok === true && nan.fpResult === '0x7ff8000000000000' && nan.fpResultDouble === null &&
  intOnly.ok === true && Number(intOnly.resultDecimal) === 84 &&
  badType.ok === false && /unknown argument type/.test(String(badType.error)) &&
  badEmpty.ok === false && /empty argument/.test(String(badEmpty.error)) &&
  badIntRange.ok === false && /out of range/.test(String(badIntRange.error)) &&
  badFloatRange.ok === false && /out of range/.test(String(badFloatRange.error)) &&
  tooManyFp.ok === false && /at most 8/.test(String(tooManyFp.error)) &&
  tooManyInt.ok === false && /at most 8/.test(String(tooManyInt.error)) &&
  hook.body.ok === true && hooked.ok === true && close(hooked.fpResultDouble, 11.0) &&
  event != null && unhook.body.ok === true && close(afterUnhook.fpResultDouble, 11.0) &&
  eventsAtUnhook >= 1 && eventsAfterUnhook === eventsAtUnhook && alive;
console.log(JSON.stringify({
  plain: { fpResult: plain.fpResult, fpResultDouble: plain.fpResultDouble, returnBank: plain.returnBank, x0MayBeStale: plain.x0MayBeStale },
  mixed: { fpResult: mixed.fpResult, fpResultDouble: mixed.fpResultDouble },
  floatReturn: { fpResult: fret.fpResult, fpResultFloat: fret.fpResultFloat },
  orderFd: { fpResult: orderFd.fpResult, value: orderFd.fpResultDouble },
  orderDf: { fpResult: orderDf.fpResult, value: orderDf.fpResultDouble },
  mixFloatWidth: { value: mix.fpResultDouble },
  nanReturn: { fpResult: nan.fpResult, fpResultDouble: nan.fpResultDouble },
  intOnly: { resultDecimal: intOnly.resultDecimal },
  rejects: { type: badType.error, empty: badEmpty.error, intRange: badIntRange.error, floatRange: badFloatRange.error, fp9: tooManyFp.error, int9: tooManyInt.error },
  hookId, hooked: { fpResultDouble: hooked.fpResultDouble },
  event: event && event.text, unhook: unhook.body.ok, afterUnhook: afterUnhook.fpResultDouble,
  eventsAtUnhook, eventsAfterUnhook, alive,
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