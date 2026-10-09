#!/usr/bin/env bash
# v4.15 Native hook argument rewrite / skip-original / return override acceptance.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${ADH_HTTP_PORT:-8088}"
set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const agents = await (await fetch(`${base}/api/agents`)).json();
const agent = agents.filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0];
if (!agent) { console.log('NO_AGENT'); console.log('RESULT:SKIP'); process.exit(0); }
async function post(path, body) {
  const r = await fetch(`${base}${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  return r.json();
}
const session = agent.sessionId;
const symbol = 'adh_add_target';
await post('/api/native/hook', { session, action: 'unhook', hookId: 0 }).catch(() => null);
const argHook = await post('/api/native/hook', {
  session, action: 'hook', mode: 'inline', module: 'libadhdetect.so', symbol,
  argIndex: 0, argValue: '7',
});
const argId = Number(argHook.hookId ?? 0);
const argStatus = await post('/api/native/hook', { session, action: 'status' });
const argSt = (argStatus?.status?.hooks ?? []).find((x) => Number(x.id) === argId) ?? {};
if (typeof argSt.argIndex === 'undefined') {
  await post('/api/native/hook', { session, action: 'unhook', hookId: argId }).catch(() => null);
  console.log('old payload / native_hook has no rewrite fields');
  console.log('RESULT:SKIP');
  process.exit(0);
}
const argCall = await post('/api/native/call', { session, module: 'libadhdetect.so', symbol, args: ['1', '2'], confirm: true });
const argUnhook = await post('/api/native/hook', { session, action: 'unhook', hookId: argId });
const skipHook = await post('/api/native/hook', {
  session, action: 'hook', mode: 'inline', module: 'libadhdetect.so', symbol,
  skipOriginal: true, returnValue: '0x54',
});
const skipId = Number(skipHook.hookId ?? 0);
const skipCall = await post('/api/native/call', { session, module: 'libadhdetect.so', symbol, args: ['1', '2'], confirm: true });
const skipStatus = await post('/api/native/hook', { session, action: 'status' });
const skipSt = (skipStatus?.status?.hooks ?? []).find((x) => Number(x.id) === skipId) ?? {};
const skipUnhook = await post('/api/native/hook', { session, action: 'unhook', hookId: skipId });
const alive = (await (await fetch(`${base}/api/agents`)).json()).some((x) => x.online && x.package === 'com.adh.sandbox');
const pass = argHook.ok === true && argId >= 1 && argCall.ok === true && Number(argCall.resultDecimal) === 18 &&
  argUnhook.ok === true && skipHook.ok === true && skipId >= 1 && skipCall.ok === true &&
  Number(skipCall.resultDecimal) === 84 && skipSt.hits >= 1 && skipSt.skipOriginal === true &&
  skipSt.returnSet === true && skipSt.returnValue === '0x54' && skipUnhook.ok === true && alive;
console.log(JSON.stringify({ argHook, argStatus: argSt, argCall: { ok: argCall.ok, result: argCall.resultDecimal }, argUnhook: argUnhook.ok,
  skipHook, skipStatus: skipSt, skipCall: { ok: skipCall.ok, result: skipCall.resultDecimal }, skipUnhook: skipUnhook.ok, alive }));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.15 native rewrite/skip/return PASS"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.15 native rewrite/skip/return SKIP (new agent not deployed)"
  exit 0
else
  echo "❌ v4.15 native rewrite/skip/return FAIL"
  exit 1
fi