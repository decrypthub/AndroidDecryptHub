#!/usr/bin/env bash
# v4.5 Java active-call acceptance.
# Calls two overloads of com.adh.sandbox.HookProbe.ping with typed JSON arguments.
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
async function call(className, method, params, args) {
  return await (await fetch(`${base}/api/java/call`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ session: agent.sessionId, className, method, params, args }),
  })).json();
}
let one, two;
try {
  one = await call('com.adh.sandbox.HookProbe', 'ping', 'java.lang.String', ['ADH_CALL_ONE']);
  two = await call('com.adh.sandbox.HookProbe', 'ping', 'java.lang.String,int', ['ADH_CALL_TWO', 3]);
} catch (e) {
  console.log(`old payload / no java_call: ${e.message}`);
  console.log('RESULT:SKIP');
  process.exit(0);
}
if (!one.ok && /unsupported|unknown op/i.test(String(one.error ?? ''))) {
  console.log(`old payload / no java_call: ${one.error}`);
  console.log('RESULT:SKIP');
  process.exit(0);
}
const oneResult = one.result?.result ?? '';
const twoResult = two.result?.result ?? '';
const pass = one.ok === true && two.ok === true &&
  oneResult === 'REAL_HOOK:ADH_CALL_ONE' &&
  twoResult === 'REAL_HOOK:ADH_CALL_TWO*3';
console.log(JSON.stringify({ one, two, oneResult, twoResult }));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.5 Java active call PASS"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.5 Java active call SKIP (new agent/sandbox not deployed yet)"
  exit 0
else
  echo "❌ v4.5 Java active call FAIL"
  exit 1
fi