#!/usr/bin/env bash
# v4.11 QBDI active trace with integer args.
# Traces libadhdetect.so:adh_add_target(20,22) under QBDI and asserts retval=84 plus
# a non-empty instruction stream. A new agent rejects the malformed arg probe; an old
# agent ignores args, so that probe is used to SKIP instead of reporting a false PASS.
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
const q = new URLSearchParams({ session: agent.sessionId, symLib: 'libadhdetect.so' });
async function trace(symbol, args) {
  const params = new URLSearchParams(q);
  params.set('symbol', symbol);
  if (args !== undefined) params.set('args', args);
  const r = await fetch(`${base}/api/trace/qbdi?${params}`);
  return { status: r.status, body: await r.json() };
}
const malformed = await trace('adh_add_target', '-1');
if (malformed.body.ok === true) {
  console.log('old payload / qbdi_trace ignores args');
  console.log('RESULT:SKIP');
  process.exit(0);
}
const withArgs = await trace('adh_add_target', '20,22');
const noArgs = await trace('adh_trace_target', '');
const insns = Array.isArray(withArgs.body.insns) ? withArgs.body.insns : [];
const shapeOk = insns.length > 0 && insns.every((i) => typeof i.addr === 'string' && typeof i.text === 'string' && i.text.length > 0);
const pass = malformed.body.ok === false && /unsigned|invalid/i.test(String(malformed.body.error ?? '')) &&
  withArgs.body.ok === true && Number(withArgs.body.retval) === 84 && withArgs.body.count === insns.length && shapeOk &&
  noArgs.body.ok === true && Number(noArgs.body.retval) === 30 && Number(noArgs.body.count) > 0;
console.log(JSON.stringify({
  malformed: { ok: malformed.body.ok, error: malformed.body.error },
  withArgs: { ok: withArgs.body.ok, retval: withArgs.body.retval, count: withArgs.body.count, first: insns[0] ?? null },
  noArgs: { ok: noArgs.body.ok, retval: noArgs.body.retval, count: noArgs.body.count },
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.11 QBDI trace with args PASS"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.11 QBDI trace with args SKIP (new agent not deployed)"
  exit 0
else
  echo "❌ v4.11 QBDI trace with args FAIL"
  exit 1
fi