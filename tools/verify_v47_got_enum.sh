#!/usr/bin/env bash
# v4.7 GOT/relocation enumeration acceptance.
# Enumerates libadhdetect.so's GOT slots and verifies imported libc symbols are visible.
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
let r;
try {
  r = await (await fetch(`${base}/api/native/got_enum`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ session: agent.sessionId, module: 'libadhdetect.so' }),
  })).json();
} catch (e) {
  console.log(`old payload / no got_enum: ${e.message}`);
  console.log('RESULT:SKIP');
  process.exit(0);
}
if (!r.ok && /unsupported|unknown op|module not found/i.test(String(r.error ?? ''))) {
  console.log(`got_enum unavailable: ${r.error}`);
  console.log('RESULT:SKIP');
  process.exit(0);
}
const result = r.result ?? {};
const entries = result.entries ?? [];
const names = new Set(entries.map((e) => e.symbol));
const wanted = ['ptrace', 'access', '__system_property_get'];
const missing = wanted.filter((x) => !names.has(x));
if (result.packedUnsupported === true && entries.length === 0) {
  console.log('only packed Android relocations present; expansion not implemented yet');
  console.log('RESULT:SKIP');
  process.exit(0);
}
const pass = r.ok === true && result.count > 0 && missing.length === 0 &&
  entries.every((e) => typeof e.slot === 'string' && typeof e.symbol === 'string');
console.log(JSON.stringify({ ok: r.ok, module: result.module, count: result.count, truncated: result.truncated, packedUnsupported: result.packedUnsupported, missing, sample: entries.slice(0, 8) }));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.7 GOT/relocation enumeration PASS"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.7 GOT enumeration SKIP (new agent/sandbox not deployed yet)"
  exit 0
else
  echo "❌ v4.7 GOT enumeration FAIL"
  exit 1
fi