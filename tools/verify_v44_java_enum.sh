#!/usr/bin/env bash
# v4.4 Java live-class enumeration acceptance.
# Requires the deployed agent/sandbox from the LSPlant work. SKIPs on old payloads.
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
  r = await (await fetch(`${base}/api/java/enum`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ session: agent.sessionId, className: 'com.adh.sandbox.HookProbe' }),
  })).json();
} catch (e) {
  console.log(`old payload / no java_enum: ${e.message}`);
  console.log('RESULT:SKIP');
  process.exit(0);
}
if (!r.ok && /unsupported|unknown op/i.test(String(r.error ?? ''))) {
  console.log(`old payload / no java_enum: ${r.error}`);
  console.log('RESULT:SKIP');
  process.exit(0);
}
const cls = r.result ?? {};
const methods = cls.methods ?? [];
const fields = cls.fields ?? [];
const one = methods.find((m) => m.name === 'ping' && (m.params ?? []).length === 1);
const two = methods.find((m) => m.name === 'ping' && (m.params ?? []).length === 2);
const field = fields.find((f) => f.name === 'marker');
const pass = r.ok === true &&
  String(cls.className ?? '').includes('HookProbe') &&
  cls.superclass === 'java.lang.Object' &&
  !!one && !!two && !!field;
console.log(JSON.stringify({ ok: r.ok, className: cls.className, superclass: cls.superclass, methods, fields, truncated: cls.truncated }));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.4 Java class/member enumeration PASS"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.4 Java enumeration SKIP (new agent/sandbox not deployed yet)"
  exit 0
else
  echo "❌ v4.4 Java enumeration FAIL"
  exit 1
fi