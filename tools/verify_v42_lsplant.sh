#!/usr/bin/env bash
# v4.2 LSPlant Java-method-hook backend probe.
#
# This checks that the deployed agent contains the optional LSPlant backend and that LSPlant
# can initialize against the target process's ART runtime. It does not install a hook.
#
# Exit 0 = PASS, or SKIP when the running agent predates javahook_probe. Exit 1 = real FAIL.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HTTP="${ADH_HTTP_PORT:-8088}"

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const agents = await (await fetch(`${base}/api/agents`)).json();
const a = agents.filter(x => x.online).sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0];
if (!a) { console.log('NO_AGENT'); console.log('RESULT:SKIP'); process.exit(0); }
const r = await (await fetch(`${base}/api/java/probe?session=${encodeURIComponent(a.sessionId)}`)).json();
const err = String(r.error ?? '');
if (!r.ok && /unsupported|unknown op|lsplant not built|java hook backend not built/i.test(err)) {
  console.log(`old payload / no LSPlant: ${err}`);
  console.log('RESULT:SKIP');
  process.exit(0);
}
const hook = await (await fetch(`${base}/api/java/hook`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ session: a.sessionId, action: 'status' }),
})).json();
const hookErr = String(hook.error ?? '');
if (!hook.ok && /unsupported|unknown op|lsplant not built|java hook backend not built/i.test(hookErr)) {
  console.log(`old payload / no java_hook: ${hookErr}`);
  console.log('RESULT:SKIP');
  process.exit(0);
}
console.log(JSON.stringify({ package: a.package, pid: a.pid, available: r.available, initOk: r.initOk, backend: r.backend, version: r.version, error: err, hookStatus: hook.status ?? null, hookError: hookErr }));
const pass = r.ok === true && r.available === true && r.initOk === true &&
             hook.ok === true && hook.status && hook.status.active === false;
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.2 LSPlant probe + java_hook status PASS (static link + ART init)"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.2 LSPlant probe SKIP (agent payload not deployed yet)"
  exit 0
else
  echo "❌ v4.2 LSPlant probe FAIL"
  exit 1
fi