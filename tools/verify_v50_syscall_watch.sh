#!/usr/bin/env bash
# v4.10 direct-syscall watch acceptance.
# Host reconstructs libadhdetect.so, finds svc #0 sites, inline-hooks them through
# native_hook, then calls adh_direct_gettid and asserts a NATIVE_HOOK event with x8=0xb2.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env
if [ -n "${SERIAL:-}" ] && adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  verify_restart_sandbox || echo "WARN  could not restart sandbox before syscall scan"
fi

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const agents = await (await fetch(`${base}/api/agents`)).json();
const agent = agents.filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0];
if (!agent) { console.log('NO_AGENT'); console.log('RESULT:SKIP'); process.exit(0); }
async function post(path, body) {
  const r = await fetch(`${base}${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  return { status: r.status, body: await r.json() };
}
const session = agent.sessionId;
await post('/api/native/hook', { session, action: 'unhook', hookId: 0 }).catch(() => null);
const watch = await post('/api/native/syscall_watch', { session, module: 'libadhdetect.so', limit: 8 });
if (watch.status === 404 || /unsupported|unknown op/i.test(String(watch.body.error ?? ''))) {
  console.log(`old payload / no syscall_watch: ${watch.body.error ?? watch.status}`);
  console.log('RESULT:SKIP');
  process.exit(0);
}
if (!watch.body || watch.body.installedCount < 1) {
  console.log(JSON.stringify({ watch }));
  console.log('RESULT:FAIL');
  process.exit(0);
}
const hookIds = (watch.body.hooks ?? []).map((h) => Number(h.hookId));
const call = await post('/api/native/call', {
  session, module: 'libadhdetect.so', symbol: 'adh_direct_gettid', args: [], confirm: true,
});
// The scan can install multiple sites in a busy sandbox process. Remove them immediately after
// the synchronous fixture call so ordinary app traffic cannot flood the event queue while this
// verifier fetches the captured probe event.
const unhook = [];
for (const id of hookIds) unhook.push(await post('/api/native/hook', { session, action: 'unhook', hookId: id }).catch(() => null));
let found = null;
for (let i = 0; i < 20; i++) {
  const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=200`)).json();
  for (const item of (list.captures ?? [])) {
    if (item.func !== 'NATIVE_HOOK') continue;
    const detail = await (await fetch(`${base}/api/captures/${item.id}`)).json();
    const text = String(detail.text ?? '');
    if (hookIds.some((id) => text.includes(`"hookId":${id}`)) && text.includes('"x8":"0xb2"')) { found = detail; break; }
  }
  if (found) break;
  await sleep(100);
}
const stillOnline = (await (await fetch(`${base}/api/agents`)).json()).some((x) => x.online && x.package === 'com.adh.sandbox');
const alive = stillOnline && call.body.ok === true && Number(call.body.resultDecimal) >= 0;
const pass = watch.body.svcCount >= 1 && watch.body.installedCount >= 1 && found != null &&
  unhook.every((r) => r?.body?.ok === true) && alive;
console.log(JSON.stringify({
  watch: { module: watch.body.module, svcCount: watch.body.svcCount, installedCount: watch.body.installedCount,
    scannedBytes: watch.body.scannedBytes, hooks: watch.body.hooks, truncated: watch.body.truncated },
  call: { ok: call.body.ok, resultDecimal: call.body.resultDecimal },
  event: found ? { id: found.id, func: found.func, preview: found.preview } : null,
  unhookOk: unhook.every((r) => r?.body?.ok === true), alive,
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.10 direct-syscall watch PASS (svc #0 -> x8=0xb2)"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.10 direct-syscall watch SKIP (new daemon/agent not deployed)"
  exit 0
else
  echo "❌ v4.10 direct-syscall watch FAIL"
  exit 1
fi
