#!/usr/bin/env bash
# v4.8 live memory disassembly acceptance.
# Uses the native hook manager to resolve adh_trace_target's runtime address, then asks the
# Host daemon to read those bytes from the agent and disassemble them with Capstone 5 (WASM).
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
// Resolve a real function address through the already-verified native hook manager.
await post('/api/native/hook', { session: agent.sessionId, action: 'unhook', hookId: 0 }).catch(() => null);
const hook = await post('/api/native/hook', {
  session: agent.sessionId, action: 'hook', mode: 'inline',
  module: 'libadhdetect.so', symbol: 'adh_trace_target',
});
if (!hook.ok) {
  console.log(JSON.stringify({ hook }));
  console.log('RESULT:FAIL');
  process.exit(0);
}
const addr = hook.status?.hooks?.[0]?.target ?? hook.status?.hooks?.[0]?.address;
const hookId = Number(hook.hookId ?? 0);
const unhook = await post('/api/native/hook', { session: agent.sessionId, action: 'unhook', hookId });
const absolute = await post('/api/memory/disasm', { session: agent.sessionId, addr, size: 256 });
const modules = await (await fetch(`${base}/api/modules?session=${encodeURIComponent(agent.sessionId)}`)).json();
const mod = Array.isArray(modules) ? modules.find((m) => m.name === 'libadhdetect.so') : null;
let byModule = null;
if (mod && addr) {
  const offset = '0x' + (BigInt(addr) - BigInt('0x' + String(mod.base))).toString(16);
  byModule = await post('/api/memory/disasm', { session: agent.sessionId, module: 'libadhdetect.so', offset, size: 64 });
}
const insns = Array.isArray(absolute.instructions) ? absolute.instructions : [];
const firstOk = insns.length > 0 && BigInt(insns[0].addr) === BigInt(addr);
const hasRet = insns.some((i) => i.mnemonic === 'ret');
const shapeOk = insns.every((i) => typeof i.addr === 'string' && typeof i.bytes === 'string' &&
  i.bytes.length >= 2 && typeof i.mnemonic === 'string' && typeof i.text === 'string');
const moduleOk = byModule && byModule.engine === 'capstone-wasm' &&
  BigInt(byModule.instructions?.[0]?.addr ?? '0x0') === BigInt(addr);
const pass = absolute.engine === 'capstone-wasm' && absolute.capstone === '5.0' &&
  absolute.count >= 4 && insns.length === absolute.count && firstOk && hasRet && shapeOk &&
  absolute.decodedBytes === absolute.count * 4 && unhook?.ok === true && moduleOk;
console.log(JSON.stringify({
  addr, hookId, unhook: unhook?.ok === true,
  absolute: { engine: absolute.engine, capstone: absolute.capstone, count: absolute.count, decodedBytes: absolute.decodedBytes, readSize: absolute.readSize, shortRead: absolute.shortRead },
  byModule: byModule ? { engine: byModule.engine, count: byModule.count, addr: byModule.addr, resolvedFrom: byModule.resolvedFrom } : null,
  first: insns[0] ?? null, hasRet, sample: insns.slice(0, 6),
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v4.8 live memory disassembly PASS (Capstone 5 WASM)"
  exit 0
elif echo "$OUT" | grep -q 'RESULT:SKIP'; then
  echo "⏭  v4.8 live memory disassembly SKIP (agent/sandbox not deployed)"
  exit 0
else
  echo "❌ v4.8 live memory disassembly FAIL"
  exit 1
fi