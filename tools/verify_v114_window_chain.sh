#!/usr/bin/env bash
# Window-chained dereference (device).
#
# One level of `@` reaches a pointer-of-pointer but stops there. The structures that matter are often
# deeper: a formatter descriptor (+0x18) points at an argument VECTOR, and the vector's slots point at
# the values being rendered. `@#<n>+<off>:<len>` follows the second hop: take an earlier window's copy,
# read the u64 at that offset inside it, and copy the window from the address it names.
#
# The gate is exact, and it uses three mallocs so a mis-follow cannot pass by luck:
#
#   C = "Z\0"            (the bytes we want)
#   A = pointer to C
#   B = pointer to A     (what the hooked function receives in x0)
#
#   hook atoi with mem "@x0:8,@#1+0:8"
#   call atoi(B)
#
# window 1 must resolve to A, window 2 must resolve to C and contain "Z\0".
#
# Missing preconditions print "SKIP ..." and exit 0 WITHOUT RESULT:PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v114_window_chain (no device)"
  exit 0
fi
if ! verify_restart_sandbox; then
  echo "SKIP  verify_v114_window_chain (could not restart the sandbox)"
  exit 0
fi

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const pick = async () => {
  const a = await (await fetch(`${base}/api/agents`)).json().catch(() => null);
  return (Array.isArray(a) ? a : []).filter((x) => x.online && x.package === 'com.adh.sandbox')
    .sort((p, q) => (q.connectedAt ?? 0) - (p.connectedAt ?? 0))[0];
};
let agent = await pick();
for (let i = 0; i < 15 && !agent; i++) { await sleep(1000); agent = await pick(); }
if (!agent) { console.log('SKIP  verify_v114_window_chain (no online sandbox agent)'); process.exit(0); }
const session = agent.sessionId;
const mcp = async (name, args) => {
  const res = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }) });
  const p = await res.json();
  const text = p.result?.content?.find((c) => c.type === 'text')?.text ?? '';
  if (p.error) throw new Error(JSON.stringify(p.error));
  if (p.result?.isError) throw new Error(text);
  return JSON.parse(text);
};
const failures = [];
const fail = (m, d) => failures.push(d === undefined ? m : `${m}: ${JSON.stringify(d).slice(0, 300)}`);
let hookId = 0;
try {
  const alloc = async (n) => {
    const r = await mcp('native_call', { session, module: 'libc.so', symbol: 'malloc', args: [String(n)], confirm: true });
    if (!r.ok) throw new Error(`malloc failed: ${r.error}`);
    return BigInt(r.result);
  };
  const le = (v) => v.toString(16).padStart(16, '0').match(/../g).reverse().join('');
  const C = await alloc(64), A = await alloc(64), B = await alloc(64);
  await mcp('memory_write', { session, addr: '0x' + C.toString(16), hex: '5a00' });
  await mcp('memory_write', { session, addr: '0x' + A.toString(16), hex: le(C) });
  await mcp('memory_write', { session, addr: '0x' + B.toString(16), hex: le(A) });

  const hook = await mcp('native_hook', { session, action: 'hook', mode: 'inline', module: 'libc.so', symbol: 'atoi', mem: '@x0:8,@#1+0:8', confirm: true });
  if (!hook.ok) throw new Error(`install failed: ${hook.error}`);
  hookId = Number(hook.hookId);
  const installed = String(hook.status?.hooks?.[0]?.mem ?? '').replace(/\s/g, '');
  if (installed !== '@x0:8,@#1:8') fail(`canonical spec changed (mem=${installed})`, hook.status?.hooks?.[0]);

  const call = await mcp('native_call', { session, module: 'libc.so', symbol: 'atoi', args: ['0x' + B.toString(16)], confirm: true });
  if (!call.ok) fail('the hooked call did not answer', call);

  let rec = null;
  for (let i = 0; i < 12 && !rec; i++) {
    await sleep(500);
    const caps = await mcp('live_captures', { session, limit: 400, includeText: true, encoding: 'b64' });
    for (const r of caps.captures ?? caps) {
      if (r.func !== 'NATIVE_HOOK_MEM' || !r.b64) continue;
      let o; try { o = JSON.parse(Buffer.from(r.b64, 'base64').toString('utf8')); } catch { continue; }
      if (Number(o.hookId) !== hookId) continue;
      if ((o.mem ?? []).some((w) => w.from === 1)) rec = o;
    }
  }
  if (!rec) fail('no chained window arrived (the second hop never resolved)');
  else {
    const w1 = rec.mem[0], w2 = rec.mem[1];
    if (w1.ptr !== '0x' + A.toString(16)) fail(`window 1 resolved to ${w1.ptr}, expected A`, w1);
    if (w2.from !== 1) fail('window 2 does not record which window it chained from', w2);
    if (w2.ptr !== '0x' + C.toString(16)) fail(`window 2 resolved to ${w2.ptr}, expected C`, w2);
    if (!String(w2.hex ?? '').startsWith('5a')) fail(`window 2 did not copy C's bytes (hex=${String(w2.hex ?? '').slice(0, 12)})`, w2);
    console.log(JSON.stringify({ A: '0x' + A.toString(16), B: '0x' + B.toString(16), C: '0x' + C.toString(16),
      w1: { ptr: w1.ptr, hex: String(w1.hex ?? '').slice(0, 16) }, w2: { from: w2.from, ptr: w2.ptr, hex: String(w2.hex ?? '').slice(0, 16) } }));
  }
} catch (e) {
  fail('exception', String(e.message ?? e));
} finally {
  if (hookId > 0) { try { await mcp('native_hook', { session, action: 'unhook', hookId, hard: true }); } catch {} }
}
if (failures.length) { console.log(failures.join('\n')); console.log('RESULT:FAIL'); } else console.log('RESULT:PASS');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
if grep -q 'RESULT:PASS' <<<"$OUT"; then
  echo "OK v114 window chain (device) PASS"
  exit 0
fi
echo "FAIL v114 window chain (device) FAIL"
exit 1
