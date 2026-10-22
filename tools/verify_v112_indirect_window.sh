#!/usr/bin/env bash
# Indirect (pointer-of-pointer) memory windows (device).
#
# A plain `mem` window can only copy from a register. That is useless for the structures that matter
# most in obfuscated targets: a VM frame holds its current instruction record in a FIELD, a dispatch
# slot holds its target, a list head holds its first node. Measured on libjdg, the interpreter's
# instruction record lived at *(state+0x20) and was gone from the mapping by the time a second
# memory_read could ask for it - the window has to follow the pointer AT THE HIT.
#
# `@x2+32:512` does exactly that: read the u64 at (reg+offset), then copy the window from THAT address.
# This script is the gate, and it is deterministic rather than "looks plausible":
#
#   buffer A = "Z"                       (the bytes we want to see)
#   buffer B = little-endian pointer A   (a pointer-of-pointer, exactly the shape in question)
#   hook atoi with mem "x0:8,@x0:8"      (atoi is cold, so it cannot disturb the process)
#   call  atoi(B)                        -> hits the hook
#
# and then the record must carry deref:true, ptr == A, and hex == the bytes of A. A plain window would
# have shown the pointer VALUE, which is the mistake this feature exists to prevent.
#
# Missing preconditions print "SKIP ..." and exit 0 WITHOUT RESULT:PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v112_indirect_window (no device)"
  exit 0
fi
if ! verify_restart_sandbox; then
  echo "SKIP  verify_v112_indirect_window (could not restart the sandbox)"
  exit 0
fi

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const pick = async () => {
  const agents = await (await fetch(`${base}/api/agents`)).json().catch(() => null);
  return (Array.isArray(agents) ? agents : [])
    .filter((x) => x.online && x.package === 'com.adh.sandbox')
    .sort((a, b) => (b.connectedAt ?? 0) - (a.connectedAt ?? 0))[0];
};
let agent = await pick();
for (let i = 0; i < 15 && !agent; i++) { await sleep(1000); agent = await pick(); }
if (!agent) { console.log('SKIP  verify_v112_indirect_window (no online sandbox agent)'); process.exit(0); }
const session = agent.sessionId;

const mcp = async (name, args) => {
  const res = await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }),
  });
  const payload = await res.json();
  const text = payload.result?.content?.find((c) => c.type === 'text')?.text ?? '';
  if (payload.error) throw new Error(JSON.stringify(payload.error));
  if (payload.result?.isError) throw new Error(text);
  return JSON.parse(text);
};
const failures = [];
const fail = (msg, detail) => failures.push(detail === undefined ? msg : `${msg}: ${JSON.stringify(detail).slice(0, 300)}`);

let hookId = 0;
try {
  // Two buffers: A holds the payload, B holds A's address.
  const a = await mcp('native_call', { session, module: 'libc.so', symbol: 'malloc', args: ['64'], confirm: true });
  const b = await mcp('native_call', { session, module: 'libc.so', symbol: 'malloc', args: ['64'], confirm: true });
  if (!a.ok || !b.ok) throw new Error(`malloc failed: ${a.error ?? b.error}`);
  const addrA = BigInt(a.result);
  const addrB = BigInt(b.result);
  const hexA = addrA.toString(16).padStart(16, '0').replace(/(..)/g, '$&').match(/../g).reverse().join('');
  await mcp('memory_write', { session, addr: '0x' + addrA.toString(16), hex: '5a00' });
  await mcp('memory_write', { session, addr: '0x' + addrB.toString(16), hex: hexA });

  const hook = await mcp('native_hook', { session, action: 'hook', mode: 'inline', module: 'libc.so', symbol: 'atoi', mem: 'x0:8,@x0:8', confirm: true });
  if (!hook.ok) throw new Error(`install failed: ${hook.error}`);
  hookId = Number(hook.hookId);
  const installedMem = String(hook.status?.hooks?.[0]?.mem ?? '').replace(/\s/g, '');
  if (installedMem !== 'x0:8,@x0:8') fail(`the canonical spec lost the deref marker (mem=${installedMem})`, hook.status?.hooks?.[0]);

  const call = await mcp('native_call', { session, module: 'libc.so', symbol: 'atoi', args: ['0x' + addrB.toString(16)], confirm: true });
  if (!call.ok) fail('the hooked call did not answer (the deref copy must not fault the target)', call);

  // The records arrive asynchronously: a hit produced by our own native_call was measured to show up
  // 1-2 s later than the reply, so polling once is a flaky gate, not a fast one.
  let rec = null;
  for (let attempt = 0; attempt < 12 && !rec; attempt++) {
    await sleep(500);
    const caps = await mcp('live_captures', { session, limit: 400, includeText: true, encoding: 'b64' });
    const rows = caps.captures ?? caps;
    for (const r of rows) {
      if (r.func !== 'NATIVE_HOOK_MEM' || !r.b64) continue;
      let o;
      try { o = JSON.parse(Buffer.from(r.b64, 'base64').toString('utf8')); } catch { continue; }
      if (Number(o.hookId) !== hookId) continue;
      if (Array.isArray(o.mem) && o.mem.some((w) => w.deref)) rec = o;
    }
  }
  if (!rec) {
    fail('no NATIVE_HOOK_MEM record with a deref window (the feature did not reach the capture ring)');
  } else {
    const win = rec.mem.find((w) => w.deref);
    if (win.ptr !== '0x' + addrA.toString(16)) fail(`the deref window resolved to ${win.ptr}, not the planted pointer`, win);
    if (!String(win.hex ?? '').startsWith('5a')) fail(`the deref window did not copy the target bytes (hex=${String(win.hex ?? '').slice(0, 16)})`, win);
    if (win.got !== 8) fail(`the deref window reported got=${win.got}, expected 8`, win);
    const plain = rec.mem.find((w) => !w.deref);
    if (plain && plain.ptr !== undefined) fail('the plain window was mislabelled as a deref', plain);
    // The plain window must still show the POINTER VALUE, little-endian - that is the contrast the
    // feature rests on, and it is the exact bytes that a naive reader mistakes for the payload.
    if (!plain) fail('the plain window is missing: the record must carry both, not only the deref');
    else if (String(plain.hex ?? '').toLowerCase() !== hexA) {
      fail(`the plain window is not the pointer value (want ${hexA}, got ${String(plain.hex ?? '')})`, plain);
    }
  }
  console.log(JSON.stringify({
    addrA: '0x' + addrA.toString(16),
    addrB: '0x' + addrB.toString(16),
    windows: rec ? rec.mem.map((w) => ({ reg: w.reg, off: w.offset, deref: !!w.deref, ptr: w.ptr, got: w.got, hex: String(w.hex ?? '').slice(0, 16) })) : null,
  }));
} catch (e) {
  fail('exception', String(e.message ?? e));
} finally {
  if (hookId > 0) { try { await mcp('native_hook', { session, action: 'unhook', hookId, hard: true }); } catch {} }
}

if (failures.length) {
  console.log(failures.join('\n'));
  console.log('RESULT:FAIL');
} else {
  console.log('RESULT:PASS');
}
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
if grep -q 'RESULT:PASS' <<<"$OUT"; then
  echo "OK v112 indirect memory window (device) PASS"
  exit 0
fi
echo "FAIL v112 indirect memory window (device) FAIL"
exit 1
