#!/usr/bin/env bash
# Negative offsets in hit-time memory windows (device): `x0-8:16` reads BEFORE the register's address.
#
# Why it exists: a template interpreter keeps its instruction records in one contiguous array, so the
# record that produced a value sits at `pc - 10` - before the pointer the handler was handed. A window
# grammar that only looks forward can never answer "what ran just before this", which is exactly the
# question left open on libjdg (who wrote the 32 bytes the hex encoder renders).
#
# The gate is exact: allocate a 64-byte buffer, write a known 16-byte pattern, call a COLD sandbox fixture
# with buf+8 as its argument, and require the copied window to be those 16 bytes with `offset:-8` in the
# record and `x0-8:16` in the status echo. (The fixture is deliberate: hooking a hot libc function to test
# a window would kill the target and prove nothing.)
#
# Missing preconditions print "SKIP ..." and exit 0 WITHOUT RESULT:PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v118_negative_window (no device)"
  exit 0
fi
if ! verify_restart_sandbox; then
  echo "SKIP  verify_v118_negative_window (could not restart the sandbox)"
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
if (!agent) { console.log('SKIP  verify_v118_negative_window (no online sandbox agent)'); process.exit(0); }
const session = agent.sessionId;

const mcp = async (name, args) => {
  const res = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }) });
  const payload = await res.json();
  const text = payload.result?.content?.find((c) => c.type === 'text')?.text ?? '';
  if (payload.error) throw new Error(JSON.stringify(payload.error));
  if (payload.result?.isError) throw new Error(text);
  return JSON.parse(text);
};
const failures = [];
const fail = (m, d) => failures.push(d === undefined ? m : `${m}: ${JSON.stringify(d).slice(0, 300)}`);

// Records only reach the store through the session's drain loop, which is armed asynchronously after
// hello; read before that and the store looks empty while nothing is wrong.
const waitDrainLoop = async () => {
  for (let i = 0; i < 40; i++) {
    const stop = await mcp('capture_stop', { session }).catch(() => null);
    if (stop?.drainLoop === 'armed' && stop?.drainedOk === true) return true;
    await sleep(500);
  }
  return false;
};
const recordsFor = async (hookId) => {
  const out = { events: [], mems: [] };
  for (let i = 0; i < 16; i++) {
    const caps = await mcp('live_captures', { session, limit: 400, includeText: true, encoding: 'b64' });
    const rows = caps.captures ?? caps;
    out.events.length = 0;
    out.mems.length = 0;
    for (const r of rows) {
      if (!r.b64) continue;
      let o;
      try { o = JSON.parse(Buffer.from(r.b64, 'base64').toString('utf8')); } catch { continue; }
      if (Number(o.hookId) !== Number(hookId)) continue;
      if (r.func === 'NATIVE_HOOK') out.events.push(o);
      else if (r.func === 'NATIVE_HOOK_MEM') out.mems.push(o);
    }
    if (out.events.length && out.mems.length) return out;
    await sleep(500);
  }
  return out;
};

const FIXTURE = { module: 'libadhdetect.so', symbol: 'adh_mem_window_target' };
let hookId = 0;
try {
  if (!(await waitDrainLoop())) fail('the session never armed its capture drain loop');

  // (0) the grammar refuses an offset beyond the documented ceiling, and a negative reference into an
  //     earlier window is meaningless (that index selects a BYTE inside a copy).
  const tooFar = await mcp('native_hook', { session, action: 'hook', mode: 'inline', ...FIXTURE, mem: 'x0-70000:8', confirm: true });
  if (tooFar.ok !== false) fail('mem offset -70000 was accepted; the ceiling is not enforced', tooFar);
  else if (!/exceeds/.test(String(tooFar.error ?? ''))) fail('the offset refusal does not say why', tooFar.error);
  const badRef = await mcp('native_hook', { session, action: 'hook', mode: 'inline', ...FIXTURE, mem: 'x0:8,@#1-8:8', confirm: true });
  if (badRef.ok !== false) fail('a negative @#<n> reference was accepted', badRef);

  // (1) a known 16-byte pattern, then a call whose x0 points INSIDE it (buf+8), so `x0-8` must land on
  //     the start of the pattern.
  const alloc = await mcp('native_call', { session, module: 'libc.so', symbol: 'malloc', args: ['64'], confirm: true });
  if (!alloc.ok) throw new Error(`malloc failed: ${alloc.error}`);
  const buf = BigInt(alloc.result);
  const pattern = '4142434445464748' + '3132333400000000';   // "ABCDEFGH" + "1234\0\0\0\0"
  const wrote = await mcp('memory_write', { session, addr: '0x' + buf.toString(16), hex: pattern });
  if (!wrote.ok) throw new Error(`memory_write failed: ${wrote.error}`);

  const hook = await mcp('native_hook', { session, action: 'hook', mode: 'inline', ...FIXTURE, mem: 'x0-8:16', confirm: true });
  if (!hook.ok) {
    const err = String(hook.error ?? '');
    if (/not found|symbol|no such/i.test(err)) {
      console.log('SKIP  verify_v118_negative_window (sandbox fixture adh_mem_window_target missing; rebuild + install the sandbox APK)');
      process.exit(0);
    }
    throw new Error(`install failed: ${err}`);
  }
  hookId = Number(hook.hookId);
  const st = (hook.status?.hooks ?? []).find((h) => Number(h.id) === hookId) ?? {};
  if (st.mem !== 'x0-8:16') fail(`status did not echo the negative window (mem=${JSON.stringify(st.mem)})`, st);

  const call = await mcp('native_call', { session, ...FIXTURE, args: ['0x' + (buf + 8n).toString(16)], confirm: true });
  if (!call.ok) fail('the hooked fixture call did not answer', call);

  const recs = await recordsFor(hookId);
  if (!recs.mems.length) fail('no NATIVE_HOOK_MEM record arrived');
  const win = (recs.mems[0].mem ?? [])[0] ?? {};
  if (win.reg !== 'x0') fail(`the window is not on x0 (got ${win.reg})`, win);
  if (Number(win.offset) !== -8) fail(`the record says offset ${win.offset}, expected -8 (the sign was lost)`, win);
  if (String(win.hex ?? '') !== pattern) fail('the bytes copied from BEFORE the pointer are not the pattern', { want: pattern, got: win.hex });
  if (Number(win.requested) !== 16 || Number(win.got) !== 16) fail('the window length is not 16', win);

  const alive = await mcp('agent_ping', { session }).catch((e) => ({ ok: false, error: String(e.message ?? e) }));
  if (alive.ok !== true) fail('the target is not answering after the negative-window copy', alive);

  // (2) the ABSOLUTE form: "what does this address hold NOW". The address is one the caller learned earlier
  // (here: a buffer it allocated), so no register is involved. A soft unhook lets the same target take a
  // new window, which is also how a real analysis re-reads a slot at a different hit.
  await mcp('native_hook', { session, action: 'unhook', hookId, hard: false });
  hookId = 0;
  const absAddr = '0x' + (buf + 8n).toString(16);
  const absHook = await mcp('native_hook', { session, action: 'hook', mode: 'inline', ...FIXTURE, mem: `${absAddr}:8`, confirm: true });
  if (!absHook.ok) fail('install with an absolute mem window failed', absHook);
  else {
    hookId = Number(absHook.hookId);
    const ast = (absHook.status?.hooks ?? []).find((h) => Number(h.id) === hookId) ?? {};
    if (ast.mem !== `${absAddr}:8`) fail(`status did not echo the absolute window (mem=${JSON.stringify(ast.mem)})`, ast);
    // The fixture flips buf[0] on every call, so re-seed before this phase: an expectation that ignores
    // the previous call would fail for the wrong reason (this assertion already did once).
    const reseed = await mcp('memory_write', { session, addr: '0x' + buf.toString(16), hex: pattern });
    if (!reseed.ok) fail('could not re-seed the buffer before the absolute phase', reseed);
    const call2 = await mcp('native_call', { session, ...FIXTURE, args: [absAddr], confirm: true });
    if (!call2.ok) fail('the absolute-window call did not answer', call2);
    const recs2 = await recordsFor(hookId);
    const win2 = (recs2.mems[0]?.mem ?? [])[0] ?? {};
    if (win2.reg !== 'abs') fail(`the record does not say it is an absolute window (reg=${JSON.stringify(win2.reg)})`, win2);
    if (String(win2.addr).toLowerCase() !== absAddr.toLowerCase()) fail(`the record says address ${win2.addr}, expected ${absAddr}`, win2);
    if (String(win2.hex ?? '') !== '3132333400000000') fail('the absolute window did not read the seeded bytes', { want: '3132333400000000', got: win2.hex });
    console.log(JSON.stringify({ hookId, buf: '0x' + buf.toString(16), window: win, statusEcho: st.mem, absoluteWindow: win2, alive: alive.ok }));
  }
} catch (e) {
  fail('exception', String(e.message ?? e));
} finally {
  if (hookId > 0) { try { await mcp('native_hook', { session, action: 'unhook', hookId, hard: true }); } catch {} }
}

if (failures.length) { console.log(failures.join('\n')); console.log('RESULT:FAIL'); }
else console.log('RESULT:PASS');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
if grep -q 'RESULT:PASS' <<<"$OUT"; then
  echo "OK v118 negative-offset windows (device) PASS"
  exit 0
fi
echo "FAIL v118 negative-offset windows (device) FAIL"
exit 1
