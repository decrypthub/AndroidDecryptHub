#!/usr/bin/env bash
# Write watch inside an in-hook trace (device): `traceWatch` answers "who wrote this memory".
#
# Why: a hardware watchpoint needs perf_event_open, which app domains are denied (errno 13) on the
# devices we use, so "which store landed in this buffer" had no answer at all - an instruction trace says
# which code ran, never which write went where. This gate proves the software replacement: while the
# traced run executes, a range is watched for writes, and the event carries the writing instruction, the
# address and the value.
#
# The fixture is generic: `adh_mem_window_target(buf)` reads 8 bytes and writes buf[0] ^= 0xff. With
# `traceWatch: "x0:8"` the event must report exactly that store (address == buf, size 1, value == the
# flipped byte), plus the status echo. A second phase installs the same hook WITHOUT the watch and
# requires the key to be absent - the default must cost nothing.
#
# Missing preconditions print "SKIP ..." and exit 0 WITHOUT RESULT:PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v119_trace_watch (no device)"
  exit 0
fi
if ! verify_restart_sandbox; then
  echo "SKIP  verify_v119_trace_watch (could not restart the sandbox)"
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
if (!agent) { console.log('SKIP  verify_v119_trace_watch (no online sandbox agent)'); process.exit(0); }
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
const fail = (m, d) => failures.push(d === undefined ? m : `${m}: ${JSON.stringify(d).slice(0, 400)}`);
const FIXTURE = { module: 'libadhdetect.so', symbol: 'adh_mem_window_target' };

const waitDrainLoop = async () => {
  for (let i = 0; i < 40; i++) {
    const stop = await mcp('capture_stop', { session }).catch(() => null);
    if (stop?.drainLoop === 'armed' && stop?.drainedOk === true) return true;
    await sleep(500);
  }
  return false;
};
const eventsFor = async (hookId) => {
  for (let i = 0; i < 20; i++) {
    const caps = await mcp('live_captures', { session, limit: 400, includeText: true, encoding: 'b64' });
    const rows = caps.captures ?? caps;
    const out = [];
    for (const r of rows) {
      if (r.func !== 'NATIVE_HOOK' || !r.b64) continue;
      let o;
      try { o = JSON.parse(Buffer.from(r.b64, 'base64').toString('utf8')); } catch { continue; }
      if (Number(o.hookId) === Number(hookId)) out.push(o);
    }
    if (out.length) return out;
    await sleep(500);
  }
  return [];
};

let hookId = 0;
try {
  if (!(await waitDrainLoop())) fail('the session never armed its capture drain loop');

  // (0) the watch needs a run: refused without traceInsns, instead of installing a hook that never watches.
  const noRun = await mcp('native_hook', { session, action: 'hook', mode: 'inline', ...FIXTURE, traceWatch: 'x0:8', confirm: true });
  if (noRun.ok !== false) fail('traceWatch without traceInsns was accepted', noRun);
  else if (!/traceWatch needs traceInsns/.test(String(noRun.error ?? ''))) fail('the refusal does not say why', noRun.error);

  // (1) a known byte, then a call that flips it.
  const alloc = await mcp('native_call', { session, module: 'libc.so', symbol: 'malloc', args: ['64'], confirm: true });
  if (!alloc.ok) throw new Error(`malloc failed: ${alloc.error}`);
  const buf = BigInt(alloc.result);
  const seed = '4142434445464748';   // "ABCDEFGH"
  const wrote = await mcp('memory_write', { session, addr: '0x' + buf.toString(16), hex: seed });
  if (!wrote.ok) throw new Error(`memory_write failed: ${wrote.error}`);

  const hook = await mcp('native_hook', {
    session, action: 'hook', mode: 'inline', ...FIXTURE,
    mem: 'x0:8', traceInsns: 200, traceWatch: 'x0:8', confirm: true,
  });
  if (!hook.ok) {
    if (/not found|symbol|no such/i.test(String(hook.error ?? ''))) {
      console.log('SKIP  verify_v119_trace_watch (sandbox fixture adh_mem_window_target missing; rebuild + install the sandbox APK)');
      process.exit(0);
    }
    throw new Error(`install failed: ${hook.error}`);
  }
  hookId = Number(hook.hookId);
  const st = (hook.status?.hooks ?? []).find((h) => Number(h.id) === hookId) ?? {};
  if (st.traceWatch !== 'x0:8') fail(`status did not echo traceWatch (got ${JSON.stringify(st.traceWatch)})`, st);
  if (Number(st.traceInsns) !== 200) fail('status did not echo traceInsns', st);

  const call = await mcp('native_call', { session, ...FIXTURE, args: ['0x' + buf.toString(16)], confirm: true });
  if (!call.ok) fail('the hooked fixture call did not answer', call);

  const evs = await eventsFor(hookId);
  if (!evs.length) fail('no NATIVE_HOOK event arrived for the watched hook');
  const ev = evs[evs.length - 1] ?? {};
  const tw = ev.traceWatch;
  if (!tw || typeof tw !== 'object') {
    fail('the event carries no traceWatch object', { keys: Object.keys(ev ?? {}) });
  } else {
    if (!(Number(tw.count) > 0)) fail('traceWatch.count is 0: the store was not seen', tw);
    if (!Array.isArray(tw.hits) || !tw.hits.length) fail('traceWatch.hits is empty', tw);
    const hit = (tw.hits ?? [])[0] ?? {};
    const wantAddr = '0x' + buf.toString(16);
    const wantValue = '0x' + (0x41 ^ 0xff).toString(16);
    if (String(hit.addr) !== wantAddr) fail(`the reported address ${hit.addr} is not the buffer ${wantAddr}`, hit);
    if (Number(hit.size) !== 1) fail(`the reported size ${hit.size} is not 1 (the fixture writes one byte)`, hit);
    if (String(hit.value) !== wantValue) fail(`the reported value ${hit.value} is not the byte written (${wantValue})`, hit);
    if (!String(hit.pc ?? '').match(/^0x[0-9a-f]+$/)) fail('the hit carries no instruction address', hit);
    if (!String(hit.insn ?? '').length) fail('the hit carries no instruction text', hit);
    if (!/str/.test(String(hit.insn ?? ''))) fail(`the reported instruction is not a store: ${hit.insn}`, hit);
    if (String(tw.lo) !== wantAddr) fail(`traceWatch.lo ${tw.lo} is not the resolved range start ${wantAddr}`, tw);
    console.log(JSON.stringify({ hookId, buf: wantAddr, count: tw.count, hit }));
  }

  // (2) the same hook without the watch: the key must be ABSENT (the default costs nothing). A soft
  //     unhook keeps the stub installed, so the same address can be reactivated with a new request.
  await mcp('native_hook', { session, action: 'unhook', hookId, hard: false });
  hookId = 0;
  const quiet = await mcp('native_hook', { session, action: 'hook', mode: 'inline', ...FIXTURE, mem: 'x0:8', traceInsns: 200, confirm: true });
  if (!quiet.ok) fail('reactivation without the watch failed', quiet);
  else {
    const qid = Number(quiet.hookId);
    hookId = qid;
    const qst = (quiet.status?.hooks ?? []).find((h) => Number(h.id) === qid) ?? {};
    if (String(qst.traceWatch ?? '') !== '') fail('status still echoes a traceWatch after reactivating without it', qst);
    const call2 = await mcp('native_call', { session, ...FIXTURE, args: ['0x' + buf.toString(16)], confirm: true });
    if (!call2.ok) fail('the untraced-watch call did not answer', call2);
    const evs2 = await eventsFor(qid);
    if (!evs2.length) fail('no event arrived for the hook without a watch');
    for (const e of evs2) {
      if ('traceWatch' in e) fail('an event of a hook installed without traceWatch carries the key', { keys: Object.keys(e) });
      if (!e.trace) fail('the event lost its trace when the watch was removed', { keys: Object.keys(e) });
    }
  }

  const alive = await mcp('agent_ping', { session }).catch((e) => ({ ok: false, error: String(e.message ?? e) }));
  if (alive.ok !== true) fail('the target is not answering after the watched trace', alive);
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
  echo "OK v119 trace write watch (device) PASS"
  exit 0
fi
echo "FAIL v119 trace write watch (device) FAIL"
exit 1
