#!/usr/bin/env bash
# In-hook QBDI trace (v117): a hook must be able to run an instruction trace AT THE HIT and put the
# summary in the SAME event record.
#
# Why the capability exists at all: on a target whose frames are request-scoped, "capture the
# arguments, then trace afterwards" runs into memory that has already been released (that route was
# measured dead three times on libjdg). The only moment the state is live is the hit itself, so the
# trace has to run inside the hook callback, on the target thread.
#
# The gate asserts the whole contract, not just "a key appeared":
#   a) traceInsns:32 on a call-site hook -> the event carries trace, seen>0, <=32, a stopReason from
#      the documented set, a non-empty mnemonic histogram, and first[0]'s address IS the hooked
#      function entry (the whole point of traceFrom/entry) - then the target is still alive and the
#      hooked function still returns what it did before (the trace observes, it does not rewrite);
#   b) traceInsns:0 on a fresh hook of the same function -> the event carries NO trace key at all
#      (default must cost nothing, and "not traced" must be distinguishable from "traced, saw 0");
#   c) the install refuses traceInsns together with skipOriginal (the trace EXECUTES the original).
#
# Missing preconditions print "SKIP ..." and exit 0 WITHOUT RESULT:PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v117_inhook_trace (no device)"
  exit 0
fi
if ! verify_restart_sandbox; then
  echo "SKIP  verify_v117_inhook_trace (could not restart the sandbox)"
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
if (!agent) { console.log('SKIP  verify_v117_inhook_trace (no online sandbox agent)'); process.exit(0); }
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
const REASONS = new Set(['completed', 'instruction-budget', 'time-budget', 'ran-away', 'left-range', 'did-not-run', 'reentrant']);
const callJava = async (method) => {
  const r = await mcp('java_call', { session, className: 'com.adh.sandbox.Detection', method, params: '', args: [] });
  return r?.result?.result ?? null;
};
// Parse first[0]'s address out of the "0x…: insn" rendering the agent emits.
const firstAddr = (trace) => {
  const line = Array.isArray(trace?.first) ? trace.first[0] : '';
  const m = /^0x([0-9a-f]+)/i.exec(String(line ?? ''));
  return m ? BigInt(`0x${m[1]}`) : null;
};
// Every NATIVE_HOOK event for one hook, newest last.
//
// Records only reach the store through the session's drain loop, which the daemon arms
// asynchronously after hello (startup hooks first, then capture_start). A script that reads
// live_captures before that loop exists sees an empty store and would call a working feature broken,
// so the wait below is part of the gate, not politeness.
const eventsFor = async (hookId) => {
  const out = [];
  for (let i = 0; i < 30; i++) {
    const caps = await mcp('live_captures', { session, limit: 400, includeText: true, encoding: 'b64' });
    const rows = caps.captures ?? caps;
    for (const r of rows) {
      if (r.func !== 'NATIVE_HOOK' || !r.b64) continue;
      let o;
      try { o = JSON.parse(Buffer.from(r.b64, 'base64').toString('utf8')); } catch { continue; }
      if (Number(o.hookId) !== hookId) continue;
      out.push(o);
    }
    if (out.length >= 1) return out;
    await sleep(500);
  }
  return out;
};
const unhook = async (hookId) => { try { await mcp('native_hook', { session, action: 'unhook', hookId, hard: true }); } catch {} };
// Wait for the drain loop, draining (and stopping the crypto hook set) as a side effect: the handover
// says to capture_stop before installing a hot hook, and this is the same call.
const waitDrainLoop = async () => {
  for (let i = 0; i < 40; i++) {
    const stop = await mcp('capture_stop', { session }).catch(() => null);
    if (stop?.drainLoop === 'armed' && stop?.drainedOk === true) return true;
    await sleep(500);
  }
  return false;
};

let hookA = 0, hookB = 0;
try {
  if (!(await waitDrainLoop())) {
    fail('the session never armed its capture drain loop, so no hook event could reach the store');
  }

  // (0) the refusal that protects skipOriginal: a trace EXECUTES the original, so the two cannot
  //     mean what they say together.
  const refused = await mcp('native_hook', { session, action: 'hook', mode: 'sites', module: 'libadhdetect.so', symbol: 'adh_add_target', sites: 2, traceInsns: 16, skipOriginal: true });
  if (refused.ok !== false) fail('traceInsns + skipOriginal was accepted; the trace would run the function the caller asked to skip', refused);
  else if (!/traceInsns cannot be combined/.test(String(refused.error ?? ''))) fail('the refusal does not name the reason', refused.error);

  // (1) trace ON: a call-site hook so the function's own entry stays byte-identical and the trace can
  //     start exactly there (an inline hook starts in the Dobby trampoline instead).
  const installA = await mcp('native_hook', { session, action: 'hook', mode: 'sites', module: 'libadhdetect.so', symbol: 'adh_trace_target', sites: 4, traceInsns: 32 });
  if (!installA.ok) throw new Error(`install (trace on) failed: ${installA.error}`);
  hookA = Number(installA.hookId);
  const statusA = (installA.status?.hooks ?? []).find((h) => Number(h.id) === hookA) ?? {};
  if (Number(statusA.traceInsns) !== 32) fail('status does not echo traceInsns:32 (the install dropped it)', statusA);
  const entry = statusA.target ? BigInt(statusA.target) : null;
  if (!entry) fail('the install did not report the hooked entry address', statusA);

  const before = Number(await callJava('nativeHookProbe'));
  if (before !== 30) fail(`the fixture no longer returns 30 before the trace (got ${before})`);
  const eventsA = await eventsFor(hookA);
  if (!eventsA.length) fail('no NATIVE_HOOK event arrived for the traced hook');
  const evA = eventsA[eventsA.length - 1];
  const tr = evA?.trace;
  if (!tr || typeof tr !== 'object') {
    fail('the event carries no trace sub-object (traceInsns:32 was dropped)', { keys: Object.keys(evA ?? {}), traceSkipped: evA?.traceSkipped });
  } else {
    if (Number(tr.insns) !== 32) fail(`trace.insns is ${tr.insns}, expected the requested 32`, tr);
    if (!(Number(tr.seen) > 0)) fail('trace.seen is 0: the run did not execute anything', tr);
    if (Number(tr.seen) > 32) fail(`trace.seen ${tr.seen} exceeds the 32-instruction budget`, tr);
    if (!REASONS.has(String(tr.stopReason))) fail(`trace.stopReason ${tr.stopReason} is outside the documented set`, tr);
    if (typeof tr.capped !== 'boolean') fail('trace.capped is not a boolean', tr);
    if (!Array.isArray(tr.first) || tr.first.length === 0) fail('trace.first is empty: nothing was disassembled', tr);
    if (!Array.isArray(tr.mnemonics) || tr.mnemonics.length === 0) fail('trace.mnemonics is empty: no histogram was built', tr);
    const at = firstAddr(tr);
    if (entry && at !== entry) fail(`trace.first[0] (${at === null ? 'unparsable' : '0x' + at.toString(16)}) is not the hooked entry`, { entry: '0x' + entry.toString(16), first: tr.first?.[0] });
    if (!String(tr.first?.[0] ?? '').includes(': ')) fail('trace.first[0] has no "0x…: instruction" shape', tr.first?.[0]);
  }
  // The trace observes: the hooked function must still answer what it did before, twice-executed or not.
  const after = Number(await callJava('nativeHookProbe'));
  if (after !== before) fail(`the traced call changed the target's answer (${before} -> ${after})`);
  await unhook(hookA);
  hookA = 0;

  // (1b) the INLINE path. Its entry carries our own branch, and following that branch is what killed
  //      the target before (QBDI never comes back from Dobby's pool), so the run has to start in the
  //      trampoline and still reach the function body. This is the shape a non-exported function
  //      forces (libjdg+0x101da0), so it is part of the gate, not an extra.
  const installInline = await mcp('native_hook', { session, action: 'hook', mode: 'inline', module: 'libadhdetect.so', symbol: 'adh_trace_target', traceInsns: 32 });
  if (!installInline.ok) {
    fail('the inline install with traceInsns failed', installInline.error);
  } else {
    const inlineId = Number(installInline.hookId);
    hookA = inlineId;
    const st = (installInline.status?.hooks ?? []).find((h) => Number(h.id) === inlineId) ?? {};
    const inlineEntry = st.target ? BigInt(st.target) : null;
    const trampoline = st.original ? BigInt(st.original) : null;
    const value = Number(await callJava('nativeHookProbe'));
    if (value !== 30) fail(`the inline traced call changed the fixture's answer (${value})`);
    const ev = (await eventsFor(inlineId)).pop();
    const tr = ev?.trace;
    if (!tr) fail('the inline hook event carries no trace', { keys: Object.keys(ev ?? {}) });
    else {
      if (!(Number(tr.seen) > 0)) fail('inline: the run executed nothing (start address not instrumentable)', tr);
      if (!REASONS.has(String(tr.stopReason))) fail(`inline: stopReason ${tr.stopReason} is outside the documented set`, tr);
      // It must say where it really started, and that address must be where first[0] is.
      if (trampoline && BigInt(tr.start) !== trampoline) fail('inline: the run did not start in the trampoline the stub uses', { start: tr.start, trampoline: '0x' + trampoline.toString(16) });
      if (inlineEntry && trampoline && inlineEntry === trampoline) fail('inline: the install reported the entry as its own trampoline', st);
      if (firstAddr(tr) !== BigInt(tr.start)) fail('inline: first[0] is not at the reported start address', { first: tr.first?.[0], start: tr.start });
      if (!String(tr.first?.[0] ?? '').match(/sub|stp|str|mov|ldr/)) fail('inline: first[0] does not look like the relocated prologue', tr.first?.[0]);
    }
    const valueAgain = Number(await callJava('nativeHookProbe'));
    if (valueAgain !== 30) fail(`the inline traced call changed the fixture's answer on a second hit (${valueAgain})`);
    await unhook(inlineId);
    hookA = 0;
    globalThis.__inlineTrace = tr ? { start: tr.start, seen: tr.seen, stopReason: tr.stopReason, first: (tr.first ?? []).slice(0, 3) } : null;
  }

  // (2) trace OFF: the same function, no trace requested - the event must not carry the key at all.
  const installB = await mcp('native_hook', { session, action: 'hook', mode: 'sites', module: 'libadhdetect.so', symbol: 'adh_trace_target', sites: 4 });
  if (!installB.ok) throw new Error(`install (trace off) failed: ${installB.error}`);
  hookB = Number(installB.hookId);
  const statusB = (installB.status?.hooks ?? []).find((h) => Number(h.id) === hookB) ?? {};
  if (Number(statusB.traceInsns) !== 0) fail('status does not echo traceInsns:0 for the untraced hook', statusB);
  const quiet = Number(await callJava('nativeHookProbe'));
  if (quiet !== 30) fail(`the untraced hook changed the fixture's answer (${quiet})`);
  const eventsB = await eventsFor(hookB);
  if (!eventsB.length) fail('no NATIVE_HOOK event arrived for the untraced hook');
  for (const ev of eventsB) {
    if ('trace' in ev) fail('an event of a hook installed with traceInsns unset carries a trace key', { keys: Object.keys(ev) });
    if ('traceSkipped' in ev) fail('an untraced event carries traceSkipped', { keys: Object.keys(ev) });
  }
  await unhook(hookB);
  hookB = 0;

  // (3) the target is alive and the agent still answers.
  const ping = await mcp('agent_ping', { session }).catch((e) => ({ ok: false, error: String(e.message ?? e) }));
  if (ping.ok !== true) fail('the target is not answering after the traces', ping);
  console.log(JSON.stringify({
    traceOn: { hookId: Number(installA.hookId), entry: statusA.target, trace: tr ? {
      insns: tr.insns, seen: tr.seen, stopReason: tr.stopReason, capped: tr.capped,
      start: tr.start, stopPc: tr.stopPc, mnemonics: (tr.mnemonics ?? []).slice(0, 4), first: (tr.first ?? []).slice(0, 3),
      error: tr.error ?? null,
    } : null },
    traceOff: { hookId: Number(installB.hookId), eventKeys: Object.keys(eventsB[eventsB.length - 1] ?? {}) },
    inlineTrace: globalThis.__inlineTrace ?? null,
    values: { before, after, quiet },
    alive: ping.ok === true,
  }));
} catch (e) {
  fail('exception', String(e.message ?? e));
} finally {
  if (hookA > 0) await unhook(hookA);
  if (hookB > 0) await unhook(hookB);
}

if (failures.length) { console.log(failures.join('\n')); console.log('RESULT:FAIL'); }
else console.log('RESULT:PASS');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
if grep -q 'RESULT:PASS' <<<"$OUT"; then
  echo "OK v117 in-hook trace (device) PASS"
  exit 0
fi
echo "FAIL v117 in-hook trace (device) FAIL"
exit 1
