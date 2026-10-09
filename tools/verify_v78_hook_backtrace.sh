#!/usr/bin/env bash
# v4.39 hook-hit caller backtrace acceptance (device).
#
# Frida users reach for Thread.backtrace() the moment a hook fires; without it a hit tells you the
# arguments but not which code path produced them. The inline-hook stub already saved x29/x30 - this
# check proves the pipeline end to end:
#   * the NATIVE_HOOK event publishes x29 (frame pointer) and x30 (return address) of the hit,
#   * native_backtrace walks the frame-pointer chain through the sandbox fixtures
#     adh_bt_outer -> adh_bt_mid1 -> adh_bt_mid2 -> adh_bt_target (built with -fno-omit-frame-pointer)
#     and names each frame from the module's dynamic symbols (module + offset + exact/nearest),
#   * a bogus frame pointer stops the walk with an explicit reason instead of inventing frames.
#
# Missing preconditions print "SKIP ..." and exit 0 WITHOUT RESULT:PASS (counted as a skip).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v78_hook_backtrace (no device)"
  exit 0
fi

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const agents = await (await fetch(`${base}/api/agents`)).json().catch(() => null);
const agent = (Array.isArray(agents) ? agents : [])
  .filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((a, b) => (b.connectedAt ?? 0) - (a.connectedAt ?? 0))[0];
if (!agent) { console.log('SKIP  verify_v78_hook_backtrace (no online sandbox agent)'); process.exit(0); }
const session = agent.sessionId;

async function post(path, body) {
  const r = await fetch(`${base}${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  let parsed = null;
  try { parsed = await r.json(); } catch { parsed = null; }
  return { status: r.status, body: parsed };
}
const fail = (msg, extra) => {
  if (extra !== undefined) console.log(JSON.stringify(extra));
  console.log('FAIL ' + msg);
  console.log('RESULT:FAIL');
  process.exit(0);
};
const mcp = async (name, args) => {
  const r = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: { session, ...args } } }) });
  const j = await r.json();
  if (j.error) return { ok: false, error: String(j.error.message ?? j.error) };
  const c = j.result?.content?.[0]?.text ?? JSON.stringify(j);
  try { return JSON.parse(c); } catch { return { raw: String(c) }; }
};

// (0) capability gate: the tool must exist and must recognise a missing hook event (an old daemon
// answers with a JSON-RPC "method not found", an old agent has no x29/x30 in its events).
const probe = await mcp('native_backtrace', { hookId: 9999 });
if (/not found|unknown tool|Method not found/i.test(String(probe?.error ?? '')) && probe?.ok === false) {
  console.log('SKIP  verify_v78_hook_backtrace (daemon has no native_backtrace tool; restart it)');
  process.exit(0);
}

// (1) hook the innermost fixture and call the outermost one.
const hook = await post('/api/native/hook', {
  session, action: 'hook', mode: 'inline', module: 'libadhdetect.so', symbol: 'adh_bt_target',
  backtrace: true,   // capture the caller chain at the hit; a later stack read is stale by design
});
if (!hook.body?.ok) fail(`hooking adh_bt_target failed: ${hook.body?.error ?? hook.status}`, hook);
const hookId = Number(hook.body.hookId);

const call = await post('/api/native/call', {
  session, module: 'libadhdetect.so', symbol: 'adh_bt_outer', args: [], confirm: true,
});
if (!call.body?.ok) {
  await post('/api/native/hook', { session, action: 'unhook', hookId });
  const err = String(call.body?.error ?? '');
  if (/not found|no such|symbol/i.test(err)) {
    console.log('SKIP  verify_v78_hook_backtrace (sandbox fixture adh_bt_outer missing; rebuild + install the sandbox APK)');
    process.exit(0);
  }
  fail(`native_call adh_bt_outer failed: ${err}`, call);
}
if (Number(call.body.resultDecimal) !== 67) fail(`adh_bt_outer returned ${call.body.resultDecimal}, expected 67`, call);

// (2) the hook event must carry the captured frame pointer / return address.
let event = null;
const evDeadline = Date.now() + 8_000;
while (Date.now() < evDeadline && !event) {
  const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=200`)).json().catch(() => ({}));
  for (const item of (list.captures ?? [])) {
    if (item.func !== 'NATIVE_HOOK') continue;
    const detail = await (await fetch(`${base}/api/captures/${item.id}`)).json().catch(() => null);
    const text = Buffer.from(String(detail?.hex ?? ''), 'hex').toString('utf8');
    if (text.includes(`"hookId":${hookId}`)) { event = JSON.parse(text); break; }
  }
  if (!event) await sleep(120);
}
if (!event) { await post('/api/native/hook', { session, action: 'unhook', hookId }); fail('no NATIVE_HOOK event for the hook', { hookId }); }
if (!Array.isArray(event.bt) || event.bt.length < 3) {
  await post('/api/native/hook', { session, action: 'unhook', hookId });
  fail(`the event did not carry an at-hit chain (bt=${JSON.stringify(event.bt)})`, { hookId, event });
}
if (event.x29 === undefined || event.x30 === undefined) {
  await post('/api/native/hook', { session, action: 'unhook', hookId });
  console.log('SKIP  verify_v78_hook_backtrace (agent predates x29/x30 publication; redeploy the agent)');
  process.exit(0);
}

// (3) the backtrace must walk the fixture chain and name every frame.
const bt = await mcp('native_backtrace', { hookId, maxFrames: 12 });
if (bt?.error) { await post('/api/native/hook', { session, action: 'unhook', hookId }); fail(`native_backtrace failed: ${bt.error}`, bt); }
if (!String(bt.source ?? '').includes('at-hit')) {
  await post('/api/native/hook', { session, action: 'unhook', hookId });
  fail(`native_backtrace used ${bt.source} instead of the at-hit chain (is backtrace:true supported by this agent?)`, bt);
}
if (bt.symbolSource !== 'dynsym') {
  await post('/api/native/hook', { session, action: 'unhook', hookId });
  fail(`symbolSource=${bt.symbolSource} (expected dynsym: the sandbox lib is not archive-mapped)`, bt);
}
const frames = bt.frames ?? [];
const want = [['adh_bt_mid2', frames[0]], ['adh_bt_mid1', frames[1]], ['adh_bt_outer', frames[2]]];
for (const [name, frame] of want) {
  if (!frame) { await post('/api/native/hook', { session, action: 'unhook', hookId }); fail(`backtrace stopped before ${name} (frameCount=${bt.frameCount}, stopReason=${bt.stopReason})`, bt); }
  if (frame.symbol !== name) {
    await post('/api/native/hook', { session, action: 'unhook', hookId });
    fail(`frame ${frame.index} resolved to ${frame.symbol ?? 'null'}, expected ${name} (stopReason=${bt.stopReason})`, bt);
  }
  if (!frame.symbolExact) {
    await post('/api/native/hook', { session, action: 'unhook', hookId });
    fail(`frame ${frame.index} (${name}) is not an exact symbol hit (size came back ${frame.symbolSize ?? 'none'})`, bt);
  }
  if (frame.module !== 'libadhdetect.so') {
    await post('/api/native/hook', { session, action: 'unhook', hookId });
    fail(`frame ${frame.index} (${name}) resolved to module ${frame.module ?? 'null'}`, bt);
  }
}
if (bt.trusted !== true) fail('backtrace did not report a trusted chain despite walking three caller frames', bt);

// (4) honesty: a bogus frame pointer must stop the walk with a reason, not invent frames.
const bogus = await mcp('native_backtrace', { fp: '0x1', lr: frames[0].pc, maxFrames: 8 });
if (bogus?.error) fail(`explicit-fp backtrace failed: ${bogus.error}`, bogus);
if ((bogus.frames ?? []).length !== 1 || bogus.trusted !== false || !bogus.stopReason) {
  fail('a bogus frame pointer did not stop the walk cleanly', bogus);
}

const unhook = await post('/api/native/hook', { session, action: 'unhook', hookId });
const online = (await (await fetch(`${base}/api/agents`)).json().catch(() => [])).some((x) => x.online && x.package === 'com.adh.sandbox');
console.log(JSON.stringify({
  hookId, call: call.body.resultDecimal, eventFp: event.x29, eventLr: event.x30, atHitChain: event.bt,
  source: bt.source, symbolSource: bt.symbolSource, frameCount: bt.frameCount, trusted: bt.trusted, stopReason: bt.stopReason,
  frames: frames.slice(0, 5),
  bogusStop: { frameCount: bogus.frames.length, stopReason: bogus.stopReason, trusted: bogus.trusted },
  unhookOk: unhook.body?.ok === true, online,
}));
const pass = unhook.body?.ok === true && online;
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v4.39 hook-hit caller backtrace (x29 chain + symbols)" 0 && exit 0 || exit 1