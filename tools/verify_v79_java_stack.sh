#!/usr/bin/env bash
# v4.40 Java hook caller chain acceptance (device).
#
# The Java analogue of the native Thread.backtrace work: with stack:true the LSPlant callback
# captures a bounded caller chain at the hit (Class#method:line, innermost first, hook plumbing
# filtered) and every JAVA_HOOK event carries it. This check drives a real Java call chain in the
# sandbox (stackOuter -> stackMiddle -> ping) and asserts:
#   * the chain names BOTH intermediate frames, in order, and contains no hook-plumbing frames,
#   * a hook installed WITHOUT stack:true emits no chain at all (the capture is opt-in, it costs a
#     stack walk per hit),
#   * status reports the last chain per hook, and unhooking leaves the process alive.
#
# Missing preconditions print "SKIP ..." and exit 0 WITHOUT RESULT:PASS (counted as a skip).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v79_java_stack (no device)"
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
if (!agent) { console.log('SKIP  verify_v79_java_stack (no online sandbox agent)'); process.exit(0); }
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
const fetchJavaEvents = async (hookId) => {
  const out = [];
  const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=300`)).json().catch(() => ({}));
  for (const item of (list.captures ?? [])) {
    if (item.func !== 'JAVA_HOOK') continue;
    const detail = await (await fetch(`${base}/api/captures/${item.id}`)).json().catch(() => null);
    const text = Buffer.from(String(detail?.hex ?? ''), 'hex').toString('utf8');
    if (!text.includes(`"hookId":${hookId}`)) continue;
    try { out.push(JSON.parse(text)); } catch { /* ignore malformed */ }
  }
  return out;
};

// (0) capability gate
const status0 = await post('/api/java/hook', { session, action: 'status' });
if (status0.body?.status?.stackCapture !== true) {
  console.log('SKIP  verify_v79_java_stack (agent predates Java stack capture; redeploy the agent)');
  process.exit(0);
}
await post('/api/java/hook', { session, action: 'unhook', hookId: 0 }).catch(() => null);

const CLASS = 'com.adh.sandbox.HookProbe';
const CALL = { session, className: CLASS, method: 'stackOuter', params: 'java.lang.String', args: ['ADH_STACK'] };

// (1) hook WITH stack:true -> the event must carry the caller chain
const withStack = await post('/api/java/hook', {
  session, action: 'hook', className: CLASS, method: 'ping', params: 'java.lang.String', stack: true,
});
if (withStack.body?.ok !== true) {
  const err = String(withStack.body?.error ?? '');
  if (/not found/i.test(err)) {
    console.log('SKIP  verify_v79_java_stack (sandbox fixture stackOuter missing; rebuild + install the sandbox APK)');
    process.exit(0);
  }
  fail(`java_hook install with stack failed: ${err}`, withStack);
}
const idWith = Number(withStack.body.hookId);
const call1 = await post('/api/java/call', CALL);
if (call1.body?.ok !== true) {
  await post('/api/java/hook', { session, action: 'unhook', hookId: idWith });
  fail(`java_call stackOuter failed: ${call1.body?.error ?? call1.status}`, call1);
}
if (String(call1.body?.result?.result ?? '') !== 'REAL_HOOK:ADH_STACK') {
  await post('/api/java/hook', { session, action: 'unhook', hookId: idWith });
  fail(`stackOuter returned ${call1.body?.result?.result ?? '?'} instead of REAL_HOOK:ADH_STACK`, call1);
}
let evWith = null;
const deadline1 = Date.now() + 8_000;
while (Date.now() < deadline1 && !evWith) {
  const events = await fetchJavaEvents(idWith);
  evWith = events.find((e) => typeof e.stack === 'string' && e.stack.length > 0) ?? null;
  if (!evWith) await sleep(150);
}
if (!evWith) {
  await post('/api/java/hook', { session, action: 'unhook', hookId: idWith });
  fail('no JAVA_HOOK event carried a caller chain although stack:true was set', { idWith });
}
const stack = String(evWith.stack);
const mid = stack.indexOf('com.adh.sandbox.HookProbe#stackMiddle');
const outer = stack.indexOf('com.adh.sandbox.HookProbe#stackOuter');
if (mid < 0 || outer < 0) {
  await post('/api/java/hook', { session, action: 'unhook', hookId: idWith });
  fail(`caller chain is missing a fixture frame (middle=${mid}, outer=${outer})`, { stack });
}
if (!(mid < outer)) {
  await post('/api/java/hook', { session, action: 'unhook', hookId: idWith });
  fail('caller chain is not innermost-first (stackMiddle must appear before stackOuter)', { stack });
}
if (stack.includes('AdhJavaHookBridge')) {
  await post('/api/java/hook', { session, action: 'unhook', hookId: idWith });
  fail('caller chain leaks hook-plumbing frames (AdhJavaHookBridge)', { stack });
}
const status1 = await post('/api/java/hook', { session, action: 'status' });
const hookStatus = (status1.body?.status?.hooks ?? []).find((h) => Number(h.id) === idWith) ?? null;
if (!hookStatus || hookStatus.stackCapture !== true || !String(hookStatus.lastStack ?? '').includes('HookProbe#stackMiddle')) {
  await post('/api/java/hook', { session, action: 'unhook', hookId: idWith });
  fail('status does not report the captured chain for this hook', { hookStatus });
}
const unhook1 = await post('/api/java/hook', { session, action: 'unhook', hookId: idWith });

// (2) hook WITHOUT the flag -> no chain, but the hook still works (opt-in proof)
const plain = await post('/api/java/hook', {
  session, action: 'hook', className: CLASS, method: 'ping', params: 'java.lang.String',
});
const idPlain = Number(plain.body?.hookId ?? 0);
const call2 = await post('/api/java/call', CALL);
let evPlain = null;
const deadline2 = Date.now() + 8_000;
while (Date.now() < deadline2 && !evPlain) {
  const events = await fetchJavaEvents(idPlain);
  evPlain = events[0] ?? null;
  if (!evPlain) await sleep(150);
}
const plainStack = evPlain ? (evPlain.stack ?? '') : null;
const unhook2 = await post('/api/java/hook', { session, action: 'unhook', hookId: idPlain });
const online = (await (await fetch(`${base}/api/agents`)).json().catch(() => [])).some((x) => x.online && x.package === 'com.adh.sandbox');

console.log(JSON.stringify({
  withStack: { hookId: idWith, stack, call: call1.body?.result?.result },
  status: { stackCapture: hookStatus?.stackCapture, lastStack: hookStatus?.lastStack },
  plain: { hookId: idPlain, eventSeen: evPlain != null, stack: plainStack, call: call2.body?.result?.result },
  unhook: { withStack: unhook1.body?.ok === true, plain: unhook2.body?.ok === true },
  online,
}));
const plainHasNoChain = evPlain != null && (evPlain.stack === undefined || evPlain.stack === '');
const pass = plainHasNoChain &&
  call2.body?.result?.result === 'REAL_HOOK:ADH_STACK' &&
  unhook1.body?.ok === true && unhook2.body?.ok === true && online;
if (!pass) console.log('FAIL the non-opt-in hook emitted a chain or the plain hook did not run');
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v4.40 Java hook caller chain (stack:true)" 0 && exit 0 || exit 1