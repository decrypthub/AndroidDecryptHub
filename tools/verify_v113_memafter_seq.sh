#!/usr/bin/env bash
# memAfter must be joinable on (hookId, seq) (device).
#
# The documented way to pair a register event with its memory record is (hookId, seq), and seq is
# numbered per hook. The post-call copy used to be emitted with NO seq at all, so a reader that joined
# on the documented key silently dropped every "what did it WRITE" record. That is not a cosmetic
# defect: three separate analysis rounds on a real target concluded "memAfter produces nothing" while
# the records were sitting in the ring, and the analysis moved on without them.
#
# The gate is exact, not approximate:
#   hook libc labs with mem "x0:8" + memAfter "x0:8", call it ourselves, and require
#   one pre row AND one phase:"after" row carrying the SAME seq.
#
# Missing preconditions print "SKIP ..." and exit 0 WITHOUT RESULT:PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v113_memafter_seq (no device)"
  exit 0
fi
if ! verify_restart_sandbox; then
  echo "SKIP  verify_v113_memafter_seq (could not restart the sandbox)"
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
if (!agent) { console.log('SKIP  verify_v113_memafter_seq (no online sandbox agent)'); process.exit(0); }
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
  const a = await mcp('native_call', { session, module: 'libc.so', symbol: 'malloc', args: ['64'], confirm: true });
  if (!a.ok) throw new Error(`malloc failed: ${a.error}`);
  const buf = '0x' + BigInt(a.result).toString(16);
  await mcp('memory_write', { session, addr: buf, hex: '4142434400000000' });

  const hook = await mcp('native_hook', { session, action: 'hook', mode: 'inline', module: 'libc.so', symbol: 'labs', mem: 'x0:8', memAfter: 'x0:8', confirm: true });
  if (!hook.ok) throw new Error(`install failed: ${hook.error}`);
  hookId = Number(hook.hookId);
  const rep = hook.status?.hooks?.[0] ?? {};
  if (rep.afterActive !== true) fail('the install did not activate the post-call stub', rep);

  const call = await mcp('native_call', { session, module: 'libc.so', symbol: 'labs', args: [buf], confirm: true });
  if (!call.ok) fail('the hooked call did not answer', call);

  let pre = null;
  let aft = null;
  for (let i = 0; i < 12 && !(pre && aft); i++) {
    await sleep(500);
    const caps = await mcp('live_captures', { session, limit: 400, includeText: true, encoding: 'b64' });
    for (const r of caps.captures ?? caps) {
      if (r.func !== 'NATIVE_HOOK_MEM' || !r.b64) continue;
      let o;
      try { o = JSON.parse(Buffer.from(r.b64, 'base64').toString('utf8')); } catch { continue; }
      if (Number(o.hookId) !== hookId) continue;
      if (o.phase === 'after') aft = o; else pre = o;
    }
  }
  if (!pre) fail('no pre-call memory record arrived');
  if (!aft) fail('no phase:"after" record arrived (memAfter still not emitted)');
  if (pre && aft) {
    if (pre.seq === undefined) fail('the pre record carries no seq', pre);
    if (aft.seq === undefined) fail('the after record carries no seq - the documented (hookId, seq) join cannot see it', aft);
    if (String(pre.seq) !== String(aft.seq)) fail(`the after seq ${aft.seq} does not match the pre seq ${pre.seq}`, { pre, aft });
    // Both records must have the SAME shape and the same window, otherwise the join "works" while the
    // two sides describe different things.
    const pw = (pre.mem ?? [])[0];
    const aw = (aft.mem ?? [])[0];
    if (!pw || !aw) fail('one of the two records has no mem window (the shapes diverged)', { pre, aft });
    else {
      if (String(pw.hex) !== String(aw.hex)) fail('the two copies disagree, so they are not the same window', { pw, aw });
      if (aw.reg !== pw.reg || aw.offset !== pw.offset || aw.requested !== pw.requested) {
        fail('the after window does not describe the same register/offset/length', { pw, aw });
      }
    }
  }
  console.log(JSON.stringify({ hookId, preSeq: pre?.seq, afterSeq: aft?.seq, preHex: (pre?.mem ?? [])[0]?.hex, afterHex: (aft?.mem ?? [])[0]?.hex, ret: aft?.ret }));
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
  echo "OK v113 memAfter seq pairing (device) PASS"
  exit 0
fi
echo "FAIL v113 memAfter seq pairing (device) FAIL"
exit 1
