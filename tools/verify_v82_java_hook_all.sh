#!/usr/bin/env bash
# v4.44 java_hook hookAll acceptance (device).
#
# Frida-style batch hooking: one call installs every matching method of a class instead of a
# hand-written enumeration loop, and the response reports how many methods MATCHED next to how many
# were installed - so a slot-limited batch cannot masquerade as a complete one.
#
# Checks: (1) a name filter installs both ping overloads and each overload really fires its own hook;
# (2) a class-wide filter with a small limit installs exactly limit hooks while reporting a larger
# matched count (truncation is visible); (3) unhook 0 removes everything and the process stays alive.
# Missing preconditions print "SKIP ..." and exit 0 WITHOUT RESULT:PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v82_java_hook_all (no device)"
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
if (!agent) { console.log('SKIP  verify_v82_java_hook_all (no online sandbox agent)'); process.exit(0); }
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
const CLASS = 'com.adh.sandbox.HookProbe';

const probe = await post('/api/java/hook', { session, action: 'hookAll', className: CLASS, method: 'ping', limit: 4 });
if (/requires action/i.test(String(probe.body?.error ?? ''))) {
  console.log('SKIP  verify_v82_java_hook_all (agent predates hook_all; redeploy the agent)');
  process.exit(0);
}
await post('/api/java/hook', { session, action: 'unhook', hookId: 0 }).catch(() => null);

// Cursor so a rerun cannot be satisfied by the PREVIOUS run's events: Java hook ids restart at 1 in
// a fresh agent, so "an event with this hookId exists" is not proof that THIS run fired it.
const cursorList = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=1`)).json().catch(() => ({}));
const sinceId = Number((cursorList.captures ?? []).slice(-1)[0]?.id ?? 0);

// (1) both ping overloads in one call
const batch = await post('/api/java/hook', { session, action: 'hookAll', className: CLASS, method: 'ping', limit: 4 });
if (batch.body?.ok !== true) fail(`hookAll(ping) failed: ${batch.body?.error ?? batch.status}`, batch);
const batchIds = (batch.body.hookIds ?? []).map((n) => Number(n));
if (batchIds.length !== 2 || Number(batch.body.matched) !== 2) {
  fail(`expected both ping overloads (ids=2, matched=2), got ids=${JSON.stringify(batchIds)} matched=${batch.body.matched}`, batch);
}
const callOne = await post('/api/java/call', { session, className: CLASS, method: 'ping', params: 'java.lang.String', args: ['ADH_ALL_ONE'] });
const callTwo = await post('/api/java/call', { session, className: CLASS, method: 'ping', params: 'java.lang.String,int', args: ['ADH_ALL_TWO', 3] });
if (callOne.body?.ok !== true || String(callOne.body?.result?.result) !== 'REAL_HOOK:ADH_ALL_ONE') {
  fail(`1-arg overload call failed: ${callOne.body?.result?.result ?? callOne.body?.error}`, callOne);
}
if (callTwo.body?.ok !== true || String(callTwo.body?.result?.result) !== 'REAL_HOOK:ADH_ALL_TWO*3') {
  fail(`2-arg overload call failed: ${callTwo.body?.result?.result ?? callTwo.body?.error}`, callTwo);
}
const sawIds = new Set();
const deadline = Date.now() + 10_000;
while (Date.now() < deadline && sawIds.size < batchIds.length) {
  const list = await (await fetch(`${base}/api/captures?session=${encodeURIComponent(session)}&limit=300`)).json().catch(() => ({}));
  for (const item of (list.captures ?? [])) {
    if (Number(item.id) <= sinceId) continue;          // older than this run
    if (item.func !== 'JAVA_HOOK') continue;
    const detail = await (await fetch(`${base}/api/captures/${item.id}`)).json().catch(() => null);
    const text = Buffer.from(String(detail?.hex ?? ''), 'hex').toString('utf8');
    for (const id of batchIds) if (text.includes(`"hookId":${id}`)) sawIds.add(id);
  }
  if (sawIds.size >= batchIds.length) break;
  await sleep(150);
}
if (sawIds.size !== batchIds.length) {
  await post('/api/java/hook', { session, action: 'unhook', hookId: 0 });
  fail(`only ${sawIds.size}/${batchIds.length} overload hooks produced events: ${JSON.stringify([...sawIds])} vs ${JSON.stringify(batchIds)}`, { batchIds, sawIds: [...sawIds] });
}
if (batch.body?.partial === true) fail('batch reported partial install on the two-overload case', batch);
const unhookAll = await post('/api/java/hook', { session, action: 'unhook', hookId: 0 });

// (2) class-wide batch with a small limit: truncation must be visible via matched
const limited = await post('/api/java/hook', { session, action: 'hookAll', className: CLASS, limit: 3 });
if (limited.body?.ok !== true) fail(`class-wide hookAll failed: ${limited.body?.error ?? limited.status}`, limited);
const limitedIds = (limited.body.hookIds ?? []).map((n) => Number(n));
const limitedMatched = Number(limited.body.matched ?? 0);
if (limitedIds.length !== 3 || limitedMatched <= 3) {
  fail(`limit=3 must install exactly 3 of a larger match set, got installed=${limitedIds.length} matched=${limitedMatched}`, limited);
}
const status = await post('/api/java/hook', { session, action: 'status' });
const statusCount = Number(status.body?.status?.count ?? -1);
if (statusCount !== limitedIds.length) {
  await post('/api/java/hook', { session, action: 'unhook', hookId: 0 });
  fail(`status count ${statusCount} != installed ${limitedIds.length}`, status);
}
const unhook2 = await post('/api/java/hook', { session, action: 'unhook', hookId: 0 });
const online = (await (await fetch(`${base}/api/agents`)).json().catch(() => [])).some((x) => x.online && x.package === 'com.adh.sandbox');

console.log(JSON.stringify({
  pingBatch: { hookIds: batchIds, matched: batch.body.matched, calls: [callOne.body?.result?.result, callTwo.body?.result?.result], events: [...sawIds] },
  limitedBatch: { hookIds: limitedIds, matched: limitedMatched, statusCount },
  unhook: { first: unhookAll.body?.ok === true, second: unhook2.body?.ok === true },
  online,
}));
// Fold every assertion into the final verdict instead of relying on the early-exit calls alone.
const pingBatchOk = batch.body?.ok === true && batchIds.length === 2 && Number(batch.body.matched) === 2 && batch.body.partial !== true;
const overloadsFired = sawIds.size === batchIds.length;
const limitedOk = limited.body?.ok === true && limitedIds.length === 3 && limitedMatched > 3 && limited.body.partial === true;
const callsOk = String(callOne.body?.result?.result) === 'REAL_HOOK:ADH_ALL_ONE' && String(callTwo.body?.result?.result) === 'REAL_HOOK:ADH_ALL_TWO*3';
const pass = pingBatchOk && overloadsFired && callsOk && limitedOk && statusCount === limitedIds.length &&
  unhookAll.body?.ok === true && unhook2.body?.ok === true && online;
if (!pass) console.log('FAIL unhook or liveness check failed');
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v4.44 java_hook hookAll (all overloads + visible truncation)" 0 && exit 0 || exit 1