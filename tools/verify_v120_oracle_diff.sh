#!/usr/bin/env bash
# Oracle + differential harness (device): record one call, replay it with one field changed, and get the
# dependency matrix back.
#
# Why it is a gate: this is the primitive that makes an unknown parameter tractable without knowing
# anything about the target - call the target's own entry point with controlled arguments, change ONE
# input field, and ask which output moved. Every real protocol analysis reimplements it by hand (and gets
# it subtly wrong: the wrong field, a stale template, a call that blocks the session).
#
# The fixture is the sandbox's own static facade: `JniCallStatics.staticCombine(label, count)` returns
# "S:<label>:<count>", so a patch to either argument MUST move the observed value and a patch to an unused
# position MUST NOT. That is an exact, target-independent check of record/replay/diff.
#
# Missing preconditions print "SKIP ..." and exit 0 WITHOUT RESULT:PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v120_oracle_diff (no device)"
  exit 0
fi
if ! verify_restart_sandbox; then
  echo "SKIP  verify_v120_oracle_diff (could not restart the sandbox)"
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
if (!agent) { console.log('SKIP  verify_v120_oracle_diff (no online sandbox agent)'); process.exit(0); }
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

try {
  const rec = await mcp('oracle', {
    session, action: 'record',
    className: 'com.adh.sandbox.JniCallStatics', method: 'staticCombine',
    params: 'java.lang.String,int', args: ['ADH', 7], extract: 'result',
  });
  if (!rec.ok) throw new Error(`record failed: ${rec.error}`);
  if (String(rec.baseline) !== 'S:ADH:7') fail(`the recorded baseline is ${JSON.stringify(rec.baseline)}, expected S:ADH:7`, rec);

  const rep = await mcp('oracle', {
    session, action: 'replay', id: rec.id,
    patches: [{ path: '[1]', value: 8 }],
  });
  if (!rep.ok) fail('replay failed', rep);
  else {
    if (String(rep.value) !== 'S:ADH:8') fail(`replay with count=8 answered ${JSON.stringify(rep.value)}`, rep);
    if (rep.changed !== true) fail('replay did not report the value as changed', rep);
  }

  const diff = await mcp('oracle', {
    session, action: 'diff', id: rec.id,
    variants: [
      { label: 'count', patches: [{ path: '[1]', value: 9 }] },
      { label: 'label', patches: [{ path: '[0]', value: 'ADH!' }] },
    ],
  });
  if (!diff.ok) fail('diff failed', diff);
  else {
    const d = diff.diff ?? {};
    if (!Array.isArray(d.rows) || d.rows.length !== 2) fail('the matrix does not carry one row per variant', d);
    if (!(d.sensitive ?? []).includes('[1]')) fail('the count argument is not reported as sensitive', d);
    if (!(d.sensitive ?? []).includes('[0]')) fail('the label argument is not reported as sensitive', d);
    if ((d.insensitive ?? []).length) fail('a patch that does move the output was reported as insensitive', d);
    if (String(d.rows?.[0]?.value) !== 'S:ADH:9') fail('the first variant value is wrong', d.rows?.[0]);
  }

  // A no-op patch (same value) must come back identical: the harness must not report a difference just
  // because a variant ran.
  const same = await mcp('oracle', {
    session, action: 'diff', id: rec.id,
    variants: [{ label: 'no-op', patches: [{ path: '[1]', value: 7 }] }],
  });
  if (!same.ok) fail('the no-op diff failed', same);
  else if (same.diff?.rows?.[0]?.same !== true) fail('a patch that changes nothing was reported as a change', same.diff);

  const list = await mcp('oracle', { session, action: 'list' });
  if (!Array.isArray(list.oracles) || !list.oracles.length) fail('the recorded template is not listed', list);
  const dropped = await mcp('oracle', { session, action: 'drop', id: rec.id });
  if (dropped.ok !== true) fail('drop failed', dropped);
  console.log(JSON.stringify({ id: rec.id, baseline: rec.baseline, replay: rep.value, diff: diff.diff, noop: same.diff }));
} catch (e) {
  fail('exception', String(e.message ?? e));
}

if (failures.length) { console.log(failures.join('\n')); console.log('RESULT:FAIL'); }
else console.log('RESULT:PASS');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
if grep -q 'RESULT:PASS' <<<"$OUT"; then
  echo "OK v120 oracle + differential (device) PASS"
  exit 0
fi
echo "FAIL v120 oracle + differential (device) FAIL"
exit 1
