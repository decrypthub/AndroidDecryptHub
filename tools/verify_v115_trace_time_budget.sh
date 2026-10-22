#!/usr/bin/env bash
# The tracer needs a WALL-CLOCK bound, not only an instruction budget (device).
#
# Measured on a real target: a trace of a synchronous bytecode interpreter never reached the
# 200000-instruction budget in 60 s and the agent's command channel was blocked the whole time. The
# caller sees only "command timeout" and cannot tell "still running" from "hung", and the target had to be
# restarted. An instruction budget bounds the WORK; nothing bounded the TIME.
#
# The gate has two halves, and the first one is what keeps the second honest:
#   a) a normal trace still completes (no regression from adding the bound), and the reply declares
#      timeBudgetMs and a stopReason from the documented set;
#   b) the bound exists as a contract: timeBudgetMs is present and positive on every trace reply.
#
# A run that hits the bound is not manufactured here - that needs a function that spins for seconds, and
# inventing one on the acceptance host would be testing the host, not the tracer. What is asserted is the
# contract the fix introduced, plus that short traces are unaffected.
#
# Missing preconditions print "SKIP ..." and exit 0 WITHOUT RESULT:PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v115_trace_time_budget (no device)"
  exit 0
fi
if ! verify_restart_sandbox; then
  echo "SKIP  verify_v115_trace_time_budget (could not restart the sandbox)"
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
if (!agent) { console.log('SKIP  verify_v115_trace_time_budget (no online sandbox agent)'); process.exit(0); }
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
const REASONS = new Set(['completed', 'instruction-budget', 'time-budget', 'ran-away']);

try {
  const tr = await mcp('trace_digest', { session, symLib: 'libadhdetect.so', symbol: 'adh_fp_target' });
  if (tr.stopReason !== 'completed') fail('a clean trace no longer completes', tr);
  if (!(Number(tr.timeBudgetMs) > 0)) fail('the reply does not declare a positive timeBudgetMs', tr);
  if (!REASONS.has(String(tr.stopReason))) fail(`stopReason ${tr.stopReason} is outside the documented set`, tr);
  if (tr.retvalValid !== true) fail('retvalValid is false on a completed run', tr);
  console.log(JSON.stringify({ stopReason: tr.stopReason, timeBudgetMs: tr.timeBudgetMs, budget: tr.budget, insns: tr.instructionCount ?? tr.seen, retvalValid: tr.retvalValid }));

  const tr2 = await mcp('trace_digest', { session, symLib: 'libc.so', symbol: 'getpid' });
  if (tr2.stopReason !== 'completed') fail('a short libc trace does not complete', tr2);
  if (Number(tr2.timeBudgetMs) !== Number(tr.timeBudgetMs)) fail('timeBudgetMs is not stable across traces', { a: tr.timeBudgetMs, b: tr2.timeBudgetMs });
} catch (e) {
  fail('exception', String(e.message ?? e));
}
if (failures.length) { console.log(failures.join('\n')); console.log('RESULT:FAIL'); } else console.log('RESULT:PASS');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
if grep -q 'RESULT:PASS' <<<"$OUT"; then
  echo "OK v115 trace time budget (device) PASS"
  exit 0
fi
echo "FAIL v115 trace time budget (device) FAIL"
exit 1
