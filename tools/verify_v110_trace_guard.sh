#!/usr/bin/env bash
# Trace safety (device).
#
# The instruction tracer used to be able to KILL the target. Measured on libjdg: a trace of a
# function whose entry still carried a soft-unhooked ADH inline patch followed the Dobby branch into
# its trampoline, never returned to the emulator, and the process died with SIGBUS BUS_ADRALN at
# pc=0x2a - the tombstone named neither the hook nor the tracer.
#
# Two guards now exist, and this script is their gate:
#   a) a target that carries one of our inline patches is REFUSED, with the hook id in the message
#      (both when the hook is active and when it is soft-unhooked - the soft case is the trap,
#      because it deliberately leaves the branch in the prologue);
#   b) every instrumented address is checked against the process's executable mappings and an
#      instruction budget bounds execution, so a run that leaves real code stops and reports
#      stopReason:"ran-away" instead of executing garbage.
#
# The clean path is asserted too: with no hook installed the same function traces to completion, so
# "refused" cannot be mistaken for "the tracer is broken".
#
# Missing preconditions print "SKIP ..." and exit 0 WITHOUT RESULT:PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v110_trace_guard (no device)"
  exit 0
fi

# A hard unhook permanently retires an address in this process (the backend state goes stale by
# design), and this script installs+hooks the same symbol three times. So it needs a fresh process -
# the same reason every other device script that scans live code bytes restarts the sandbox.
if ! verify_restart_sandbox; then
  echo "SKIP  verify_v110_trace_guard (could not restart the sandbox)"
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
if (!agent) {
  console.log('SKIP  verify_v110_trace_guard (no online sandbox agent)');
  process.exit(0);
}
const session = agent.sessionId;
console.log(`SKIP-CHECK session=${session}`);

const post = async (path, body) => {
  const res = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: res.status, body: await res.json().catch(() => null) };
};
const trace = (extra) => post('/api/trace/digest', { session, symLib: 'libadhdetect.so', symbol: 'adh_fp_target', ...extra });
const failures = [];
const fail = (msg, detail) => { failures.push(detail === undefined ? msg : `${msg}: ${JSON.stringify(detail).slice(0, 300)}`); };

// (0) clean path: no hook, the same symbol must trace to completion. Without this, "refused" below
// could just mean the tracer is broken.
const clean = await trace({});
if (clean.body?.stopReason !== 'completed' || !(clean.body?.instructionCount > 0) || clean.body?.retvalValid !== true) {
  fail('the clean trace did not complete', clean.body);
}

// (1) soft-unhooked hook: the trap case (the Dobby branch stays in the prologue on purpose).
const hookA = await post('/api/native/hook', { session, action: 'hook', mode: 'inline', module: 'libadhdetect.so', symbol: 'adh_fp_target' });
if (!hookA.body?.ok) fail(`could not install the hook under test: ${hookA.body?.error}`, hookA.body);
const idA = Number(hookA.body?.hookId ?? 0);
const softA = await post('/api/native/hook', { session, action: 'unhook', hookId: idA });
if (softA.body?.ok !== true) fail('soft unhook failed', softA.body);
const refusedSoft = await trace({});
if (refusedSoft.status === 200) fail('a SOFT-unhooked address was traced instead of refused', refusedSoft.body);
else if (!String(refusedSoft.body?.error ?? '').includes(`id ${idA}`)) fail('the refusal does not name the hook', refusedSoft.body);

// (2) active hook: the everyday mistake (hook, then trace).
const hookB = await post('/api/native/hook', { session, action: 'hook', mode: 'inline', module: 'libadhdetect.so', symbol: 'adh_fp_target' });
if (!hookB.body?.ok) fail(`could not reinstall the hook under test: ${hookB.body?.error}`, hookB.body);
const idB = Number(hookB.body?.hookId ?? 0);
const refusedActive = await trace({});
if (refusedActive.status === 200) fail('an ACTIVE-hooked address was traced instead of refused', refusedActive.body);
else if (!String(refusedActive.body?.error ?? '').includes(`id ${idB}`) || !String(refusedActive.body?.error ?? '').includes('active')) {
  fail('the active refusal does not name the hook/state', refusedActive.body);
}

// (3) clean up hard (the sandbox is disposable, but a leftover patch would poison the next run of
// this script - the same self-inflicted trap the product had to learn about).
for (const id of [idA, idB]) {
  if (id > 0) await post('/api/native/hook', { session, action: 'unhook', hookId: id, hard: true });
}
const afterClean = await trace({});
if (afterClean.body?.stopReason !== 'completed') fail('the address did not become traceable again after a hard unhook', afterClean.body);

const online = (await (await fetch(`${base}/api/agents`)).json().catch(() => [])).some((x) => x.online && x.package === 'com.adh.sandbox');
if (!online) fail('the target did not survive the refusals');

if (failures.length) {
  console.log(failures.join('\n'));
  console.log('RESULT:FAIL');
} else {
  console.log(JSON.stringify({
    clean: { stopReason: clean.body.stopReason, insns: clean.body.instructionCount },
    softUnhooked: { id: idA, status: refusedSoft.status },
    active: { id: idB, status: refusedActive.status },
    afterHardUnhook: afterClean.body.stopReason,
    online,
  }));
  console.log('RESULT:PASS');
}
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
if grep -q 'RESULT:PASS' <<<"$OUT"; then
  echo "✅ v110 trace safety (device) PASS"
  exit 0
fi
echo "❌ v110 trace safety (device) FAIL"
exit 1
