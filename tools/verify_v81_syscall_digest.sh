#!/usr/bin/env bash
# v4.43 syscall digest (HOST-ONLY, no device).
#
# The watch answers "a syscall happened"; the digest answers "which app function issued it, how often,
# and was the hook even attributed the right number". Its core (grouping + caller selection + runtime
# vs attributed x8) is a pure function, so the whole thing is verifiable without a phone.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

OUT="$(node - "$ROOT" <<'EOF'
const [root] = process.argv.slice(2);
const { spawnSync } = await import('node:child_process');
const base = 'file:///' + String(root).replace(/\\/g, '/').replace(/^\//, '');
const problems = [];
const notes = [];

// Per-FILE minimums: a single total would still pass if one file's tests were deleted while another
// grew, which is exactly the hole this check is supposed to close.
const TEST_FILES = [
  ['syscall_digest.test.ts', 13],
  ['syscall_args.test.ts', 15],
  ['syscall_watch.test.ts', 14],
  ['trace_digest.test.ts', 7],
  ['backtrace.test.ts', 4],
];
let passed = 0, failed = 0;
for (const [file, minimum] of TEST_FILES) {
  const t = spawnSync(process.execPath, ['--test', `${root}/daemon/test/${file}`], { encoding: 'utf8' });
  const text = `${t.stdout ?? ''}${t.stderr ?? ''}`;
  const p = Number(/pass (\d+)/.exec(text)?.[1] ?? -1);
  const f = Number(/fail (\d+)/.exec(text)?.[1] ?? -1);
  if (t.status !== 0) problems.push(`${file}: exited ${t.status}`);
  if (p < minimum) problems.push(`${file}: expected >=${minimum} passing tests, saw ${p}`);
  if (f !== 0) problems.push(`${file}: reports ${f} failures`);
  passed += Math.max(0, p); failed += Math.max(0, f);
}
if (passed < 53) problems.push(`expected >=53 passing unit tests in total, saw ${passed}`);
notes.push(`unit tests: pass=${passed} fail=${failed} (per-file minimums enforced)`);

let digestSyscallSamples;
try {
  ({ digestSyscallSamples } = await import(`${base}/daemon/src/syscall_digest.ts`));
} catch (e) {
  problems.push('import syscall_digest.ts failed: ' + e.message);
}
if (digestSyscallSamples) {
  const caller = (module, symbol) => ({ module, symbol, offset: '0x10' });
  const d = digestSyscallSamples([
    { hookId: 3, observedNr: 160, ts: 10, tid: 7, callers: [caller('libc.so', 'uname'), caller('libadhdetect.so', 'adh_libc_uname_probe')] },
    { hookId: 3, observedNr: 160, ts: 20, tid: 7, callers: [caller('libc.so', 'uname'), caller('libadhdetect.so', 'adh_libc_uname_probe')] },
    { hookId: 4, observedNr: 63, ts: 30, tid: 8, callers: [caller('libc.so', 'read'), caller('libapp.so', 'readSecret')] },
  ], { expected: { 3: 160, 4: 160 } });
  const uname = d.groups.find((g) => g.caller.includes('adh_libc_uname_probe'));
  if (!uname || uname.count !== 2 || uname.nr !== 160) problems.push(`uname grouping drifted: ${JSON.stringify(d.groups)}`);
  if (d.groups.some((g) => g.caller.startsWith('libc.so'))) problems.push('caller selection kept a libc frame instead of the issuing frame');
  if (!d.mismatches.some((m) => m.hookId === 4 && m.attributed === 160 && m.observed === 63)) problems.push(`mismatch detection drifted: ${JSON.stringify(d.mismatches)}`);
  notes.push(`synthetic hits -> groups=${d.groups.length} mismatches=${d.mismatches.length} observed=${JSON.stringify(d.observed)}`);

  // Argument decoding: the path argument becomes a group example and feeds the path histogram.
  let decodeArgs, argPlan, digestWithArgs;
  try {
    ({ decodeArgs, argPlan } = await import(`${base}/daemon/src/syscall_args.ts`));
  } catch (e) {
    problems.push('import syscall_args.ts failed: ' + e.message);
  }
  if (decodeArgs && argPlan) {
    const plan = argPlan(56, [0n, 0x1000n, 0x80000n, 0n]);
    if (plan.reads.length !== 1 || plan.reads[0].reg !== 1) problems.push(`openat arg plan drifted: ${JSON.stringify(plan)}`);
    const args = decodeArgs(56, [-100n, 0x1000n, 0x80000n, 0n], { 1: Buffer.from('/proc/cpuinfo\0', 'utf8') });
    const path = args.find((a) => a.name === 'path')?.value;
    if (path !== '/proc/cpuinfo') problems.push(`openat path decoding drifted: ${path}`);
    const flags = String(args.find((a) => a.name === 'flags')?.value ?? '');
    if (!/O_RDONLY/.test(flags) || !/O_CLOEXEC/.test(flags)) problems.push(`openat flag decoding drifted: ${flags}`);
    if (digestSyscallSamples) {
      const withArgs = digestSyscallSamples([
        { hookId: 9, observedNr: 56, ts: 1, tid: 1, callers: [caller('libapp.so', 'probe')], args },
        { hookId: 9, observedNr: 56, ts: 2, tid: 1, callers: [caller('libapp.so', 'probe')], args },
      ]);
      if (withArgs.paths[0]?.path !== '/proc/cpuinfo' || withArgs.paths[0]?.count !== 2) problems.push(`path histogram drifted: ${JSON.stringify(withArgs.paths)}`);
      if (!String(withArgs.groups[0]?.example ?? '').includes('/proc/cpuinfo')) problems.push('group example missing the decoded path');
      notes.push(`arg decode -> path=${path} flags=${flags} histogram=${JSON.stringify(withArgs.paths)}`);
    }
  }
}

try {
  const { MCP_TOOLS } = await import(`${base}/daemon/src/mcp.ts`);
  const tool = (MCP_TOOLS ?? []).find((x) => x.name === 'syscall_digest');
  if (!tool) problems.push('syscall_digest tool missing from the MCP registry');
  else {
    if (!tool.inputSchema?.properties?.hookIds) problems.push('syscall_digest does not accept hookIds');
    if (!tool.inputSchema?.properties?.expected) problems.push('syscall_digest does not accept the expected attribution map');
    if (!tool.inputSchema?.properties?.decode) problems.push('syscall_digest does not accept the decode toggle');
    notes.push(`MCP tools=${MCP_TOOLS.length}, syscall_digest present`);
  }
} catch (e) {
  problems.push('import mcp.ts failed: ' + e.message);
}

for (const n of notes) console.log('  ' + n);
for (const p of problems) console.log('FAIL ' + p);
console.log(problems.length === 0 ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v4.43 syscall digest (unit + grouping + MCP shape)" 0