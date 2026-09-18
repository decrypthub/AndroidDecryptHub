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

const t = spawnSync(process.execPath, ['--test',
  `${root}/daemon/test/syscall_digest.test.ts`,
  `${root}/daemon/test/syscall_watch.test.ts`,
  `${root}/daemon/test/trace_digest.test.ts`,
  `${root}/daemon/test/backtrace.test.ts`], { encoding: 'utf8' });
const text = `${t.stdout ?? ''}${t.stderr ?? ''}`;
const passed = Number(/pass (\d+)/.exec(text)?.[1] ?? -1);
const failed = Number(/fail (\d+)/.exec(text)?.[1] ?? -1);
if (t.status !== 0) problems.push(`unit tests exited ${t.status}`);
if (passed < 33) problems.push(`expected >=33 passing unit tests (8 syscall-digest + 14 syscall + 7 trace + 4 backtrace), saw ${passed}`);
if (failed !== 0) problems.push(`unit tests report ${failed} failures`);
notes.push(`unit tests: pass=${passed} fail=${failed}`);

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
}

try {
  const { MCP_TOOLS } = await import(`${base}/daemon/src/mcp.ts`);
  const tool = (MCP_TOOLS ?? []).find((x) => x.name === 'syscall_digest');
  if (!tool) problems.push('syscall_digest tool missing from the MCP registry');
  else {
    if (!tool.inputSchema?.properties?.hookIds) problems.push('syscall_digest does not accept hookIds');
    if (!tool.inputSchema?.properties?.expected) problems.push('syscall_digest does not accept the expected attribution map');
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