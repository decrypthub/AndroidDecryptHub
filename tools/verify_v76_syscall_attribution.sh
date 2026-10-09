#!/usr/bin/env bash
# v4.38 syscall attribution (HOST-ONLY, no device).
#
# The syscall watch attributes each `svc #0` site to a syscall number by decoding the MOV that
# materialises x8 before it. That decoder is pure arithmetic over the reconstructed file, so it is
# unit-testable without a device - and it has to be tested, because JS bitwise AND yields a SIGNED
# int32: the first version compared `0xd2800008 & mask` (negative) with the positive literal and
# therefore never attributed anything, while every static check stayed green.
#
# Checks: (1) the daemon unit tests for the decoder/filter pass, (2) the MCP registry still imports
# and syscall_watch advertises the syscalls filter.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

OUT="$(node - "$ROOT" <<'EOF'
const [root] = process.argv.slice(2);
const { spawnSync } = await import('node:child_process');
const base = 'file:///' + String(root).replace(/\\/g, '/').replace(/^\//, '');
const problems = [];
const notes = [];

// (1) unit tests for the attribution decoder
const t = spawnSync(process.execPath, ['--test', `${root}/daemon/test/syscall_watch.test.ts`, `${root}/daemon/test/backtrace.test.ts`], { encoding: 'utf8' });
const text = `${t.stdout ?? ''}${t.stderr ?? ''}`;
const passed = Number(/pass (\d+)/.exec(text)?.[1] ?? -1);
const failed = Number(/fail (\d+)/.exec(text)?.[1] ?? -1);
if (t.status !== 0) problems.push(`unit tests exited ${t.status}`);
if (passed < 11) problems.push(`expected >=11 passing unit tests (7 syscall + 4 backtrace), saw ${passed}`);
if (failed !== 0) problems.push(`unit tests report ${failed} failures`);
notes.push(`unit tests: pass=${passed} fail=${failed}`);

// (2) the decoder + filter helpers are importable and behave on a synthetic bionic-style stub
let attributeSite, parseSyscallToken;
try {
  ({ attributeSite, parseSyscallToken } = await import(`${base}/daemon/src/syscall_watch.ts`));
} catch (e) {
  problems.push('import syscall_watch.ts failed: ' + e.message);
}
if (attributeSite) {
  const movz = (nr, w = false) => ((w ? 0x52800000 : 0xd2800000) | ((nr & 0xffff) << 5) | 8) >>> 0;
  const words = [movz(160), 0xd4000001, 0xd65f03c0];
  const buf = Buffer.alloc(words.length * 4);
  words.forEach((w, i) => buf.writeUInt32LE(w >>> 0, i * 4));
  const r = attributeSite(buf, 4);
  if (r.nr !== 160) problems.push(`synthetic uname stub attributed as ${r.nr} (expected 160)`);
  if (parseSyscallToken('0xa0') !== 160 || parseSyscallToken('nope') !== null) problems.push('filter token parsing drifted');
  notes.push(`synthetic stub -> nr=${r.nr} how=${r.how}`);
}

// (3) MCP registry imports and advertises the filter
try {
  const { MCP_TOOLS } = await import(`${base}/daemon/src/mcp.ts`);
  const tool = (MCP_TOOLS ?? []).find((x) => x.name === 'syscall_watch');
  if (!tool) problems.push('syscall_watch tool missing from the MCP registry');
  else {
    if (!tool.inputSchema?.properties?.syscalls) problems.push('syscall_watch does not advertise the syscalls filter');
    if (!/libc/i.test(String(tool.description))) problems.push('syscall_watch description does not mention libc coverage');
    notes.push(`syscall_watch schema properties: ${Object.keys(tool.inputSchema?.properties ?? {}).join(',')}`);
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
verify_gate "v4.38 syscall attribution (unit + MCP schema)" 0