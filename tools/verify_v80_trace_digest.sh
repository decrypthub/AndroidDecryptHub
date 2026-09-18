#!/usr/bin/env bash
# v4.41 trace digest (HOST-ONLY, no device).
#
# `qbdi_trace` returns up to 8192 raw instructions; that is accurate but useless to skim. The digest
# (loops / calls / memory shapes / constants / branch shape / hottest instructions) is the layer that
# makes an autonomous trace usable, and its core is a pure function - so it is unit-tested here, and
# the MCP registry has to advertise the tool.
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
  `${root}/daemon/test/trace_digest.test.ts`,
  `${root}/daemon/test/backtrace.test.ts`,
  `${root}/daemon/test/syscall_watch.test.ts`], { encoding: 'utf8' });
const text = `${t.stdout ?? ''}${t.stderr ?? ''}`;
const passed = Number(/pass (\d+)/.exec(text)?.[1] ?? -1);
const failed = Number(/fail (\d+)/.exec(text)?.[1] ?? -1);
if (t.status !== 0) problems.push(`unit tests exited ${t.status}`);
if (passed < 18) problems.push(`expected >=18 passing unit tests (7 digest + 4 backtrace + 7 syscall), saw ${passed}`);
if (failed !== 0) problems.push(`unit tests report ${failed} failures`);
notes.push(`unit tests: pass=${passed} fail=${failed}`);

let digestTrace;
try {
  ({ digestTrace } = await import(`${base}/daemon/src/trace_digest.ts`));
} catch (e) {
  problems.push('import trace_digest.ts failed: ' + e.message);
}
if (digestTrace) {
  const d = digestTrace([
    { addr: '0x1000', text: 'mov w8, #0x9e3779b9' },
    { addr: '0x1004', text: 'ldr w0, [x1, #0x10]' },
    { addr: '0x1008', text: 'bl #0x2000' },
    { addr: '0x100c', text: 'b #0x1004' },
    { addr: '0x1004', text: 'ldr w0, [x1, #0x10]' },
    { addr: '0x1008', text: 'bl #0x2000' },
    { addr: '0x1010', text: 'ret' },
  ]);
  if (d.loops.length !== 1 || d.loops[0].target !== '0x1004') problems.push(`loop detection drifted: ${JSON.stringify(d.loops)}`);
  if (d.calls[0]?.target !== '0x2000' || d.calls[0]?.count !== 2) problems.push(`call aggregation drifted: ${JSON.stringify(d.calls)}`);
  if (!d.memory.some((m) => m.base === 'x1' && m.offset === '0x10')) problems.push(`memory shapes drifted: ${JSON.stringify(d.memory)}`);
  if (!d.constants.some((c) => c.value === '0x9e3779b9' && c.note)) problems.push(`constant flagging drifted: ${JSON.stringify(d.constants)}`);
  notes.push(`synthetic trace -> loops=${d.loops.length} calls=${d.calls.length} memory=${d.memory.length} constants=${d.constants.length}`);
}

try {
  const { MCP_TOOLS } = await import(`${base}/daemon/src/mcp.ts`);
  const tool = (MCP_TOOLS ?? []).find((x) => x.name === 'trace_digest');
  if (!tool) problems.push('trace_digest tool missing from the MCP registry');
  else {
    if (!tool.inputSchema?.properties?.symbol) problems.push('trace_digest does not require a symbol');
    if (typeof tool.handler !== 'function') problems.push('trace_digest handler is not a function');
    notes.push(`MCP tools=${MCP_TOOLS.length}, trace_digest present`);
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
verify_gate "v4.41 trace digest (unit + MCP shape)" 0