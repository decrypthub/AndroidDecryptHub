#!/usr/bin/env bash
# v4.45 Java class-level trace digest (HOST-ONLY, no device).
#
# `java_trace` wires hook_all (start), the capture ring (digest) and per-id unhook (stop) into the
# workflow an analyst actually uses when recovering an algorithm in Java: hook a class, trigger it,
# read what ran with which arguments. The digest is a pure function, so it is verified here; the live
# three-phase flow needs a device and is tracked in FEATURE_STATUS section 2.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

OUT="$(node - "$ROOT" <<'EOF'
const [root] = process.argv.slice(2);
const { spawnSync } = await import('node:child_process');
const base = 'file:///' + String(root).replace(/\\/g, '/').replace(/^\//, '');
const problems = [];
const notes = [];

const t = spawnSync(process.execPath, ['--test', `${root}/daemon/test/java_trace.test.ts`], { encoding: 'utf8' });
const text = `${t.stdout ?? ''}${t.stderr ?? ''}`;
const passed = Number(/pass (\d+)/.exec(text)?.[1] ?? -1);
const failed = Number(/fail (\d+)/.exec(text)?.[1] ?? -1);
if (t.status !== 0) problems.push(`java_trace unit tests exited ${t.status}`);
if (passed < 15) problems.push(`expected >=15 java_trace unit tests (digest + three-phase assembly + drain/cursor/stop guards), saw ${passed}`);
if (failed !== 0) problems.push(`java_trace unit tests report ${failed} failures`);
notes.push(`java_trace unit tests: pass=${passed} fail=${failed}`);

let digestJavaTrace, callerOfStack;
try {
  ({ digestJavaTrace, callerOfStack } = await import(`${base}/daemon/src/java_trace.ts`));
} catch (e) {
  problems.push('import java_trace.ts failed: ' + e.message);
}
if (digestJavaTrace) {
  const d = digestJavaTrace([
    { hookId: 1, target: 'com.adh.sandbox.HookProbe.ping(java.lang.String)', ts: 10, tid: 7, arg: 'A', ret: 'REAL_HOOK:A', error: '', stack: 'com.adh.sandbox.HookProbe#stackMiddle:33' },
    { hookId: 2, target: 'com.adh.sandbox.HookProbe.ping(java.lang.String,int)', ts: 20, tid: 7, arg: 'B', ret: 'REAL_HOOK:B*2', error: '' },
    { hookId: 1, target: 'com.adh.sandbox.HookProbe.ping(java.lang.String)', ts: 30, tid: 8, arg: 'C', ret: 'REAL_HOOK:C', error: '' },
  ]);
  if (d.samples !== 3 || d.methods.length !== 2) problems.push(`grouping drifted: ${JSON.stringify({ samples: d.samples, methods: d.methods.length })}`);
  const busiest = d.methods[0];
  if (busiest.count !== 2 || busiest.lastArg !== 'C') problems.push(`method aggregation drifted: ${JSON.stringify(busiest)}`);
  if (d.observedFrom !== 10 || d.observedTo !== 30) problems.push(`window drifted: ${d.observedFrom}..${d.observedTo}`);
  if (!d.callers.some((c) => c.caller === 'com.adh.sandbox.HookProbe#stackMiddle')) problems.push('caller histogram missing the stack frame');
  if (callerOfStack('a.B#c:1 <- d.E#f:2') !== 'a.B#c') problems.push('callerOfStack drifted');
  notes.push(`synthetic trace -> methods=${d.methods.length} samples=${d.samples} callers=${d.callers.length}`);
}

try {
  const { MCP_TOOLS } = await import(`${base}/daemon/src/mcp.ts`);
  const tool = (MCP_TOOLS ?? []).find((x) => x.name === 'java_trace');
  if (!tool) problems.push('java_trace tool missing from the MCP registry');
  else {
    const actions = tool.inputSchema?.properties?.action?.enum ?? [];
    for (const need of ['start', 'digest', 'stop']) if (!actions.includes(need)) problems.push(`java_trace action ${need} missing`);
    if (!tool.inputSchema?.properties?.hookIds) problems.push('java_trace does not accept hookIds');
    notes.push(`MCP tools=${MCP_TOOLS.length}, java_trace actions=${actions.join('/')}`);
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
verify_gate "v4.45 java trace digest (unit + MCP shape)" 0