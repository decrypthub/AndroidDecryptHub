#!/usr/bin/env bash
# v4.47 one-shot syscall tracing (HOST-ONLY, no device).
#
# The three syscall tools (watch / digest / unhook) only add up to an answer when the static
# attribution travels from the watch into the digest and the drain goes through the shared path - both
# are exactly what a hand-run sequence gets wrong. This checks the assembly with injected deps; the
# live run needs a device and is tracked in FEATURE_STATUS section 2.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

OUT="$(node - "$ROOT" <<'EOF'
const [root] = process.argv.slice(2);
const { spawnSync } = await import('node:child_process');
const base = 'file:///' + String(root).replace(/\\/g, '/').replace(/^\//, '');
const problems = [];
const notes = [];

const t = spawnSync(process.execPath, ['--test', `${root}/daemon/test/syscall_trace.test.ts`], { encoding: 'utf8' });
const text = `${t.stdout ?? ''}${t.stderr ?? ''}`;
const passed = Number(/pass (\d+)/.exec(text)?.[1] ?? -1);
const failed = Number(/fail (\d+)/.exec(text)?.[1] ?? -1);
if (t.status !== 0) problems.push(`syscall_trace unit tests exited ${t.status}`);
if (passed < 8) problems.push(`expected >=8 syscall_trace unit tests, saw ${passed}`);
if (failed !== 0) problems.push(`syscall_trace unit tests report ${failed} failures`);
notes.push(`syscall_trace unit tests: pass=${passed} fail=${failed}`);

let start, digest, stop;
try {
  ({ syscallTraceStart: start, syscallTraceDigest: digest, syscallTraceStop: stop } = await import(`${base}/daemon/src/syscall_trace.ts`));
} catch (e) {
  problems.push('import syscall_trace.ts failed: ' + e.message);
}
if (start && digest && stop) {
  const calls = { watch: [], digest: [], unhook: [] };
  const deps = {
    watch: async (s, o) => { calls.watch.push(o); return { module: 'libc.so', installedCount: 1, matchedCount: 1, svcCount: 224, hooks: [{ hookId: 5, addr: '0xf8848', syscall: { nr: 160, name: 'uname' } }] }; },
    digest: async (s, o) => { calls.digest.push(o); return { samples: 1, groups: [{ nr: 160, name: 'uname', caller: 'libadhdetect.so:adh_libc_uname_probe', count: 1, firstTs: 1, lastTs: 1, tids: [7] }], observed: [{ nr: 160, count: 1 }], mismatches: [], hooksSeen: [5], paths: [], decodedSamples: 0, observedFrom: 1, observedTo: 1, notes: [], window: { sinceMs: null, limit: 1000 }, symbolSource: 'dynsym' }; },
    unhook: async (s, ids) => { calls.unhook.push(ids); return { unhooked: ids, failures: [] }; },
  };
  const s = await start('s1', { module: 'libc.so', syscalls: ['uname'], limit: 2 }, deps);
  const d = await digest('s1', { hookIds: s.hookIds, expected: s.expected }, deps);
  const e = await stop('s1', { hookIds: s.hookIds }, deps);
  if (s.hookIds.length !== 1 || s.expected[5] !== 160) problems.push(`start drifted: ${JSON.stringify(s)}`);
  if (calls.digest[0]?.expected?.[5] !== 160) problems.push('the digest did not receive the attribution built by start');
  if (!d.digest.groups?.[0]?.caller?.includes('adh_libc_uname_probe')) problems.push('digest passthrough drifted');
  if (!e.ok || calls.unhook[0]?.[0] !== 5) problems.push('stop did not unhook exactly the start ids');
  notes.push(`start->digest->stop -> ids=${JSON.stringify(s.hookIds)} expected=${JSON.stringify(s.expected)} unhooked=${JSON.stringify(e.unhooked)}`);
}

try {
  const { MCP_TOOLS } = await import(`${base}/daemon/src/mcp.ts`);
  const tool = (MCP_TOOLS ?? []).find((x) => x.name === 'syscall_trace');
  if (!tool) problems.push('syscall_trace tool missing from the MCP registry');
  else {
    const actions = tool.inputSchema?.properties?.action?.enum ?? [];
    for (const need of ['start', 'digest', 'stop']) if (!actions.includes(need)) problems.push(`syscall_trace action ${need} missing`);
    if (!tool.inputSchema?.properties?.syscalls) problems.push('syscall_trace does not accept the syscalls filter');
    notes.push(`MCP tools=${MCP_TOOLS.length}, syscall_trace actions=${actions.join('/')}`);
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
verify_gate "v4.47 syscall tracing (assembly + MCP shape)" 0