#!/usr/bin/env bash
# v4.48 per-hook native event throttle (HOST-ONLY, no device).
#
# A hot hook (read/write/futex) emits more events than the capture ring holds, and a digest of a
# flooded ring reads like a quiet target. This checks the host half: the shared payload shaping that
# actually puts throttleMs on the wire, the MCP/REST surface, and - by source assertion, because the
# agent only runs on a device - that the agent clamps the window, counts every hit it did NOT emit
# and keeps applying the argument/return rewrite to throttled hits. The device half (events really
# thin out, hits == emitted + throttled) is tracked in FEATURE_STATUS section 2.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

OUT="$(node - "$ROOT" <<'EOF'
const [root] = process.argv.slice(2);
const { spawnSync } = await import('node:child_process');
const fs = await import('node:fs');
const base = 'file:///' + String(root).replace(/\\/g, '/').replace(/^\//, '');
const problems = [];
const notes = [];
const read = (rel) => fs.readFileSync(`${root}/${rel}`, 'utf8');
const has = (text, needle, label) => {
  if (!text.includes(needle)) problems.push(`${label}: missing ${JSON.stringify(needle)}`);
};
const before = (text, a, b, label) => {
  const ia = text.indexOf(a), ib = text.indexOf(b);
  if (ia < 0 || ib < 0) problems.push(`${label}: anchor(s) not found`);
  else if (!(ia < ib)) problems.push(`${label}: ${JSON.stringify(a)} must come before ${JSON.stringify(b)}`);
};

// ---- 1. the shared shaping unit tests ----
const t = spawnSync(process.execPath, ['--test', `${root}/daemon/test/native_hook_throttle.test.ts`], { encoding: 'utf8' });
const text = `${t.stdout ?? ''}${t.stderr ?? ''}`;
const passed = Number(/pass (\d+)/.exec(text)?.[1] ?? -1);
const failed = Number(/fail (\d+)/.exec(text)?.[1] ?? -1);
if (t.status !== 0) problems.push(`throttle unit tests exited ${t.status}`);
if (passed < 12) problems.push(`expected >=12 throttle unit tests, saw ${passed}`);
if (failed !== 0) problems.push(`throttle unit tests report ${failed} failures`);
notes.push(`payload/clamp/install-loop unit tests: pass=${passed} fail=${failed}`);

let normalizeThrottleMs, nativeHookInstallPayload;
try {
  ({ normalizeThrottleMs, nativeHookInstallPayload } = await import(`${base}/daemon/src/native_hook_args.ts`));
} catch (e) {
  problems.push('import native_hook_args.ts failed: ' + e.message);
}
if (normalizeThrottleMs) {
  if (normalizeThrottleMs(undefined) !== 0) problems.push('a missing throttleMs must mean off');
  if (normalizeThrottleMs(90000) !== 60000) problems.push('an oversized window must clamp to 60000');
  if (nativeHookInstallPayload({ addr: '0x1', throttleMs: 250 }).throttleMs !== 250) problems.push('the install payload must carry throttleMs');
  let threw = false;
  try { normalizeThrottleMs('abc'); } catch { threw = true; }
  if (!threw) problems.push('a non-numeric window must be refused, not silently treated as off');
  notes.push('shaping: default off, clamps at 60000, refuses garbage');
}

// ---- 2. agent side: clamp, gate placement, counters, status ----
const hdr = read('agent/src/hook/native_hooks.h');
has(hdr, 'int throttle_ms, int *hook_id_out', 'native_hooks.h install signature');
has(hdr, 'suppresses EVENTS ONLY', 'native_hooks.h must state that only the event is suppressed');

const hooks = read('agent/src/hook/native_hooks.cpp');
has(hooks, 'ADH_NATIVE_THROTTLE_MAX_MS', 'native_hooks.cpp must clamp with the shared ceiling');
has(hooks, 'g_native_hook_throttled_total', 'native_hooks.cpp suppressed-hit total');
has(hooks, '\\"throttled\\":%llu', 'native_hooks.cpp event must carry the suppressed delta');
has(hooks, 'ctx.throttle_ms = effective_throttle_ms', 'native_hooks.cpp must store the clamped window');
has(hooks, 'reset_throttle_counters(slot)', 'native_hooks.cpp must reset counters on install');
has(hooks, 'reset_throttle_counters(i)', 'native_hooks.cpp must reset counters when reactivating a slot');
has(hooks, '\\"throttleMs\\":%d,\\"throttled\\":%llu', 'native_hooks.cpp status must report window + running total');
has(hooks, 'ctx.throttle_ms = 0;', 'native_hooks.cpp must clear the window on slot reuse');
// Ordering is the honesty invariant: the arg/return rewrite first, then the throttle gate, and the
// suppressed path returns BEFORE any JSON is built (no event, but the rewrite already happened).
before(hooks, 'if (arg_index >= 0 && arg_index < 8) regs[arg_index] = arg_value;',
       'const int throttle_ms = __atomic_load_n(&ctx.throttle_ms', 'throttle gate placement');
before(hooks, 'const int throttle_ms = __atomic_load_n(&ctx.throttle_ms', 'char json[3072]', 'throttle gate must precede the event build');
const gate = hooks.slice(hooks.indexOf('const int throttle_ms = __atomic_load_n(&ctx.throttle_ms'), hooks.indexOf('char json[3072]'));
if (!/return \(?skip_original \|\| return_set\)? \? 1 : 0;/.test(gate)) problems.push('a suppressed hit must return either the configured replacement or the original-skip result for the site backend');
if (!/fetch_add\(1, std::memory_order_relaxed\)/.test(gate)) problems.push('a suppressed hit must be counted, not dropped silently');
// The per-event delta is the one subtle piece: load+store would let two concurrent emitters both
// claim the same suppressed hits (the totals would still add up, the deltas would lie).
has(hooks, 'exchange(total, std::memory_order_relaxed)', 'the suppressed delta must be taken with exchange');
if (/g_native_hook_throttled_reported\[hook_id\]\.load/.test(hooks)) problems.push('the reported counter must never be read with a plain load');
notes.push('agent: rewrite before gate, suppressed hits counted and answered');

const main = read('agent/src/bootstrap/agent_main.c');
has(main, 'json_get_num(line, "throttleMs")', 'agent_main.c must parse throttleMs');
has(main, 'ADH_NATIVE_THROTTLE_MAX_MS', 'agent_main.c must clamp with the shared ceiling');
if (/nthrottle > 60000/.test(main)) problems.push('agent_main.c must not hardcode 60000 (it would drift from the header)');
has(read('agent/src/hook/native_hooks.h'), '#define ADH_NATIVE_THROTTLE_MAX_MS 60000', 'the ceiling must be defined once, in the header');
has(main, 'backtrace_flag, nthrottle_ms', 'agent_main.c must pass the window into cmd_native_hook');

// ---- 3. host tools really send it ----
has(read('daemon/src/native_hook_all.ts'), 'nativeHookInstallPayload(', 'native_hook_all must use the shared payload');
has(read('daemon/src/syscall_watch.ts'), 'nativeHookInstallPayload(', 'syscall_watch must use the shared payload');
// ...and the install loops must be the ones the unit tests drive (not a copy that quietly diverges).
has(read('daemon/src/native_hook_all.ts'), 'installSymbolHooks(session, base, selected, opts)', 'native_hook_all must install through installSymbolHooks');
has(read('daemon/src/syscall_watch.ts'), 'installSvcSiteHooks(sid, sites, opts.throttleMs)', 'syscall_watch must install through installSvcSiteHooks');
has(read('daemon/src/native_hook_all.ts'), 'throttleMs,', 'native_hook_all response must echo the window');
has(read('daemon/src/syscall_watch.ts'), 'throttleMs,', 'syscall_watch response must echo the window');
has(read('daemon/src/http/routes_runtime.ts'), 'parseThrottleMs', 'REST routes must validate the window');
if (!/throttle\.ms/.test(read('daemon/src/http/routes_runtime.ts'))) problems.push('REST routes must pass the validated window through');

// ---- 4. MCP surface ----
try {
  const { MCP_TOOLS } = await import(`${base}/daemon/src/mcp.ts`);
  const tool = (name) => (MCP_TOOLS ?? []).find((x) => x.name === name);
  for (const name of ['native_hook', 'native_hook_all', 'syscall_watch', 'syscall_trace']) {
    const t2 = tool(name);
    if (!t2) { problems.push(`${name} tool missing from the MCP registry`); continue; }
    if (!t2.inputSchema?.properties?.throttleMs) problems.push(`${name} does not expose throttleMs`);
    if (typeof t2.handler !== 'function') problems.push(`${name} handler is not a function`);
  }
  if (!/throttled/.test(String(tool('native_hook')?.description))) problems.push('native_hook description must explain throttled');
  if (!/throttleMs/.test(String(tool('syscall_watch')?.description))) problems.push('syscall_watch description must mention throttleMs');
  notes.push(`MCP tools=${MCP_TOOLS.length}, throttleMs on native_hook/native_hook_all/syscall_watch/syscall_trace`);
} catch (e) {
  problems.push('import mcp.ts failed: ' + e.message);
}

for (const n of notes) console.log('  ' + n);
for (const p of problems) console.log('FAIL ' + p);
console.log(problems.length === 0 ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v4.48 native per-hook event throttle (payload + agent wiring + MCP shape)" 0
