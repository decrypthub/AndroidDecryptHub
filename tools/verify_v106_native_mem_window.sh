#!/usr/bin/env bash
# Hit-time native memory windows (HOST-ONLY).
#
# The host half of "copy what x0 points at when the hook fires, before the original
# function overwrites it". The grammar, the caps, and the canonical spec the agent
# stores all live in one pure function. A typo must throw: sending the hook anyway
# with the window dropped would look exactly like a target that never touched the
# buffer. The device half (the bytes really match the pre-call buffer, and a small
# integer register is reported unreadable without killing the process) is
# verify_v107_native_mem_window.sh.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

if ! verify_unit_pass "native hook memory windows" native_hook_mem.test.ts 9; then
  echo "RESULT:FAIL (native hook memory-window unit tests did not all pass)"
  exit 1
fi

set +e
OUT="$(node - "$ROOT" <<'EOF'
const [root] = process.argv.slice(2);
const fs = await import('node:fs');
const read = (rel) => fs.readFileSync(`${String(root).replace(/\\/g, '/')}/${rel}`, 'utf8');
const problems = [];
const has = (text, needle, label) => {
  if (!text.includes(needle)) problems.push(`${label}: missing ${JSON.stringify(needle)}`);
};
const mcp = read('daemon/src/mcp.ts');
const routes = read('daemon/src/http/routes_runtime.ts');
const agent = read('agent/src/hook/native_hooks.cpp');
const header = read('agent/src/hook/native_hooks.h');
const state = read('daemon/src/state.ts');
has(mcp, 'parseMemWindows', 'mcp');
has(mcp, 'mem: memSpec', 'mcp payload');
has(routes, 'parseMemSpec', 'rest');
has(routes, 'mem: memSpec', 'rest payload');
has(agent, 'process_vm_readv', 'agent copy');
has(agent, 'NATIVE_HOOK_MEM', 'agent companion event');
has(agent, 'memcmp(spec, "auto", 4)', 'agent auto spec');
has(state, "func === 'NATIVE_HOOK_MEM'", 'capture category');
has(state, 'memCapturePreview', 'capture preview');
// The caps are asserted as a CROSS-CHECK, not as literals: the agent header and the daemon constant
// must agree, because a mismatch means the host accepts a window the agent silently clamps (or the
// reverse). Hard-coding 192/512 here only proved that nobody had changed the caps yet - it went red
// the moment they were raised, while the thing it was meant to protect was still fine.
const num = (text, name) => {
  // `#define NAME 4` in the C header and `export const NAME = 4;` in TypeScript: one pattern has no
  // `=` at all, and assuming it does is how this check first reported "could not read both sides".
  const m = new RegExp(`(?:#define\\s+${name}\\s+|${name}\\s*=\\s*)(\\d+)`).exec(text);
  return m ? Number(m[1]) : null;
};
const caps = ['ADH_MEM_WIN_MAX', 'ADH_MEM_WIN_LEN', 'ADH_MEM_WIN_TOTAL'];
for (const name of caps) has(header, `#define ${name} `, 'agent cap');
const want = ['NATIVE_MEM_WIN_MAX', 'NATIVE_MEM_WIN_LEN', 'NATIVE_MEM_WIN_TOTAL'];
const argsTs = read('daemon/src/native_hook_args.ts');
for (const name of want) has(argsTs, `export const ${name}`, 'daemon cap');
for (const [i, name] of want.entries()) {
  const a = num(header, caps[i]);
  const b = num(argsTs, `export const ${name}`);
  if (a == null || b == null) problems.push(`cap ${name}: could not read both sides (header ${a}, daemon ${b})`);
  else if (a !== b) problems.push(`cap ${name}: header ${a} != daemon ${b} (host would accept what the agent clamps)`);
}
// The binding guard is the TOTAL, and it can only fire if at least one full window fits: MAX*LEN >= TOTAL.
// This was an EQUALITY until the window count went 4 -> 6 (6 x 1024 = 6144 > 4096 is the intended state:
// a formatter descriptor needs six pointers and the 4 KB total is what actually stops a caller). The
// equality assertion was the very thing its own comment warned about - "it went red the moment they were
// raised, while the thing it was meant to protect was still fine".
const winMax = num(header, 'ADH_MEM_WIN_MAX');
const winLen = num(header, 'ADH_MEM_WIN_LEN');
const winTotal = num(header, 'ADH_MEM_WIN_TOTAL');
if (winMax == null || winLen == null || winTotal == null) {
  problems.push('mem caps: could not read ADH_MEM_WIN_{MAX,LEN,TOTAL} from the agent header');
} else if (winMax * winLen < winTotal) {
  problems.push(`mem caps: WIN_MAX*WIN_LEN (${winMax * winLen}) < WIN_TOTAL (${winTotal}) - one window cannot even fill the total budget`);
}
if (problems.length) {
  console.log(problems.join('\n'));
  console.log('RESULT:FAIL');
} else {
  console.log('host wiring ok');
  console.log('RESULT:PASS');
}
EOF
)"
set -e
echo "$OUT"
verify_gate "v106 native hook hit-time memory windows (host)" 0 && exit 0 || exit 1
