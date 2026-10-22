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
has(header, 'ADH_MEM_WIN_MAX 4', 'agent cap');
has(header, 'ADH_MEM_WIN_LEN 192', 'agent cap');
has(header, 'ADH_MEM_WIN_TOTAL 512', 'agent cap');
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
