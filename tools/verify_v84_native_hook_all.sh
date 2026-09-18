#!/usr/bin/env bash
# v4.46 native batch hooking by export pattern (HOST-ONLY, no device).
#
# "Hook every EVP_* in libcrypto" is a normal first move on a native target; doing it by hand means
# dumping symbols, converting offsets to addresses and installing one hook per symbol. This checks the
# selection logic that makes it one call (the install half needs a device and is tracked in
# FEATURE_STATUS section 2).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

OUT="$(node - "$ROOT" <<'EOF'
const [root] = process.argv.slice(2);
const { spawnSync } = await import('node:child_process');
const base = 'file:///' + String(root).replace(/\\/g, '/').replace(/^\//, '');
const problems = [];
const notes = [];

const t = spawnSync(process.execPath, ['--test', `${root}/daemon/test/native_hook_all.test.ts`], { encoding: 'utf8' });
const text = `${t.stdout ?? ''}${t.stderr ?? ''}`;
const passed = Number(/pass (\d+)/.exec(text)?.[1] ?? -1);
const failed = Number(/fail (\d+)/.exec(text)?.[1] ?? -1);
if (t.status !== 0) problems.push(`native_hook_all unit tests exited ${t.status}`);
if (passed < 7) problems.push(`expected >=7 native_hook_all unit tests, saw ${passed}`);
if (failed !== 0) problems.push(`native_hook_all unit tests report ${failed} failures`);
notes.push(`native_hook_all unit tests: pass=${passed} fail=${failed}`);

let selectExportSymbols;
try {
  ({ selectExportSymbols } = await import(`${base}/daemon/src/native_hook_all.ts`));
} catch (e) {
  problems.push('import native_hook_all.ts failed: ' + e.message);
}
if (selectExportSymbols) {
  const sym = (name, addr, size, kind = 'func') => ({ name, addr, size, kind });
  const table = [sym('EVP_a', 0x100n, 16), sym('EVP_b', 0x200n, 16), sym('SSL_write', 0x300n, 16), sym('data_tbl', 0x400n, 8, 'object')];
  const { selected, matched } = selectExportSymbols(table, { prefix: 'EVP_', limit: 1 });
  if (matched !== 2) problems.push(`matched drifted: ${matched}`);
  if (selected.length !== 1 || selected[0].name !== 'EVP_a') problems.push(`selection drifted: ${JSON.stringify(selected)}`);
  const all = selectExportSymbols(table, { limit: 16 });
  if (all.matched !== 3 || all.selected.some((s) => s.name === 'data_tbl')) problems.push('data symbols must never be selected');
  notes.push(`synthetic export table -> matched=${matched} selected=${selected.length}`);
}

try {
  const { MCP_TOOLS } = await import(`${base}/daemon/src/mcp.ts`);
  const tool = (MCP_TOOLS ?? []).find((x) => x.name === 'native_hook_all');
  if (!tool) problems.push('native_hook_all tool missing from the MCP registry');
  else {
    const actions = tool.inputSchema?.properties?.action?.enum ?? [];
    if (!actions.includes('hook') || !actions.includes('unhook')) problems.push(`native_hook_all actions drifted: ${JSON.stringify(actions)}`);
    if (!tool.inputSchema?.properties?.confirm) problems.push('native_hook_all does not expose the confirm gate');
    if (!/confirm:true/.test(String(tool.description))) problems.push('native_hook_all description does not state the confirm requirement');
    if (typeof tool.handler !== 'function') problems.push('native_hook_all handler is not a function');
    notes.push(`MCP tools=${MCP_TOOLS.length}, native_hook_all actions=${actions.join('/')}`);
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
verify_gate "v4.46 native batch hooking (selection + MCP shape)" 0