#!/usr/bin/env bash
# v4.34 MCP registry sanity (HOST-ONLY, no device, <1s).
#
# Why this exists: the MCP tool table in daemon/src/mcp.ts is made of single-quoted strings, so one
# apostrophe inside a description breaks the whole module - and `node --check` does NOT catch it
# (the type stripper is what fails), so the daemon just refuses to boot while every static check
# stays green. This script actually imports the registry and checks the shape of every tool, which
# turns that class of mistake into an immediate, loud failure.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

OUT="$(node - "$ROOT" <<'EOF'
const [root] = process.argv.slice(2);
const url = 'file:///' + String(root).replace(/\\/g, '/').replace(/^\//, '') + '/daemon/src/mcp.ts';
let tools;
try {
  const mod = await import(url);
  tools = mod.MCP_TOOLS;
} catch (e) {
  console.log('IMPORT FAILED: ' + e.message);
  console.log('RESULT:FAIL');
  process.exit(0);
}
const problems = [];
if (!Array.isArray(tools) || tools.length === 0) problems.push('MCP_TOOLS is not a non-empty array');
const seen = new Set();
for (const t of tools ?? []) {
  if (!t || typeof t.name !== 'string' || !/^[a-z][a-z0-9_]*$/.test(t.name)) problems.push(`bad name: ${JSON.stringify(t?.name)}`);
  if (seen.has(t?.name)) problems.push(`duplicate tool name: ${t.name}`);
  seen.add(t?.name);
  if (typeof t.description !== 'string' || t.description.length < 20) problems.push(`${t?.name}: description too short/not a string`);
  if (/undefined|\[object Object\]/.test(String(t.description))) problems.push(`${t?.name}: description contains undefined`);
  if (!t.inputSchema || t.inputSchema.type !== 'object' || typeof t.inputSchema.properties !== 'object') problems.push(`${t?.name}: bad inputSchema`);
  if (typeof t.handler !== 'function') problems.push(`${t?.name}: handler is not a function`);
}
console.log(`tools=${tools?.length ?? 0} problems=${problems.length}`);
for (const p of problems.slice(0, 12)) console.log('  - ' + p);
console.log(problems.length === 0 ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v4.34 MCP registry sanity (import + per-tool shape)" 0