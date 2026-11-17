#!/usr/bin/env bash
# v130 — scope control + one-call app analysis: component contract (host only).
#
# What this gates:
#   - the allowlist merge rules (the C++ companion parses this JSON on a hot path, so a malformed
#     package name must never reach the file);
#   - the analysis-session pick (main process wins over a companion process);
#   - the three new MCP tools exist with the registry shape the client contract requires.
#
# It deliberately does NOT touch the device: writing scope.json and cold-starting an app are product
# actions and are covered by verify_v129/int1 acceptance, not by a daily host gate.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

set +e
OUT="$(ADH_SKIP_ARTIFACT_LOAD=1 node --input-type=module - "$ROOT" <<'EOF'
import { pathToFileURL } from 'node:url';
const root = process.argv[2];
const src = (p) => pathToFileURL(`${root}/daemon/src/${p}`).href;
const { mergeScope, parseScopePackages } = await import(src('scope_list.ts'));
const { pickAnalysisSession } = await import(src('app_analyze.ts'));
const { MCP_TOOLS } = await import(src('mcp.ts'));

const chk = [];
const eq = (name, got, want) => chk.push({ name, ok: JSON.stringify(got) === JSON.stringify(want), got });
eq('merge add/dedupe', mergeScope(['com.a.app'], { add: ['com.b.app', 'com.a.app'] }), ['com.a.app', 'com.b.app']);
eq('remove wins', mergeScope(['com.a.app', 'com.b.app'], { add: ['com.a.app'], remove: ['com.a.app'] }), ['com.b.app']);
eq('junk refused', mergeScope([], { add: ['bad name', 'com..x', 'com.adh.manager', 'com.ok.app'] }), ['com.ok.app']);
eq('parse drops manager', parseScopePackages('{"packages":["com.a.app","com.a.app","com.adh.manager"]}'), ['com.a.app']);
eq('main process wins', pickAnalysisSession([
  { package: 'com.x.app', process: 'com.x.app:push', online: true },
  { package: 'com.x.app', process: 'com.x.app', online: true },
])?.process, 'com.x.app');

for (const name of ['analyze_app', 'scope_list', 'scope_set']) {
  const t = MCP_TOOLS.find((x) => x.name === name);
  const shape = !!t && t.inputSchema?.type === 'object' && !!t.inputSchema.properties &&
    typeof t.handler === 'function' && String(t.description || '').length > 40;
  chk.push({ name: `tool ${name}`, ok: shape, got: t ? 'present' : 'MISSING' });
}

const bad = chk.filter((c) => !c.ok);
for (const c of chk) console.log(`  ${c.ok ? 'ok  ' : 'FAIL'} ${c.name} -> ${JSON.stringify(c.got)}`);
console.log(`checks ${chk.length - bad.length}/${chk.length}`);
console.log(bad.length ? 'RESULT:FAIL' : 'RESULT:PASS');
EOF
)"
echo "$OUT" | tail -12
if echo "$OUT" | grep -q 'RESULT:PASS'; then
  echo "✅ v130 scope control + analyze_app contract PASS"
  exit 0
fi
echo "❌ v130 scope control + analyze_app contract FAIL"
exit 1
