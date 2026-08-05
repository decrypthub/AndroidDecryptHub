#!/usr/bin/env bash
# v2.3 persistent DEX index (HOST-ONLY). Indexes every sandbox multidex through REST,
# proves the second pass is cached, and resolves a concrete Class.forName edge through REST + MCP.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host
APK="$ROOT/sandbox-app/app/build/outputs/apk/debug/app-debug.apk"
[ -f "$APK" ] || { echo "APK missing"; echo "RESULT:FAIL"; exit 1; }

DEXDIR="$(mktemp -d)"
trap 'rm -rf "$DEXDIR"' EXIT
while read -r dex; do unzip -p "$APK" "$dex" > "$DEXDIR/$dex"; done < <(unzip -l "$APK" | awk '/classes[0-9]*\.dex/{print $4}')

set +e
OUT="$(node - "$HTTP" "$DEXDIR" <<'EOF'
import fs from 'node:fs';
import path from 'node:path';
const [http, dexDir] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const post = async (route, body) => {
  const response = await fetch(base + route, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const result = await response.json();
  if (!response.ok) throw new Error(`${route} HTTP ${response.status}: ${result.error}`);
  return result;
};
const rpc = async (method, params) => {
  const response = await fetch(base + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 29, method, params }) });
  return response.json();
};

let totalMethods = 0, totalSkipped = 0, maxCachedMs = 0, hit = null;
for (const file of fs.readdirSync(dexDir).filter(x => /^classes\d*\.dex$/.test(x)).sort()) {
  const b64 = fs.readFileSync(path.join(dexDir, file)).toString('base64');
  const first = await post('/api/dex/index', { b64 });
  const second = await post('/api/dex/index', { b64 });
  const search = await post('/api/dex/index/search', { sha: first.sha, query: 'com.adh.sandbox.JavaCrypto' });
  const symbols = await post('/api/dex/index/search', { sha: first.sha, query: 'JavaCrypto' });
  const invoke = await post('/api/dex/index/search', { sha: first.sha, query: 'forName' });
  const refs = await post('/api/dex/index/reflections', { sha: first.sha });
  totalMethods += first.counts.methods || 0;
  totalSkipped += first.counts.skipped || 0;
  maxCachedMs = Math.max(maxCachedMs, second.elapsedMs || 0);
  const reflection = (refs.reflections || []).find(x => x.targetDescriptor === 'Lcom/adh/sandbox/JavaCrypto;' && x.cls === 'Lcom/adh/sandbox/ReflectionProbe;' && x.name === 'load');
  const caller = (search.stringCallers || []).find(x => x.cls === 'Lcom/adh/sandbox/ReflectionProbe;' && x.name === 'load');
  const fieldAccess = (symbols.fields || []).find(x => /JavaCrypto/.test(x.cls) && x.access && x.callerClass);
  const invokeCaller = (invoke.callers || []).find(x => x.calleeName === 'forName' && x.callerClass === 'Lcom/adh/sandbox/ReflectionProbe;' && x.callerName === 'load');
  if (reflection && caller && fieldAccess && invokeCaller) hit = { file, sha: first.sha, reflection, queryMs: Math.max(search.elapsedMs, symbols.elapsedMs, invoke.elapsedMs), cached: second.cached };
  console.log(`${file}: methods=${first.counts.methods} skipped=${first.counts.skipped} cached=${second.cached} cachedMs=${second.elapsedMs}`);
}

let mcpHit = false, mcpTools = false;
if (hit) {
  const listed = await rpc('tools/list', {});
  const names = (listed.result?.tools || []).map(x => x.name);
  mcpTools = ['dex_index', 'dex_index_search', 'dex_reflections'].every(x => names.includes(x));
  const called = await rpc('tools/call', { name: 'dex_index_search', arguments: { sha: hit.sha, query: 'com.adh.sandbox.JavaCrypto' } });
  const text = called.result?.content?.[0]?.text || '';
  mcpHit = /Lcom\/adh\/sandbox\/ReflectionProbe;/.test(text) && /Lcom\/adh\/sandbox\/JavaCrypto;/.test(text);
}
const skipRate = totalMethods ? totalSkipped / totalMethods : 1;
console.log(`totalMethods=${totalMethods} skipped=${totalSkipped} skipRate=${(skipRate * 100).toFixed(3)}% maxCachedMs=${maxCachedMs}`);
console.log('reflection:', hit);
console.log(`mcpTools=${mcpTools} mcpHit=${mcpHit}`);
const pass = totalMethods > 21820 && skipRate < 0.02 && hit?.cached === true && maxCachedMs < 250 && hit.queryMs < 250 && mcpTools && mcpHit;
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v2.3 persistent DEX index + string caller + reflection edge" 0 && exit 0 || exit 1
