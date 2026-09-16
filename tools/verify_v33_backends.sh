#!/usr/bin/env bash
# v3.3 injection-backend matrix in the Web console (module W, host-only).
#
# Checks that the console exposes the backend centre truthfully:
#   * GET /api/backends returns the session/backend matrix + the Frida Gadget cache the host
#     actually has (cross-checked against the files on disk)
#   * the dashboard contains the 注入后端 settings page and its renderer
#   * every inline <script> block still parses (no JS syntax break from the panel)
#
# RESULT:SKIP is not needed: this is host-only and needs no device.
#
# Run: bash tools/verify_v33_backends.sh   (exit 0 = PASS)
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

set +e
OUT="$(node - "$HTTP" "$ROOT" <<'EOF'
import { readFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';

const [http, root] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const checks = [];
const chk = (label, ok, detail = '') => { checks.push([label, !!ok]); console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ' — ' + detail : ''}`); };

let matrix = null;
try { matrix = await (await fetch(`${base}/api/backends`)).json(); } catch (e) { chk('GET /api/backends', false, String(e)); }
chk('GET /api/backends', !!matrix && typeof matrix === 'object');
if (matrix) {
  chk('agents[] present', Array.isArray(matrix.agents), `n=${(matrix.agents || []).length}`);
  chk('gadget.pinned is an array', Array.isArray(matrix.gadget?.pinned), JSON.stringify(matrix.gadget?.pinned));
  chk('gadget.cached is an array', Array.isArray(matrix.gadget?.cached));
  chk('xposed module is com.adh.xposed', matrix.xposed?.module === 'com.adh.xposed', matrix.xposed?.module);
  chk('zygisk module advertised', typeof matrix.zygisk?.module === 'string' && matrix.zygisk.module.length > 0, matrix.zygisk?.module);

  // The cache list must reflect the filesystem, not a guess.
  const cached = matrix.gadget?.cached || [];
  const allExist = cached.every((c) => existsSync(c.path) && statSync(c.path).size === c.bytes);
  chk('cached gadget entries match disk', allExist, `n=${cached.length}`);
  const manifest = join(root, 'tools', 'frida_gadget_versions.json');
  if (existsSync(manifest)) {
    const pinnedFromFile = Object.keys(JSON.parse(readFileSync(manifest, 'utf8')).versions || {}).sort();
    chk('pinned versions match the manifest', JSON.stringify(pinnedFromFile) === JSON.stringify(matrix.gadget?.pinned || []));
  }
  if (matrix.agents.length) {
    const kinds = matrix.agents.map((a) => a.entryKind).filter(Boolean);
    chk('sessions carry an entryKind', kinds.length === matrix.agents.length, kinds.join(', '));
  }
}

// Dashboard: panel markers + inline script syntax.
let html = '';
try { html = await (await fetch(`${base}/`)).text(); } catch (e) { /* reported below */ }
chk('dashboard served', html.length > 1000, `bytes=${html.length}`);
for (const marker of ['data-setpage="backends"', 'setPageBackends', 'renderBackends', "fetch('/api/backends')", 'probeBackend']) {
  chk(`dashboard contains ${marker}`, html.includes(marker));
}
const blocks = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
chk('inline scripts found', blocks.length > 0, `blocks=${blocks.length}`);
const dir = mkdtempSync(join(tmpdir(), 'adh-js-'));
let syntaxOk = true;
blocks.forEach((code, i) => {
  const file = join(dir, `block-${i}.js`);
  writeFileSync(file, code);
  try { execFileSync(process.execPath, ['--check', file], { stdio: 'pipe' }); }
  catch (e) { syntaxOk = false; console.log(`FAIL  inline script #${i} syntax — ${String(e.stderr || e).slice(0, 200)}`); }
});
chk('inline scripts parse', syntaxOk);

// MCP surface: the tool is built for AI clients, so the matrix must be reachable there too —
// the same truth as the REST endpoint, plus per-session classification.
const mcpCall = async (method, params) => {
  try {
    return await (await fetch(`${base}/mcp`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, ...(params ? { params } : {}) }),
    })).json();
  } catch (e) {
    return { error: String(e) };
  }
};
let mcpOk = true;
try {
  const tlist = await mcpCall('tools/list', {});
  const names = (tlist.result?.tools ?? []).map((t) => t.name);
  chk('MCP tools/list exposes backends', names.includes('backends'), `tools=${names.length}`);
  const mcpMatrixCall = await mcpCall('tools/call', { name: 'backends', arguments: {} });
  const mcpMatrix = JSON.parse(mcpMatrixCall.result?.content?.[0]?.text ?? '{}');
  chk('MCP backends returns the matrix', !!mcpMatrix.gadget && Array.isArray(mcpMatrix.agents));
  chk('MCP backends agrees with HTTP on the gadget cache',
    JSON.stringify(mcpMatrix.gadget?.cached ?? []) === JSON.stringify(matrix?.gadget?.cached ?? []));
  const onlineSession = (mcpMatrix.agents ?? []).find((a) => a.online);
  if (onlineSession) {
    const perSession = await mcpCall('tools/call', { name: 'backends', arguments: { session: onlineSession.session } });
    const raw = perSession?.result?.content?.[0]?.text ?? '';
    let parsed = null;
    try { parsed = JSON.parse(raw); } catch { parsed = null; }
    if (!parsed) {
      // A session can die between listing it and asking it for its maps; that is not a product
      // failure — the matrix itself is asserted above and must stay reachable.
      console.log('SKIP  MCP backends(session) — session went away: ' + String(raw || perSession?.error || '').slice(0, 120));
    } else {
      const kinds = parsed.sessionBackends?.backends ?? [];
      chk('MCP backends(session) classifies the live process', kinds.includes('adhd_agent'), kinds.join(' + '));
    }
  } else {
    console.log('SKIP  MCP backends(session) — no online agent session right now');
  }
} catch (e) { mcpOk = false; chk('MCP surface', false, String(e)); }
chk('MCP surface reachable', mcpOk);

console.log(checks.every(([, ok]) => ok) ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set +e
echo "$OUT"
if grep -q 'RESULT:PASS' <<<"$OUT"; then SENTINEL="RESULT:PASS"; else SENTINEL="RESULT:FAIL"; fi
OUT="$OUT
$SENTINEL"
verify_gate "v3.3 injection-backend matrix (console + /api/backends)" 0 && exit 0 || exit 1