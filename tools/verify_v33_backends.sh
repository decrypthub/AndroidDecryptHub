#!/usr/bin/env bash
# v3.3 injection-backend matrix in the Web console (module W, host-only).
#
# Checks that the console exposes the backend centre truthfully:
#   * GET /api/backends returns sessions + Zygisk pointers (no Frida Gadget product surface)
#   * the dashboard contains the 注入后端 settings page and its renderer
#   * Frida Gadget UI / API fields are gone
#   * every inline <script> block still parses
#
# RESULT:SKIP is not needed: this is host-only and needs no device.
#
# Run: bash tools/verify_v33_backends.sh   (exit 0 = PASS)
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env_host

set +e
OUT="$(node --input-type=module - "$HTTP" "$ROOT" <<'EOF'
import { writeFileSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { request as httpRequest } from 'node:http';

const [httpPort] = process.argv.slice(2);
const base = `http://127.0.0.1:${httpPort}`;
const checks = [];
const chk = (label, ok, detail = '') => { checks.push([label, !!ok]); console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ' — ' + detail : ''}`); };

function get(url, { method = 'GET', body } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = httpRequest({
      hostname: u.hostname, port: u.port, path: u.pathname + u.search,
      method, headers: body ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } : {},
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

let matrix = null;
try {
  const r = await get(`${base}/api/backends`);
  matrix = JSON.parse(r.text);
} catch (e) { chk('GET /api/backends', false, String(e)); }
chk('GET /api/backends', !!matrix && typeof matrix === 'object');
if (matrix) {
  chk('agents[] present', Array.isArray(matrix.agents), `n=${(matrix.agents || []).length}`);
  chk('no gadget product field', matrix.gadget === undefined, JSON.stringify(matrix.gadget));
  chk('zygisk module advertised', typeof matrix.zygisk?.module === 'string' && matrix.zygisk.module.length > 0, matrix.zygisk?.module);
  if (matrix.agents.length) {
    const kinds = matrix.agents.map((a) => a.entryKind).filter(Boolean);
    chk('sessions carry an entryKind', kinds.length === matrix.agents.length, kinds.join(', '));
  }
}

let html = '';
try { html = (await get(`${base}/`)).text; } catch (e) { /* reported below */ }
chk('dashboard served', html.length > 1000, `bytes=${html.length}`);
for (const marker of ['data-setpage="backends"', 'setPageBackends', 'renderBackends', "fetch('/api/backends')", 'probeBackend']) {
  chk(`dashboard contains ${marker}`, html.includes(marker));
}
chk('dashboard has no Frida Gadget panel', !html.includes('backendsGadget') && !html.includes('load_frida_gadget'));
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

const mcpCall = async (method, params) => {
  try {
    const r = await get(`${base}/mcp`, {
      method: 'POST',
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, ...(params ? { params } : {}) }),
    });
    return JSON.parse(r.text);
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
  chk('MCP backends returns the matrix', Array.isArray(mcpMatrix.agents) && !!mcpMatrix.zygisk);
  chk('MCP backends has no gadget field', mcpMatrix.gadget === undefined);
  const onlineSession = (mcpMatrix.agents ?? []).find((a) => a.online);
  if (onlineSession) {
    const perSession = await mcpCall('tools/call', { name: 'backends', arguments: { session: onlineSession.session } });
    const raw = perSession?.result?.content?.[0]?.text ?? '';
    let parsed = null;
    try { parsed = JSON.parse(raw); } catch { parsed = null; }
    if (!parsed) {
      console.log('SKIP  MCP backends(session) — session went away: ' + String(raw || perSession?.error || '').slice(0, 120));
    } else {
      const kinds = parsed.sessionBackends?.backends ?? [];
      chk('MCP backends(session) classifies the live process', kinds.includes('adhd_agent'), kinds.join(' + '));
      chk('MCP backends(session) does not claim frida_gadget', !kinds.includes('frida_gadget'));
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
