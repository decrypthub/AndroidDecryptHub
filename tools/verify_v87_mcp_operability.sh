#!/usr/bin/env bash
# v4.49 MCP operability (HOST-ONLY, no device).
#
# "MCP 完全可操作" is only a claim until something checks it: the objective is that an AI client can
# reach every capability the agent has. This script audits the two directions that can silently
# break:
#   1. an agent op that no host code drives (found: `ping` had been dead since v0.2), and
#   2. a capability that exists only on the REST surface / in an acceptance script, so MCP clients
#      cannot use it (found: device filesystem browsing, the hook-engine self-test, the channel
#      self-test).
# Rule: every agent op must be reachable through the MCP import graph, EXCEPT the ops listed in
# INTERNAL_OPS below - each of which carries the reason it is not a tool. The list is asserted both
# ways, so it cannot rot into a dumping ground.
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

// ---- run the unit tests behind the new tools ----
const t = spawnSync(process.execPath, ['--test', `${root}/daemon/test/agent_probe.test.ts`, `${root}/daemon/test/fs_browse.test.ts`, `${root}/daemon/test/flow.test.ts`], { encoding: 'utf8' });
const text = `${t.stdout ?? ''}${t.stderr ?? ''}`;
const passed = Number(/pass (\d+)/.exec(text)?.[1] ?? -1);
const failed = Number(/fail (\d+)/.exec(text)?.[1] ?? -1);
if (t.status !== 0) problems.push(`agent_probe/fs_browse/flow unit tests exited ${t.status}`);
if (passed < 22) problems.push(`expected >=22 probe/fs/flow unit tests, saw ${passed}`);
if (failed !== 0) problems.push(`probe/fs/flow unit tests report ${failed} failures`);
notes.push(`probe + filesystem + flow unit tests: pass=${passed} fail=${failed}`);

// ---- agent ops ----
const agentSrc = read('agent/src/bootstrap/agent_main.c');
const agentOps = [...agentSrc.matchAll(/strcmp\(op, "([a-z0-9_]+)"\)/g)].map((m) => m[1]);
if (new Set(agentOps).size !== agentOps.length) problems.push('the agent dispatch has a duplicate op');

// ops the agent deliberately does NOT have to expose as tools
const INTERNAL_OPS = {
  capture_drain: 'the shared drainSession owns the ring - a tool that drained it directly is the java_trace P0 (capture_start / capture_stop ARE tools: setCapture is their one implementation)',
};
for (const op of Object.keys(INTERNAL_OPS)) {
  if (!agentOps.includes(op)) problems.push(`INTERNAL_OPS lists ${op}, which the agent no longer has (stale entry)`);
}

// ---- walk the MCP import graph and collect every op it can send ----
function resolveImport(fromRel, spec) {
  const parts = fromRel.split('/'); parts.pop();
  for (const seg of spec.split('/')) {
    if (seg === '.' || seg === '') continue;
    if (seg === '..') parts.pop(); else parts.push(seg);
  }
  const joined = parts.join('/');
  return /\.(ts|js)$/.test(joined) ? joined : `${joined}.ts`;   // imports may or may not carry the extension
}
function closure(entry) {
  const seen = new Set();
  const queue = [entry];
  while (queue.length) {
    const rel = queue.pop();
    if (seen.has(rel)) continue;
    seen.add(rel);
    let src;
    try { src = read(rel); } catch { problems.push(`import graph: cannot read ${rel}`); continue; }
    for (const m of src.matchAll(/from\s+'(\.[^']+)'/g)) queue.push(resolveImport(rel, m[1]));
    for (const m of src.matchAll(/import\('(\.\.[^']+)'\)/g)) queue.push(resolveImport(rel, m[1]));   // dynamic imports count too
  }
  return seen;
}
const opsFromFiles = (files) => {
  const ops = new Set();
  for (const rel of files) {
    let src;
    try { src = read(rel); } catch { continue; }
    // sendCmd/agentCmd plus the injected-sender form used by the extracted helpers (deps.send(...))
    // deps.send is the injected-sender form used by the extracted helpers; a bare `.send(` on any other
    // receiver would be a false positive that could mask a genuinely unreachable op, so it is not accepted.
    for (const m of src.matchAll(/(?:\bsendCmd|\bagentCmd|\b(?:deps|opts)\.send)\([^,]+,\s*'([a-z0-9_]+)'/g)) ops.add(m[1]);
  }
  return ops;
};

const mcpClosure = closure('daemon/src/mcp.ts');
const mcpOps = opsFromFiles(mcpClosure);
const unreachable = agentOps.filter((o) => !mcpOps.has(o) && !(o in INTERNAL_OPS));
if (unreachable.length) problems.push(`agent ops not reachable from MCP and not declared internal: ${unreachable.join(', ')}`);
const ghosts = [...mcpOps].filter((o) => !agentOps.includes(o));
if (ghosts.length) problems.push(`MCP drives ops the agent does not know: ${ghosts.join(', ')}`);
const internalReachable = Object.keys(INTERNAL_OPS).filter((o) => mcpOps.has(o));
const internalBlocked = Object.keys(INTERNAL_OPS).filter((o) => !mcpOps.has(o));
notes.push(`agent ops=${agentOps.length}, reachable from the MCP import graph=${agentOps.filter((o) => mcpOps.has(o)).length}, declared internal=${Object.keys(INTERNAL_OPS).length} (${internalReachable.length} of them also reachable indirectly, ${internalBlocked.length} deliberately not tool-backed: ${internalBlocked.join(', ')})`);

// ---- the tools added by this slice must exist and be shaped ----
const { MCP_TOOLS } = await import(`${base}/daemon/src/mcp.ts`).catch((e) => { problems.push('import mcp.ts failed: ' + e.message); return {}; });
const tool = (name) => (MCP_TOOLS ?? []).find((x) => x.name === name);
const names = (MCP_TOOLS ?? []).map((x) => x.name);
if (new Set(names).size !== names.length) problems.push('duplicate MCP tool name');
for (const [name, requiredKeys] of [['agent_ping', ['session']], ['engine_selftest', ['session']], ['protocol_selftest', ['session']], ['fs_list', ['session', 'path']], ['fs_read', ['session', 'path']], ['capture_start', ['session']], ['capture_stop', ['session']]]) {
  const t2 = tool(name);
  if (!t2) { problems.push(`MCP tool ${name} is missing`); continue; }
  if (typeof t2.handler !== 'function') problems.push(`${name} handler is not a function`);
  for (const k of requiredKeys) if (!t2.inputSchema?.properties?.[k]) problems.push(`${name} does not expose ${k}`);
  if (!/MCP/i.test('') && !t2.description) problems.push(`${name} has no description`);
}
for (const name of ['agent_ping', 'engine_selftest', 'protocol_selftest', 'fs_list', 'fs_read', 'capture_start', 'capture_stop']) {
  if (!(tool(name)?.description ?? '').length) problems.push(`${name} has an empty description`);
}
if (!/(VERDICT|verdict)/.test(String(tool('engine_selftest')?.description))) problems.push('engine_selftest must say that ok is the verdict, not just "the command ran"');
// capture_start: ok must be described as a derived verdict (the agent answers ok:true regardless),
// and capture_stop: it must say that it drains first (a stop that resets the ring silently is the
// silent-loss bug the v2.0 checklist exists to prevent).
if (!/(VERDICT|verdict)/.test(String(tool('capture_start')?.description))) problems.push('capture_start must say that ok is the verdict, not the agent\'s unconditional ok:true');
if (!/(DRAIN|drains|drain first)/i.test(String(tool('capture_stop')?.description))) problems.push('capture_stop must say that it drains the ring before stopping');
notes.push(`MCP tools=${names.length} (agent_ping, engine_selftest, protocol_selftest, fs_list, fs_read, capture_start, capture_stop)`);

// ---- WS-B red line (2026-10-01): no target-specific names in the product code ----
// Two couplings used to hide here: the agent hardcoded the JCE provider module at 10 call
// sites (inside the one-shot probe ops) and the daemon carried the sandbox trigger classes in
// state.ts. Neither was visible to any gate. This is that gate.
function walkSrc(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = `${dir}/${e.name}`;
    if (e.isDirectory()) walkSrc(p, out);
    else if (/\.(c|cpp|h)$/.test(e.name)) out.push(p);
  }
  return out;
}
const BANNED_OPS = ['crypto_hook_test', 'net_hook_test', 'file_hook_test', 'flow_watch', 'detect_watch', 'trace_run', 'inline_crypto_test', 'crypto_probe', 'jni_probe'];
const backAgain = BANNED_OPS.filter((o) => agentOps.includes(o));
if (backAgain.length) problems.push(`sandbox-coupled one-shot ops are back in the agent dispatch: ${backAgain.join(', ')}`);
const nameHits = [];
for (const rel of [...walkSrc(`${root}/daemon/src`), ...walkSrc(`${root}/agent/src`)]) {
  const src = read(rel.replace(`${root}/`, ''));
  const where = rel.replace(`${root}/`, '');
  if (src.includes('com.adh.sandbox')) nameHits.push(`${where}: com.adh.sandbox`);
  if (/\.(c|cpp|h)$/.test(where) && src.includes('libjavacrypto')) nameHits.push(`${where}: libjavacrypto`);
}
if (nameHits.length) problems.push(`target-specific names in product code (red line, agent AND daemon): ${nameHits.join(', ')}`);
notes.push(`red line: agent dispatch ops=${agentOps.length}, banned one-shot ops present=${backAgain.length}, target-name hits=${nameHits.length}`);

// ---- capture_start/stop must go through the ONE implementation (no second copy to drift) ----
const mcpSrc = read('daemon/src/mcp.ts');
if (!/setCapture\(/.test(mcpSrc)) problems.push('mcp.ts must reach capture_start/capture_stop through setCapture, not by sending the ops itself');
if (!read('daemon/src/service.ts').includes('export async function setCapture')) problems.push('service.ts must export setCapture (the one implementation behind the capture tools)');
if (/\bsendCmd\([^,]+,\s*'capture_start'/.test(mcpSrc)) problems.push('mcp.ts sends capture_start directly instead of using setCapture');

// ---- REST and MCP must share the same implementation (no second copy to drift) ----
const routes = read('daemon/src/http/routes_runtime.ts');
for (const helper of ['protocolSelfTest', 'hookEngineSelftest', 'listDeviceDir', 'readDeviceFile', 'agentPing']) {
  if (!routes.includes(helper + '(')) problems.push(`routes_runtime.ts does not use ${helper} (the REST copy would drift from the MCP tool)`);
}
// v25_fsbrowser reads /proc/self/cmdline through the route text field, and demands ok:false + errno
// on a bad path; those two contracts must survive the refactor.
if (!/text = Buffer\.from\(r\.b64 \?\? ''/.test(routes)) problems.push('the fs/read route must keep producing the legacy text field');
if (!/\{ ok: false, error:/.test(routes)) problems.push('fs routes must answer ok:false on failure (v25 asserts it)');

// ---- the ping op must be wired end to end, not just declared ----
if (!read('daemon/src/agent_probe.ts').includes("send(session, 'ping'")) problems.push('agent_ping must actually send the ping op');
if (!routes.includes("path: '/api/agent/ping'")) problems.push('/api/agent/ping route is missing');

for (const n of notes) console.log('  ' + n);
for (const p of problems) console.log('FAIL ' + p);
console.log(problems.length === 0 ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v4.49 MCP operability (op coverage + probe/fs tools + shared helpers)" 0
