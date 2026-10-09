#!/usr/bin/env bash
# v4.56 JNIEnv field digest (HOST-ONLY, no device).
#
# v4.55 added the Get/Set<Type>Field slots, but their events carry an opaque jfieldID ("field=0x.."),
# which is not something an analyst can read. This digest joins them with the GetFieldID events that
# handed those ids out, so the answer is "com.example.Foo#isDebug:Z was read 12x, last value 0".
# The pure join is unit-tested here; the live path reuses the shared drainSession (the java_trace P0).
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

const t = spawnSync(process.execPath, ['--test', `${root}/daemon/test/jni_field_digest.test.ts`], { encoding: 'utf8' });
const text = `${t.stdout ?? ''}${t.stderr ?? ''}`;
const passed = Number(/pass (\d+)/.exec(text)?.[1] ?? -1);
const failed = Number(/fail (\d+)/.exec(text)?.[1] ?? -1);
if (t.status !== 0) problems.push(`jni_field_digest unit tests exited ${t.status}`);
if (passed < 7) problems.push(`expected >=7 digest unit tests, saw ${passed}`);
if (failed !== 0) problems.push(`digest unit tests report ${failed} failures`);
notes.push(`digest unit tests: pass=${passed} fail=${failed}`);

// the agent must hand out the id, otherwise nothing can ever be resolved
const agentSrc = fs.readFileSync(`${root}/agent/src/runtime/jni_env_hooks.c`, 'utf8');
if (!agentSrc.includes('" -> %p"')) problems.push('GetFieldID/GetStaticFieldID events must carry the returned jfieldID (" -> %p")');
const digestSrc = fs.readFileSync(`${root}/daemon/src/jni_field_digest.ts`, 'utf8');
if (!digestSrc.includes('drainSession(')) problems.push('the live digest must drain through the shared drainSession');
if (!digestSrc.includes('rewrittenSamples')) problems.push('the digest must surface rewritten writes (setValue) separately');
if (/capture_drain/.test(digestSrc)) problems.push('the digest must never send a raw capture_drain (it would eat another consumer\'s events)');
notes.push('agent hands out the id; digest drains through the shared path');

try {
  const { MCP_TOOLS } = await import(`${base}/daemon/src/mcp.ts`);
  const tool = (MCP_TOOLS ?? []).find((x) => x.name === 'jni_field_digest');
  if (!tool) problems.push('jni_field_digest is missing from the MCP registry');
  else {
    if (typeof tool.handler !== 'function') problems.push('jni_field_digest handler is not a function');
    for (const k of ['session']) if (!tool.inputSchema?.properties?.[k]) problems.push(`jni_field_digest does not expose ${k}`);
    if (!/jni_env_hook/.test(String(tool.description))) problems.push('the description must say the field slots have to be hooked first');
    notes.push(`MCP tools=${MCP_TOOLS.length}, jni_field_digest present`);
  }
} catch (e) {
  problems.push('import mcp.ts failed: ' + e.message);
}

try {
  const routes = fs.readFileSync(`${root}/daemon/src/http/routes_runtime.ts`, 'utf8');
  if (!routes.includes("path: '/api/jni/field_digest'")) problems.push('the REST route /api/jni/field_digest is missing');

  // Parameter-face check (the P0 class from the v4.58 review: setValue was wired into MCP only and
  // the REST route silently dropped it, which made the device script impossible to pass):
  // every property the MCP tool accepts must appear inside the matching REST handler block.
  const { MCP_TOOLS } = await import(`${base}/daemon/src/mcp.ts`);
  const tool = (MCP_TOOLS ?? []).find((x) => x.name === 'jni_env_hook');
  const props = Object.keys(tool?.inputSchema?.properties ?? {});
  const at = routes.indexOf("path: '/api/jni/env_hook'");
  if (at < 0) problems.push('the REST route /api/jni/env_hook is missing');
  else {
    const block = routes.slice(at, at + 900);
    const missing = props.filter((k) => !new RegExp('\\b' + k + '\\b').test(block));
    if (missing.length) problems.push(`/api/jni/env_hook does not forward: ${missing.join(', ')}`);
    else notes.push(`REST parity: /api/jni/env_hook forwards all ${props.length} MCP parameters (${props.join(', ')})`);
  }
} catch (e) { problems.push('read routes failed: ' + e.message); }

for (const n of notes) console.log('  ' + n);
for (const p of problems) console.log('FAIL ' + p);
console.log(problems.length === 0 ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
verify_gate "v4.56 JNIEnv field digest (name/id join + shared drain + MCP shape)" 0
