#!/usr/bin/env bash
# v4.50 device half: the LOADED agent image must not carry our identity strings either.
#
# The host-side v88 scan proves the artifact. This proves the same thing about the process that is
# actually running: it searches the target memory (through the agent own search op) for the tokens
# that stage 1 removed, and it needs a POSITIVE CONTROL - a token that must be present - so that
# "zero hits" cannot be the result of a search that covered nothing.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v88_device_memory_signature (no device)"
  exit 0
fi

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const skip = (msg) => { console.log('SKIP  verify_v88_device_memory_signature (' + msg + ')'); console.log('RESULT:SKIP'); process.exit(0); };
const fail = (msg, extra) => { if (extra !== undefined) console.log(JSON.stringify(extra)); console.log('FAIL ' + msg); console.log('RESULT:FAIL'); process.exit(0); };
async function post(path, body) {
  const r = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  let parsed = null; try { parsed = await r.json(); } catch { parsed = null; }
  return { status: r.status, body: parsed };
}
const agents = await (await fetch(`${base}/api/agents`)).json().catch(() => null);
const agent = (Array.isArray(agents) ? agents : []).filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((a, b) => (b.connectedAt ?? 0) - (a.connectedAt ?? 0))[0];
if (!agent) skip('no online sandbox agent');
const session = agent.sessionId;

const clean = ['ADH_RT', 'ADH_NATIVE_HOOK', 'ADH_JAVA_ENUM', 'Host ADH Daemon', 'libadh_agent.so', 'libadhdetect.so', 'adh_trace_target'];
const mustBePresent = ['native_hook'];   // the op name we keep; proves the search really reads our image

// The sandbox process also holds the FIXTURE's own strings (its log tags such as ADH_NATIVE_HOOK,
// the fixture library name, the fixture symbol adh_trace_target) and every module PATH from
// /proc/self/maps - a whole-address-space search therefore cannot say anything about the agent
// image. Every hit carries its module path, so count only the ones inside the agent's own module.
const agentModule = String(agent.selfModule ?? '');
async function search(token) {
  const hex = Buffer.from(token, 'ascii').toString('hex');
  const body = (await post('/api/memory/search', { session, hex, limit: 200 })).body ?? {};
  const hits = Array.isArray(body.hits) ? body.hits : [];
  // Only the compiled image counts: the agent's rw-p segment legitimately holds RUNTIME data (the
  // capture ring's event text names the modules we hooked, so "libadhdetect.so" shows up there
  // after any test that touched the fixture). Identity strings compiled into the image would sit in
  // r--p/r-xp, which is exactly what this check is about.
  const mine = hits.filter((h) => String(h?.path ?? '') === agentModule && !String(h?.perms ?? '').includes('w'));
  return { ok: body.ok, total: Number(body.count ?? hits.length), mine: mine.length, sample: mine[0] ?? null, hits: hits.length };
}

const control = await search(mustBePresent[0]);
const controlHits = control.mine;
console.log(`positive control "${mustBePresent[0]}": ok=${control.ok} hits-in-agent=${controlHits} (whole process ${control.total})`);
if (!(controlHits > 0)) {
  // A search that finds nothing at all cannot prove anything: report it as such instead of passing.
  console.log('❌ positive control found nothing - the search did not cover the agent image');
  console.log('RESULT:FAIL');
  process.exit(0);
}

const found = [];
for (const token of clean) {
  const r = await search(token);
  console.log(`  ${token}: hits-in-agent=${r.mine} (whole process ${r.total}${r.sample ? ', first at ' + r.sample.addr : ''})`);
  if (r.mine > 0) found.push(`${token} x${r.mine}`);
}
const alive = String((await import('node:child_process')).spawnSync('adb', ['-s', process.env.ANDROID_SERIAL || process.env.ADH_SERIAL || '', 'shell', 'pidof', 'com.adh.sandbox'], { encoding: 'utf8' }).stdout || '').trim();
if (found.length) console.log('❌ identity strings still in the loaded image: ' + found.join(', '));
console.log(found.length === 0 && alive.length > 0 ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v4.50 runtime signature scan (no identity strings in the loaded image)" 0 && exit 0 || exit 1
