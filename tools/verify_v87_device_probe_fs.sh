#!/usr/bin/env bash
# v4.49 device half: the MCP operability tools must work against a real agent.
#
# agent_ping (liveness + latency), engine_selftest (GOT engine really fires and leaves the RELRO page
# alone), protocol_selftest (an oversized frame arrives whole) and the device filesystem
# (fs_list/fs_read through the target). All four go through the same helpers the MCP tools use.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v87_device_probe_fs (no device)"
  exit 0
fi

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const skip = (msg) => { console.log('SKIP  verify_v87_device_probe_fs (' + msg + ')'); console.log('RESULT:SKIP'); process.exit(0); };
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

// 1) liveness
const ping = await (await fetch(`${base}/api/agent/ping?session=${encodeURIComponent(session)}`)).json().catch(() => ({}));
console.log(`agent_ping: ok=${ping.ok} latencyMs=${ping.latencyMs}`);

// 2) engine self-test: the verdict must be ok AND the page protection restored
const engine = await (await fetch(`${base}/api/hook/selftest?session=${encodeURIComponent(session)}`)).json().catch(() => ({}));
console.log(`engine_selftest: ok=${engine.ok} replaced=${engine.replaced} fired=${engine.fired} protRestored=${engine.protRestored} perms=${engine.origPerms}->${engine.slotPerms}`);

// 3) protocol self-test: 1 MB frame, tail past the old 8192-byte cap
const frame = await (await fetch(`${base}/api/debug/frame_echo?session=${encodeURIComponent(session)}&kb=1024`)).json().catch(() => ({}));
console.log(`protocol_selftest: ok=${frame.ok} sent=${frame.sentPadLen} recv=${frame.recvBytes} tailOk=${frame.tailOk} notTruncated=${frame.notTruncated}`);

// 4) device filesystem through the target process
const dir = await (await fetch(`${base}/api/fs/list?session=${encodeURIComponent(session)}&path=${encodeURIComponent('/data/data/' + agent.package)}`)).json().catch(() => ({}));
console.log(`fs_list: ok=${dir.ok} count=${dir.count} truncated=${dir.truncated}`);
const read = await post('/api/fs/read', { session, path: '/proc/self/cmdline' });
const text = String(read.body?.text ?? '');
console.log(`fs_read: ok=${read.body?.ok} size=${read.body?.size} binary=${read.body?.binary} hasPackage=${text.includes(agent.package)}`);
const bad = await (await fetch(`${base}/api/fs/list?session=${encodeURIComponent(session)}&path=${encodeURIComponent('/nonexistent-' + Date.now())}`)).json().catch(() => ({}));
console.log(`fs_list bad path: ok=${bad.ok} err=${JSON.stringify(String(bad.error ?? '').slice(0, 40))}`);

// 5) file_probe (v4.90): which loaded module's GOT holds the libc file-I/O pointers. That answer
//    is what capture_start's fileModule argument comes from, so a probe that returns nothing useful
//    has to be visible here instead of surfacing as a confusing capture_start failure later.
const fp = await (await fetch(`${base}/api/file/probe?session=${encodeURIComponent(session)}`)).json().catch(() => ({}));
const fpFns = fp.fns ?? {};
const fpModules = Array.isArray(fp.modules) ? fp.modules : [];
const fpAddrsOk = ['open', 'openat', 'read', 'write', 'close'].every((n) => /^0x[0-9a-f]+$/.test(String(fpFns[n] ?? '')) && String(fpFns[n]) !== '0x0');
const fpModulesOk = fpModules.length >= 1 && fpModules.every((m) => typeof m.name === 'string' && m.name.endsWith('.so'));
// Any of the five is enough: which symbols a module imports varies by ROM (libjavacore imports
// open/close plus the __read_chk/__write_chk wrappers, other modules hold plain read/write).
const fpAnyOk = fpModules.some((m) => ['open', 'openat', 'read', 'write', 'close'].some((k) => Number(m[k] ?? 0) >= 1));
console.log(`file_probe: ok=${fp.ok} fns=${Object.keys(fpFns).length} modules=${fpModules.length} first=${fpModules[0]?.name ?? '(none)'} openHits=${fpModules.reduce((a, m) => a + Number(m.open ?? 0), 0)}`);

const pass = ping.ok === true && Number(ping.latencyMs) >= 0 && Number(ping.latencyMs) < 5000
  && engine.ok === true && Number(engine.replaced) >= 1 && engine.fired === true && engine.protRestored === true
  && String(engine.slotPerms ?? '')[1] === '-'
  && frame.ok === true && frame.tailOk === true && frame.notTruncated === true
  && dir.ok === true && Number(dir.count) > 0
  && read.body?.ok === true && Number(read.body?.size) > 0 && text.includes(agent.package)
  && bad.ok === false
  && fp.ok === true && fpAddrsOk && fpModulesOk && fpAnyOk;
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v4.49 MCP probes + device filesystem (ping/engine/protocol/fs on a real target)" 0 && exit 0 || exit 1
