#!/usr/bin/env bash
# v9.7 memory-read backend acceptance (device).
#
# Every ADH read path used to go through /proc/self/mem. A target that makes that fd fail —
# open() returns EACCES — lost read / search / magic-scan / dump / art_dexfiles all at once, with
# nothing in the reply saying why. The agent now falls back to a bounds-checked direct read
# (mem_read.c), and `read ... via=direct` exposes that route on its own.
#
# This checks the new route deterministically:
#   1) a known-readable address read through BOTH routes returns identical bytes
#   2) each reply names the route that actually answered (via)
#   3) a non-readable address fails cleanly through the direct route instead of killing the
#      target, and the target is still alive afterwards (agent_ping)
#   4) compat_probe reports the route (memBackend / memOpenErrno / libartJniGetVms), so the
#      capability can no longer downgrade silently
#   5) no standing /proc/self/mem descriptor is left behind after a read
#
# The signal guard that turns a mid-copy fault into a failed read is NOT reachable from here: it
# only fires when a mapping goes away underneath the copy. This test covers the bounds check and
# the two routes; it does not claim to have exercised the fault path.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

# Fresh process: the fd is opened per command window, and a previous command could have left a
# cache behind that would mask the route this test wants to observe.
verify_restart_sandbox >/dev/null 2>&1
sleep 2

set +e
OUT="$(node - "$HTTP" <<'EOF'
const [http] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const agents = await (await fetch(`${base}/api/agents`)).json();
const agent = agents.filter((x) => x.online && x.package === 'com.adh.sandbox')
  .sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0];
if (!agent) { console.log('NO_AGENT'); console.log('RESULT:SKIP'); process.exit(0); }
const sid = agent.sessionId;
async function mcp(name, args) {
  const r = await fetch(`${base}/mcp`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call',
      params: { name, arguments: { session: sid, ...args } } }),
  });
  const j = await r.json();
  const t = j?.result?.content?.[0]?.text;
  try { return JSON.parse(t); } catch { return { raw: t }; }
}

// Anchor on a STABLE readable address: the start of a read-only executable mapping. A heap string
// would move (or be collected) between the two reads and make the byte-identity check meaningless.
// A deliberately non-readable address: the start of a mapping /proc/self/maps denies read on.
const maps = await mcp('memory_maps', {});
const regions = Array.isArray(maps.regions) ? maps.regions : [];
const code = regions.find((r) => String(r.perms).startsWith('r-x') && /\.so$/.test(String(r.path)));
const denied = regions.find((r) => !String(r.perms).startsWith('r') && r.perms);
if (!code) {
  console.log(JSON.stringify({ regionCount: regions.length }));
  console.log('RESULT:FAIL (no read-only code mapping to anchor on)');
  process.exit(0);
}
const addr = `0x${code.start}`;
const deniedAddr = denied ? `0x${denied.start}` : '0x1';

const auto = await mcp('memory_read', { addr, size: 64 });
const direct = await mcp('memory_read', { addr, size: 64, via: 'direct' });
const bad = await mcp('memory_read', { addr: deniedAddr, size: 64, via: 'direct' });
const ping = await mcp('agent_ping', {});
const probe = await mcp('compat_probe', {});

const sameBytes = !!auto.b64 && auto.b64 === direct.b64;
const routesNamed = auto.via === 'proc-self-mem' && direct.via === 'direct';
const badClean = bad.ok === false && typeof bad.error === 'string' && bad.error.includes('direct');
const survived = ping.ok === true;
const probeOk = typeof probe.memBackend === 'string' &&
  Number.isInteger(probe.memOpenErrno) && typeof probe.libartJniGetVms === 'boolean';

const pass = auto.ok === true && direct.ok === true && sameBytes && routesNamed &&
  badClean && survived && probeOk;

console.log(JSON.stringify({
  addr, deniedAddr, deniedPerms: denied ? denied.perms : null,
  auto: { ok: auto.ok, via: auto.via, size: auto.size, short: auto.short },
  direct: { ok: direct.ok, via: direct.via, size: direct.size, short: direct.short },
  sameBytes, routesNamed,
  bad: { ok: bad.ok, error: bad.error },
  ping: { ok: ping.ok, latencyMs: ping.latencyMs },
  probe: { memBackend: probe.memBackend, memOpenErrno: probe.memOpenErrno, libartJniGetVms: probe.libartJniGetVms, memRead: probe.backends?.memRead },
  checks: { sameBytes, routesNamed, badClean, survived, probeOk },
}, null, 1));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"

# Footprint: a read must not leave a standing /proc/self/mem descriptor in the target. That open fd
# is itself an observable "someone is reading my memory" signal, so it is opened per command.
PID="$(adb -s "$SERIAL" shell pidof com.adh.sandbox 2>/dev/null | tr -d '\r' | awk '{print $1}')"
MEM_FDS="?"
if [ -n "$PID" ]; then
  MEM_FDS="$(adb -s "$SERIAL" shell "su -c 'ls -l /proc/$PID/fd'" 2>/dev/null | grep -c 'self/mem' | tr -d '\r')"
  [ -z "$MEM_FDS" ] && MEM_FDS=0
fi
echo "standing /proc/self/mem fds in sandbox pid=${PID:-none}: $MEM_FDS"
if [ "$MEM_FDS" != "0" ]; then
  echo "RESULT:FAIL (a /proc/self/mem fd outlived the command)"
fi

verify_sandbox_alive
verify_gate "v9.7 memory-read backend (direct route byte-identical, route named, bad range fails clean, no standing mem fd)" 1 && exit 0 || exit 1
