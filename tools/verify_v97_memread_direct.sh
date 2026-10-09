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
#   6) with the backend FORCED to direct, every read command still works — search, magic-scan,
#      art_dexfiles and the chunked dump path — and the dump hashes identically to the same dump
#      taken on the automatic route. `via` alone only reaches `read`, so without this the other
#      commands never ran on the fallback at all.
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
  Number.isInteger(probe.memOpenErrno) && typeof probe.libartJniGetVms === 'boolean' &&
  // The agent's own build version must be answerable: "which agent is flashed?" and "which module
  // is flashed?" are the same question (the module ships this .so).
  typeof probe.agentVer === 'string' && probe.agentVer.length > 0;

// --- forced-direct coverage of EVERY read command -------------------------------------------
// `via` only reaches `read`. On a real target the fd is refused for the whole process, so search /
// magic-scan / dump / art_dexfiles have to work on the direct route too. Forcing the backend puts
// every read command there at once; a target that refuses /proc/self/mem cannot be produced on
// demand, so this is the only way those paths get exercised at all.
const forced = await mcp('mem_backend', { backend: 'direct' });
const forcedProbe = await mcp('compat_probe', {});
const forcedRead = await mcp('memory_read', { addr, size: 64 });
const forcedSearch = await mcp('memory_search', { text: 'Lcom/adh/sandbox/MainActivity;', limit: 4 });
const forcedScan = await mcp('memory_scan_magic', {});
const forcedDex = await mcp('art_dexfiles', {});
const forcedDump = await mcp('memory_dump', { addr, size: 4096 });
// Back to auto: the same dump must dedup to the same sha, which proves the two routes produced
// byte-identical content through the whole chunked-dump path (not just one 64-byte read).
const restored = await mcp('mem_backend', { backend: 'auto' });
const autoDump = await mcp('memory_dump', { addr, size: 4096 });
const afterPing = await mcp('agent_ping', {});

const forceApplied = forced.ok === true && forced.backend === 'direct(forced)' && forced.forced === true;
const probeSeesForce = forcedProbe.memBackend === 'direct(forced)' && forcedProbe.backends?.memRead === true;
// With no per-call `via`, the route name comes from the backend itself: "direct(forced)".
const forcedReadSame = !!forcedRead.b64 && forcedRead.b64 === auto.b64 && forcedRead.via === 'direct(forced)';
const searchOnDirect = forcedSearch.ok === true && forcedSearch.backend === 'direct(forced)';
const scanOnDirect = forcedScan.ok === true && forcedScan.backend === 'direct(forced)' && forcedScan.count > 0;
const dexOnDirect = forcedDex.ok === true && forcedDex.count >= 1;
// memory_dump replies with the artifact meta (sha256/size/complete/dedup) and has no `ok` field.
const dumpOnDirect = forcedDump.complete === true && Number(forcedDump.size) === 4096 && !!forcedDump.sha256;
const dumpIdentical = !!forcedDump.sha256 && forcedDump.sha256 === autoDump.sha256 && autoDump.dedup === true;
const unforced = restored.ok === true && restored.forced === false &&
  typeof restored.backend === 'string' && !restored.backend.includes('forced');
const survivedForce = afterPing.ok === true;

const pass = auto.ok === true && direct.ok === true && sameBytes && routesNamed &&
  badClean && survived && probeOk &&
  forceApplied && probeSeesForce && forcedReadSame && searchOnDirect && scanOnDirect &&
  dexOnDirect && dumpOnDirect && dumpIdentical && unforced && survivedForce;

console.log(JSON.stringify({
  addr, deniedAddr, deniedPerms: denied ? denied.perms : null,
  auto: { ok: auto.ok, via: auto.via, size: auto.size, short: auto.short },
  direct: { ok: direct.ok, via: direct.via, size: direct.size, short: direct.short },
  sameBytes, routesNamed,
  bad: { ok: bad.ok, error: bad.error },
  ping: { ok: ping.ok, latencyMs: ping.latencyMs },
  probe: { agentVer: probe.agentVer, memBackend: probe.memBackend, memOpenErrno: probe.memOpenErrno, libartJniGetVms: probe.libartJniGetVms, memRead: probe.backends?.memRead },
  forcedRoute: {
    applied: { backend: forced.backend, forced: forced.forced },
    probeBackend: forcedProbe.memBackend,
    read: { ok: forcedRead.ok, via: forcedRead.via, sameAsAuto: forcedReadSame },
    search: { ok: forcedSearch.ok, backend: forcedSearch.backend, count: forcedSearch.count },
    scanMagic: { ok: forcedScan.ok, backend: forcedScan.backend, count: forcedScan.count, truncated: forcedScan.truncated },
    artDexfiles: { ok: forcedDex.ok, count: forcedDex.count, error: forcedDex.error },
    dump: { size: forcedDump.size, complete: forcedDump.complete, sha16: String(forcedDump.sha256 ?? '').slice(0, 16) },
    dumpIdenticalAcrossRoutes: dumpIdentical,
    restoredBackend: restored.backend,
  },
  checks: { sameBytes, routesNamed, badClean, survived, probeOk, forceApplied, probeSeesForce,
    forcedReadSame, searchOnDirect, scanOnDirect, dexOnDirect, dumpOnDirect, dumpIdentical, unforced, survivedForce },
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
verify_gate "v9.7 memory-read backend (two routes byte-identical, direct route covers every read command, bad range fails clean, no standing mem fd)" 1 && exit 0 || exit 1
