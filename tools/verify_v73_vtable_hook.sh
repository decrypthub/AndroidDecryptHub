#!/usr/bin/env bash
# v4.35 pointer-slot ("vtable") hooking: indirect dispatch intercepted without touching any code.
#
# The sandbox fixture reaches adh_add_target ONLY through a function-pointer table (a const vtable in
# .data.rel.ro, i.e. read-only after relocation), which is how hardened apps call their crypto. The
# backend patches the DATA slot, so:
#   * the function's own bytes are identical before and after (read directly, not through a symbol)
#   * the indirect call is intercepted (slotProbe returns 84 and hits >= 1)
#   * the neighbouring slot (a different function) is untouched
#   * a hard unhook puts the slot bytes back bit-for-bit and unmaps the thunk page
# Note the honest side effect this test also documents: patching a module's GOT slot (the second slot
# found here) changes what &symbol resolves to INSIDE that module, so the sandbox audit - which reads
# the symbol address - reports prologueDiffers=true afterwards even though the code never changed.
# Exit 0 = PASS. Device-only; SKIPs when no sandbox agent is connected.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

set +e
OUT="$(node - "$HTTP" "$SERIAL" <<'EOF'
const [http, serial] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const { spawnSync } = await import('node:child_process');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const adb = (...args) => spawnSync('adb', ['-s', serial, ...args], { encoding: 'utf8' });
const pidOfSandbox = () => String(adb('shell', 'pidof', 'com.adh.sandbox').stdout ?? '').trim();
const restartSandbox = () => {
  const before = pidOfSandbox();
  adb('shell', 'am', 'force-stop', 'com.adh.sandbox');
  adb('shell', 'am', 'start', '-n', 'com.adh.sandbox/.MainActivity');
  return before;
};
const waitFreshAgent = async (oldPid, timeoutMs = 40000) => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const pid = pidOfSandbox();
    if (pid && pid !== oldPid) {
      const agents = await (await fetch(`${base}/api/agents`)).json();
      const a = agents.filter((x) => x.online && x.package === 'com.adh.sandbox')
        .sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0];
      if (a) return a;
    }
    await sleep(700);
  }
  return null;
};
let session = null;
async function mcp(name, args, timeoutMs = 60000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, signal: ctl.signal,
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: { session, ...args } } }) });
    const j = await r.json();
    const c = j.result?.content?.[0]?.text ?? JSON.stringify(j);
    try { return JSON.parse(c); } catch { return c; }
  } finally { clearTimeout(t); }
}
const jc = async (m) => (await mcp('java_call', { className: 'com.adh.sandbox.Detection', method: m, params: '', args: [] }))?.result?.result;
const hexOf = (v) => '0x' + BigInt(v).toString(16);
const leHex = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b.toString('hex'); };
const readHex = async (addr, size) => {
  const r = await mcp('memory_read', { addr, size });
  const b64 = String(r?.b64 ?? '');
  return r?.ok && b64 ? Buffer.from(b64, 'base64').toString('hex') : null;
};
const hookStatus = async () => (await mcp('native_hook', { action: 'status' })).status?.hooks ?? [];
const regions = async () => (await mcp('memory_maps', {})).regions ?? [];
const mappingOf = (rs, addr) => rs.find((m) => BigInt('0x' + m.start) <= BigInt(addr) && BigInt(addr) < BigInt('0x' + m.end));

const pid = restartSandbox();
const agent = await waitFreshAgent(pid);
if (!agent) { console.log('NO_AGENT'); console.log('RESULT:SKIP'); process.exit(0); }
session = agent.sessionId;

const vtable = hexOf(await jc('vtableAddress'));
const slotsBefore = await readHex(vtable, 16);
const fn = '0x' + Buffer.from(slotsBefore ?? '00'.repeat(8), 'hex').readBigUInt64LE(0).toString(16);
const sub = '0x' + Buffer.from(slotsBefore ?? '00'.repeat(16), 'hex').readBigUInt64LE(8).toString(16);
const baselineProbe = Number(await jc('slotProbe'));
const entryBefore = await readHex(fn, 24);

const install = await mcp('native_hook', { action: 'hook', hookId: 0, mode: 'vtable', module: 'libadhdetect.so', symbol: 'adh_add_target', slots: 4 });
const h = install.status?.hooks?.[0];
const slots = h?.slots ?? [];
const kinds = [...new Set(slots.map((s) => s.kind))];
const vtableSlot = slots.find((s) => s.at.toLowerCase() === vtable.toLowerCase());
const entryAfter = await readHex(fn, 24);
const slotsAfter = await readHex(vtable, 16);
// independent read-back of EVERY slot (not just the 16 bytes at the table), while still installed
const slotReadsAfter = [];
for (const sl of slots) slotReadsAfter.push(await readHex(sl.at, 8));
const subAfter = '0x' + Buffer.from(slotsAfter ?? '00'.repeat(16), 'hex').readBigUInt64LE(8).toString(16);
// Hit attribution: the vtable slot is read only by slotProbe, so call it FIRST and read the counter
// here - the direct siteProbe below can only add more (it goes through the module GOT slot that this
// same hook also patched, so an aggregate counter alone could not tell the two paths apart).
const probeHooked = Number(await jc('slotProbe'));
const hitsAfterIndirect = Number(((await hookStatus())[0]?.hits) ?? 0);
const directStill = Number(await jc('siteProbe'));
const hits = Number(((await hookStatus())[0]?.hits) ?? 0);
const audit = await (async () => { try { return JSON.parse(String(await jc('antiHookProbe'))); } catch { return {}; } })();
const rs = await regions();
const thunkPaths = slots.map((s) => String(mappingOf(rs, s.thunk)?.path ?? ''));
const unhook = await mcp('native_hook', { action: 'unhook', hookId: h?.id, hard: true });
const slotsRestored = await readHex(vtable, 16);
const slotReadsRestored = [];
for (const sl of slots) slotReadsRestored.push(await readHex(sl.at, 8));
const rs2 = await regions();
const pagesGone = rs2.length > 0 && slots.every((s) => mappingOf(rs2, s.thunk) == null);
const probeAfter = Number(await jc('slotProbe'));
const alive = pidOfSandbox().length > 0;

const pass =
  slotsBefore !== null && slotsBefore.length === 32 && baselineProbe === 84 && entryBefore !== null &&
  install.ok === true && slots.length >= 1 &&
  vtableSlot != null && vtableSlot.kind === 'data' && vtableSlot.now !== vtableSlot.orig &&
  vtableSlot.orig === fn &&                                    // the slot really held the function
  slots.every((s) => /^r/.test(s.perms) && !/w/.test(s.perms)) &&   // default = read-only slots only
  audit.prologueDiffers === true &&                            // honest: the GOT redirect is visible
  kinds.includes('got') &&                                     // the module PLT slot is a GOT entry
  entryAfter === entryBefore &&                                // NO code was written
  slotsAfter !== null && slotsAfter !== slotsBefore &&
  subAfter === sub &&                                          // neighbouring slot untouched
  probeHooked === 84 && hitsAfterIndirect >= 1 &&                 // the INDIRECT path entered the thunk
  directStill === 84 && hits >= hitsAfterIndirect &&
  slotReadsAfter.length === slots.length &&
  slots.every((sl, i) => slotReadsAfter[i] === leHex(sl.now)) &&          // every slot really holds the thunk
  slots.every((sl, i) => slotReadsRestored[i] === leHex(sl.orig)) &&     // ... and is back to the original
  vtableSlot.orig === fn &&
  audit.entryBranchesOutside === false &&
  thunkPaths.every((p) => /^\/memfd:jit-cache/.test(p)) &&
  unhook.ok === true && slotsRestored === slotsBefore && pagesGone && probeAfter === 84 &&
  alive;

console.log(JSON.stringify({
  vtable, fn, sub, baselineProbe, entryBefore,
  install: { ok: install.ok, error: install.error, slotCount: h?.slotCount, scanned: h?.scanned, truncated: h?.truncated },
  slots: slots.map((s) => ({ at: s.at, kind: s.kind, perms: s.perms, module: s.module, orig: s.orig, now: s.now })),
  kinds,
  entryUnchanged: entryAfter === entryBefore,
  slotsBefore, slotsAfter, subUnchanged: subAfter === sub,
  probeHooked, hitsAfterIndirect, directStill, hits, slotReadsAfter, slotReadsRestored,
  auditView: { prologueDiffers: audit.prologueDiffers, entryBranchesOutside: audit.entryBranchesOutside,
               note: 'the audit reads the symbol through the patched GOT slot; the direct 24-byte read above is the code truth' },
  thunkPaths, unhook: unhook.ok, slotsRestored, pagesGone, probeAfter, alive,
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if grep -q 'RESULT:SKIP' <<<"$OUT"; then
  echo "SKIP v4.35 vtable (pointer-slot) hooking (no fresh sandbox agent)"
  exit 0
fi
verify_sandbox_alive
verify_gate "v4.35 vtable (pointer-slot) hooking without touching code" 0