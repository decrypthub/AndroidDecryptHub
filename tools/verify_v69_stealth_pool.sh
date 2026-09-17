#!/usr/bin/env bash
# v4.32 anti-detection acceptance: the anonymous trampoline pool an inline hook leaves behind.
#
# Measured by the TARGET's own audit (com.adh.sandbox.Detection.antiHookProbe reads /proc/self/maps
# and its own code bytes), never by our own accounting:
#   * fresh process, no hook            -> no anonymous exec mapping, prologue intact
#   * install an inline hook            -> the audit SEES it (anonymous r-x page + changed prologue +
#                                          an entry branching outside its own module)
#   * hard unhook                       -> prologue and entry are restored (pool page stays, documented)
#   * stealth on (opt-in camouflage)    -> the pool lands in /memfd:jit-cache, the audit's anonymous
#                                          exec count stays 0, and the hook still works
#   * stealth off                       -> the mmap GOT slot is restored
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
async function mcp(name, args) {
  const r = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: { session, ...args } } }) });
  const j = await r.json();
  const c = j.result?.content?.[0]?.text ?? JSON.stringify(j);
  try { return JSON.parse(c); } catch { return c; }
}
const audit = async () => {
  const r = await mcp('java_call', { className: 'com.adh.sandbox.Detection', method: 'antiHookProbe', params: '', args: [] });
  const raw = r?.result?.result ?? r?.result ?? null;
  try { return JSON.parse(String(raw)); } catch { return { raw: String(raw), error: r?.error }; }
};
const regionsOf = async () => (await mcp('memory_maps', {})).regions ?? [];
const mappingOf = (regions, addr) => regions.find((m) => BigInt('0x' + m.start) <= BigInt(addr) && BigInt(addr) < BigInt('0x' + m.end));

// ---- scenario A: fresh process, camouflage OFF ------------------------------------------
const pidA = restartSandbox();
const agentA = await waitFreshAgent(pidA);
if (!agentA) { console.log('NO_AGENT'); console.log('RESULT:SKIP'); process.exit(0); }
session = agentA.sessionId;
const a0 = await audit();
const hookA = await mcp('native_hook', { action: 'hook', hookId: 0, mode: 'inline', module: 'libadhdetect.so', symbol: 'adh_add_target' });
const hA = hookA.status?.hooks?.[0];
const a1 = await audit();
const regionsA = hA ? await regionsOf() : [];
const trampA = hA ? mappingOf(regionsA, hA.original) : null;
// hard unhook must really restore the entry bytes
const unhookA = hA ? await mcp('native_hook', { action: 'unhook', hookId: hA.id, hard: true }) : { ok: false };
const a2 = await audit();

// ---- scenario B: fresh process, camouflage ON -------------------------------------------
const pidB = restartSandbox();
const agentB = await waitFreshAgent(pidB);
if (!agentB) { console.log('NO_AGENT_B'); console.log('RESULT:SKIP'); process.exit(0); }
session = agentB.sessionId;
const b0 = await audit();
const st0 = await mcp('stealth', { action: 'status' });
const on = await mcp('stealth', { action: 'on', confirm: true });
const hookB = await mcp('native_hook', { action: 'hook', hookId: 0, mode: 'inline', module: 'libadhdetect.so', symbol: 'adh_add_target' });
const hB = hookB.status?.hooks?.[0];
const b1 = await audit();
const regionsB = hB ? await regionsOf() : [];
const trampB = hB ? mappingOf(regionsB, hB.original) : null;
const callB = await mcp('native_call', { module: 'libadhdetect.so', symbol: 'adh_add_target', args: ['20', '22'], confirm: true });
// 84 alone would also be produced by an unhooked function: require the hook to have been hit too.
const statusB = await mcp('native_hook', { action: 'status' });
const hitsB = Number(statusB.status?.hooks?.find((h) => h.id === hB?.id)?.hits ?? 0);
const off = await mcp('stealth', { action: 'off', confirm: true });
const unhookB = hB ? await mcp('native_hook', { action: 'unhook', hookId: hB.id, hard: true }) : { ok: false };
const alive = pidOfSandbox().length > 0;

const pathOf = (m) => (m?.path ?? '');
const pass =
  // A: a clean process reports no anonymous exec mapping and an intact entry
  a0.mapsReadOk === true && a0.prologueBytes === 24 &&
  a0.anonExec === 0 && a0.prologueDiffers === false && a0.entryBranchesOutside === false && a0.baselineCaptured === true &&
  // A: the inline hook is visible to the target's own audit ...
  hookA.ok === true && a1.anonExec >= 1 && a1.prologueDiffers === true && a1.entryBranchesOutside === true &&
  // ... via an anonymous pool page the branch points into
  trampA != null && pathOf(trampA) === '' &&
  // A: hard unhook restores the entry (the pool page itself stays - documented limitation)
  unhookA.ok === true && a2.prologueDiffers === false && a2.entryBranchesOutside === false && a2.anonExec >= 1 &&
  // B: camouflage is available and installs
  st0.memfdAvailable === true && on.ok === true && on.enabled === true && on.installed === true &&
  // B: the same hook now leaves NO anonymous exec mapping behind
  hookB.ok === true && b1.anonExec === 0 && b1.memfdExec > b0.memfdExec &&
  // ... the pool really is a named memfd mapping ...
  trampB != null && /^\/memfd:jit-cache/.test(pathOf(trampB)) &&
  // ... the hook still works AND really ran (hits), while the audit honestly still sees the entry
  // patch (camouflage removes the anonymous page, not the prologue rewrite)
  callB.ok === true && Number(callB.resultDecimal) === 84 && hitsB >= 1 &&
  b1.prologueDiffers === true && b1.entryBranchesOutside === true &&
  // ... and off puts the ORIGINAL libc mmap back into the GOT slot (live slot read, not our flag)
  off.ok === true && off.enabled === false && off.installed === false &&
  off.slotNow === '0x0' && off.originalMmap !== '0x0' &&
  unhookB.ok === true && alive;

console.log(JSON.stringify({
  A_clean: { anonExec: a0.anonExec, prologueDiffers: a0.prologueDiffers, entryBranchesOutside: a0.entryBranchesOutside },
  A_hooked: { anonExec: a1.anonExec, prologueDiffers: a1.prologueDiffers, entryBranchesOutside: a1.entryBranchesOutside, trampolinePath: pathOf(trampA) || '(anon)' },
  A_afterHardUnhook: { anonExec: a2.anonExec, prologueDiffers: a2.prologueDiffers, entryBranchesOutside: a2.entryBranchesOutside },
  B_before: { anonExec: b0.anonExec, memfdExec: b0.memfdExec, prologueDiffers: b0.prologueDiffers },
  B_stealthStatus: { memfdAvailable: st0.memfdAvailable, onOk: on.ok, enabled: on.enabled, installed: on.installed, mmapSlot: on.mmapSlot, originalMmap: on.originalMmap },
  B_hooked: { anonExec: b1.anonExec, memfdExec: b1.memfdExec, prologueDiffers: b1.prologueDiffers, entryBranchesOutside: b1.entryBranchesOutside, trampolinePath: pathOf(trampB) },
  B_call: { resultDecimal: callB.resultDecimal, hits: hitsB },
  B_off: { ok: off.ok, enabled: off.enabled, installed: off.installed, slotNow: off.slotNow, originalMmap: off.originalMmap, redirected: off.redirected, failed: off.failed, memfdErrno: off.memfdErrno },
  alive,
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if grep -q 'RESULT:SKIP' <<<"$OUT"; then
  echo "SKIP v4.32 stealth trampoline pool (no fresh sandbox agent)"
  exit 0
fi
verify_sandbox_alive
verify_gate "v4.32 stealth trampoline pool (anonymous exec mapping removed)" 0