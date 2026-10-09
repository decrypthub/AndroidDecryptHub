#!/usr/bin/env bash
# v4.33 call-site ("sites") hooking acceptance.
#
# Why: an entry-based inline hook rewrites the target function's own first bytes, and the sandbox
# audit (Detection.antiHookProbe) sees exactly that (prologueDiffers / entryBranchesOutside). This
# backend leaves the FUNCTION untouched and rewrites the BL instructions that call it instead, so:
#   * the target's prologue stays byte-identical while the call is still intercepted,
#   * the patch is ours, so install -> unhook -> install is fully reversible (no Dobby state),
#   * the thunk page is a memfd mapping (no anonymous executable page).
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
const callJava = async (method) => {
  const r = await mcp('java_call', { className: 'com.adh.sandbox.Detection', method, params: '', args: [] });
  return r?.result?.result ?? null;
};
const audit = async () => {
  const raw = await callJava('antiHookProbe');
  try { return JSON.parse(String(raw)); } catch { return { raw: String(raw) }; }
};
const readWord = async (addr) => {
  const r = await mcp('memory_read', { addr, size: 4 });
  const b64 = String(r?.b64 ?? '');
  if (!r?.ok || !b64) return null;
  const b = Buffer.from(b64, 'base64');
  if (b.length < 4) return null;
  return ('0x' + b.readUInt32LE(0).toString(16).padStart(8, '0'));
};
const hookStatus = async () => (await mcp('native_hook', { action: 'status' })).status?.hooks ?? [];
const regions = async () => (await mcp('memory_maps', {})).regions ?? [];
const mappingOf = (rs, addr) => rs.find((m) => BigInt('0x' + m.start) <= BigInt(addr) && BigInt(addr) < BigInt('0x' + m.end));

const pid = restartSandbox();
const agent = await waitFreshAgent(pid);
if (!agent) { console.log('NO_AGENT'); console.log('RESULT:SKIP'); process.exit(0); }
session = agent.sessionId;

// 1) clean baseline
const baselineValue = Number(await callJava('siteProbe'));
const a0 = (await audit()) || {};

// 2) install the call-site hook
const install = await mcp('native_hook', { action: 'hook', hookId: 0, mode: 'sites', module: 'libadhdetect.so', symbol: 'adh_add_target', sites: 4 });
const rejectReplace = await mcp('native_hook', { action: 'hook', hookId: 0, mode: 'sites', module: 'libadhdetect.so', symbol: 'adh_add_target', sites: 1, skipOriginal: true });
const h0 = install.status?.hooks?.[0];

// 3) both call forms are intercepted (b tail call + real bl) ...
const hookedValue = Number(await callJava('siteProbe'));
const hookedValueBl = Number(await callJava('siteProbeBl'));
const h1 = (await hookStatus())[0];
const hitsAfterCall = Number(h1?.hits ?? 0);
// ... while the target's own entry is untouched (this is the whole point)
const a1 = (await audit()) || {};
const a2 = (await audit()) || {};   // twice: the entry must stay clean on repeated scans too

// 4) the patch really is in the CALLER: the site word changed, and it is a memfd-backed thunk page
const siteForms = (h0?.sites ?? []).map((x) => x.form);
const site0 = h0?.sites?.[0];
// no anonymous executable page may appear for a sites hook either
const anonWhileHooked = (a1.anonExec ?? -1);
const siteWordHooked = site0 ? await readWord(site0.at) : null;
const rs = await regions();
const thunkMap = h0?.thunkPage && h0.thunkPage !== '0x0' ? mappingOf(rs, h0.thunkPage) : null;

// 5) hard unhook restores the caller bytes exactly
const unhook = await mcp('native_hook', { action: 'unhook', hookId: h0?.id, hard: true });
const siteWordRestored = site0 ? await readWord(site0.at) : null;
const siteWordRestoredBl = (h0?.sites ?? [])[1] ? await readWord(h0.sites[1].at) : null;
// the thunk page must be gone (not merely "not referenced") after a successful revert
const thunkGone = h0?.thunkPage ? mappingOf(await regions(), h0.thunkPage) : null;
// same-process reinstall: the sites backend owns the patch, so this must work without a restart
const reinstallSame = await mcp('native_hook', { action: 'hook', hookId: 0, mode: 'sites', module: 'libadhdetect.so', symbol: 'adh_add_target', sites: 2 });
const hSame = reinstallSame.status?.hooks?.[0];
const valueSame = Number(await callJava('siteProbe'));
const hitsSame = Number(((await hookStatus())[0]?.hits) ?? 0);
const unhookSame = hSame ? await mcp('native_hook', { action: 'unhook', hookId: hSame.id, hard: true }) : { ok: false };
const valueAfterUnhook = Number(await callJava('siteProbe'));
// After a HARD unhook there is no hook entry left to read: the meaningful check is that the
// status is empty again and the call site bytes are byte-identical to the original.
const hooksAfterUnhook = (await hookStatus()).length;

// 6) re-install on a fresh process must work again (no Dobby-style stale state)
const pid2 = restartSandbox();
const agent2 = await waitFreshAgent(pid2);
if (!agent2) { console.log('NO_AGENT_2'); console.log('RESULT:SKIP'); process.exit(0); }
session = agent2.sessionId;
const install2 = await mcp('native_hook', { action: 'hook', hookId: 0, mode: 'sites', module: 'libadhdetect.so', symbol: 'adh_add_target', sites: 2 });
const h2 = install2.status?.hooks?.[0];
const valueSecond = Number(await callJava('siteProbe'));
const hitsSecond = Number(((await hookStatus())[0]?.hits) ?? 0);
const a3 = (await audit()) || {};
const unhook2 = h2 ? await mcp('native_hook', { action: 'unhook', hookId: h2.id, hard: true }) : { ok: false };
const alive = pidOfSandbox().length > 0;

const pass =
  baselineValue === 84 && a0.prologueDiffers === false && a0.entryBranchesOutside === false &&
  install.ok === true && h0?.mode === 'sites' && Number(h0?.siteCount) >= 1 &&
  h0?.thunkPage && h0.thunkPage !== '0x0' &&
  (h0?.sites ?? []).every((s) => s.now !== s.orig && s.thunk !== '0x0') &&
  hookedValue === 84 && hookedValueBl === 84 && hitsAfterCall >= 2 &&
  rejectReplace.ok === false && /cannot replace the return value/.test(String(rejectReplace.error || '')) &&
  siteForms.includes('b') && siteForms.includes('bl') &&
  anonWhileHooked === 0 &&
  a1.prologueDiffers === false && a1.entryBranchesOutside === false && a1.prologueBytes === 24 &&
  a2.prologueDiffers === false &&
  siteWordHooked === site0?.now && siteWordHooked !== site0?.orig &&
  thunkMap != null && /^\/memfd:jit-cache/.test(String(thunkMap.path || "")) &&
  unhook.ok === true &&
  siteWordRestored === site0?.orig &&
  ((h0?.sites ?? []).length < 2 || siteWordRestoredBl === h0.sites[1].orig) &&
  thunkGone == null &&
  valueAfterUnhook === 84 && hooksAfterUnhook === 0 &&
  reinstallSame.ok === true && Number(hSame?.siteCount) >= 1 && valueSame === 84 && hitsSame >= 1 && unhookSame.ok === true &&
  install2.ok === true && Number(h2?.siteCount) >= 1 && valueSecond === 84 && hitsSecond >= 1 &&
  a3.prologueDiffers === false && unhook2.ok === true && alive;

console.log(JSON.stringify({
  baseline: { siteProbe: baselineValue, prologueDiffers: a0.prologueDiffers, entryBranchesOutside: a0.entryBranchesOutside },
  install: { ok: install.ok, error: install.error, mode: h0?.mode, siteCount: h0?.siteCount, thunkPage: h0?.thunkPage, sites: (h0?.sites ?? []).map((s) => ({ at: s.at, orig: s.orig, now: s.now, thunk: s.thunk })) },
  hookedCall: { value: hookedValue, valueBl: hookedValueBl, hits: hitsAfterCall, siteForms },
  auditWhileHooked: { prologueDiffers: a1.prologueDiffers, entryBranchesOutside: a1.entryBranchesOutside, prologueBytes: a1.prologueBytes, anonExec: a1.anonExec },
  siteWord: { hooked: siteWordHooked, expectedHooked: site0?.now, restored: siteWordRestored, expectedRestored: site0?.orig, restoredBl: siteWordRestoredBl },
  anonWhileHooked,
  thunkPageAfterUnhook: thunkGone ? thunkGone.path : '(unmapped)',
  rejectReplace: { ok: rejectReplace.ok, error: rejectReplace.error },
  sameProcessReinstall: { ok: reinstallSame.ok, siteCount: hSame?.siteCount, value: valueSame, hits: hitsSame, unhookOk: unhookSame.ok },
  thunkMapping: thunkMap ? { perms: thunkMap.perms, path: thunkMap.path } : null,
  unhook: { ok: unhook.ok, error: unhook.error, value: valueAfterUnhook, activeHooksLeft: hooksAfterUnhook },
  reinstall: { ok: install2.ok, error: install2.error, siteCount: h2?.siteCount, value: valueSecond, hits: hitsSecond, prologueDiffers: a3.prologueDiffers },
  alive,
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if grep -q 'RESULT:SKIP' <<<"$OUT"; then
  echo "SKIP v4.33 call-site hooking (no fresh sandbox agent)"
  exit 0
fi
verify_sandbox_alive
verify_gate "v4.33 call-site hooking (entry prologue untouched)" 0