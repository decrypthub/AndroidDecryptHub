#!/usr/bin/env bash
# v4.34 call-site hooking across modules (scope=all / scope=<module>).
#
# v4.33 proved the target's own prologue can stay untouched by patching the call sites inside its own
# module. This one proves the same for CALLERS IN OTHER MODULES: the sandbox plugin library calls
# adh_add_target through its own PLT, and the sites backend has to resolve that stub and give the
# site its own thunk page (a page near the target module would be out of BL range).
#   * clean process, plugin loaded: all three probes return 84
#   * scope=all: 3 sites across 2 modules (b + bl in the target module, b in the plugin), every
#     probe intercepted (hits >= 3), audit still clean, thunk pages are memfd mappings
#   * every site word read back bit-identical after a hard unhook, thunk pages unmapped
#   * scope=<plugin basename> selects only that module
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
const audit = async () => { try { return JSON.parse(String(await jc('antiHookProbe'))) || {}; } catch { return {}; } };
const readWord = async (addr) => {
  const r = await mcp('memory_read', { addr, size: 4 });
  const b64 = String(r?.b64 ?? '');
  if (!r?.ok || !b64) return null;
  const b = Buffer.from(b64, 'base64');
  return b.length >= 4 ? ('0x' + b.readUInt32LE(0).toString(16).padStart(8, '0')) : null;
};
const hookStatus = async () => (await mcp('native_hook', { action: 'status' })).status?.hooks ?? [];
const regions = async () => (await mcp('memory_maps', {})).regions ?? [];
const mappingOf = (rs, addr) => rs.find((m) => BigInt('0x' + m.start) <= BigInt(addr) && BigInt(addr) < BigInt('0x' + m.end));

const pid = restartSandbox();
const agent = await waitFreshAgent(pid);
if (!agent) { console.log('NO_AGENT'); console.log('RESULT:SKIP'); process.exit(0); }
session = agent.sessionId;

// load the cross-module caller and take a clean baseline
await jc('loadPluginA');
const clean = { plugin: Number(await jc('pluginProbe')), same: Number(await jc('siteProbe')), bl: Number(await jc('siteProbeBl')) };
const a0 = await audit();

// 1) scope=all must cover the plugin's call site too
const all = await mcp('native_hook', { action: 'hook', hookId: 0, mode: 'sites', module: 'libadhdetect.so', symbol: 'adh_add_target', scope: 'all', sites: 8 });
const hAll = all.status?.hooks?.[0];
const sites = hAll?.sites ?? [];
const modules = [...new Set(sites.map((s) => s.module))];
const forms = [...new Set(sites.map((s) => s.form))];
const hooked = { plugin: Number(await jc('pluginProbe')), same: Number(await jc('siteProbe')), bl: Number(await jc('siteProbeBl')) };
const hits = Number(((await hookStatus())[0]?.hits) ?? 0);
const a1 = await audit();
const rs = await regions();
const thunkPaths = sites.map((s) => String(mappingOf(rs, s.thunk)?.path ?? ''));
const wordsHooked = [];
for (const s of sites) wordsHooked.push(await readWord(s.at));

// 2) hard unhook restores every site byte-for-byte and unmaps every thunk page
const unhookAll = await mcp('native_hook', { action: 'unhook', hookId: hAll?.id, hard: true });
const wordsRestored = [];
for (const s of sites) wordsRestored.push(await readWord(s.at));
const rs2 = await regions();
const mapsReadAfterUnhook = rs2.length;
const pagesGone = rs2.length > 0 && sites.every((s) => mappingOf(rs2, s.thunk) == null);
const after = { plugin: Number(await jc('pluginProbe')), same: Number(await jc('siteProbe')) };

// 3) a named module scope selects only that module
const named = await mcp('native_hook', { action: 'hook', hookId: 0, mode: 'sites', module: 'libadhdetect.so', symbol: 'adh_add_target', scope: 'libadhplugin_a.so', sites: 4 });
const hNamed = named.status?.hooks?.[0];
const namedModules = [...new Set((hNamed?.sites ?? []).map((s) => s.module))];
const namedValue = Number(await jc('pluginProbe'));
const namedHits = Number(((await hookStatus())[0]?.hits) ?? 0);
const unhookNamed = hNamed ? await mcp('native_hook', { action: 'unhook', hookId: hNamed.id, hard: true }) : { ok: false };
const alive = pidOfSandbox().length > 0;

const pass =
  clean.plugin === 84 && clean.same === 84 && clean.bl === 84 &&
  a0.prologueDiffers === false && a0.entryBranchesOutside === false &&
  all.ok === true &&
  sites.length >= 3 && modules.includes('libadhplugin_a.so') && modules.includes('libadhdetect.so') &&
  forms.includes('b') && forms.includes('bl') &&
  sites.every((s) => s.now !== s.orig) &&
  sites.every((s) => !/memfd/i.test(s.module)) &&          // JIT memfds must never be scan targets
  String(hAll?.pageKept ?? '') === 'false' &&
  hooked.plugin === 84 && hooked.same === 84 && hooked.bl === 84 && hits >= 3 &&
  a1.prologueDiffers === false && a1.entryBranchesOutside === false && a1.anonExec === 0 &&
  thunkPaths.every((p) => /^\/memfd:jit-cache/.test(p)) &&
  wordsHooked.every((w, i) => w === sites[i].now) &&
  unhookAll.ok === true &&
  wordsRestored.every((w, i) => w === sites[i].orig) && pagesGone &&
  after.plugin === 84 && after.same === 84 &&
  named.ok === true && namedModules.length === 1 && namedModules[0] === 'libadhplugin_a.so' &&
  namedValue === 84 && namedHits >= 1 && unhookNamed.ok === true &&
  alive;

console.log(JSON.stringify({
  clean, auditClean: { prologueDiffers: a0.prologueDiffers, entryBranchesOutside: a0.entryBranchesOutside },
  scopeAll: { ok: all.ok, error: all.error, siteCount: sites.length, modules, forms, scanned: hAll?.scanned, truncated: hAll?.truncated,
              sites: sites.map((s) => ({ at: s.at, form: s.form, module: s.module, orig: s.orig, now: s.now, page: s.page })) },
  hookedProbes: hooked, hits, auditWhileHooked: { prologueDiffers: a1.prologueDiffers, entryBranchesOutside: a1.entryBranchesOutside, anonExec: a1.anonExec },
  thunkPaths, wordsHooked, pageKeptField: hAll?.pageKept, mapsReadAfterUnhook, unhookAll: unhookAll.ok, wordsRestored, pagesGone, after,
  scopeNamed: { ok: named.ok, error: named.error, modules: namedModules, value: namedValue, hits: namedHits, unhookOk: unhookNamed.ok },
  alive,
}));
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
echo "$OUT"
if grep -q 'RESULT:SKIP' <<<"$OUT"; then
  echo "SKIP v4.34 cross-module call-site hooking (no fresh sandbox agent)"
  exit 0
fi
verify_sandbox_alive
verify_gate "v4.34 cross-module call-site hooking (scope=all)" 0