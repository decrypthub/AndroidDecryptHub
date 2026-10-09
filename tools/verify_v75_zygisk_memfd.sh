#!/usr/bin/env bash
# v4.37 Zygisk memfd injection acceptance: the agent .so must be loaded from an unnamed memfd, so the
# target's maps never show the module path, AND the injected agent must be alive and functional.
#
# Honesty contract (a bare "grep -c libadh_agent == 0" would also pass when nothing was injected):
#   * the root-side decision log must show the scope answer + the inject decision for THIS cold start
#   * the target pid must be the pid the agent reports (same process)
#   * outside view: /proc/<pid>/maps has zero "libadh_agent" / module-dir entries
#   * inside view: the agent's own memory_maps lists its image as "/memfd:jit-cache (deleted)"
#     with a private r-xp code mapping (ART's own jit-cache regions are shared r--s/r-xs/rw-s)
#   * the agent is online in /api/agents with entry=start (the .so actually ran)
# Device-only. A missing precondition prints "SKIP ..." and exits 0 WITHOUT the RESULT:PASS sentinel,
# so tools/verify_all.sh counts it as a skip - not as a passing acceptance of memfd injection.
# Restores the operator's Zygisk scope on exit.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v75_zygisk_memfd (no device)"
  exit 0
fi
ROOT_MGR="$(adb -s "$SERIAL" shell 'su -c "if test -x /data/adb/ksud || test -x /data/adb/ksu/bin/ksud; then echo KSU; elif test -d /data/adb/magisk; then echo MAGISK; else echo NO; fi"' 2>/dev/null | tr -d '\r' || true)"
if [ "$ROOT_MGR" != "KSU" ] && [ "$ROOT_MGR" != "MAGISK" ]; then
  echo "SKIP  verify_v75_zygisk_memfd (no Magisk/KernelSU on device)"
  exit 0
fi
if ! adb -s "$SERIAL" shell 'su -c "test -d /data/adb/modules/adh"' >/dev/null 2>&1; then
  echo "SKIP  verify_v75_zygisk_memfd (adh Zygisk module not installed)"
  exit 0
fi
if ! adb -s "$SERIAL" shell 'su -c "test -f /data/adb/adh/zygisk_inject.log"' >/dev/null 2>&1; then
  echo "SKIP  verify_v75_zygisk_memfd (module predates the decision log / memfd loader)"
  exit 0
fi
# The injected agent reports to the Host ADH Daemon through adb reverse; without the tunnel the
# liveness half of this check cannot run (tools/dev_up.sh sets it up).
if ! adb -s "$SERIAL" reverse --list 2>/dev/null | grep -q 'tcp:876'  ; then
  echo "SKIP  verify_v75_zygisk_memfd (no adb reverse tunnel; run tools/dev_up.sh first)"
  exit 0
fi

set +e
OUT="$(node - "$HTTP" "$SERIAL" <<'EOF'
const [http, serial] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const { spawnSync } = await import('node:child_process');
const target = process.env.ADH_MEMFD_TARGET || 'com.android.settings';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const adb = (...args) => spawnSync('adb', ['-s', serial, ...args], { encoding: 'utf8' });
const sh = (...args) => String(adb('shell', ...args).stdout ?? '').replace(/\r/g, '');
const root = (cmd) => sh(`su -c ${JSON.stringify(cmd)}`);
const logLines = (from) => root(`tail -n +${from} /data/adb/adh/zygisk_inject.log`);

const prePids = new Set(sh('pidof', target).trim().split(/\s+/).filter(Boolean));
const priorScope = root('base64 /data/adb/adh/scope.json 2>/dev/null || true').replace(/\s+/g, '');
let restored = false;
const restore = () => {
  if (restored) return;
  restored = true;
  const b64 = priorScope || Buffer.from('{"version":1,"mode":"allowlist","packages":[]}').toString('base64');
  root(`echo ${b64} | base64 -d > /data/adb/adh/scope.json && chmod 644 /data/adb/adh/scope.json`);
  adb('shell', 'am', 'force-stop', target);
  root(`rm -f /data/data/${target}/cache/adh_zygisk.log`);
};
process.on('exit', restore);
process.on('SIGINT', () => { restore(); process.exit(130); });

const fail = (msg, extra) => {
  restore();
  if (extra) console.error('---- evidence ----\n' + extra);
  console.error('FAIL: ' + msg);
  console.log('RESULT:FAIL');
  process.exit(1);
};

// (1) scope this run to the target package only.
const scope = JSON.stringify({ version: 1, mode: 'allowlist', packages: [target] });
root(`echo ${Buffer.from(scope).toString('base64')} | base64 -d > /data/adb/adh/scope.json && chmod 644 /data/adb/adh/scope.json`);
const applied = root('cat /data/adb/adh/scope.json').trim();
if (!applied.includes(target)) fail(`scope write did not round-trip (got: ${applied.slice(0, 120)})`);

const linesBefore = Number(root('wc -l < /data/adb/adh/zygisk_inject.log').trim()) || 0;
const startedAt = Date.now();   // a session older than this is stale and must not satisfy the check

// (2) cold start. The next preAppSpecialize for this package must answer 1 and decide to inject.
adb('shell', 'am', 'force-stop', target);
// Launch through the package manager so ADH_MEMFD_TARGET can point at any package (the hardcoded
// .Settings activity only exists for the default target). resolve-activity may print extra
// "priority=..." lines, so pick the token that actually looks like a component; monkey is the
// fallback (and the retry when the component start produces no process).
const launchTarget = () => {
  const out = sh('cmd', 'package', 'resolve-activity', '--brief', '-c', 'android.intent.category.LAUNCHER', target);
  const component = out.trim().split(/\s+/).find((t) => /^[A-Za-z0-9._]+\/[A-Za-z0-9._$]+$/.test(t));
  if (component) {
    adb('shell', 'am', 'start', '-n', component);
    return `am start -n ${component}`;
  }
  adb('shell', 'monkey', '-p', target, '-c', 'android.intent.category.LAUNCHER', '1');
  return 'monkey (no component resolved)';
};
let launchMode = launchTarget();
let session = null;
let freshCandidates = [];
let retriedLaunch = false;
const deadline = Date.now() + 45000;
while (Date.now() < deadline) {
  if (!retriedLaunch && Date.now() > deadline - 35000 && sh('pidof', target).trim() === '') {
    retriedLaunch = true;   // the component start produced no process: try the monkey path once
    launchMode += ' -> retry ' + launchTarget();
  }
  let agents = [];
  try { agents = await (await fetch(`${base}/api/agents`)).json(); } catch { /* daemon down -> handled below */ }
  freshCandidates = (Array.isArray(agents) ? agents : [])
    .filter((a) => a.online && a.package === target && (a.connectedAt ?? 0) >= startedAt);
  session = freshCandidates.sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0] ?? null;
  if (session) break;
  await sleep(700);
}

// A ColorOS cross-app confirmation dialog (SystemUI in front) blocks the cold start before the app
// process is even created - the run then has no scope line and no session. Name that condition in the
// failure instead of reporting it as "the module never answered".
const focusLine = sh('dumpsys window | grep -E "mCurrentFocus" | head -n1').trim();
const blockedByDialog = /systemui/i.test(focusLine);

let newLines = logLines(linesBefore + 1);
if (newLines.trim() === '') {
  // The decision log is bounded in place; if it was truncated between the two reads the window is
  // empty. Fall back to a generous tail (the freshness/entry checks below still tie the run to a
  // process started after this script began).
  newLines = logLines(1);
}
const evidence = () => [
  `target=${target} pid=${session?.pid ?? '?'} entry=${session?.entry ?? '?'}`,
  `current focus: ${focusLine || '(unknown)'}`,
  `decision log (since line ${linesBefore + 1}):\n${newLines.trim() || '(none)'}`,
].join('\n');

if (!newLines.includes(`in scope pkg=${target}`))
  fail(blockedByDialog
    ? `the cold start never reached the module: a system dialog is in front (${focusLine}) - dismiss it and re-run`
    : 'the module never answered the scope query for this cold start (no injection attempt)', evidence());
if (!session)
  fail(`no FRESH (connectedAt >= ${startedAt}) online agent session for ${target} within 45s`, evidence());
if (session.entry !== 'start')
  fail(`the fresh session was not started by the Zygisk loader (entry=${session.entry}, expected "start")`, evidence());
if (!newLines.includes(`will inject pkg=${target}`))
  fail('scope was granted but the loader never logged an inject decision', evidence());

const pid = String(session.pid);
const livePid = sh('pidof', target).trim();
if (!pid || pid === 'undefined') fail('agent session carries no pid', evidence());
if (!livePid.split(/\s+/).includes(pid))
  fail(`agent pid ${pid} is not the live ${target} process (${livePid || 'none'})`, evidence());
if (prePids.has(pid))
  fail(`agent pid ${pid} existed before this cold start (not a fresh process)`, evidence());
const samePid = freshCandidates.filter((a) => String(a.pid) === pid);
if (samePid.length !== 1)
  fail(`expected exactly one fresh online session for pid ${pid}, found ${samePid.length} (duplicate agent copies?)`, evidence());

// The agent's own hello (shown by the daemon) must name the memfd, not a file path: this is the
// per-session identity channel that works for every backend, not just the maps this script reads.
if (!String(session.selfModule || '').includes('memfd'))
  fail(`the agent reports its own image as "${session.selfModule || '?'}" (no memfd) — the module path was loaded directly`, evidence());

// (3) outside view: the module path must not be in the target's maps.
// A maps read that failed (dead pid / no permission) yields no parseable first line; the file
// itself does not necessarily contain a "/proc/" path, so the shape of the first line is the check.
const maps = root(`cat /proc/${pid}/maps`);
if (!/^[0-9a-f]+-[0-9a-f]+ [rwxps-]{4} /m.test(maps))
  fail(`cannot read /proc/${pid}/maps as root (empty or unparseable)`, evidence());
const agentPathHits = maps.split('\n').filter((l) => l.includes('libadh_agent') || l.includes('/data/adb/modules/adh')).length;
if (agentPathHits !== 0) {
  const hits = maps.split('\n').filter((l) => l.includes('libadh_agent') || l.includes('/data/adb/modules/adh')).join('\n');
  fail(`agent module path visible in the target maps (${agentPathHits} entries):\n${hits}`, evidence());
}

// (4) inside view: the agent's own maps must place its image in a memfd, not on disk.
async function mcp(name, args) {
  const r = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call',
      params: { name, arguments: { session: session.sessionId, ...args } } }) });
  const j = await r.json();
  const c = j.result?.content?.[0]?.text ?? JSON.stringify(j);
  try { return JSON.parse(c); } catch { return c; }
}
const regions = (await mcp('memory_maps', {}))?.regions ?? [];
if (!regions.length) fail('memory_maps returned no regions for the injected agent', evidence());
const MEMFD = '/memfd:jit-cache (deleted)';   // exact name: "jit-cache-anything" must not pass
const mine = regions.filter((m) => String(m.path || '') === MEMFD);
const priv = mine.filter((m) => !String(m.perms || '').endsWith('s'));   // our image: private
const shared = mine.filter((m) => String(m.perms || '').endsWith('s'));  // ART's own JIT cache
const privateExec = priv.filter((m) => String(m.perms || '').startsWith('r-xp'));
if (!privateExec.length)
  fail(`the agent's own maps list no private r-xp "${MEMFD}" image (found ${mine.length} exact-name regions)`, evidence());
const privInodes = new Set(priv.map((m) => String(m.inode)));
const sharedInodes = new Set(shared.map((m) => String(m.inode)));
if (privInodes.size !== 1)
  fail(`the private memfd regions do not share one inode (${[...privInodes].join(',')}) - this is not one image`, evidence());
if (sharedInodes.size && privInodes.has([...sharedInodes][0]))
  fail('the private image reuses ART jit-cache inodes - cannot tell our copy apart from the runtime cache', evidence());
// ELF header: read it from the region whose file offset is 0 (true for any normal build layout, and
// not tied to the private r-xp region the way a "read at the code mapping" shortcut would be).
const headerRegion = priv.find((m) => Number(BigInt('0x' + String(m.offset || '0'))) === 0);
if (!headerRegion) fail('no private memfd region maps file offset 0 (no ELF header to check)', evidence());
const leaked = regions.filter((m) => String(m.path || '').includes('libadh_agent'));
if (leaked.length)
  fail(`the agent's own maps still expose its module path (${leaked.length} regions)`, evidence());

// The private r-xp region must be a real ELF image, not just a name ART could also use. Read the
// first bytes of the mapping from the host (root, /proc/<pid>/mem) - inside a system app the agent's
// own read(2) path can be refused by SELinux, so the check runs outside the target.
const elfHex = root(`od -An -tx1 -j ${BigInt('0x' + headerRegion.start)} -N 4 /proc/${pid}/mem 2>/dev/null`)
  .trim().toLowerCase().replace(/\s+/g, ' ');
if (elfHex !== '7f 45 4c 46')
  fail(`the memfd image at ${headerRegion.start} is not an ELF (read back: ${elfHex || 'unreadable'})`, evidence());

// The agent's own accounting must see its image too (compat_probe counts the mapping by ADDRESS).
const probe = await mcp('compat_probe', {});
const agentExecMappings = Number(probe?.agentExecMappings ?? -1);
if (!(agentExecMappings >= 1))
  fail(`compat_probe reports agentExecMappings=${agentExecMappings} (the agent does not recognise its own image)`, evidence());

console.log(`ok  decision log: scope + inject for ${target} (${launchMode}, line ${linesBefore + 1}+)`);
console.log(`ok  focus at decision time: ${focusLine.replace(/^mCurrentFocus=/, '') || '(unknown)'}`);
console.log(`ok  agent online (fresh, unique): pid=${pid} entry=${session.entry} selfModule=${session.selfModule}`);
console.log(`ok  target maps: 0 libadh_agent / module-dir entries`);
console.log(`ok  agent maps: ${priv.length} private + ${shared.length} shared jit-cache regions, code ${privateExec[0].start}-${privateExec[0].end}, inode ${[...privInodes][0]}`);
console.log(`ok  compat_probe agentExecMappings=${agentExecMappings}`);
console.log('ok  ELF header read back at the offset-0 memfd mapping (7f 45 4c 46)');
console.log('RESULT:PASS');
restore();
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v4.37 zygisk memfd injection" 0 && exit 0 || exit 1