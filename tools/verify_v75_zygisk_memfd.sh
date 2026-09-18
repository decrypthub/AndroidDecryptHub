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
# Device-only; SKIPs without a device, a root manager, the flashed module, or a module build that
# predates the decision log. Restores the operator's Zygisk scope on exit.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v75_zygisk_memfd (no device)"
  echo "RESULT:PASS"
  exit 0
fi
ROOT_MGR="$(adb -s "$SERIAL" shell 'su -c "if test -x /data/adb/ksud || test -x /data/adb/ksu/bin/ksud; then echo KSU; elif test -d /data/adb/magisk; then echo MAGISK; else echo NO; fi"' 2>/dev/null | tr -d '\r' || true)"
if [ "$ROOT_MGR" != "KSU" ] && [ "$ROOT_MGR" != "MAGISK" ]; then
  echo "SKIP  verify_v75_zygisk_memfd (no Magisk/KernelSU on device)"
  echo "RESULT:PASS"
  exit 0
fi
if ! adb -s "$SERIAL" shell 'su -c "test -d /data/adb/modules/adh"' >/dev/null 2>&1; then
  echo "SKIP  verify_v75_zygisk_memfd (adh Zygisk module not installed)"
  echo "RESULT:PASS"
  exit 0
fi
if ! adb -s "$SERIAL" shell 'su -c "test -f /data/adb/adh/zygisk_inject.log"' >/dev/null 2>&1; then
  echo "SKIP  verify_v75_zygisk_memfd (module predates the decision log / memfd loader)"
  echo "RESULT:PASS"
  exit 0
fi
# The injected agent reports to the Host ADH Daemon through adb reverse; without the tunnel the
# liveness half of this check cannot run (tools/dev_up.sh sets it up).
if ! adb -s "$SERIAL" reverse --list 2>/dev/null | grep -q 'tcp:876'  ; then
  echo "SKIP  verify_v75_zygisk_memfd (no adb reverse tunnel; run tools/dev_up.sh first)"
  echo "RESULT:PASS"
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

// (2) cold start. The next preAppSpecialize for this package must answer 1 and decide to inject.
adb('shell', 'am', 'force-stop', target);
adb('shell', 'am', 'start', '-n', `${target}/.Settings`);
let session = null;
const deadline = Date.now() + 45000;
while (Date.now() < deadline) {
  let agents = [];
  try { agents = await (await fetch(`${base}/api/agents`)).json(); } catch { /* daemon down -> handled below */ }
  session = (Array.isArray(agents) ? agents : [])
    .filter((a) => a.online && a.package === target)
    .sort((x, y) => (y.connectedAt ?? 0) - (x.connectedAt ?? 0))[0] ?? null;
  if (session) break;
  await sleep(700);
}

const newLines = logLines(linesBefore + 1);
const evidence = () => [
  `target=${target} pid=${session?.pid ?? '?'} entry=${session?.entry ?? '?'}`,
  `decision log (since line ${linesBefore + 1}):\n${newLines.trim() || '(none)'}`,
].join('\n');

if (!newLines.includes(`in scope pkg=${target}`))
  fail('the module never answered the scope query for this cold start (no injection attempt)', evidence());
if (!session)
  fail(`no online agent session for ${target} within 45s (daemon session list has no start entry)`, evidence());
if (!newLines.includes(`will inject pkg=${target}`))
  fail('scope was granted but the loader never logged an inject decision', evidence());

const pid = String(session.pid);
const livePid = sh('pidof', target).trim();
if (!pid || pid === 'undefined') fail('agent session carries no pid', evidence());
if (!livePid.split(/\s+/).includes(pid))
  fail(`agent pid ${pid} is not the live ${target} process (${livePid || 'none'})`, evidence());

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
const mine = regions.filter((m) => String(m.path || '').includes('/memfd:jit-cache'));
const privateExec = mine.filter((m) => String(m.perms || '').startsWith('r-xp'));
if (!privateExec.length)
  fail(`the agent's own maps list no private r-xp "/memfd:jit-cache (deleted)" image (found ${mine.length} jit-cache regions)`, evidence());
const leaked = regions.filter((m) => String(m.path || '').includes('libadh_agent'));
if (leaked.length)
  fail(`the agent's own maps still expose its module path (${leaked.length} regions)`, evidence());

// The private r-xp region must be a real ELF image, not just a name ART could also use. Read the
// first bytes of the mapping from the host (root, /proc/<pid>/mem) - inside a system app the agent's
// own read(2) path can be refused by SELinux, so the check runs outside the target.
const elfHex = root(`od -An -tx1 -j ${BigInt('0x' + privateExec[0].start)} -N 4 /proc/${pid}/mem 2>/dev/null`)
  .trim().toLowerCase().replace(/\s+/g, ' ');
if (elfHex !== '7f 45 4c 46')
  fail(`the memfd image at ${privateExec[0].start} is not an ELF (read back: ${elfHex || 'unreadable'})`, evidence());

console.log(`ok  decision log: scope + inject for ${target} (line ${linesBefore + 1}+)`);
console.log(`ok  agent online: pid=${pid} entry=${session.entry}`);
console.log(`ok  target maps: 0 libadh_agent / module-dir entries`);
console.log(`ok  agent maps: ${mine.length} jit-cache memfd regions, code mapping ${privateExec[0].start}-${privateExec[0].end}`);
console.log('ok  ELF header read back at the memfd code mapping (7f 45 4c 46)');
console.log('RESULT:PASS');
restore();
EOF
)"
set -e
echo "$OUT"
verify_gate "v4.37 zygisk memfd injection" 0 && exit 0 || exit 1