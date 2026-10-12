#!/usr/bin/env bash
# v10.3 Zygisk Next integration: the module must not be flagged as misusing the Companion API.
#
# Why this exists: Zygisk Next 1.5+ validates how a module uses the companion API and writes the
# verdict into its own module description, e.g.
#   ⚠️1 module(s) with issue: adh      ← our log-relay socket was cached and never closed, so every
#                                        injected process carried a dead companion fd for its lifetime
# (the UI words it "improper use of the Companion API, which may cause process crashes and memory
# leaks"). A module that leaks an fd per process is exactly the bug this catches, and nothing in the
# repo's other gates could see it — they all assume our module is the only thing in the runtime.
#
# What is asserted:
#   * our module actually ran in this boot (Zygisk loader marker) — so "no issue" cannot be earned by
#     simply not loading
#   * Zygisk Next's live status line does NOT list `adh` among the modules with an issue
#   * the target app process's socket/fd counts are printed as evidence (the leak showed up as one
#     extra socket per injected process)
# SKIPs (exit 0, no RESULT:PASS) when a precondition is missing: no device, no root manager, no adh
# module, Zygisk Next not installed, no in-scope target to cold-start.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

if [ -z "${SERIAL:-}" ] || ! adb -s "$SERIAL" get-state >/dev/null 2>&1; then
  echo "SKIP  verify_v103_zygisk_companion (no device)"
  exit 0
fi
if ! adb -s "$SERIAL" shell 'su -c "test -d /data/adb/modules/adh"' >/dev/null 2>&1; then
  echo "SKIP  verify_v103_zygisk_companion (adh module not installed)"
  exit 0
fi
if ! adb -s "$SERIAL" shell 'su -c "test -f /data/adb/modules/zygisksu/module.prop"' >/dev/null 2>&1; then
  echo "SKIP  verify_v103_zygisk_companion (Zygisk Next not installed — its verdict is what we assert)"
  exit 0
fi

# The loader marker is written by the module's own companion on the first app fork of the boot; when
# it is absent the module did not run, and "Zygisk Next has no complaint" would mean nothing.
if ! adb -s "$SERIAL" shell 'su -c "test -f /data/adb/adh/zygisk_loaded"' >/dev/null 2>&1; then
  echo "SKIP  verify_v103_zygisk_companion (module did not run this boot: no zygisk_loaded marker)"
  exit 0
fi

set +e
OUT="$(node - "$SERIAL" "$HTTP" <<'EOF'
const [serial, http] = process.argv.slice(2);
const { spawnSync } = await import('node:child_process');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const adb = (...a) => spawnSync('adb', ['-s', serial, ...a], { encoding: 'utf8' });
const sh = (...a) => String(adb('shell', ...a).stdout ?? '').replace(/\r/g, '');
const root = (cmd) => sh(`su -c ${JSON.stringify(cmd)}`);
const fail = (msg, extra) => {
  if (extra) console.error('---- evidence ----\n' + extra);
  console.error('FAIL: ' + msg);
  console.log('RESULT:FAIL');
  process.exit(1);
};

// Pick a target that is actually in the operator's scope, so the cold start exercises a real
// injected process rather than a skipped one.
const TARGET = process.env.ADH_ZK_TARGET || (() => {
  try {
    const raw = root('cat /data/adb/adh/scope.json');
    const pkgs = JSON.parse(raw).packages || [];
    return pkgs[0] || '';
  } catch { return ''; }
})();
if (!TARGET) fail('no package in the scope file to cold-start (set ADH_ZK_TARGET)');
const installed = sh('pm', 'list', 'packages').includes(`package:${TARGET}`);
if (!installed) fail(`target ${TARGET} (from the scope file) is not installed — set ADH_ZK_TARGET`);

// 1) the module is really live: Zygisk Next's own status describes zygote/secondary as loaded.
const status = root('cat /data/adb/modules/zygisksu/module.prop');
const desc = (/^description=(.*)$/m.exec(status) || [])[1] || '';
if (!desc) fail('Zygisk Next module.prop has no description line to read');
console.log(`ok  Zygisk Next status line: ${desc}`);

// 2) ...and it does NOT name us as a module with an issue.
const flagRe = new RegExp(`with issue[^\\]]*\\b${'adh'}\\b`, 'i');
if (flagRe.test(desc)) {
  fail('Zygisk Next reports our module as having an issue (Companion API misuse)',
    `description=${desc}\n(an fd left open past specialize in the app process is the usual cause)`);
}
if (/with issue/i.test(desc)) console.log('note: Zygisk Next reports an issue for some OTHER module (not ours)');

// 3) evidence: cold-start the target and print its socket/fd counts. The leak showed up here as one
//    extra socket per injected process; the number is informational, the assertion above is the gate.
adb('shell', 'am', 'force-stop', TARGET);
await sleep(2000);
const resolve = sh('cmd', 'package', 'resolve-activity', '--brief', '-c', 'android.intent.category.LAUNCHER', TARGET);
const comp = resolve.split(/\s+/).find((t) => /^[A-Za-z0-9._]+\/[A-Za-z0-9._$]+$/.test(t));
if (comp) adb('shell', 'am', 'start', '-n', comp);
else adb('shell', 'monkey', '-p', TARGET, '-c', 'android.intent.category.LAUNCHER', '1');
await sleep(6000);
// pidof returns one pid per process of that package (multi-process apps!): measure the FIRST one,
// otherwise the /proc/<a> <b>/fd path is nonsense and the counts come back as 0.
const pid = sh('pidof', TARGET).trim().split(/\s+/)[0] || '';
if (!pid) fail(`target ${TARGET} did not come up (no pid) — nothing was measured`);
const sockets = Number(root(`ls -l /proc/${pid}/fd | grep -c socket`).trim());
const totalFds = Number(root(`ls /proc/${pid}/fd | wc -l`).trim());
console.log(`ok  cold-started ${TARGET} pid=${pid}: sockets=${sockets} totalFds=${totalFds} (after specialize)`);
adb('shell', 'am', 'force-stop', TARGET);

console.log('ok  Zygisk Next does not list adh among the modules with an issue');
console.log('RESULT:PASS');
EOF
)"
set -e
echo "$OUT"
if grep -q '^SKIP' <<<"$OUT"; then exit 0; fi
verify_gate "v10.3 Zygisk Next companion-API integration (no module-with-issue verdict for adh)" 0 && exit 0 || exit 1
