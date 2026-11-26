#!/usr/bin/env bash
# App control (open / stop / restart) prefers the device domain and falls back to adb explicitly.
# Acceptance: the process really changes, the result names the channel that ran, and a forged
# expected set is refused by the device itself - the process-identity fence must not be the Host's.
# Uses our own demo package; never the observation target and never a third-party app.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env
verify_unit_pass 'app control channel' app_launch_channel.test.ts 12 || exit 1
cd "$ROOT"
if ! node --input-type=module - "$ROOT" "$SERIAL" <<'EOF'
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
const [repo, serial] = process.argv.slice(2);
const skip = reason => { console.log(`SKIP verify_v134_app_control_device (${reason})`); process.exit(0); };
const pkg = process.env.ADH_APP_CONTROL_PKG || 'com.adh.sandbox.apilab';
if (!serial) skip('no device attached');
const adb = args => {
  const r = spawnSync('adb', ['-s', serial, ...args], { encoding: 'utf8', timeout: 20000, windowsHide: true });
  return { ok: !r.error && r.status === 0, out: String(r.stdout ?? '').trim(), err: String(r.error ?? r.stderr ?? '') };
};
if (adb(['shell', 'su', '-c', 'id -u']).out !== '0') skip('rooted verification device required');
if (!adb(['shell', 'pm', 'path', pkg]).out.startsWith('package:')) skip(`${pkg} is not installed on this device`);
if (!adb(['shell', 'cmd', 'package', 'resolve-activity', '--brief', '-c', 'android.intent.category.LAUNCHER', pkg]).out.includes('/')) {
  skip(`${pkg} has no launcher activity; set ADH_APP_CONTROL_PKG to a launchable demo`);
}
process.env.ANDROID_SERIAL = serial;
const load = name => import(pathToFileURL(`${repo}/daemon/src/${name}`).href);
const { startPackage, stopPackage, coldStartPackage, runningPid } = await load('app_launch.ts');
const { deviceProcessControl, deviceProcesses, deviceState } = await load('device_bridge.ts');
const sleep = ms => new Promise(r => setTimeout(r, ms));

const stopped = await stopPackage(pkg);
if (stopped.via === 'adb') skip('device daemon predates process.control; reflash the module to exercise this path');
assert.equal(stopped.ok, true, JSON.stringify(stopped));
assert.equal(stopped.via, 'device');
assert.equal(stopped.mode, 'device:stop');

const opened = await startPackage(pkg);
assert.equal(opened.via, 'device', JSON.stringify(opened));
assert.equal(opened.ok, true, JSON.stringify(opened));
await sleep(2000);
const first = await runningPid(pkg);
assert.ok(first > 0, 'the package must own a process after open');

const restarted = await coldStartPackage(pkg);
assert.equal(restarted.via, 'device', JSON.stringify(restarted));
assert.equal(restarted.ok, true, JSON.stringify(restarted));
await sleep(2500);
const second = await runningPid(pkg);
assert.ok(second > 0 && second !== first, `restart must replace the process (${first} -> ${second})`);

const cleared = await stopPackage(pkg);
assert.equal(cleared.via, 'device', JSON.stringify(cleared));
await sleep(800);
assert.equal(await runningPid(pkg), 0, 'stop must leave no process');

// The fence lives on the phone: an empty expected set cannot match a running package.
await startPackage(pkg);
await sleep(1500);
const snapshot = await deviceProcesses(serial, pkg);
const state = await deviceState(serial);
const fence = await deviceProcessControl(serial, pkg, 'stop', [], Number(state?.stateRevision)).then(
  () => ({ refused: false }), error => ({ refused: true, code: error?.code }));
assert.equal(fence.refused, true, 'the device must refuse a forged expected set');
assert.match(String(fence.code), /TARGET_CHANGED|IDENTITY_UNVERIFIED/);
await stopPackage(pkg);

console.log(`PASS verify_v134_app_control_device (${pkg}: stop/open/restart via device domain, pid ${first}->${second}, rows=${snapshot?.rows?.length ?? '?'}, fence=${fence.code})`);
EOF
then
  exit 1
fi
