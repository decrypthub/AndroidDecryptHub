#!/usr/bin/env bash
# v4.0 acceptance: the root Device Daemon surface (protocol v6-v8) through MCP.
#
# Covers what used to be "only after flashing":
#   * phone_app open takes the root path (no OEM cross-app dialog) and verifies the foreground
#   * phone_device status/lock/wake/unlock reflect and drive the real screen state
#   * the daemon's 5s ensure loop repairs the accessibility service after an OEM-style wipe
#
# SKIPs when the resident Device Daemon is older than the module payload (open falls back to the
# accessibility path) so it stays honest on devices that have not been flashed yet.
# Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

STATE="$(adb -s "$SERIAL" get-state 2>/dev/null | tr -d '\r')"
if [ "$STATE" != "device" ]; then
  echo "RESULT:SKIP"
  echo "⏭ v4.0 device daemon SKIP (no device)"
  exit 0
fi

BRIDGE="$(node - "$BASE" <<'EOF'
const base = process.argv[2];
try {
  const r = await (await fetch(`${base}/api/automation/status`)).json();
  console.log(r.bridge?.connected ? 'connected' : 'offline');
} catch { console.log('offline'); }
EOF
)"
if [ "$BRIDGE" != "connected" ]; then
  echo "RESULT:SKIP"
  echo "⏭ v4.0 device daemon SKIP (bridge not connected)"
  exit 0
fi

# Protocol probe: the v6+ path reports via=device-daemon; the old daemon falls back to accessibility.
VIA="$(node - "$BASE" <<'EOF'
const base = process.argv[2];
try {
  const body = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'phone_app', arguments: { action: 'open', package: 'com.adh.sandbox' } } };
  const r = await (await fetch(base + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).json();
  const item = r.result?.content?.find((c) => c.type === 'text');
  const parsed = item ? JSON.parse(item.text) : {};
  console.log(parsed.via ?? 'unknown');
} catch { console.log('unknown'); }
EOF
)"
if [ "$VIA" != "device-daemon" ]; then
  echo "RESULT:SKIP"
  echo "⏭ v4.0 device daemon SKIP (resident daemon still uses the $VIA path — flash the bundle or restart the payload)"
  exit 0
fi

ENABLED_SERVICES="$(adb -s "$SERIAL" shell settings get secure enabled_accessibility_services 2>/dev/null | tr -d '\r')"

OUT="$(node - "$BASE" "$SERIAL" <<'EOF'
const [base, serial] = process.argv.slice(2);
const checks = [];
const { spawnSync } = await import('node:child_process');
const chk = (label, ok, detail = '') => {
  checks.push([label, !!ok]);
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ' — ' + detail : ''}`);
};
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const tool = async (name, args) => {
  const body = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } };
  const r = await (await fetch(base + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).json();
  if (r.result?.isError) throw new Error(r.result.content?.[0]?.text ?? `${name} failed`);
  return JSON.parse(r.result.content.find((item) => item.type === 'text').text);
};

try {
  const started = await tool('phone_device', { action: 'status' });
  chk('device status reports the real screen state', typeof started.interactive === 'boolean' && typeof started.locked === 'boolean', JSON.stringify(started));

  // Right after a reboot ColorOS raises a cross-app confirmation owned by SystemUI, which sits in
  // front and makes the foreground check fail even though the open itself was fine. The operator
  // taps it away; the harness does the same (adb BACK + retry) - and still fails if that did not
  // help, so a real regression cannot hide behind it.
  let opened = await tool('phone_app', { action: 'open', package: 'com.adh.sandbox' });
  for (let attempt = 0; attempt < 3 && (opened.verified !== true || opened.foreground !== 'com.adh.sandbox'); attempt++) {
    const focus = String(spawnSync('adb', ['-s', serial, 'shell', 'dumpsys window | grep mCurrentFocus'], { encoding: 'utf8' }).stdout ?? '').trim();
    if (!/com\.android\.systemui/.test(focus)) break;   // not the OEM dialog: a real failure
    spawnSync('adb', ['-s', serial, 'shell', 'input', 'keyevent', '4'], { encoding: 'utf8' });
    await sleep(900);
    opened = await tool('phone_app', { action: 'open', package: 'com.adh.sandbox' });
  }
  chk('root open bypasses the OEM dialog and verifies the foreground', opened.via === 'device-daemon' && opened.verified === true && opened.foreground === 'com.adh.sandbox', `via=${opened.via} fg=${opened.foreground}`);

  const locked = await tool('phone_device', { action: 'lock' });
  await sleep(1200);
  const afterLock = await tool('phone_device', { action: 'status' });
  chk('lock turns the screen off and locks it', locked.result === 'ok' && afterLock.interactive === false && afterLock.locked === true, `interactive=${afterLock.interactive} locked=${afterLock.locked}`);

  const woke = await tool('phone_device', { action: 'wake' });
  const unlocked = await tool('phone_device', { action: 'unlock' });
  await sleep(1200);
  const afterUnlock = await tool('phone_device', { action: 'status' });
  chk('wake + unlock restore an interactive, unlocked screen', woke.interactive === true && unlocked.dismissed === true && afterUnlock.locked === false, `woke=${woke.interactive} dismissed=${unlocked.dismissed} locked=${afterUnlock.locked}`);

  if (started.locked && !started.interactive) {
    await tool('phone_device', { action: 'lock' }).catch(() => {});
  }
} catch (error) {
  chk('device daemon acceptance path completed', false, error.message || String(error));
}
console.log(checks.every(([, ok]) => ok) ? 'RESULT:PASS' : 'RESULT:FAIL');
process.exit(checks.every(([, ok]) => ok) ? 0 : 1);
EOF
)"
echo "$OUT"

# Self-heal: wipe the service the way the OEM does and let the daemon's 5s loop repair it.
if grep -q 'RESULT:PASS' <<<"$OUT" && [ -n "$ENABLED_SERVICES" ]; then
  echo ">> wiping the accessibility service to test the daemon's ensure loop"
  adb -s "$SERIAL" shell "su -c 'settings put secure enabled_accessibility_services \"\"'" >/dev/null 2>&1
  adb -s "$SERIAL" shell "su -c 'settings put secure accessibility_enabled 0'" >/dev/null 2>&1
  RESTORED=""
  for _ in $(seq 1 20); do
    sleep 1
    NOW="$(adb -s "$SERIAL" shell settings get secure enabled_accessibility_services 2>/dev/null | tr -d '\r')"
    if [[ "$NOW" == *"AdhAutomationAccessibilityService"* ]]; then RESTORED=1; break; fi
  done
  if [ -n "$RESTORED" ]; then
    echo "PASS  the daemon's ensure loop restores the accessibility service after an OEM-style wipe"
  else
    echo "FAIL  the ensure loop did not restore the service within 20s"
    OUT="RESULT:FAIL"
  fi
fi

if grep -q 'RESULT:PASS' <<<"$OUT"; then
  echo "✅ v4.0 device daemon PASS"
  exit 0
else
  echo "❌ v4.0 device daemon FAIL"
  exit 1
fi
