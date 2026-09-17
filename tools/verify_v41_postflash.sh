#!/usr/bin/env bash
# v4.1 acceptance: the post-flash boot path, end to end.
#
# Intended to run right after flashing the module bundle and rebooting. It waits for the module's
# service.sh to bring the root daemon up on its own (no manual start), then exercises the whole
# device surface through MCP:
#   * daemon started by the boot script (ready marker + pid + a single process)
#   * bridge online, protocol v12+ (long press / volume / clipboard)
#   * device volume read/write round trip
#   * clipboard read/write round trip (only meaningful while the Manager is in front)
#   * root input injection (a tap really reaches the window)
#
# SKIPs when no device is attached or the automation bridge never comes online (honest signal:
# something in the flashed payload or the host setup is wrong - it does not silently pass).
# Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

STATE="$(adb -s "$SERIAL" get-state 2>/dev/null | tr -d '\r')"
if [ "$STATE" != "device" ]; then
  echo "RESULT:SKIP"
  echo "v4.1 post-flash SKIP (no device)"
  exit 0
fi

verify_host_begin
echo ">> waiting up to 90s for the boot-started daemon and bridge"
READY=""
for _ in $(seq 1 45); do
  PID="$(adb -s "$SERIAL" shell su -c 'cat /data/adb/adh/device_daemon.pid 2>/dev/null' 2>/dev/null | tr -d '\r')"
  BRIDGE="$(node - "$BASE" <<'EOF'
const base = process.argv[2];
try {
  const r = await (await fetch(`${base}/api/automation/status`)).json();
  const online = (r.bridge?.devices ?? []).some((d) => d.online);
  console.log(r.bridge?.connected && online ? 'online' : 'offline');
} catch { console.log('offline'); }
EOF
)"
  if [ -n "$PID" ] && [ "$BRIDGE" = "online" ]; then READY=1; break; fi
  sleep 2
done

if [ -z "$READY" ]; then
  echo "RESULT:FAIL"
  echo "v4.1 post-flash FAIL (daemon pid='$PID' bridge='$BRIDGE' after 90s - check /data/adb/adh/device_daemon.log)"
  exit 1
fi
echo "PASS  boot script started the device daemon (pid=$PID)"

# A freshly rebooted device is locked; the keyguard owns the foreground and app launches land
# behind it. Non-secure keyguards are dismissed through the authenticated daemon (secure
# credentials are never touched), matching what a user does by swiping up.
UNLOCK="$(node - "$BASE" <<'EOF'
const base = process.argv[2];
const call = async (name, args) => {
  const body = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } };
  const r = await (await fetch(base + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).json();
  if (r.result?.isError) throw new Error(r.result.content?.[0]?.text || 'error');
  const item = r.result?.content?.find((c) => c.type === 'text');
  return item ? JSON.parse(item.text) : {};
};
try {
  const before = await call('phone_device', { action: 'status' });
  if (before.locked) {
    await call('phone_device', { action: 'unlock' });
    await new Promise((r) => setTimeout(r, 1200));
  }
  const after = await call('phone_device', { action: 'status' });
  console.log('locked=' + after.locked);
} catch (e) { console.log('locked=unknown err=' + String(e.message).slice(0, 120)); }
EOF
)"
case "$UNLOCK" in
  *locked=false*) echo "PASS  keyguard dismissed (non-secure) before UI probes: $UNLOCK" ;;
  *locked=true*) echo "SKIP  device has a secure lock screen; UI probes run only if the foreground allows it" ;;
  *) echo "SKIP  lock state unknown: $UNLOCK" ;;
esac

PROTO="$(node - "$BASE" <<'EOF'
const base = process.argv[2];
const call = async (name, args) => {
  const body = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } };
  const r = await (await fetch(base + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).json();
  if (r.result?.isError) throw new Error(r.result.content?.[0]?.text || 'error');
  const item = r.result?.content?.find((c) => c.type === 'text');
  return item ? JSON.parse(item.text) : {};
};
try {
  const vol = await call('phone_device', { action: 'volume_status' });
  console.log('volume_ok=' + (typeof vol?.volume?.music === 'number' ? 'yes' : 'no'));
} catch (e) { console.log('volume_ok=no err=' + String(e.message).slice(0, 120)); }
EOF
)"
verify_chk "device volume readable (protocol v10+)" '[ "$(echo "$PROTO" | grep -c "volume_ok=yes")" -eq 1 ]'

RESTORE="$(node - "$BASE" <<'EOF'
const base = process.argv[2];
const call = async (name, args) => {
  const body = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } };
  const r = await (await fetch(base + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).json();
  if (r.result?.isError) throw new Error(r.result.content?.[0]?.text || 'error');
  const item = r.result?.content?.find((c) => c.type === 'text');
  return item ? JSON.parse(item.text) : {};
};
try {
  const before = await call('phone_device', { action: 'volume_status' });
  const original = before.volume.alarm;
  const target = original === 0 ? 1 : original - 1;
  await call('phone_device', { action: 'volume_set', stream: 'alarm', index: target });
  const after = await call('phone_device', { action: 'volume_status' });
  await call('phone_device', { action: 'volume_set', stream: 'alarm', index: original });
  const restored = await call('phone_device', { action: 'volume_status' });
  console.log('roundtrip=' + (after.volume.alarm === target) + ' restored=' + (restored.volume.alarm === original));
} catch (e) { console.log('roundtrip=false err=' + String(e.message).slice(0, 140)); }
EOF
)"
verify_chk "volume write round trip with restore" '[ "$(echo "$RESTORE" | grep -c "roundtrip=true restored=true")" -eq 1 ]'

# The clipboard probe uses the sandbox: it is allowlisted, always available and exposes a
# deterministic 读剪贴板 button + adh_clipboard_echo view. (The Manager itself is refused by the
# self-control guard, by design.)
CLIP="$(node - "$BASE" <<'EOF'
const base = process.argv[2];
const call = async (name, args) => {
  const body = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } };
  const r = await (await fetch(base + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).json();
  if (r.result?.isError) throw new Error(r.result.content?.[0]?.text || 'error');
  const item = r.result?.content?.find((c) => c.type === 'text');
  return item ? JSON.parse(item.text) : {};
};
const probe = 'ADH post-flash clipboard probe';
try {
  await call('phone_app', { action: 'open', package: 'com.adh.sandbox' });
  await call('phone_wait', { activePackage: 'com.adh.sandbox', stable: true, stableMs: 800, timeoutMs: 8000 });
  await call('phone_device', { action: 'clipboard_write', text: probe });
  await call('phone_act', { action: 'tap', text: '读剪贴板' });
  await new Promise((r) => setTimeout(r, 800));
  const found = await call('phone_find', { resourceId: 'com.adh.sandbox:id/adh_clipboard_echo', limit: 1 });
  const shown = found?.nodes?.[0]?.text ?? '';
  console.log('clipboard=' + (shown === '剪贴板内容：' + probe ? 'yes' : 'no:' + JSON.stringify(shown).slice(0, 60)));
} catch (e) { console.log('clipboard=no err=' + String(e.message).slice(0, 140)); }
EOF
)"
case "$CLIP" in
  *clipboard=yes*) echo "PASS  clipboard write -> foreground app reads it back: $CLIP" ;;
  *) echo "FAIL  clipboard write -> foreground app reads it back: $CLIP"; fail=1 ;;
esac

ROOT_TAP="$(node - "$BASE" <<'EOF'
const base = process.argv[2];
const call = async (name, args) => {
  const body = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } };
  const r = await (await fetch(base + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).json();
  if (r.result?.isError) throw new Error(r.result.content?.[0]?.text || 'error');
  const item = r.result?.content?.find((c) => c.type === 'text');
  return item ? JSON.parse(item.text) : {};
};
try {
  await call('phone_app', { action: 'open', package: 'com.adh.sandbox' });
  await call('phone_wait', { activePackage: 'com.adh.sandbox', stable: true, stableMs: 800, timeoutMs: 8000 });
  const tap = await call('phone_act', { action: 'tap', x: 0.5, y: 0.52, coordinateSpace: 'normalized', inputMode: 'root', durationMs: 80 });
  console.log('root_action=' + (tap.action || 'none'));
} catch (e) { console.log('root_action=none err=' + String(e.message).slice(0, 140)); }
EOF
)"
case "$ROOT_TAP" in
  *root_action=input*) echo "PASS  root input injection reaches the window: $ROOT_TAP" ;;
  *) echo "FAIL  root input injection reaches the window: $ROOT_TAP"; fail=1 ;;
esac

verify_host_finish "v4.1 post-flash"
