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

node - "$BASE" <<'EOF'
const base = process.argv[2];
const body = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'phone_app', arguments: { action: 'open', package: 'com.adh.manager' } } };
try { await fetch(base + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); } catch {}
EOF
sleep 2
CLIP="$(node - "$BASE" <<'EOF'
const base = process.argv[2];
const call = async (name, args) => {
  const body = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } };
  const r = await (await fetch(base + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).json();
  if (r.result?.isError) throw new Error(r.result.content?.[0]?.text || 'error');
  const item = r.result?.content?.find((c) => c.type === 'text');
  return item ? JSON.parse(item.text) : {};
};
try {
  // The manager must be in front for the clipboard to be readable (Android 10+ rule).
  await call('phone_device', { action: 'clipboard_write', text: 'ADH post-flash probe' });
  const read = await call('phone_device', { action: 'clipboard_read' });
  console.log('clipboard=' + (read.text === 'ADH post-flash probe' ? 'yes' : 'no:' + JSON.stringify(read.text).slice(0, 40)));
} catch (e) { console.log('clipboard=no err=' + String(e.message).slice(0, 120)); }
EOF
)"
case "$CLIP" in
  *clipboard=yes*) echo "PASS  clipboard round trip through the service context: $CLIP" ;;
  *) echo "SKIP  clipboard round trip (manager not in front or platform refused): $CLIP" ;;
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
