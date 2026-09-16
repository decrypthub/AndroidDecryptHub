#!/usr/bin/env bash
# v3.9 acceptance: reading notifications through the opt-in NotificationListenerService.
#
# Android 15 strips notification bodies out of accessibility events (verified on-device), so titles
# and text can only come from a listener the user grants via "notification access". This script
# BORROWS that grant for the duration of the run and revokes it again afterwards, so the phone ends
# up exactly as it started — the product itself still requires the user's own tap in ADH Manager.
#
# SKIPs when there is no device, no bridge, or when the shell lacks the pieces to post a
# notification. Exit 0 = PASS.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

STATE="$(adb -s "$SERIAL" get-state 2>/dev/null | tr -d '\r')"
if [ "$STATE" != "device" ]; then
  echo "RESULT:SKIP"
  echo "⏭ v3.9 notifications SKIP (no device)"
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
  echo "⏭ v3.9 notifications SKIP (bridge not connected)"
  exit 0
fi

COMPONENT="com.adh.manager/com.adh.manager.notify.AdhNotificationListener"
BEFORE_LISTENERS="$(adb -s "$SERIAL" shell settings get secure enabled_notification_listeners 2>/dev/null | tr -d '\r')"
BORROWED=0
if [[ "$BEFORE_LISTENERS" != *"AdhNotificationListener"* ]]; then
  BORROWED=1
fi

restore() {
  if [ "$BORROWED" = "1" ]; then
    adb -s "$SERIAL" shell "su -c 'cmd notification disallow_listener $COMPONENT'" >/dev/null 2>&1
    adb -s "$SERIAL" shell "su -c \"settings put secure enabled_notification_listeners $BEFORE_LISTENERS\"" >/dev/null 2>&1
    echo ">> released the borrowed notification-access grant"
  fi
}
trap restore EXIT

if [ "$BORROWED" = "1" ]; then
  echo ">> borrowing notification access for this run (will be released at the end)"
  adb -s "$SERIAL" shell "su -c 'cmd notification allow_listener $COMPONENT'" >/dev/null 2>&1
fi
sleep 2

MARKER="ADH_NOTIFY_v1_$(date +%s)"
adb -s "$SERIAL" shell cmd notification post -S bigtext -t "ADH_ACCEPTANCE" "adhtest" "$MARKER" >/dev/null 2>&1
sleep 2

OUT="$(node - "$BASE" "$MARKER" "$SERIAL" <<'EOF'
const [base, marker, serial] = process.argv.slice(2);
const checks = [];
const chk = (label, ok, detail = '') => {
  checks.push([label, !!ok]);
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ' — ' + detail : ''}`);
};
const getConfig = async () => (await (await fetch(base + '/api/config')).json()).settings.automation;
const post = async (path, body) => (await (await fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).json());
const tool = async (name, args) => {
  const body = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } };
  const r = await (await fetch(base + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).json();
  if (r.result?.isError) throw new Error(r.result.content?.[0]?.text ?? `${name} failed`);
  return JSON.parse(r.result.content.find((item) => item.type === 'text').text);
};

const before = await getConfig();
try {
  let gate = '';
  try { await tool('phone_notifications', { limit: 5 }); } catch (error) { gate = error.message || String(error); }
  chk('reads stay gated until the operator opts in', /notifications_disabled/.test(gate), gate.slice(0, 80));

  await post('/api/config', { automation: { ...before, enabled: true, notifications: true } });
  const read = await tool('phone_notifications', { limit: 10 });
  chk('the listener is connected and granted on the device', read.granted === true && read.listener?.connected === true, `granted=${read.granted} connected=${read.listener?.connected}`);
  const hit = (read.notifications ?? []).find((entry) => String(entry.text ?? '').includes(marker) || String(entry.title ?? '').includes(marker));
  chk('a freshly posted notification is readable through MCP', !!hit, hit ? `pkg=${hit.package} title=${hit.title}` : `marker=${marker} count=${read.count}`);
  if (hit) {
    const again = await tool('phone_notifications', { limit: 10, sinceMs: hit.ts + 1 });
    chk('sinceMs lets the AI poll incrementally', (again.notifications ?? []).every((entry) => entry.ts >= hit.ts + 1), `count=${again.count}`);
  }

  // The loop an AI actually needs: fire "send code", then block until the notification lands.
  const { execFileSync } = await import('node:child_process');
  const waitMarker = 'ADH_OTP_' + Date.now().toString().slice(-6);
  const waiting = tool('phone_wait', { notificationContains: waitMarker, timeoutMs: 15_000, intervalMs: 400 });
  await new Promise((resolve) => setTimeout(resolve, 1500));
  execFileSync('adb', ['-s', serial, 'shell', 'cmd', 'notification', 'post', '-S', 'bigtext', '-t', 'ADH_OTP', 'adhotp', waitMarker], { stdio: 'ignore' });
  const waited = await waiting;
  chk('phone_wait blocks on an incoming notification and returns it', waited.matched === true && waited.kind === 'notification' && String(waited.item?.text ?? '').includes(waitMarker), `elapsed=${waited.elapsedMs} text=${waited.item?.text}`);

  // Composition: one task waits for the code, then types that exact text via {{...}} and submits.
  const taskMarker = 'ADH_OTP_task_' + Date.now().toString().slice(-6);
  const taskPromise = tool('phone_task', { steps: [
    { type: 'app', args: { action: 'restart', package: 'com.adh.sandbox' } },
    { type: 'wait', args: { activePackage: 'com.adh.sandbox', timeoutMs: 10_000, intervalMs: 300, maxNodes: 120 } },
    { id: 'code', type: 'wait', args: { notificationContains: taskMarker, timeoutMs: 20_000, intervalMs: 400, lookbackMs: 30_000 } },
    { type: 'act', args: { action: 'set_text', resourceId: 'com.adh.sandbox:id/adh_input_probe', text: '{{code.item.text}}', submit: true, maxNodes: 150 } },
  ] });
  await new Promise((resolve) => setTimeout(resolve, 1500));
  execFileSync('adb', ['-s', serial, 'shell', 'cmd', 'notification', 'post', '-S', 'bigtext', '-t', 'ADH_OTP', 'adhotp', taskMarker], { stdio: 'ignore' });
  const task = await taskPromise;
  const codeStep = task.steps?.find((step) => step.id === 'code');
  const typedStep = task.steps?.find((step) => step.type === 'act');
  chk('a task waits for the code and types that exact text through a template', task.ok === true && String(codeStep?.result?.item?.text ?? '') === taskMarker && typedStep?.result?.submitted === true, `ok=${task.ok} code=${codeStep?.result?.item?.text} submitted=${typedStep?.result?.submitted}`);
  // Wait for the echo label instead of sampling once — the app updates it on the IME action.
  const echo = await tool('phone_wait', { textContains: '提交回显', timeoutMs: 5_000, intervalMs: 250, maxNodes: 150 });
  chk('the app received the typed code', echo.matched === true && String(echo.node?.text ?? '').includes(taskMarker), `node=${echo.node?.text ?? '-'}`);
} catch (error) {
  chk('notification acceptance path completed', false, error.message || String(error));
} finally {
  await post('/api/config', { automation: before });
}
console.log(checks.every(([, ok]) => ok) ? 'RESULT:PASS' : 'RESULT:FAIL');
process.exit(checks.every(([, ok]) => ok) ? 0 : 1);
EOF
)"
echo "$OUT"
if grep -q 'RESULT:PASS' <<<"$OUT"; then
  echo "✅ v3.9 notifications PASS"
  exit 0
else
  echo "❌ v3.9 notifications FAIL"
  exit 1
fi
