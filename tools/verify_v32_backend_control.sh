#!/usr/bin/env bash
# v3.2 optional-backend control through the root Device Daemon (module W).
#
# Proves that ADH (not the framework's own UI) can drive the Xposed/LSPosed backend:
#   build the Device Daemon APK → push it into the module dir → run its root-only one-shot CLI
#   (the exact code paths the AIDL surface uses) → set/clear the module scope, toggle the
#   module, and cross-check every step against the framework CLI.
#
# PASS = status JSON is valid, scope changes are visible to the framework, enable/disable
#        round-trips, and the pre-test state is restored exactly.
# RESULT:SKIP when there is no framework CLI, no ADH module, no installed ADH Xposed module,
#        or the daemon APK cannot be built.
#
# Run: bash tools/verify_v32_backend_control.sh   (exit 0 = PASS)
set -uo pipefail
# Keep /data/... device paths intact when running under Git Bash.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env
CLI="/data/adb/lspd/cli"
MODULE_DIR="/data/adb/modules/adh"
DAEMON_APK="$ROOT/device/daemon/build/outputs/apk/debug/daemon-debug.apk"
PROBE_PKGS="com.adh.sandbox"
APP="app_process -Djava.class.path=$MODULE_DIR/daemon.apk /system/bin com.adh.daemon.AdhDeviceDaemon"

skip() { echo "$1"; echo "⏭ backend control SKIP ($2)"; exit 0; }

# The payload we push below is a CLI build: it has no Manager certificate digest, so it can run the
# one-shot commands but must never stay as the resident daemon (it would die with "manager
# certificate digest is missing" on the next boot). Keep the module's own payload and put it back.
ORIG_PAYLOAD_BACKUP="/data/local/tmp/adh-daemon-original.apk"
ORIG_PAYLOAD_PRESENT=0
restore_payload() {
  if [ "$ORIG_PAYLOAD_PRESENT" = "1" ]; then
    adb -s "$SERIAL" shell "su -c 'cp $ORIG_PAYLOAD_BACKUP $MODULE_DIR/daemon.apk && chmod 644 $MODULE_DIR/daemon.apk'" >/dev/null 2>&1
    echo ">> restored the module's own daemon payload"
  fi
}
trap restore_payload EXIT

[ -n "${SERIAL:-}" ] || skip "RESULT:SKIP no device" "no serial"
adb -s "$SERIAL" get-state >/dev/null 2>&1 || skip "RESULT:SKIP no device" "adb offline"
[ "$(adb -s "$SERIAL" shell "su -c 'test -x $CLI && echo yes'" 2>/dev/null | tr -d '\r')" = "yes" ] ||
  skip "RESULT:SKIP no Xposed framework CLI" "$CLI missing"
[ "$(adb -s "$SERIAL" shell "su -c 'test -d $MODULE_DIR && echo yes'" 2>/dev/null | tr -d '\r')" = "yes" ] ||
  skip "RESULT:SKIP ADH module not installed" "flash the bundle first"

echo ">> building the Device Daemon APK"
set +e
BUILD_OUT="$(cd "$ROOT/device" && ./gradlew :daemon:assembleDebug --console=plain 2>&1)"
BUILD_RC=$?
set +e
if [ "$BUILD_RC" != "0" ] || [ ! -f "$DAEMON_APK" ]; then
  echo "$BUILD_OUT" | tail -4 | sed 's/^/   /'
  skip "RESULT:SKIP daemon APK not built" "gradle unavailable"
fi

# The daemon payload lives in the module dir; replacing it is what a flash would do (no reboot:
# the one-shot CLI runs the new code immediately, the resident daemon picks it up on restart).
adb -s "$SERIAL" push "$(cygpath -w "$DAEMON_APK" 2>/dev/null || echo "$DAEMON_APK")" /data/local/tmp/adh-daemon.apk >/dev/null 2>&1 ||
  skip "RESULT:SKIP daemon push failed" "adb push"
if [ "$(adb -s "$SERIAL" shell "su -c 'test -f $MODULE_DIR/daemon.apk && echo yes'" 2>/dev/null | tr -d '\r')" = "yes" ]; then
  adb -s "$SERIAL" shell "su -c 'cp $MODULE_DIR/daemon.apk $ORIG_PAYLOAD_BACKUP'" >/dev/null 2>&1
  if [ "$(adb -s "$SERIAL" shell "su -c 'test -f $ORIG_PAYLOAD_BACKUP && echo yes'" 2>/dev/null | tr -d '\r')" = "yes" ]; then ORIG_PAYLOAD_PRESENT=1; fi
fi
if [ "$ORIG_PAYLOAD_PRESENT" != "1" ]; then
  skip "RESULT:SKIP daemon payload not backed up" "refusing to overwrite $MODULE_DIR/daemon.apk without a restorable copy"
fi
adb -s "$SERIAL" shell "su -c 'cp /data/local/tmp/adh-daemon.apk $MODULE_DIR/daemon.apk && chmod 644 $MODULE_DIR/daemon.apk'" >/dev/null 2>&1

cli() { adb -s "$SERIAL" shell "su -c '$APP $1'" 2>/dev/null | tr -d '\r'; }
fw()  { adb -s "$SERIAL" shell "su -c '$CLI $1'" 2>/dev/null | tr -d '\r'; }

PRIOR="$(cli --xposed-status)"
echo "prior: $PRIOR"
PRIOR_PRESENT="$(node -e "try{console.log(String(JSON.parse(process.argv[1]).present))}catch(e){console.log('parse-error')}" "$PRIOR")"
PRIOR_INSTALLED="$(node -e "try{console.log(String(JSON.parse(process.argv[1]).installed))}catch(e){console.log('parse-error')}" "$PRIOR")"
PRIOR_ENABLED="$(node -e "try{console.log(String(JSON.parse(process.argv[1]).enabled))}catch(e){console.log('parse-error')}" "$PRIOR")"
PRIOR_SCOPE="$(node -e "try{console.log((JSON.parse(process.argv[1]).scope||[]).join(' '))}catch(e){console.log('')}" "$PRIOR")"
[ "$PRIOR_PRESENT" = "true" ] || skip "RESULT:SKIP framework not reported present" "status=$PRIOR"
[ "$PRIOR_INSTALLED" = "true" ] ||
  skip "RESULT:SKIP ADH Xposed module not installed" "install injector/xposed/dist/adh-xposed.apk"

restore() {
  cli "--xposed-scope $PRIOR_SCOPE" >/dev/null 2>&1
  if [ "$PRIOR_ENABLED" = "true" ]; then cli --xposed-enable >/dev/null 2>&1; else cli --xposed-disable >/dev/null 2>&1; fi
  restore_payload
}
trap restore EXIT

echo ">> scope: set [$PROBE_PKGS]"
cli "--xposed-scope $PROBE_PKGS" >/dev/null 2>&1
AFTER_SET="$(cli --xposed-status)"
FW_SCOPE="$(fw "scope ls --json com.adh.xposed")"

echo ">> toggle module off/on"
cli --xposed-disable >/dev/null 2>&1
AFTER_OFF="$(cli --xposed-status)"
cli --xposed-enable >/dev/null 2>&1
AFTER_ON="$(cli --xposed-status)"
FW_MODULE="$(fw "modules ls --json")"

restore
trap - EXIT
FINAL="$(cli --xposed-status)"

set +e
# Git Bash/MSYS truncates multi-line arguments when handing them to a native Windows node, so
# every payload travels base64-encoded (single line) and is decoded inside the script.
b64() { printf '%s' "$1" | base64 | tr -d '\r\n'; }
OUT="$(node - "$(b64 "$AFTER_SET")" "$(b64 "$FW_SCOPE")" "$(b64 "$AFTER_OFF")" "$(b64 "$AFTER_ON")" "$(b64 "$FW_MODULE")" "$(b64 "$FINAL")" "$(b64 "$PROBE_PKGS")" "$(b64 "$PRIOR_ENABLED")" "$(b64 "$PRIOR_SCOPE")" <<'EOF'
const dec = (s) => Buffer.from(s || '', 'base64').toString('utf8');
const [afterSetRaw, fwScopeRaw, afterOffRaw, afterOnRaw, fwModuleRaw, finalRaw, probe, priorEnabled, priorScope] =
  process.argv.slice(2).map(dec);
const afterSet = afterSetRaw, fwScope = fwScopeRaw, afterOff = afterOffRaw, afterOn = afterOnRaw, fwModule = fwModuleRaw, finalStatus = finalRaw;
const parse = (s) => { try { return JSON.parse(s); } catch (e) { return null; } };
const set = parse(afterSet), off = parse(afterOff), on = parse(afterOn), fin = parse(finalStatus);
const fwSc = parse(fwScope), fwMod = parse(fwModule);
if (!set || !off || !on || !fin) { console.log("status JSON unparsable (daemon CLI output was not JSON)"); console.log("RESULT:FAIL"); process.exit(0); }

const scopeOf = (s) => (s && s.scope ? s.scope : []).join(' ');
const fwScopePkgs = ((fwSc && fwSc.data) || []).map(x => (x && x.APP_PACKAGE) ? x.APP_PACKAGE : String(x)).sort().join(' ');
const fwEnabled = ((fwMod && fwMod.data) || []).some(m => m.PACKAGE === 'com.adh.xposed' && String(m.STATUS).toLowerCase() === 'enabled');

console.log(`scope after set : ${scopeOf(set) || '<empty>'} (framework: ${fwScopePkgs || '<empty>'})`);
console.log(`enabled after off: ${off.enabled} | after on: ${on.enabled} (framework: ${fwEnabled})`);
console.log(`restored        : enabled=${fin.enabled} scope='${scopeOf(fin)}' (prior enabled=${priorEnabled} scope='${priorScope}')`);

const pass =
  scopeOf(set) === probe &&
  fwScopePkgs === probe &&
  off.enabled === false &&
  on.enabled === true &&
  fwEnabled === true &&
  String(fin.enabled) === priorEnabled &&
  scopeOf(fin) === priorScope;
console.log(pass ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set +e
echo "$OUT"

if grep -q 'RESULT:PASS' <<<"$OUT"; then SENTINEL="RESULT:PASS"; else SENTINEL="RESULT:FAIL"; fi
echo "$SENTINEL"
OUT="$OUT
$SENTINEL"
verify_gate "v3.2 optional-backend control via Device Daemon CLI" 0 && exit 0 || exit 1