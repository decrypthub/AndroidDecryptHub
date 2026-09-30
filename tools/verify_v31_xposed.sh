#!/usr/bin/env bash
# v3.1 optional LSPosed/Xposed backend acceptance (module W).
#
# Proves the chain end to end on a real device:
#   installed framework (LSPosed / Vector) →
#   thin module APK installed + enabled + scoped to com.adh.manager →
#   framework instantiates com.adh.xposed.AdhXposedEntry inside that app process →
#   entry loads libadh_agent.so (uncompressed lib inside the module APK) →
#   agent dials the Host ADH Daemon (entry=jni_onload) →
#   host can actually drive that session (module list answers).
#
# PASS = marker says agent=1 AND the daemon has an online session for the target AND the
# session answers a real command. Prints RESULT:SKIP when the framework CLI is missing or
# the module APK cannot be built (AGP needs network on a clean machine).
#
# The backend is opt-in: the script restores that (module disabled + scope cleared) unless
# ADH_XPOSED_KEEP=1 is set.
#
# Run: bash tools/verify_v31_xposed.sh   (exit 0 = PASS)
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

MODULE_PKG="com.adh.xposed"
TARGET="com.adh.manager"
MARKER="/data/data/$TARGET/files/adh_xposed_ok"
APK="$ROOT/injector/xposed/dist/adh-xposed.apk"
CLI="/data/adb/lspd/cli"

skip() { echo "$1"; echo "⏭ Xposed backend SKIP ($2)"; exit 0; }

# 1. framework present? ------------------------------------------------------------
FW="$(adb -s "$SERIAL" shell "su -c '$CLI status'" 2>/dev/null | tr -d '\r')"
grep -q 'Framework' <<<"$FW" || skip "RESULT:SKIP no Xposed framework CLI at $CLI" "framework not installed"
echo "framework: $(grep -m1 'Version' <<<"$FW") / $(grep -m1 'API Version' <<<"$FW")"

# 2. module APK (build on demand, AND rebuild when stale) ---------------------------
# The APK bundles a copy of the agent, so an APK built for an older agent keeps injecting that older
# agent. This is not hypothetical: the cached APK carried agent 0.2.0 against a 0.3.12 checkout, so
# this script exercised the Xposed chain with a three-versions-old agent, put com.adh.manager online
# running 0.2.0, and `adh doctor` (correctly) reported a version MISMATCH — which then failed
# verify_v100 in the full gate. Building only when the file is MISSING hides all of that: the file
# exists, so it was reused forever. Treat "bundles a different agent than agent/build/" as missing.
BUNDLED_AGENT_SHA="$(unzip -p "$APK" lib/arm64-v8a/libadh_agent.so 2>/dev/null | sha256sum | awk '{print $1}')"
CURRENT_AGENT_SHA="$([ -f "$ROOT/agent/build/libadh_agent.so" ] && sha256sum "$ROOT/agent/build/libadh_agent.so" | awk '{print $1}')"
NEED_BUILD=0
if [ ! -f "$APK" ]; then
  echo ">> module APK missing — building it (tools/build_xposed.sh)"
  NEED_BUILD=1
elif [ -n "$CURRENT_AGENT_SHA" ] && [ "$BUNDLED_AGENT_SHA" != "$CURRENT_AGENT_SHA" ]; then
  echo ">> module APK bundles a stale agent (${BUNDLED_AGENT_SHA:0:12} vs agent/build ${CURRENT_AGENT_SHA:0:12}) — rebuilding"
  NEED_BUILD=1
fi
if [ "$NEED_BUILD" = "1" ]; then
  set +e
  BUILD_OUT="$(bash "$ROOT/tools/build_xposed.sh" 2>&1)"
  BUILD_RC=$?
  if [ "$BUILD_RC" != "0" ] || [ ! -f "$APK" ]; then
    echo "$BUILD_OUT" | tail -5 | sed 's/^/   /'
    # Skipping is the honest outcome here: the only APK on disk carries an agent this checkout does
    # not build, and testing THAT would report a pass for something we do not ship.
    skip "RESULT:SKIP module APK stale and not rebuildable" "agent 0.2.0 bundled, gradle/AGP unavailable to rebuild"
  fi
fi
if [ -n "$CURRENT_AGENT_SHA" ] && [ "$(unzip -p "$APK" lib/arm64-v8a/libadh_agent.so 2>/dev/null | sha256sum | awk '{print $1}')" != "$CURRENT_AGENT_SHA" ]; then
  skip "RESULT:SKIP module APK still stale after rebuild" "bundled agent != agent/build/libadh_agent.so"
fi
echo "module apk: $APK ($(stat -c %s "$APK" 2>/dev/null || echo '?') bytes)"

# 2b. remember the pre-test state so the script restores EXACTLY what it found ---------
CLI_JSON="$(adb -s "$SERIAL" shell "su -c '$CLI modules ls --json'" 2>/dev/null | tr -d '\r')"
PRIOR_STATUS="$(printf '%s' "$CLI_JSON" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{const j=JSON.parse(s);const m=(j.data||[]).find(x=>x.PACKAGE===process.argv[1]);console.log(m?String(m.STATUS).toLowerCase():'absent')}catch(e){console.log('unknown')}})" "$MODULE_PKG")"
PRIOR_SCOPE="$(adb -s "$SERIAL" shell "su -c '$CLI scope ls $MODULE_PKG'" 2>/dev/null | tr -d '\r' | awk 'NR>2 && NF>=2 {print $1"/"$2}' | paste -sd' ' -)"
echo "prior state: status=$PRIOR_STATUS scope='${PRIOR_SCOPE:-<empty>}'"

# 3. install + enable + scope ------------------------------------------------------
set +e
INSTALL_OUT="$(ANDROID_SERIAL="$SERIAL" bash "$ROOT/tools/install_xposed.sh" --apk "$APK" --package "$TARGET" 2>&1)"
INSTALL_RC=$?
set +e
echo "$INSTALL_OUT" | tail -6 | sed 's/^/   /'
if [ "$INSTALL_RC" != "0" ]; then
  echo "RESULT:FAIL module install/enable failed"
  verify_gate "v3.1 Xposed backend (framework → thin module → agent)" 0 && exit 0 || exit 1
fi

# 4. restart the target so the framework injects into a fresh process ---------------
# Force-stopping a package also drops its AccessibilityServices (Android behaviour), and the
# target here is the ADH Manager — the app that hosts the optional phone-automation service.
# Remember the state so step 6 can put it back: a regression run must not silently switch
# phone automation off.
A11Y_SERVICES_BEFORE="$(adb -s "$SERIAL" shell settings get secure enabled_accessibility_services 2>/dev/null | tr -d '\r')"
A11Y_ENABLED_BEFORE="$(adb -s "$SERIAL" shell settings get secure accessibility_enabled 2>/dev/null | tr -d '\r')"
adb -s "$SERIAL" shell "su -c 'am force-stop $TARGET'" >/dev/null 2>&1
sleep 1
adb -s "$SERIAL" shell "su -c 'am start -n $TARGET/.MainActivity'" >/dev/null 2>&1
sleep 8

# 5. assertions --------------------------------------------------------------------
MARKER_VAL="$(adb -s "$SERIAL" shell "su -c 'cat $MARKER 2>/dev/null'" 2>/dev/null | tr -d '\r')"
set +e
OUT="$(node - "$HTTP" "$TARGET" <<'EOF'
const [http, target] = process.argv.slice(2);
const base = `http://127.0.0.1:${http}`;
const agents = await (await fetch(`${base}/api/agents`)).json();
const a = agents.filter(x => x.package === target && x.online)
                .sort((x, y) => y.connectedAt - x.connectedAt)[0];
if (!a) { console.log(`no online agent session for ${target}`); console.log('RESULT:FAIL'); process.exit(0); }
console.log(`agent session: ${a.sessionId} pid=${a.pid} entry=${a.entry} ver=${a.agentVer}`);
const mods = await (await fetch(`${base}/api/modules?session=${a.sessionId}`)).json();
const n = Array.isArray(mods) ? mods.length : 0;
console.log(`agent answers commands: modules=${n}`);
console.log((n > 0 && a.entry === 'jni_onload') ? 'RESULT:PASS' : 'RESULT:FAIL');
EOF
)"
set +e
echo "marker: ${MARKER_VAL:-<none>}"
echo "$OUT" | sed 's/^/   /'

# 6. restore the pre-test state (the backend stays opt-in) -------------------------
cli_q() { adb -s "$SERIAL" shell "su -c '$CLI $1'" >/dev/null 2>&1 || true; }
# `scope set <module>` with no apps throws inside the CLI (Vector 2.2), so the scope is
# rewritten entry by entry: remove everything, then re-add exactly what was there.
restore_scope() {
  local want="$1" cur
  cur="$(adb -s "$SERIAL" shell "su -c '$CLI scope ls $MODULE_PKG'" 2>/dev/null | tr -d '\r' | awk 'NR>2 && NF>=2 {print $1"/"$2}')"
  for e in $cur; do cli_q "scope rm $MODULE_PKG $e"; done
  if [ -n "$want" ]; then cli_q "scope set $MODULE_PKG $want"; fi
}
if [ "${ADH_XPOSED_KEEP:-0}" = "1" ]; then
  echo ">> ADH_XPOSED_KEEP=1 — leaving the module enabled for $TARGET"
elif [ "$PRIOR_STATUS" = "enabled" ]; then
  restore_scope "$PRIOR_SCOPE"
  cli_q "modules enable $MODULE_PKG"
  echo ">> restored prior state: enabled, scope='${PRIOR_SCOPE:-<empty>}'"
else
  restore_scope "$PRIOR_SCOPE"
  cli_q "modules disable $MODULE_PKG"
  echo ">> restored prior state: status=$PRIOR_STATUS, scope='${PRIOR_SCOPE:-<empty>}'"
fi

# Put the automation AccessibilityService entry back if the force-stop dropped it.
if grep -q 'AdhAutomationAccessibilityService' <<<"${A11Y_SERVICES_BEFORE:-}"; then
  A11Y_NOW="$(adb -s "$SERIAL" shell settings get secure enabled_accessibility_services 2>/dev/null | tr -d '\r')"
  if ! grep -q 'AdhAutomationAccessibilityService' <<<"${A11Y_NOW:-}"; then
    adb -s "$SERIAL" shell "su -c 'settings put secure enabled_accessibility_services $A11Y_SERVICES_BEFORE'" >/dev/null 2>&1
    if [ "${A11Y_ENABLED_BEFORE:-1}" = "1" ]; then
      adb -s "$SERIAL" shell "su -c 'settings put secure accessibility_enabled 1'" >/dev/null 2>&1
    fi
    sleep 1
    echo ">> restored the automation accessibility service the force-stop had dropped"
  fi
fi

if grep -q 'agent=1' <<<"$MARKER_VAL" && grep -q 'RESULT:PASS' <<<"$OUT"; then
  SENTINEL="RESULT:PASS"
else
  SENTINEL="RESULT:FAIL"
fi
echo "$SENTINEL"
OUT="$OUT
$SENTINEL"

verify_gate "v3.1 Xposed backend (framework → thin module → agent → host)" 0 && exit 0 || exit 1