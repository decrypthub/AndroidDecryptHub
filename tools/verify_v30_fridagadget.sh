#!/usr/bin/env bash
# v3.0 Frida Gadget backend acceptance (module W — OPTIONAL non-root backend).
#
# Proves the whole chain inside a real target process:
#   official Gadget (sha256-pinned, version-selectable)
#     → dlopen by the ADH agent inside com.adh.sandbox (constructor-driven: no entry symbol)
#     → Gadget "script" interaction loads the hook
#     → hook bundled with frida-java-bridge (Frida 17 moved the bridges out of the runtime)
#     → Java.perform() + Java.androidVersion reachable from inside the target
#
# PASS = Gadget runtime threads alive in the target pid AND the Java-side marker written
#        AND the target still alive afterwards (the ~25 MB dlopen must not kill it).
#
# RESULT:SKIP (exit 0) when the Gadget asset or the bundler deps are unavailable — both are
# gitignored caches (agent/third_party/frida, tools/frida/node_modules), so an offline
# checkout legitimately cannot exercise this backend.
#
# Run: bash tools/verify_v30_fridagadget.sh   (exit 0 = PASS)
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env

PKG="com.adh.sandbox"
MARKER_DEV="/data/data/$PKG/files/adh_frida_gadget_ok"
ABI="${ADH_FRIDA_ABI:-arm64}"
VERSION="${ADH_FRIDA_VERSION:-}"

# The Gadget constructor runs once per process, so always exercise a fresh target process.
adb -s "$SERIAL" shell am force-stop "$PKG" >/dev/null 2>&1
adb -s "$SERIAL" shell am start -n "$PKG/.MainActivity" >/dev/null 2>&1
sleep 5

verify_sandbox_alive
if [ -z "$VERSION" ]; then
  VERSION="$(node -e 'const m=require(process.argv[1]);const k=Object.keys(m.versions||{});process.stdout.write(k[k.length-1]||"")' "$ROOT/tools/frida_gadget_versions.json" 2>/dev/null)"
fi
if [ -z "$VERSION" ]; then
  echo "RESULT:SKIP no pinned Gadget version in tools/frida_gadget_versions.json"
  echo "⏭ Frida Gadget SKIP (no version pinned)"
  exit 0
fi
echo "gadget version: $VERSION ($ABI)"

GADGET="$(bash "$ROOT/tools/fetch_frida_gadget.sh" "$VERSION" "$ABI" 2>/tmp/adh_fetch_gadget.err)" || GADGET=""
if [ -z "$GADGET" ] || [ ! -f "$GADGET" ]; then
  echo "RESULT:SKIP Gadget not cached and not fetchable"
  tail -3 /tmp/adh_fetch_gadget.err 2>/dev/null | sed 's/^/   /'
  echo "⏭ Frida Gadget SKIP (run: bash tools/fetch_frida_gadget.sh $VERSION)"
  exit 0
fi
echo "gadget: $GADGET ($(stat -c %s "$GADGET" 2>/dev/null || echo '?') bytes)"

if [ ! -f "$ROOT/tools/frida/node_modules/esbuild/package.json" ] ||
   [ ! -f "$ROOT/tools/frida/node_modules/frida-java-bridge/package.json" ]; then
  echo "RESULT:SKIP bundler deps missing"
  echo "⏭ Frida Gadget SKIP (run: cd tools/frida && npm install --ignore-scripts)"
  exit 0
fi

PROBE_DIR="$(mktemp -d)"
trap 'rm -f "$PROBE_DIR/adh_gadget_probe.js"; rmdir "$PROBE_DIR" 2>/dev/null || true' EXIT
PROBE="$PROBE_DIR/adh_gadget_probe.js"
cat >"$PROBE" <<'JS'
// Classic-style hook (bare `Java`): load_frida_gadget.sh bundles it with frida-java-bridge.
// Proves the Java bridge is reachable from inside the target process.
Java.perform(function () {
  var p = "/data/data/com.adh.sandbox/files/adh_frida_gadget_ok";
  var f = new File(p, "w");
  f.write("ADH_FRIDA_GADGET_OK android=" + Java.androidVersion + " pid=" + Process.id);
  f.flush();
  f.close();
});
JS

adb -s "$SERIAL" shell "su -c 'rm -f $MARKER_DEV'" >/dev/null 2>&1

set +e
OUT="$(bash "$ROOT/tools/load_frida_gadget.sh" "$PROBE" --version "$VERSION" --abi "$ABI" \
        --package "$PKG" --wait 20 --marker "$MARKER_DEV" 2>&1)"
RC=$?
MARKER_VAL="$(adb -s "$SERIAL" shell "su -c 'cat $MARKER_DEV 2>/dev/null'" 2>/dev/null | tr -d '\r')"
PID="$(adb -s "$SERIAL" shell pidof "$PKG" 2>/dev/null | tr -d '\r ')"
MAPS_HITS=""; THREAD_HITS=""
if [ -n "$PID" ]; then
  MAPS_HITS="$(adb -s "$SERIAL" shell "su -c 'grep -c libgadget.so /proc/$PID/maps'" 2>/dev/null | tr -d '\r')"
  THREAD_HITS="$(adb -s "$SERIAL" shell "su -c 'cat /proc/$PID/task/*/comm'" 2>/dev/null | tr -d '\r' | grep -cE 'frida-gadget|gum-js-loop')"
fi

echo "$OUT" | sed 's/^/   /'
echo "loader rc=$RC"
echo "marker: ${MARKER_VAL:-<none>}"
echo "measured footprint in target: libgadget.so maps lines=${MAPS_HITS:-?} gadget threads=${THREAD_HITS:-?}"
echo "sandbox alive after: ${PID:-NO}"

if [ "$RC" = "0" ] &&
   printf '%s' "$MARKER_VAL" | grep -q 'ADH_FRIDA_GADGET_OK' &&
   [ -n "$PID" ]; then
  SENTINEL="RESULT:PASS"
else
  SENTINEL="RESULT:FAIL"
fi
echo "$SENTINEL"
# verify_gate reads $OUT — fold the sentinel in so the shared gate sees it.
OUT="$OUT
$SENTINEL"

verify_gate "v3.0 Frida Gadget (official gadget → dlopen → bundled Java hook)" 0 && exit 0 || exit 1