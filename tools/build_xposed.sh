#!/usr/bin/env bash
# Build the optional LSPosed/Xposed thin module APK (module W optional backend).
#
# Usage:
#   tools/build_xposed.sh [--no-agent] [--release]
#
# Steps:
#   1. ensure agent/build/libadh_agent.so (built on demand via tools/build_agent.sh)
#   2. stage it into injector/xposed/module/src/main/jniLibs/arm64-v8a/ (gitignored)
#   3. write injector/xposed/local.properties from $SDK (gitignored, same as sandbox-app)
#   4. gradle :module:assembleDebug|assembleRelease
#   5. publish the APK to injector/xposed/dist/adh-xposed[-release].apk
#
# The APK path is printed as the LAST line of stdout; progress goes to stderr.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"   # SDK/NDK/ROOT/ABI + install_apk_root

usage() { sed -n '2,15p' "$0"; }
die() { echo "!! $*" >&2; exit 1; }

WITH_AGENT=1
VARIANT="debug"
while [ $# -gt 0 ]; do
  case "$1" in
    --no-agent) WITH_AGENT=0; shift ;;
    --release) VARIANT="release"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

AGENT_SO="$ROOT/agent/build/libadh_agent.so"
if [ "$WITH_AGENT" = "1" ] && [ ! -f "$AGENT_SO" ]; then
  echo ">> agent .so missing — building it first (tools/build_agent.sh)" >&2
  bash "$ROOT/tools/build_agent.sh" >&2
fi
[ -f "$AGENT_SO" ] || die "missing $AGENT_SO (run tools/build_agent.sh, or pass --no-agent for a stub-less build)"

JNI_DIR="$ROOT/injector/xposed/module/src/main/jniLibs/arm64-v8a"
mkdir -p "$JNI_DIR"
cp "$AGENT_SO" "$JNI_DIR/libadh_agent.so"
echo ">> staged libadh_agent.so ($(stat -c %s "$AGENT_SO") bytes) into the module APK" >&2

# Gradle reads the SDK location from local.properties (gitignored). The JVM is a Windows
# process, so translate the Git-Bash /c/... path (cygpath -m keeps forward slashes).
LP="$ROOT/injector/xposed/local.properties"
SDK_HOST="$SDK"
if command -v cygpath >/dev/null 2>&1; then SDK_HOST="$(cygpath -m "$SDK")"; fi
printf 'sdk.dir=%s\n' "$SDK_HOST" >"$LP"

if [ "$VARIANT" = "release" ]; then TASK="assembleRelease"; else TASK="assembleDebug"; fi
cd "$ROOT/injector/xposed"
# `sh gradlew` keeps this working whether or not the exec bit survived the checkout.\nsh ./gradlew --console=plain ":module:$TASK" >&2

APK="$(ls -t "$ROOT"/injector/xposed/module/build/outputs/apk/*/*.apk 2>/dev/null | head -1)"
[ -n "$APK" ] && [ -f "$APK" ] || die "gradle produced no APK"

# Fail-loud on a stale payload: AGP can judge the packaging up-to-date after we swapped the
# staged .so, and the module APK is what injects the agent into targets — shipping the previous
# build silently is exactly the kind of thing that wastes a debugging session.
staged_sha() { sha256sum "$JNI_DIR/libadh_agent.so" | awk '{print $1}'; }
apk_sha() { unzip -p "$1" lib/arm64-v8a/libadh_agent.so 2>/dev/null | sha256sum | awk '{print $1}'; }
if command -v unzip >/dev/null 2>&1; then
  if [ "$(staged_sha)" != "$(apk_sha "$APK")" ]; then
    echo ">> packaged agent .so is stale — re-running the packaging tasks" >&2
    sh ./gradlew --console=plain --rerun-tasks ":module:$TASK" >&2
    APK="$(ls -t "$ROOT"/injector/xposed/module/build/outputs/apk/*/*.apk 2>/dev/null | head -1)"
    [ -n "$APK" ] && [ -f "$APK" ] || die "gradle produced no APK after rerun"
    [ "$(staged_sha)" = "$(apk_sha "$APK")" ] || die "module APK still carries a stale libadh_agent.so"
  fi
fi

DIST="$ROOT/injector/xposed/dist"
mkdir -p "$DIST"
if [ "$VARIANT" = "release" ]; then OUT="$DIST/adh-xposed-release.apk"; else OUT="$DIST/adh-xposed.apk"; fi
cp "$APK" "$OUT"
echo ">> module APK: $OUT ($(stat -c %s "$OUT") bytes)" >&2
printf '%s\n' "$OUT"