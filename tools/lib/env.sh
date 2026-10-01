#!/usr/bin/env bash
# Source from build scripts (build_agent.sh / build_detect.sh): resolves Android
# SDK/NDK/CMake/Ninja/toolchain paths + ABI + ROOT for the Win-path NDK build.
#
# Pure variable assignment — does NOT touch shell options. The caller's own
# `set -e/-u/-o pipefail` (set BEFORE sourcing this file) stands unchanged.
# This was previously inlined verbatim in build_agent.sh:6-12 and build_detect.sh:5-11.
#
# WSL builds do NOT use this — they use wsl_env.sh (which adds /mnt/c SDK detection,
# READELF, node24, adb override, JAVA_HOME). Kept separate because the WSL path
# translation + SDK discovery order is genuinely different and untested from Win.
SDK="${ANDROID_SDK_ROOT:-$HOME/AppData/Local/Android/Sdk}"
NDK="${ANDROID_NDK_HOME:-$SDK/ndk/28.2.13676358}"
# Host OS decides the executable suffix and the LLVM prebuilt triple. Everything else in this file
# still assumes a Win-path SDK (this is the Windows build env), but READELF is consumed by HOST-side
# acceptance scripts (verify_v02_so, verify_v26_footprint) that also run on Linux — so it resolves
# per host, and falls back to PATH when the SDK is not installed at all. Hardcoding
# windows-x86_64/…exe made those two scripts fail on Linux with ENOENT, which reads as "the .so is
# unparseable" rather than "the tool is missing".
case "$(uname -s 2>/dev/null)" in
  MINGW*|MSYS*|CYGWIN*) _adh_triple="windows-x86_64"; _adh_exe=".exe" ;;
  *)                    _adh_triple="linux-x86_64";   _adh_exe="" ;;
esac
CMAKE="$SDK/cmake/3.22.1/bin/cmake$_adh_exe"
NINJA="$SDK/cmake/3.22.1/bin/ninja$_adh_exe"
TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"
_adh_ndk_readelf="$NDK/toolchains/llvm/prebuilt/$_adh_triple/bin/llvm-readelf$_adh_exe"
if [ -x "$_adh_ndk_readelf" ]; then READELF="${READELF:-$_adh_ndk_readelf}"; else READELF="${READELF:-llvm-readelf}"; fi

# ---- host-usable NDK toolchain (for HOST-side acceptance scripts) --------------------------------
# ADH_NDK_BIN = the prebuilt bin dir of an NDK that actually HAS this host's toolchain; JNI_H = that
# NDK's jni.h. Deliberately SEPARATE from $NDK above, which drives the Windows build path and must
# not be silently repointed.
#
# Why it exists: two host-side checks need real toolchain files rather than the pinned Win-path set —
# verify_v90 reads jni.h to machine-check the JNIEnv field order, and build_crypto_variants compiles
# the crypto-variant fixtures. Both hardcoded `windows-x86_64`/`.exe`, so on a Linux host that had a
# perfectly good NDK installed they SKIPped (v90) or failed (v101). The JNINativeInterface field
# order v90 compares against has been stable across NDK majors, so a different installed NDK is an
# acceptable source when the pinned one is absent.
ADH_NDK_BIN=""; ADH_JNI_H=""; ADH_NDK_ROOT=""; ADH_NDK_STRIP=""
for _root in \
  "${ANDROID_NDK_HOME:-}" \
  "$NDK" \
  "$HOME/tools"/android-ndk-* \
  "$HOME/Android/Sdk/ndk"/* \
  "${ANDROID_SDK_ROOT:-$SDK}/ndk"/* \
  /opt/android-ndk-*; do
  [ -n "$_root" ] || continue
  _bin="$_root/toolchains/llvm/prebuilt/$_adh_triple/bin"
  if [ -x "$_bin/clang$_adh_exe" ]; then
    ADH_NDK_BIN="$_bin"
    ADH_NDK_ROOT="$_root"
    ADH_NDK_STRIP="$_bin/llvm-strip$_adh_exe"
    _jni="$_root/toolchains/llvm/prebuilt/$_adh_triple/sysroot/usr/include/jni.h"
    [ -f "$_jni" ] && ADH_JNI_H="$_jni"
    break
  fi
done
unset _root _bin _jni
CLANG="${CLANG:-${ADH_NDK_BIN:+$ADH_NDK_BIN/clang$_adh_exe}}"
JNI_H="${JNI_H:-$ADH_JNI_H}"
# The NDK toolchain file of the SAME installation the host toolchain came from, so a host that
# cannot see the pinned Windows NDK can still configure a build (build_agent.sh uses it only as a
# fallback; $TOOLCHAIN above stays the authoritative Windows path).
ADH_NDK_TOOLCHAIN=""
[ -n "$ADH_NDK_ROOT" ] && [ -f "$ADH_NDK_ROOT/build/cmake/android.toolchain.cmake" ] && ADH_NDK_TOOLCHAIN="$ADH_NDK_ROOT/build/cmake/android.toolchain.cmake"
export ADH_NDK_BIN ADH_JNI_H ADH_NDK_ROOT ADH_NDK_STRIP ADH_NDK_TOOLCHAIN CLANG JNI_H
# BASH_SOURCE[0] is this file (tools/lib/env.sh) — two levels up = repo root.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Git Bash `pwd` is /x/Project/... ; Windows Java/NDK tools need a drive path.
if command -v cygpath >/dev/null 2>&1; then
  ROOT="$(cygpath -m "$ROOT")"
fi
ABI="${ABI:-arm64-v8a}"
export SDK NDK CMAKE NINJA TOOLCHAIN READELF ROOT ABI

# ColorOS / OEM `adb install` waits for an on-screen USB confirm. This device is
# rooted — push + `pm install` as uid=0 and never sit on that prompt.
install_apk_root() {
  local apk="$1"
  local remote="${2:-/data/local/tmp/adh-install.apk}"
  local serial="${3:-${SERIAL:-${ANDROID_SERIAL:-}}}"
  local adb_cmd="${ADB:-adb}"
  [ -n "$serial" ] || { echo "!! install_apk_root: no serial" >&2; return 1; }
  [ -f "$apk" ] || { echo "!! apk missing: $apk" >&2; return 1; }
  local host="$apk"
  if command -v cygpath >/dev/null 2>&1; then
    host="$(cygpath -w "$apk")"
  fi
  local saved="${MSYS_NO_PATHCONV-}"
  export MSYS_NO_PATHCONV=1
  "$adb_cmd" -s "$serial" push "$host" "$remote" >/dev/null
  local out
  out="$("$adb_cmd" -s "$serial" shell "su -c 'pm install -r -t $remote'" | tr -d '\r')"
  if [ -n "${saved}" ]; then export MSYS_NO_PATHCONV="$saved"; else unset MSYS_NO_PATHCONV; fi
  printf '%s\n' "$out"
  grep -q 'Success' <<<"$out" || return 1
  # A reinstall of the sandbox APK RESETS the agent .so to the copy baked into that APK, which can
  # be many revisions behind agent/build/. Every device acceptance script after `verify_v01` then
  # silently tests the wrong agent - measured 2026-10-01: the gate had been running an agent three
  # rebuilds old (82e0cfb5 vs 78d9d20f) while the tree said otherwise. So the install step puts our
  # build back. The sandbox extracts native libs at install time, so this is a plain file copy (no
  # APK rebuild, no gradle); the Zygisk module path gets the same file.
  refresh_agent_so "$serial"
}

# Put agent/build/libadh_agent.so into the installed sandbox (and the flashed module) so the device
# runs what the tree builds. No-op when the .so is absent. Prints the hash for the log.
refresh_agent_so() {
  local serial="${1:-${SERIAL:-${ANDROID_SERIAL:-}}}"
  local adb_cmd="${ADB:-adb}"
  local so="$ROOT/agent/build/libadh_agent.so"
  [ -n "$serial" ] || return 0
  [ -f "$so" ] || return 0
  local script="/data/local/tmp/adh_agent_refresh.sh"
  cat > /tmp/adh_agent_refresh.sh <<'EOS'
#!/system/bin/sh
set -e
NEW=/data/local/tmp/libadh_agent.current.so
LIB=$(ls -d /data/app/*/com.adh.sandbox*/lib/arm64 2>/dev/null | head -1)
if [ -n "$LIB" ]; then
  cp "$NEW" "$LIB/libadh_agent.so"
  chcon u:object_r:apk_data_file:s0 "$LIB/libadh_agent.so" 2>/dev/null || restorecon "$LIB/libadh_agent.so" 2>/dev/null || true
  echo "sandbox $(sha256sum "$LIB/libadh_agent.so" | cut -c1-16)"
fi
if [ -d /data/adb/modules/adh ]; then
  cp "$NEW" /data/adb/modules/adh/libadh_agent.so
  chcon u:object_r:system_file:s0 /data/adb/modules/adh/libadh_agent.so 2>/dev/null || true
  echo "module $(sha256sum /data/adb/modules/adh/libadh_agent.so | cut -c1-16)"
fi
EOS
  local host_so="/tmp/adh_agent_refresh.sh"
  "$adb_cmd" -s "$serial" push "$so" /data/local/tmp/libadh_agent.current.so >/dev/null 2>&1
  "$adb_cmd" -s "$serial" push "$host_so" "$script" >/dev/null 2>&1
  "$adb_cmd" -s "$serial" shell "su -c 'sh $script'" 2>/dev/null | tr -d '\r' | sed 's/^/   agent: /'
}
