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
ADH_NDK_BIN=""; ADH_JNI_H=""
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
    _jni="$_root/toolchains/llvm/prebuilt/$_adh_triple/sysroot/usr/include/jni.h"
    [ -f "$_jni" ] && ADH_JNI_H="$_jni"
    break
  fi
done
unset _root _bin _jni
CLANG="${CLANG:-${ADH_NDK_BIN:+$ADH_NDK_BIN/clang$_adh_exe}}"
JNI_H="${JNI_H:-$ADH_JNI_H}"
export ADH_NDK_BIN ADH_JNI_H CLANG JNI_H
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
  grep -q 'Success' <<<"$out"
}
