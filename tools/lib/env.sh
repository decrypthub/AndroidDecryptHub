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
CMAKE="$SDK/cmake/3.22.1/bin/cmake.exe"
NINJA="$SDK/cmake/3.22.1/bin/ninja.exe"
TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"
READELF="$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-readelf.exe"
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
