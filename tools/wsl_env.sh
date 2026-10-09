#!/usr/bin/env bash
# Source from WSL build/verify scripts: sets Android SDK/NDK paths and path helpers.
# Do not enable errexit here — callers source this file.
set -uo pipefail

SDK="${ANDROID_SDK_ROOT:-}"
if [ -z "$SDK" ]; then
  for _candidate in "$HOME/AppData/Local/Android/Sdk" /mnt/c/Users/*/AppData/Local/Android/Sdk; do
    if [ -d "$_candidate" ]; then SDK="$_candidate"; break; fi
  done
fi
if [ -z "$SDK" ] || [ ! -d "$SDK" ]; then
  echo "!! Android SDK not found (set ANDROID_SDK_ROOT)" >&2
  exit 1
fi

NDK="${ANDROID_NDK_HOME:-$SDK/ndk/28.2.13676358}"
CMAKE="$SDK/cmake/3.22.1/bin/cmake.exe"
NINJA="$SDK/cmake/3.22.1/bin/ninja.exe"
TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"
READELF="$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-readelf.exe"

# Windows cmake.exe needs Windows paths when invoked from WSL.
if grep -qi microsoft /proc/version 2>/dev/null; then
  WSL_BUILD=1
  wpath() { wslpath -w "$1"; }
else
  WSL_BUILD=0
  wpath() { printf '%s' "$1"; }
fi

export SDK NDK CMAKE NINJA TOOLCHAIN READELF WSL_BUILD

# Node 24+ required to run daemon .ts directly; WSL distro often ships older node.
_wsl_env_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE24="$_wsl_env_root/.tools/node24/bin/node"
if [ "$WSL_BUILD" = 1 ] && [ -x "$NODE24" ]; then
  export PATH="$(dirname "$NODE24"):$PATH"
fi

# Prefer Windows platform-tools adb when WSL's adb sees no devices.
if [ "$WSL_BUILD" = 1 ] && [ -x "$SDK/platform-tools/adb.exe" ]; then
  export ADB="$SDK/platform-tools/adb.exe"
  export PATH="$SDK/platform-tools:$PATH"
  export ADB_SERVER_SOCKET="tcp:127.0.0.1:5037"
  adb() { "$ADB" "$@"; }
  export -f adb
  _adh_serial="$(adb devices | awk '/\tdevice$/{print $1; exit}')"
  if [ -n "$_adh_serial" ]; then
    export ADH_SERIAL="${ADH_SERIAL:-$_adh_serial}"
  fi
  export ADH_LLVM_BIN="${ADH_LLVM_BIN:-$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin}"
fi

# Gradle in WSL: use Linux JDK (Windows Studio JBR is not a Linux JVM).
if [ "$WSL_BUILD" = 1 ]; then
  if [ -d "/usr/lib/jvm/java-17-openjdk-amd64" ]; then
    export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
  elif command -v java >/dev/null 2>&1; then
    export JAVA_HOME="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")}"
  fi
fi
