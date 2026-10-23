#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"
test -n "$ADH_NDK_BIN" || { echo 'No host NDK toolchain; set ANDROID_NDK_HOME' >&2; exit 1; }
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) compiler="$ADH_NDK_BIN/clang.exe" ;; *) compiler="$ADH_NDK_BIN/clang" ;; esac
mkdir -p "$ROOT/agent/build"
"$compiler" --target=aarch64-linux-android26 -O2 -Wall -Wextra -Werror \
  "$ROOT/tools/native/root_watch.c" -o "$ROOT/agent/build/adh-root-watch"
echo 'Built agent/build/adh-root-watch (arm64-v8a; root-side perf collector)'
