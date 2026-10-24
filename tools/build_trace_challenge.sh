#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"
mkdir -p "$ROOT/agent/build"
CLANG="$ADH_NDK_BIN/aarch64-linux-android26-clang$_adh_exe"
[ -x "$CLANG" ] || CLANG="$NDK/toolchains/llvm/prebuilt/$_adh_triple/bin/aarch64-linux-android26-clang$_adh_exe"
"$CLANG" -shared -fPIC -O0 -Wall -Wextra -Werror "$ROOT/fixtures/trace-challenge/challenge.c" -o "$ROOT/agent/build/libadh_trace_fixture.so"
echo 'built libadh_trace_fixture.so (verification fixture only)'
