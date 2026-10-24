#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"
mkdir -p "$ROOT/agent/build"
CLANG="$ADH_NDK_BIN/clang$_adh_exe"
[ -x "$CLANG" ] || CLANG="$NDK/toolchains/llvm/prebuilt/$_adh_triple/bin/clang$_adh_exe"
"$CLANG" --target=aarch64-linux-android26 -shared -fPIC -O0 -Wall -Wextra -Werror "$ROOT/fixtures/native-controls/native_controls.c" "$ROOT/fixtures/native-controls/watch.c" -o "$ROOT/agent/build/libadh_native_controls.so"
"$CLANG" --target=aarch64-linux-android26 -O2 -Wall -Wextra -Werror "$ROOT/fixtures/native-controls/host.c" -ldl -o "$ROOT/agent/build/adh-native-host"
echo 'built libadh_native_controls.so (native hook ABI/concurrency fixture only)'
