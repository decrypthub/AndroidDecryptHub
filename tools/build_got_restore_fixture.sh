#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"
mkdir -p "$ROOT/agent/build"
CLANG="$ADH_NDK_BIN/clang$_adh_exe"
"$CLANG" --target=aarch64-linux-android26 -O2 -Wall -Wextra -Werror \
  -ffunction-sections -fdata-sections -Wl,--gc-sections \
  "$ROOT/agent/test/got_restore.c" "$ROOT/agent/src/hook/got.c" \
  -ldl -llog -o "$ROOT/agent/build/adh-got-restore"
echo 'built adh-got-restore (production GOT restore runtime fixture; no ADB)'
