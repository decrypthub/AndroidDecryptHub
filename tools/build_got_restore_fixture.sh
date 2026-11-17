#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"
mkdir -p "$ROOT/agent/build"
CLANG="$ADH_NDK_BIN/clang$_adh_exe"
"$CLANG" --target=aarch64-linux-android26 -O2 -Wall -Wextra -Werror \
  -ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,--pack-dyn-relocs=android \
  "$ROOT/agent/test/got_restore.c" "$ROOT/agent/src/hook/got.c" "$ROOT/agent/src/bootstrap/mem_read.c" \
  -ldl -llog -o "$ROOT/agent/build/adh-got-restore"
DYNAMIC="$("$READELF" -d "$ROOT/agent/build/adh-got-restore")"
grep -q ANDROID_RELA <<<"$DYNAMIC" || { echo 'fixture has no actual APS2 relocation table' >&2; exit 1; }
echo 'built adh-got-restore (production GOT restore runtime fixture; no ADB)'
