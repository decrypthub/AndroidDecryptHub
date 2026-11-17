#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"
mkdir -p "$ROOT/agent/build"
"$ADH_NDK_BIN/clang$_adh_exe" --target=aarch64-linux-android26 -O2 -Wall -Wextra -Werror \
  -ffunction-sections -fdata-sections -Wl,--gc-sections -I"$ROOT/agent/third_party/qbdi/include" \
  "$ROOT/agent/test/qbdi_stack.c" "$ROOT/agent/src/trace/qbdi_trace.c" "$ROOT/agent/src/bootstrap/mem_read.c" \
  -ldl -llog -pthread -o "$ROOT/agent/build/adh-qbdi-stack"
echo 'built adh-qbdi-stack (production tracer/stack/watch runtime fixture; no ADB)'
