#!/usr/bin/env bash
# Build only. No ADB, install, service, production module packaging or deploy.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"
NONCE="${1:?explicit 12-hex nonce required}"
OUTPUT="${2:?explicit isolated output directory required}"
[[ "$NONCE" =~ ^[a-f0-9]{12}$ ]] || exit 2
"$CMAKE" -S "$ROOT/injector/zygisk/fixture" -B "$OUTPUT/companion-build" -G Ninja \
  -DCMAKE_MAKE_PROGRAM="$NINJA" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-26 -DANDROID_STL=c++_static -DCMAKE_BUILD_TYPE=Release \
  -DADH_P5_NONCE="$NONCE" >/dev/null
"$CMAKE" --build "$OUTPUT/companion-build"
for symbol in zygisk_module_entry zygisk_companion_entry; do
  "$READELF" --dyn-syms --wide "$OUTPUT/companion-build/libadh.so" | awk -v name="$symbol" '$NF == name {found=1} END {exit !found}'
done
echo 'PASS isolated companion exports; no device operation performed'
