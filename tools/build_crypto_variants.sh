#!/usr/bin/env bash
# Build the crypto-variant scan fixtures:
#   fixtures/crypto-variants/build/libadhcrypto_std.so      — textbook constants (negative control)
#   fixtures/crypto-variants/build/libadhcrypto_variant.so  — the real mutations (see variant.c)
#
# Why compiled artifacts instead of buffers built in a test: the detector's whole claim is that it
# recognises a mutation from the bytes a binary actually contains. Checking it against a Buffer the
# test itself assembled would only prove the test can spell the constants. These two .so files are
# real arm64 ELF data sections, and tools/verify_v101_crypto_variants.sh scans them through the
# daemon's REST surface, exactly as it would scan a dumped target.
#
# -O0 on purpose: an optimising build may fold these tables into immediates, and a fixture that no
# longer contains its own constants would make the acceptance meaningless.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"

# env.sh resolves CLANG from an NDK that has THIS host's toolchain (falling back to other installed
# NDKs when the pinned Win-path one is absent). Hardcoding the Windows path here made the compiled
# fixtures unbuildable on Linux, which surfaced as verify_v101 failing for "no clang".
if [ ! -x "$CLANG" ]; then
  echo "no clang resolved (CLANG='${CLANG:-<empty>}' — set ANDROID_NDK_HOME or install an NDK)" >&2
  exit 1
fi

SRC="$ROOT/fixtures/crypto-variants"
OUT="$SRC/build"
mkdir -p "$OUT"

for name in std variant; do
  # shellcheck disable=SC2086
  "$CLANG" --target=aarch64-linux-android26 -O0 -fPIC -shared \
    -o "$OUT/libadhcrypto_$name.so" "$SRC/$name.c"
  printf '>> %s  (%s bytes)\n' "libadhcrypto_$name.so" "$(wc -c < "$OUT/libadhcrypto_$name.so" | tr -d ' ')"
done
