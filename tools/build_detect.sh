#!/usr/bin/env bash
# Build the sandbox's mock native detection lib (libadhdetect.so) and stage it
# into the sandbox jniLibs. Separate from the agent; a target-side native lib.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"

"$CMAKE" -S "$ROOT/sandbox-native" -B "$ROOT/sandbox-native/build" -G Ninja \
  -DCMAKE_MAKE_PROGRAM="$NINJA" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
  -DANDROID_ABI="$ABI" -DANDROID_PLATFORM=android-26 -DCMAKE_BUILD_TYPE=Release >/dev/null
"$CMAKE" --build "$ROOT/sandbox-native/build" >/dev/null
DEST="$ROOT/sandbox-app/app/src/main/jniLibs/$ABI"
mkdir -p "$DEST"
cp "$ROOT/sandbox-native/build/libadhdetect.so" "$DEST/libadhdetect.so"
cp "$ROOT/sandbox-native/build/libadhplugin_a.so" "$DEST/libadhplugin_a.so"
cp "$ROOT/sandbox-native/build/libadhplugin_b.so" "$DEST/libadhplugin_b.so"
echo ">> built libadhdetect.so + libadhplugin_a/b.so -> $DEST"
