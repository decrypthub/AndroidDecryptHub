#!/usr/bin/env bash
# Build the sandbox's mock native detection lib (libidhdetect.so) and stage it
# into the sandbox jniLibs. Separate from the agent; a target-side native lib.
set -euo pipefail
SDK="${ANDROID_SDK_ROOT:-$HOME/AppData/Local/Android/Sdk}"
NDK="${ANDROID_NDK_HOME:-$SDK/ndk/28.2.13676358}"
CMAKE="$SDK/cmake/3.22.1/bin/cmake.exe"
NINJA="$SDK/cmake/3.22.1/bin/ninja.exe"
TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ABI="${ABI:-arm64-v8a}"

"$CMAKE" -S "$ROOT/sandbox-native" -B "$ROOT/sandbox-native/build" -G Ninja \
  -DCMAKE_MAKE_PROGRAM="$NINJA" -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
  -DANDROID_ABI="$ABI" -DANDROID_PLATFORM=android-26 -DCMAKE_BUILD_TYPE=Release >/dev/null
"$CMAKE" --build "$ROOT/sandbox-native/build" >/dev/null
DEST="$ROOT/sandbox-app/app/src/main/jniLibs/$ABI"
mkdir -p "$DEST"
cp "$ROOT/sandbox-native/build/libidhdetect.so" "$DEST/libidhdetect.so"
echo ">> built libidhdetect.so -> $DEST"
