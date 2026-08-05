#!/usr/bin/env bash
# Build libidh_agent.so (arm64-v8a) with the NDK + SDK cmake, then stage it into
# the sandbox app's jniLibs. Reproducible build step — run from anywhere.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"

for f in "$CMAKE" "$NINJA" "$TOOLCHAIN"; do
  [ -f "$f" ] || { echo "missing toolchain file: $f"; exit 1; }
done

echo ">> configuring agent ($ABI)"
"$CMAKE" -S "$ROOT/agent" -B "$ROOT/agent/build" -G Ninja \
  -DCMAKE_MAKE_PROGRAM="$NINJA" \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
  -DANDROID_ABI="$ABI" \
  -DANDROID_PLATFORM=android-26 \
  -DANDROID_STL=c++_static \
  -DCMAKE_BUILD_TYPE=Release >/dev/null

echo ">> building"
# Do NOT hide build output — a hidden compile error once shipped a stale .so.
if ! "$CMAKE" --build "$ROOT/agent/build"; then echo "!! AGENT BUILD FAILED"; exit 1; fi

SO="$ROOT/agent/build/libidh_agent.so"
DEST="$ROOT/sandbox-app/app/src/main/jniLibs/$ABI"
mkdir -p "$DEST"
cp "$SO" "$DEST/libidh_agent.so"
echo ">> built $(ls -la "$SO" | awk '{print $5}') bytes -> $DEST/libidh_agent.so"
"$READELF" --dyn-syms "$SO" \
  | grep -iE "adh_agent_start|idh_agent_start|JNI_OnLoad" | awk '{print "   export:", $8}'
