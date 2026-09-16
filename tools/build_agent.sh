#!/usr/bin/env bash
# Build libadh_agent.so (arm64-v8a) with the NDK + SDK cmake, then stage it into
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

SO="$ROOT/agent/build/libadh_agent.so"
DEBUG_SO="$ROOT/agent/build/libadh_agent.so.debug"
DEST="$ROOT/sandbox-app/app/src/main/jniLibs/$ABI"
STRIP="$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-strip.exe"
[ -f "$STRIP" ] || { echo "missing strip tool: $STRIP"; exit 1; }

# Keep debug info locally (gitignored) for crash symbolication, but ship a
# stripped .so: an unstripped agent carries thousands of internal names and
# debug strings into every target process.
if "$READELF" -SW "$SO" | grep -qE '\.debug_info|\.symtab'; then
  cp "$SO" "$DEBUG_SO"
fi
"$STRIP" --strip-unneeded "$SO"
if "$READELF" -SW "$SO" | grep -qE '\.debug_|\.symtab'; then
  echo "!! release agent still contains debug/symbol sections"; exit 1
fi

mkdir -p "$DEST"
cp "$SO" "$DEST/libadh_agent.so"
echo ">> built $(ls -la "$SO" | awk '{print $5}') bytes -> $DEST/libadh_agent.so"
if [ -f "$DEBUG_SO" ]; then echo ">> unstripped debug copy -> $DEBUG_SO"; fi
"$READELF" --dyn-syms "$SO" \
  | grep -iE "adh_agent_set_package|adh_agent_start|idh_agent_start|JNI_OnLoad" | awk '{print "   export:", $8}'
