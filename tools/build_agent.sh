#!/usr/bin/env bash
# Build libadh_agent.so (arm64-v8a) with the NDK + SDK cmake, then stage it into
# the sandbox app's jniLibs. Reproducible build step — run from anywhere.
#
# Works on BOTH hosts:
#   - the Windows workstation (pinned SDK cmake 3.22.1 + NDK 28.2.13676358, the original path);
#   - a Linux takeover machine that only has a system cmake/ninja plus some NDK r2x
#     (`tools/lib/env.sh` finds that NDK and exports ADH_NDK_TOOLCHAIN / ADH_NDK_STRIP).
# The Windows path is unchanged when its toolchain exists. On the other host the build goes to a
# separate build dir so it cannot fight the Windows-generated CMakeCache, and the stripped .so is
# copied back to agent/build/libadh_agent.so so every host-side gate that reads that canonical
# path is looking at what was just built.
#
# --deploy: after a successful build, push the .so into the installed sandbox (and the flashed
#           Zygisk module) so the device runs this build. Same code path install_apk_root uses.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/env.sh"

DEPLOY=0
for arg in "$@"; do case "$arg" in --deploy) DEPLOY=1 ;; *) echo "unknown flag: $arg" >&2; exit 2 ;; esac; done

# ---- toolchain: pinned Windows paths first, host fallbacks second --------------------------
TC="$TOOLCHAIN"
if [ ! -f "$TC" ]; then TC="$ADH_NDK_TOOLCHAIN"; fi
[ -f "$TC" ] || { echo "missing toolchain file: $TOOLCHAIN (and no host NDK toolchain was found)"; exit 1; }

CMAKE_BIN="$CMAKE"
[ -x "$CMAKE_BIN" ] || CMAKE_BIN="$(command -v cmake || true)"
NINJA_BIN="$NINJA"
[ -x "$NINJA_BIN" ] || NINJA_BIN="$(command -v ninja || true)"
[ -n "$CMAKE_BIN" ] && [ -x "$CMAKE_BIN" ] || { echo "no cmake: $CMAKE is absent and none is on PATH"; exit 1; }
[ -n "$NINJA_BIN" ] && [ -x "$NINJA_BIN" ] || { echo "no ninja: $NINJA is absent and none is on PATH"; exit 1; }

STRIP="$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-strip.exe"
[ -x "$STRIP" ] || STRIP="$ADH_NDK_STRIP"
[ -n "$STRIP" ] && [ -x "$STRIP" ] || { echo "missing strip tool (neither the pinned NDK nor the host NDK provides llvm-strip)"; exit 1; }

# ---- build dir: never reuse the other host's cache ----------------------------------------
BUILD_DIR="${ADH_BUILD_DIR:-$ROOT/agent/build}"
if [ -f "$BUILD_DIR/CMakeCache.txt" ] && grep -qE '^CMAKE_TOOLCHAIN_FILE:[^=]*=[A-Za-z]:[/\\]' "$BUILD_DIR/CMakeCache.txt"; then
  BUILD_DIR="$ROOT/agent/build-$(uname -s | tr 'A-Z' 'a-z')"
  echo ">> existing cache at $ROOT/agent/build is from another host — building in $BUILD_DIR"
fi

echo ">> configuring agent ($ABI) with $CMAKE_BIN"
"$CMAKE_BIN" -S "$ROOT/agent" -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_MAKE_PROGRAM="$NINJA_BIN" \
  -DCMAKE_TOOLCHAIN_FILE="$TC" \
  -DANDROID_ABI="$ABI" \
  -DANDROID_PLATFORM=android-26 \
  -DANDROID_STL=c++_static \
  -DCMAKE_BUILD_TYPE=Release >/dev/null

echo ">> building"
# Do NOT hide build output — a hidden compile error once shipped a stale .so.
if ! "$CMAKE_BIN" --build "$BUILD_DIR"; then echo "!! AGENT BUILD FAILED"; exit 1; fi

SO="$BUILD_DIR/libadh_agent.so"
DEBUG_SO="$BUILD_DIR/libadh_agent.so.debug"
DEST="$ROOT/sandbox-app/app/src/main/jniLibs/$ABI"

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
# The canonical artifact path: host-side gates (verify_v26_footprint, verify_v88_agent_signatures)
# read agent/build/libadh_agent.so, so on a host-suffixed build dir it must still hold THIS build.
if [ "$BUILD_DIR" != "$ROOT/agent/build" ]; then
  mkdir -p "$ROOT/agent/build"
  cp "$SO" "$ROOT/agent/build/libadh_agent.so"
fi
echo ">> built $(ls -la "$SO" | awk '{print $5}') bytes -> $DEST/libadh_agent.so"
if [ "$BUILD_DIR" != "$ROOT/agent/build" ]; then echo ">> canonical copy -> agent/build/libadh_agent.so"; fi
if [ -f "$DEBUG_SO" ]; then echo ">> unstripped debug copy -> $DEBUG_SO"; fi
"$READELF" --dyn-syms "$SO" \
  | grep -iE "adh_agent_set_package|adh_agent_start|JNI_OnLoad" | awk '{print "   export:", $8}'

if [ "$DEPLOY" = "1" ]; then
  SERIAL="${ANDROID_SERIAL:-$(adb devices | awk 'NR==2{print $1}')}"
  if [ -z "$SERIAL" ]; then
    echo ">> --deploy: no device attached, skipping"
  else
    echo ">> deploying to $SERIAL"
    refresh_agent_so "$SERIAL"
  fi
fi
