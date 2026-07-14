#!/usr/bin/env bash
# Fetch LSPlant (ART Java-method hook, WS-A) + ShadowHook (arm64 inline hook backend).
# LSPlant is pinned to v6.4 — master migrated to C++23 modules + CMake 3.28 which our
# CMake 3.22.1 cannot build; v6.4 is plain C++20 single-source. Sources land in
# agent/third_party/ (gitignored); ShadowHook's .so is staged into sandbox jniLibs so the
# app carries it. Idempotent, fail-loud.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TP="$ROOT/agent/third_party"
JNILIBS="$ROOT/sandbox-app/app/src/main/jniLibs/arm64-v8a"
LSP_VER="${LSPLANT_VERSION:-v6.4}"
SH_VER="${SHADOWHOOK_VERSION:-2.0.1}"
mkdir -p "$TP" "$JNILIBS"

# ---- LSPlant v6.4 + dex_builder + parallel_hashmap (HTTPS submodules only) ------------
LSP="$TP/lsplant"
if [ -f "$LSP/lsplant/src/main/jni/lsplant.cc" ] \
   && [ -f "$LSP/lsplant/src/main/jni/external/dex_builder/dex_builder.cc" ] \
   && [ -d "$LSP/lsplant/src/main/jni/external/dex_builder/external/parallel_hashmap/parallel_hashmap" ]; then
  echo ">> LSPlant already present ($LSP)"
else
  echo ">> cloning LSPlant $LSP_VER"
  rm -rf "$LSP"
  git clone --depth 1 --branch "$LSP_VER" https://github.com/LSPosed/LSPlant.git "$LSP"
  echo ">> init dex_builder submodule"
  git -C "$LSP" submodule update --init --depth 1 lsplant/src/main/jni/external/dex_builder
  echo ">> init parallel_hashmap submodule"
  git -C "$LSP/lsplant/src/main/jni/external/dex_builder" \
      submodule update --init --depth 1 external/parallel_hashmap
  [ -f "$LSP/lsplant/src/main/jni/lsplant.cc" ] || { echo "!! lsplant.cc missing after clone"; exit 1; }
  [ -f "$LSP/lsplant/src/main/jni/external/dex_builder/dex_builder.cc" ] || { echo "!! dex_builder.cc missing"; exit 1; }
  echo ">> LSPlant sources ready"
fi

# ---- Dobby prebuilt STATIC lib (arm64) — the exact backend LSPlant's own tests use ------
# io.github.vvb2060.ndk:dobby (find_package(dobby CONFIG) in LSPlant test). Static libdobby.a
# links into the agent: no separate .so, no JNI_OnLoad, no ShadowHook-style linker monitor —
# a self-contained by-address inline hooker. Known-good with LSPlant v6.4.
DOB="$TP/dobby"
DOB_VER="${DOBBY_VERSION:-1.2}"
if [ -f "$DOB/lib/arm64-v8a/libdobby.a" ] && [ -f "$DOB/include/dobby.h" ]; then
  echo ">> Dobby prebuilt already present ($DOB)"
else
  echo ">> downloading Dobby $DOB_VER AAR"
  tmp="$(mktemp -d)"
  URL="https://repo1.maven.org/maven2/io/github/vvb2060/ndk/dobby/$DOB_VER/dobby-$DOB_VER.aar"
  curl -sL --max-time 180 -o "$tmp/dobby.aar" "$URL"
  [ "$(wc -c < "$tmp/dobby.aar")" -gt 100000 ] || { echo "!! Dobby AAR download failed / too small"; exit 1; }
  unzip -oq "$tmp/dobby.aar" -d "$tmp/d"
  A="$(find "$tmp/d" -name libdobby.a -path '*arm64-v8a*' | head -1)"
  HDR="$(find "$tmp/d" -name 'dobby.h' | head -1)"
  [ -n "$A" ] && [ -n "$HDR" ] || { echo "!! could not locate libdobby.a / dobby.h in AAR"; exit 1; }
  rm -rf "$DOB"; mkdir -p "$DOB/lib/arm64-v8a" "$DOB/include"
  cp "$A" "$DOB/lib/arm64-v8a/libdobby.a"
  cp "$HDR" "$DOB/include/dobby.h"
  rm -rf "$tmp"
  echo ">> extracted libdobby.a ($(wc -c < "$DOB/lib/arm64-v8a/libdobby.a") bytes) + dobby.h"
fi
# Dobby is static — no runtime .so to stage. Remove any stale ShadowHook .so.
rm -f "$JNILIBS/libshadowhook.so" "$TP/shadowhook/lib/arm64-v8a/libshadowhook.so" 2>/dev/null || true
echo ">> done. LSPlant=$LSP_VER Dobby(prebuilt)=$DOB_VER"
