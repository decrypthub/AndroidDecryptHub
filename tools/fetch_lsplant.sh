#!/usr/bin/env bash
# Fetch LSPlant (ART Java-method hook, WS-A) + Dobby (arm64 inline hook backend).
# LSPlant is pinned to v6.4 — master migrated to C++23 modules + CMake 3.28 which our
# CMake 3.22.1 cannot build; v6.4 is plain C++20 single-source. Sources land in
# agent/third_party/ (gitignored). Dobby is linked statically into the agent. Idempotent,
# fail-loud.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TP="$ROOT/agent/third_party"
JNILIBS="$ROOT/sandbox-app/app/src/main/jniLibs/arm64-v8a"
LSP_VER="${LSPLANT_VERSION:-v6.4}"
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
  # Patch: some ROMs (ColorOS/Android 15+) strip the internal-linkage art::GetMethodShorty from
  # libart.so dynsym, so LSPlant's symbol resolution fails and Init returns false. Make it fall
  # back to computing the shorty via JNI reflection (idh_compute_shorty, in our shim) and not
  # fail Init when the symbol is absent. Reproducible so re-fetch stays consistent.
  AM="$LSP/lsplant/src/main/jni/art/runtime/art_method.hpp"
  perl -0777 -pi -e 's/namespace lsplant::art \{/namespace lsplant::art {\nextern "C" const char *idh_compute_shorty(JNIEnv *env, jobject method);/' "$AM"
  perl -0777 -pi -e 's/return GetMethodShorty\(env, env->FromReflectedMethod\(method\)\);/if (GetMethodShortySym) return GetMethodShorty(env, env->FromReflectedMethod(method));\n        return idh_compute_shorty(env, method);/' "$AM"
  perl -0777 -pi -e 's/LOGE\("Failed to find GetMethodShorty"\);\s*\n\s*return false;/LOGW("art::GetMethodShorty absent - computing shorty via JNI reflection");/' "$AM"
  grep -q "idh_compute_shorty" "$AM" || { echo "!! LSPlant GetMethodShorty patch did not apply"; exit 1; }
  # Patch 2: this ROM also strips SetEntryPointsToInterpreter + art_quick_*_bridge/trampoline
  # (deopt entrypoints). They're only used by the optional Deoptimize() API, never by Hook, so
  # make ClassLinker::Init not fail when they're absent (basic hooking still works).
  CL="$LSP/lsplant/src/main/jni/art/runtime/class_linker.hpp"
  perl -0777 -pi -e 's/if \(!RETRIEVE_FUNC_SYMBOL\(art_quick_to_interpreter_bridge,\s*"art_quick_to_interpreter_bridge"\)\)\s*\[\[unlikely\]\]\s*\{\s*return false;\s*\}/RETRIEVE_FUNC_SYMBOL(art_quick_to_interpreter_bridge, "art_quick_to_interpreter_bridge");/s' "$CL"
  perl -0777 -pi -e 's/if \(!RETRIEVE_FUNC_SYMBOL\(art_quick_generic_jni_trampoline,\s*"art_quick_generic_jni_trampoline"\)\)\s*\[\[unlikely\]\]\s*\{\s*return false;\s*\}/RETRIEVE_FUNC_SYMBOL(art_quick_generic_jni_trampoline, "art_quick_generic_jni_trampoline");/s' "$CL"
  echo ">> LSPlant sources ready (patched GetMethodShorty + deopt-entrypoint fallbacks)"
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
