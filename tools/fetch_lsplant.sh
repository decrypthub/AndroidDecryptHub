#!/usr/bin/env bash
# Fetch and patch LSPlant v6.4 for the ADH in-process agent.
#
# LSPlant is an ART Java-method hook library. v6.4 is pinned because it is a C++20
# single-source build compatible with the project's NDK/CMake toolchain; newer master
# builds require C++23 modules and a newer CMake. The sources land in the gitignored
# agent/third_party/lsplant directory and are compiled directly into libadh_agent.so.
#
# Two local patches are required for the OnePlus/ColorOS Android 15 test ROM:
#   1. art::GetMethodShorty may be stripped from libart.so; compute the shorty through
#      JNI reflection instead.
#   2. optional deopt entrypoint symbols may be stripped; basic Hook/UnHook must not
#      fail when only those optional symbols are missing.
#
# The script is idempotent and fail-loud. Dobby is fetched through the existing script.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TP="$ROOT/agent/third_party"
LSP="$TP/lsplant"
LSP_VER="${LSPLANT_VERSION:-v6.4}"
mkdir -p "$TP"

if [ -f "$LSP/lsplant/src/main/jni/lsplant.cc" ] \
   && [ -f "$LSP/lsplant/src/main/jni/external/dex_builder/dex_builder.cc" ] \
   && [ -d "$LSP/lsplant/src/main/jni/external/dex_builder/external/parallel_hashmap/parallel_hashmap" ]; then
  echo ">> LSPlant sources already present ($LSP)"
else
  echo ">> cloning LSPlant $LSP_VER"
  rm -rf "$LSP"
  git clone --depth 1 --branch "$LSP_VER" https://github.com/LSPosed/LSPlant.git "$LSP"
  echo ">> init dex_builder submodule"
  git -C "$LSP" submodule update --init --depth 1 lsplant/src/main/jni/external/dex_builder
  echo ">> init parallel_hashmap submodule"
  git -C "$LSP/lsplant/src/main/jni/external/dex_builder" \
      submodule update --init --depth 1 external/parallel_hashmap
fi

[ -f "$LSP/lsplant/src/main/jni/lsplant.cc" ] || { echo "!! lsplant.cc missing after clone"; exit 1; }
[ -f "$LSP/lsplant/src/main/jni/external/dex_builder/dex_builder.cc" ] || { echo "!! dex_builder.cc missing after clone"; exit 1; }
[ -d "$LSP/lsplant/src/main/jni/external/dex_builder/external/parallel_hashmap/parallel_hashmap" ] \
  || { echo "!! parallel_hashmap submodule missing"; exit 1; }

# ---- patch 1: symbol-free GetMethodShorty fallback --------------------------------
AM="$LSP/lsplant/src/main/jni/art/runtime/art_method.hpp"
# Normalize the earlier ADH prototype name if a previous local integration used it.
if grep -q 'idh_compute_shorty' "$AM"; then
  perl -pi -e 's/idh_compute_shorty/adh_compute_shorty/g' "$AM"
fi
if ! grep -q 'adh_compute_shorty' "$AM"; then
  perl -0777 -pi -e 's/namespace lsplant::art \{/namespace lsplant::art {\nextern "C" const char *adh_compute_shorty(JNIEnv *env, jobject method);/' "$AM"
  perl -0777 -pi -e 's/return GetMethodShorty\(env, env->FromReflectedMethod\(method\)\);/if (GetMethodShortySym) return GetMethodShorty(env, env->FromReflectedMethod(method));\n        return adh_compute_shorty(env, method);/' "$AM"
  perl -0777 -pi -e 's/LOGE\("Failed to find GetMethodShorty"\);\s*\n\s*return false;/LOGW("art::GetMethodShorty absent - computing shorty via JNI reflection");/' "$AM"
fi
grep -q 'adh_compute_shorty' "$AM" || { echo "!! LSPlant GetMethodShorty patch did not apply"; exit 1; }

# ---- patch 2: optional deopt entrypoints must not block basic hooking -------------
CL="$LSP/lsplant/src/main/jni/art/runtime/class_linker.hpp"
if grep -q 'if (!RETRIEVE_FUNC_SYMBOL(art_quick_to_interpreter_bridge' "$CL"; then
  perl -0777 -pi -e 's/if \(!RETRIEVE_FUNC_SYMBOL\(art_quick_to_interpreter_bridge,\s*"art_quick_to_interpreter_bridge"\)\)\s*\[\[unlikely\]\]\s*\{\s*return false;\s*\}/RETRIEVE_FUNC_SYMBOL(art_quick_to_interpreter_bridge, "art_quick_to_interpreter_bridge");/s' "$CL"
fi
if grep -q 'if (!RETRIEVE_FUNC_SYMBOL(art_quick_generic_jni_trampoline' "$CL"; then
  perl -0777 -pi -e 's/if \(!RETRIEVE_FUNC_SYMBOL\(art_quick_generic_jni_trampoline,\s*"art_quick_generic_jni_trampoline"\)\)\s*\[\[unlikely\]\]\s*\{\s*return false;\s*\}/RETRIEVE_FUNC_SYMBOL(art_quick_generic_jni_trampoline, "art_quick_generic_jni_trampoline");/s' "$CL"
fi
if grep -q 'if (!RETRIEVE_FUNC_SYMBOL(art_quick_to_interpreter_bridge' "$CL" \
   || grep -q 'if (!RETRIEVE_FUNC_SYMBOL(art_quick_generic_jni_trampoline' "$CL"; then
  echo "!! LSPlant deopt-entrypoint patch did not apply"; exit 1
fi

# ---- patch 3: JIT code cache is optional on stripped ROMs -------------------------
# ColorOS/A15 may not export JitCodeCache::GarbageCollectCache. Basic Java hooking does not
# need that GC-maintenance hook; LSPlant can continue, only JIT movement tracking is disabled.
# Signature scrub: the vendored strings are renamed so the shipped .rodata does not carry the
# framework name (and so the generated dex source name is neutral). Idempotent; verified by
# tools/verify_v88_agent_signatures.sh via the artifact scan.
bash "$ROOT/tools/patch_vendor_signatures.sh"
LSC="$LSP/lsplant/src/main/jni/lsplant.cc"
if ! grep -q 'JIT code cache unavailable' "$LSC"; then
  perl -0777 -pi -e 's/if \(!JitCodeCache::Init\(handler\)\) \{\s*\n\s*LOGE\("Failed to init jit code cache"\);\s*\n\s*return false;\s*\n\s*\}/if (!JitCodeCache::Init(handler)) {\n        LOGW("JIT code cache unavailable - continuing without JIT movement tracking");\n    }/s' "$LSC"
fi
grep -q 'JIT code cache unavailable' "$LSC" || { echo "!! LSPlant JIT-cache fallback patch did not apply"; exit 1; }

# ---- patch 4: ADH's own exception clearing must not look like target behaviour ----------------
# LSPlant clears exceptions on its own paths (art_method.hpp's access-flag probe and
# jni_helper.hpp's ClearException helper). ExceptionClear is a hookable JNIEnv entry, so without
# this every ADH-side clear would be recorded as a target event. The replacement calls the agent's
# bypass (jni_env_hooks.c), which uses the saved original and never travels through the table.
JH="$LSP/lsplant/src/main/jni/include/utils/jni_helper.hpp"
for f in "$AM" "$JH"; do
  if ! grep -q 'adh_jni_exception_clear' "$f"; then
    perl -0777 -pi -e 's/namespace (lsplant(?:::art)? \{)/extern "C" void adh_jni_exception_clear(JNIEnv *env);\n\nnamespace $1/' "$f"
  fi
done
if grep -q 'env->ExceptionClear()' "$AM"; then
  perl -0777 -pi -e 's/env->ExceptionClear\(\),/adh_jni_exception_clear(env),/' "$AM"
fi
if grep -q 'env->ExceptionClear()' "$JH"; then
  perl -0777 -pi -e 's/env->ExceptionClear\(\);/adh_jni_exception_clear(env);/' "$JH"
fi
grep -q 'adh_jni_exception_clear(env),' "$AM" || { echo "!! LSPlant exception-clear patch did not apply (art_method.hpp)"; exit 1; }
grep -q 'adh_jni_exception_clear(env);' "$JH" || { echo "!! LSPlant exception-clear patch did not apply (jni_helper.hpp)"; exit 1; }
# ---- Dobby: the statically linked inline-hook backend LSPlant uses -----------------
bash "$ROOT/tools/fetch_dobby.sh"
[ -f "$TP/dobby/lib/arm64-v8a/libdobby.a" ] && [ -f "$TP/dobby/include/dobby.h" ] \
  || { echo "!! Dobby static library missing after fetch"; exit 1; }

echo ">> done. LSPlant=$LSP_VER + patched ART fallbacks + Dobby"