#!/usr/bin/env bash
# Fetch and patch LSPlant v6.4 for the ADH in-process agent.
#
# LSPlant is an ART Java-method hook library. v6.4 is pinned because it is a C++20
# single-source build compatible with the project's NDK/CMake toolchain; newer master
# builds require C++23 modules and a newer CMake. The sources land in the gitignored
# agent/third_party/lsplant directory and are compiled directly into libadh_agent.so.
#
# Local patches for the OnePlus/ColorOS Android 15 test ROM (all idempotent, all fail-loud):
#   1. art::GetMethodShorty may be stripped from libart.so; compute the shorty through
#      JNI reflection instead.
#   2. optional deopt entrypoint symbols may be stripped; basic Hook/UnHook must not
#      fail when only those optional symbols are missing.
#   3. JitCodeCache::Init must degrade, not fail, when the ROM drops its symbols.
#   4. ADH's own exception clearing must not travel through the hooked JNIEnv table.
#   5. JitCodeCache::GarbageCollectCache is RENAMED on this ROM; add the new name as a
#      second candidate so JIT movement tracking actually initializes (see patch 5).
#   7. API 31+ class-init backup uses kInitialized (14). 15 is kVisiblyInitialized.
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
# ---- patch 5: the JIT code-cache GC hook under its renamed symbol -----------------
# Patch 3 makes Init survive a missing JitCodeCache symbol, but "surviving" is not "working":
# the stub it guards is what moves LSPlant's hooked-method BACKUPS out of the way before the
# JIT collects code. With `available_ = false` the stub never installs and `RecordJitMovement`
# is skipped (lsplant.cc: guarded by JitCodeCache::Available()), so a hooked method can be left
# pointing at JIT code the collector has freed.
#
# Measured on the ColorOS/A15 test device: the symbol is not stripped, it is RENAMED.
#   absent (dynsym AND symtab): _ZN3art3jit12JitCodeCache19GarbageCollectCacheEPNS_6ThreadE
#   present and exported:       _ZN3art3jit12JitCodeCache12DoCollectionEPNS_6ThreadE
#   present and exported:       _ZN3art3jit12JitCodeCache18MoveObsoleteMethodEPNS_9ArtMethodES3_
# Same argument shape (JitCodeCache*, Thread*), so the existing stub body applies unchanged.
# Consequence of the bug, reproduced on a real obfuscated target: hooking a HOT method
# (java.lang.String#length) SIGSEGVs the process inside the JIT thread
# (art::LiveInterval::AddUse) within ~3 s, while a cold method survives minutes.
#
# HookSyms() already accepts alternatives (it ORs them), so this only ADDS a candidate: on a
# ROM that ships the original name unchanged, behaviour is identical to upstream.
JIT="$LSP/lsplant/src/main/jni/art/runtime/jit/jit_code_cache.hpp"
if ! grep -q 'JitCacheCollection' "$JIT"; then
  perl -0777 -pi -e 's/\n(public:\n    static bool Available)/\n    CREATE_MEM_HOOK_STUB_ENTRY("_ZN3art3jit12JitCodeCache12DoCollectionEPNS_6ThreadE", void,\n                               JitCacheCollection, (JitCodeCache *thiz, Thread *self), {\n                                   auto movements = GetJitMovements();\n                                   for (auto [target, backup] : movements) MoveObsoleteMethod(thiz, target, backup);\n                                   backup(thiz, self);\n                               });\n\n$1/s' "$JIT"
  perl -0777 -pi -e 's/HookSyms\(handler, GarbageCollectCache\)/HookSyms(handler, GarbageCollectCache, JitCacheCollection)/' "$JIT"
fi
grep -q 'JitCacheCollection' "$JIT" || { echo "!! LSPlant renamed JIT-cache symbol patch did not apply"; exit 1; }

# ---- patch 6: let the agent report whether JIT movement tracking came up -----------
# lsplant.cc is the TU that already includes the internal ART interface layer, so the accessor
# lives at its end (outside every namespace) rather than dragging four internal headers into the
# agent's own translation unit. The agent declares it and surfaces it as javahook_probe's
# `jitTracking` / java_hook status's `jitTracking`. Patch 5's whole point is to make this true; a
# caller that still sees false knows a HOT-method hook will kill the target.
LSC2="$LSP/lsplant/src/main/jni/lsplant.cc"
if ! grep -q 'adh_art_jit_available' "$LSC2"; then
  cat >> "$LSC2" <<'ADH_JIT_ACCESSOR'

// ADH patch 6: capability accessor for tools/fetch_lsplant.sh. Kept here because this TU already
// includes art/runtime/jit/jit_code_cache.hpp; the agent itself does not.
extern "C" int adh_art_jit_available(void) {
    return lsplant::art::jit::JitCodeCache::Available() ? 1 : 0;
}
ADH_JIT_ACCESSOR
fi
grep -q 'adh_art_jit_available' "$LSC2" || { echo "!! LSPlant JIT-accessor patch did not apply"; exit 1; }

# ---- patch 7: API 31+ backups at kInitialized (14), not kVisiblyInitialized (15) ----
# v6.4 sets initialized_status=15 for every API>=30. On the ColorOS Android 15 libart,
# SetStatus compares the previous status with 14 and the new status with 15: 14 is
# kInitialized, 15 is kVisiblyInitialized. Backup at 15 runs from MarkVisiblyInitialized's
# SetStatus call (file offset +1664) and can publish a non-code entry point. Android 11
# (API 30) keeps 15. Idempotent.
CLASS_HPP="$LSP/lsplant/src/main/jni/art/mirror/class.hpp"
if ! grep -q '__ANDROID_API_S__' "$CLASS_HPP"; then
  perl -0777 -pi -e 's/if \(sdk_int >= __ANDROID_API_R__\) \{\s*\n\s*initialized_status = 15;/if (sdk_int >= __ANDROID_API_S__) {\n            initialized_status = 14;\n        } else if (sdk_int >= __ANDROID_API_R__) {\n            initialized_status = 15;/s' "$CLASS_HPP"
fi
grep -q 'sdk_int >= __ANDROID_API_S__' "$CLASS_HPP" || { echo "!! LSPlant class-status patch did not apply"; exit 1; }
grep -q 'initialized_status = 14;' "$CLASS_HPP" || { echo "!! LSPlant class-status value missing"; exit 1; }
# SetStatus itself starts with paciasp on this ROM. Dobby's prologue rewrite sends that
# call into the unmapped zygote GC gap. Skip the hook at API >= 31. Callers initialize
# the class before installing a method hook, so the snapshot is unused.
if ! grep -q 'skip Class::SetStatus hook' "$CLASS_HPP"; then
  perl -0777 -pi -e 's/\} else \{\s*\n\s*if \(!HookSyms\(handler, SetClassStatus, TrivialSetStatus\)\) \{\s*\n\s*return false;\s*\n\s*\}\s*\n\s*\}/} else if (sdk_int < __ANDROID_API_S__) {\n            if (!HookSyms(handler, SetClassStatus, TrivialSetStatus)) {\n                return false;\n            }\n        } else {\n            LOGW("skip Class::SetStatus hook on API %d", sdk_int);\n        }/s' "$CLASS_HPP"
fi
grep -q 'skip Class::SetStatus hook on API' "$CLASS_HPP" || { echo "!! LSPlant SetStatus skip patch did not apply"; exit 1; }

# ClassLinker::RegisterNative's inline hook breaks JNI_OnLoad on this API 31+ libart
# (imagepipeline dies in RegisterNatives). Java hooks do not need it.
LINKER_HPP="$LSP/lsplant/src/main/jni/art/runtime/class_linker.hpp"
if ! grep -q 'skip ClassLinker::RegisterNative hook' "$LINKER_HPP"; then
  perl -0777 -pi -e 's/if \(!HookSyms\(handler, RegisterNativeClassLinker, RegisterNative, RegisterNativeFast,\s*\n\s*RegisterNativeThread\) \|\|\s*\n\s*!HookSyms\(handler, UnregisterNativeClassLinker, UnregisterNative, UnregisterNativeFast,\s*\n\s*UnregisterNativeThread\)\) \{\s*\n\s*return false;\s*\n\s*\}/if (sdk_int < __ANDROID_API_S__) {\n            if (!HookSyms(handler, RegisterNativeClassLinker, RegisterNative, RegisterNativeFast,\n                          RegisterNativeThread) ||\n                !HookSyms(handler, UnregisterNativeClassLinker, UnregisterNative, UnregisterNativeFast,\n                          UnregisterNativeThread)) {\n                return false;\n            }\n        } else {\n            LOGW("skip ClassLinker::RegisterNative hook on API %d", sdk_int);\n        }/s' "$LINKER_HPP"
fi
grep -q 'skip ClassLinker::RegisterNative hook on API' "$LINKER_HPP" || { echo "!! LSPlant RegisterNative skip patch did not apply"; exit 1; }

# ---- Dobby: the statically linked inline-hook backend LSPlant uses -----------------
bash "$ROOT/tools/fetch_dobby.sh"
[ -f "$TP/dobby/lib/arm64-v8a/libdobby.a" ] && [ -f "$TP/dobby/include/dobby.h" ] \
  || { echo "!! Dobby static library missing after fetch"; exit 1; }

echo ">> done. LSPlant=$LSP_VER + patched ART fallbacks + Dobby"