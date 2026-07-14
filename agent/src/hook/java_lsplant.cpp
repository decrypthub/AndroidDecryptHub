// LSPlant (ART Java-method hook) integration — C++ side. Exposes a C ABI (java_lsplant.h)
// so the pure-C agent_main.c can drive it. Inline-hook backend = Dobby (prebuilt STATIC
// libdobby.a, the exact backend LSPlant's own tests use — self-contained, hooks by address,
// no separate .so / JNI_OnLoad / linker monitor). ART symbol resolution reuses the agent's
// .dynsym parser. LSPlant is pinned to v6.4 (master needs C++23 modules). See fetch_lsplant.sh.
#include "java_lsplant.h"
#include "lsplant.hpp"
#include "dobby.h"

#include <string>
#include <cstring>
#include <pthread.h>
#include <android/log.h>

#define LTAG "IDH_LSP"
#define LLOGI(...) __android_log_print(ANDROID_LOG_INFO,  LTAG, __VA_ARGS__)
#define LLOGE(...) __android_log_print(ANDROID_LOG_ERROR, LTAG, __VA_ARGS__)

// Provided by agent_main.c: in-memory .dynsym resolver (exact + prefix).
extern "C" void *idh_resolve_sym(const char *mod, const char *sym);
extern "C" void *idh_resolve_sym_prefix(const char *mod, const char *pre);

// ---- Dobby adapter (LSPlant's inline_hooker/unhooker contract) -------------------------
static void *dobby_hooker(void *target, void *hooker) {
    void *origin = nullptr;
    if (DobbyHook(target, hooker, &origin) != RS_SUCCESS) { LLOGE("DobbyHook failed for %p", target); return nullptr; }
    return origin;                       // LSPlant wants the backup/original callable
}
static bool dobby_unhooker(void *func) { return DobbyDestroy(func) == RT_SUCCESS; }

// ---- one-time LSPlant init -------------------------------------------------------------
static int g_init_ok = 0;
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;
static JNIEnv *g_init_env = nullptr;

static void do_init(void) {
    dobby_enable_near_branch_trampoline();     // arm64 far-branch support (as LSPlant's test)
    lsplant::InitInfo info {
        .inline_hooker = dobby_hooker,
        .inline_unhooker = dobby_unhooker,
        .art_symbol_resolver = [](std::string_view s) -> void * {
            std::string name(s); return idh_resolve_sym("libart.so", name.c_str());
        },
        .art_symbol_prefix_resolver = [](std::string_view p) -> void * {
            std::string pre(p); return idh_resolve_sym_prefix("libart.so", pre.c_str());
        },
    };
    bool ok = lsplant::Init(g_init_env, info);
    g_init_ok = ok ? 1 : 0;
    LLOGI("lsplant::Init -> %s", g_init_ok ? "ok" : "FAIL");
}

extern "C" int idh_javahook_init(JNIEnv *env) {
    g_init_env = env;
    pthread_once(&g_init_once, do_init);
    return g_init_ok;
}

extern "C" jobject idh_javahook_hook(JNIEnv *env, jobject target_method, jobject hooker_object, jobject callback_method) {
    if (!g_init_ok) return nullptr;
    return lsplant::Hook(env, target_method, hooker_object, callback_method);
}

extern "C" int idh_javahook_unhook(JNIEnv *env, jobject target_method) {
    return lsplant::UnHook(env, target_method) ? 1 : 0;
}

extern "C" int idh_javahook_is_hooked(JNIEnv *env, jobject method) {
    return lsplant::IsHooked(env, method) ? 1 : 0;
}

// Compute a Dalvik method shorty (return-type char + param-type chars) from a reflected
// Method/Constructor via JNI. Used when the ROM's libart.so does not export
// art::GetMethodShorty (ColorOS/Android 15+ strips that internal-linkage symbol) — LSPlant's
// patched art_method.hpp calls this fallback. Shorty chars: V/Z/B/C/S/I/J/F/D for primitives,
// L for any reference/array. Returns a pointer valid until the next call on the same thread.
static char idh_shorty_char(JNIEnv *env, jclass cls) {
    jclass cClass = env->FindClass("java/lang/Class");
    jmethodID isPrim = env->GetMethodID(cClass, "isPrimitive", "()Z");
    char r = 'L';
    if (env->CallBooleanMethod(cls, isPrim)) {
        jmethodID getName = env->GetMethodID(cClass, "getName", "()Ljava/lang/String;");
        jstring nm = (jstring)env->CallObjectMethod(cls, getName);
        const char *s = nm ? env->GetStringUTFChars(nm, nullptr) : nullptr;
        if (s) {
            if (!strcmp(s, "int")) r = 'I';        else if (!strcmp(s, "boolean")) r = 'Z';
            else if (!strcmp(s, "byte")) r = 'B';  else if (!strcmp(s, "char")) r = 'C';
            else if (!strcmp(s, "short")) r = 'S'; else if (!strcmp(s, "long")) r = 'J';
            else if (!strcmp(s, "float")) r = 'F'; else if (!strcmp(s, "double")) r = 'D';
            else if (!strcmp(s, "void")) r = 'V';
            env->ReleaseStringUTFChars(nm, s);
        }
        if (nm) env->DeleteLocalRef(nm);
    }
    env->DeleteLocalRef(cClass);
    return r;
}
extern "C" const char *idh_compute_shorty(JNIEnv *env, jobject method) {
    static thread_local std::string shorty;
    shorty.clear();
    jclass cMethod = env->FindClass("java/lang/reflect/Method");
    jclass cExec   = env->FindClass("java/lang/reflect/Executable");
    char rc = 'V';                                   // constructors: void return
    if (env->IsInstanceOf(method, cMethod)) {
        jmethodID getRet = env->GetMethodID(cMethod, "getReturnType", "()Ljava/lang/Class;");
        jobject rt = env->CallObjectMethod(method, getRet);
        if (rt) { rc = idh_shorty_char(env, (jclass)rt); env->DeleteLocalRef(rt); }
    }
    shorty.push_back(rc);
    jmethodID getParams = env->GetMethodID(cExec, "getParameterTypes", "()[Ljava/lang/Class;");
    jobjectArray params = (jobjectArray)env->CallObjectMethod(method, getParams);
    jsize n = params ? env->GetArrayLength(params) : 0;
    for (jsize i = 0; i < n; i++) {
        jobject p = env->GetObjectArrayElement(params, i);
        if (p) { shorty.push_back(idh_shorty_char(env, (jclass)p)); env->DeleteLocalRef(p); }
    }
    if (params) env->DeleteLocalRef(params);
    env->DeleteLocalRef(cMethod); env->DeleteLocalRef(cExec);
    LLOGI("computed shorty via reflection: \"%s\"", shorty.c_str());
    return shorty.c_str();
}
