// LSPlant (ART Java-method hook) integration — C++ side.
//
// LSPlant v6.4 is compiled directly into libadh_agent.so. The inline-hook backend is the
// existing statically linked Dobby implementation, exposed through native_inline.h. ART
// symbol resolution reuses the agent's in-memory .dynsym resolver from got.h.
//
// LSPlant is not initialized during JNI_OnLoad. adh_javahook_init() is a lazy, explicit
// operation so the default injection footprint and startup behavior stay unchanged.
#include "java_lsplant.h"
#include "got.h"
#include "lsplant.hpp"
#include "native_inline.h"

#include <android/log.h>
#include <cstring>
#include <pthread.h>
#include <string>

#define LTAG "ADH_LSP"
#define LLOGI(...) __android_log_print(ANDROID_LOG_INFO,  LTAG, __VA_ARGS__)
#define LLOGE(...) __android_log_print(ANDROID_LOG_ERROR, LTAG, __VA_ARGS__)

// ---- Dobby adapter (LSPlant inline_hooker/unhooker contract) -------------------------
static void *dobby_hooker(void *target, void *hooker) {
    void *origin = nullptr;
    if (!adh_inline_hook(target, hooker, &origin)) {
        LLOGE("inline hook failed target=%p", target);
        return nullptr;
    }
    return origin;                       // LSPlant wants the backup/original callable
}

static bool dobby_unhooker(void *func) {
    return adh_inline_unhook(func) != 0;
}

// ---- one-time LSPlant init -------------------------------------------------------------
static int g_init_ok = 0;
static char g_init_error[256] = "";
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;
static JNIEnv *g_init_env = nullptr;

static void set_init_error(const char *message) {
    if (!message) message = "unknown LSPlant initialization failure";
    std::strncpy(g_init_error, message, sizeof(g_init_error) - 1);
    g_init_error[sizeof(g_init_error) - 1] = 0;
}

static void do_init(void) {
    if (!g_init_env) {
        set_init_error("no JavaVM/JNIEnv available");
        return;
    }

    lsplant::InitInfo info{
        .inline_hooker = dobby_hooker,
        .inline_unhooker = dobby_unhooker,
        .art_symbol_resolver = [](std::string_view s) -> void * {
            std::string name(s);
            return adh_resolve_sym("libart.so", name.c_str());
        },
        .art_symbol_prefix_resolver = [](std::string_view p) -> void * {
            std::string prefix(p);
            return adh_resolve_sym_prefix("libart.so", prefix.c_str());
        },
    };

    try {
        g_init_ok = lsplant::Init(g_init_env, info) ? 1 : 0;
    } catch (...) {
        g_init_ok = 0;
        set_init_error("LSPlant init threw a C++ exception");
    }

    if (g_init_ok) {
        g_init_error[0] = 0;
        LLOGI("lsplant::Init -> ok");
    } else {
        if (!g_init_error[0]) set_init_error("lsplant::Init returned false (check logcat tag ADH_LSP)");
        LLOGE("lsplant::Init -> FAIL: %s", g_init_error);
    }
}

extern "C" int adh_javahook_available(void) {
    return 1;
}

extern "C" int adh_javahook_init(JNIEnv *env) {
    if (!env) {
        set_init_error("no JavaVM/JNIEnv available");
        return 0;
    }
    g_init_env = env;
    pthread_once(&g_init_once, do_init);
    return g_init_ok;
}

extern "C" const char *adh_javahook_last_error(void) {
    return g_init_error;
}

extern "C" jobject adh_javahook_hook(JNIEnv *env, jobject target_method,
                                     jobject hooker_object, jobject callback_method) {
    if (!g_init_ok || !env || !target_method || !hooker_object || !callback_method) return nullptr;
    return lsplant::Hook(env, target_method, hooker_object, callback_method);
}

extern "C" int adh_javahook_unhook(JNIEnv *env, jobject target_method) {
    if (!g_init_ok || !env || !target_method) return 0;
    return lsplant::UnHook(env, target_method) ? 1 : 0;
}

extern "C" int adh_javahook_is_hooked(JNIEnv *env, jobject method) {
    if (!env || !method) return 0;
    return lsplant::IsHooked(env, method) ? 1 : 0;
}

// Compute a Dalvik method shorty (return-type char + param-type chars) from a reflected
// Method/Constructor via JNI. Used when the ROM's libart.so does not export
// art::GetMethodShorty (ColorOS/Android 15+ strips that internal-linkage symbol) — LSPlant's
// patched art_method.hpp calls this fallback. Shorty chars: V/Z/B/C/S/I/J/F/D for primitives,
// L for any reference/array. Returns a pointer valid until the next call on the same thread.
static char adh_shorty_char(JNIEnv *env, jclass cls) {
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

extern "C" const char *adh_compute_shorty(JNIEnv *env, jobject method) {
    static thread_local std::string shorty;
    shorty.clear();
    jclass cMethod = env->FindClass("java/lang/reflect/Method");
    jclass cExec = env->FindClass("java/lang/reflect/Executable");
    char rc = 'V';                                   // constructors: void return
    if (env->IsInstanceOf(method, cMethod)) {
        jmethodID getRet = env->GetMethodID(cMethod, "getReturnType", "()Ljava/lang/Class;");
        jobject rt = env->CallObjectMethod(method, getRet);
        if (rt) {
            rc = adh_shorty_char(env, (jclass)rt);
            env->DeleteLocalRef(rt);
        }
    }
    shorty.push_back(rc);
    jmethodID getParams = env->GetMethodID(cExec, "getParameterTypes", "()[Ljava/lang/Class;");
    jobjectArray params = (jobjectArray)env->CallObjectMethod(method, getParams);
    jsize n = params ? env->GetArrayLength(params) : 0;
    for (jsize i = 0; i < n; i++) {
        jobject p = env->GetObjectArrayElement(params, i);
        if (p) {
            shorty.push_back(adh_shorty_char(env, (jclass)p));
            env->DeleteLocalRef(p);
        }
    }
    if (params) env->DeleteLocalRef(params);
    env->DeleteLocalRef(cMethod);
    env->DeleteLocalRef(cExec);
    LLOGI("computed shorty via reflection: \"%s\"", shorty.c_str());
    return shorty.c_str();
}