// LSPlant (ART Java-method hook) integration — C++ side. Exposes a C ABI (java_lsplant.h)
// so the pure-C agent_main.c can drive it. Inline-hook backend = Dobby (prebuilt STATIC
// libdobby.a, the exact backend LSPlant's own tests use — self-contained, hooks by address,
// no separate .so / JNI_OnLoad / linker monitor). ART symbol resolution reuses the agent's
// .dynsym parser. LSPlant is pinned to v6.4 (master needs C++23 modules). See fetch_lsplant.sh.
#include "java_lsplant.h"
#include "lsplant.hpp"
#include "dobby.h"

#include <string>
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
