// Runtime library-load watch: patch JNI_OnLoad between dlopen() returning and the VM calling it.
//
// The VM's load path is dlopen (or android_dlopen_ext) followed by dlsym("JNI_OnLoad") and the
// call. Patching the entry point and re-mapping inside the wrapper therefore happens at exactly
// the right moment: the module is mapped, the VM has not called JNI_OnLoad yet.
//
// Scope: exactly ONE dlopen entry point is hooked (the first one that resolves), the wrapper is
// inert unless a watch is armed, and the watch is one-shot. Nothing here runs for the agent's own
// library loads unless a watch is armed for that library name.

#include "dlopen_watch.h"

#include "../bootstrap/agent_internal.h"
#include "../hook/got.h"
#include "../hook/native_inline.h"
#include "jni_onload.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

typedef void *(*dlopen_fn)(const char *, int);
typedef void *(*dlopen_ext_fn)(const char *, int, const void *);

static pthread_mutex_t g_watch_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_watch_installed = 0;
static void *g_watch_target = NULL;
static void *g_watch_original = NULL;
static char g_watch_symbol[64] = "";
static __thread int g_watch_in_wrapper = 0;

static void *watch_common(const char *file, void *handle) {
    if (!handle || g_watch_in_wrapper) return handle;
    char error[192] = "";
    g_watch_in_wrapper = 1;
    if (adh_jni_onload_on_module_loaded(file ? file : "", handle, error, sizeof(error))) {
        LOGI("dlopen watch: JNI_OnLoad patched before the VM call for %s", file ? file : "?");
    } else if (error[0]) {
        LOGI("dlopen watch: %s", error);
    }
    g_watch_in_wrapper = 0;
    return handle;
}

static void *dlopen_wrapper(const char *file, int flags) {
    dlopen_fn original = (dlopen_fn)g_watch_original;
    if (!original) return NULL;
    void *handle = original(file, flags);
    return watch_common(file, handle);
}

static void *dlopen_ext_wrapper(const char *file, int flags, const void *info) {
    dlopen_ext_fn original = (dlopen_ext_fn)g_watch_original;
    if (!original) return NULL;
    void *handle = original(file, flags, info);
    return watch_common(file, handle);
}

int adh_dlopen_watch_installed(void) {
    return __atomic_load_n(&g_watch_installed, __ATOMIC_ACQUIRE);
}

int adh_dlopen_watch_install(char *error, size_t error_size) {
    pthread_mutex_lock(&g_watch_lock);
    if (g_watch_installed) {
        pthread_mutex_unlock(&g_watch_lock);
        return 1;
    }
    pthread_mutex_unlock(&g_watch_lock);

    // Prefer the namespace-aware entry the VM actually uses; fall back to plain dlopen.
    const char *symbols[3] = { "android_dlopen_ext", "dlopen", "__loader_android_dlopen_ext" };
    void *target = NULL;
    const char *chosen = NULL;
    for (int i = 0; i < 3 && !target; i++) {
        target = adh_resolve_sym("libdl.so", symbols[i]);
        if (!target) target = dlsym(RTLD_DEFAULT, symbols[i]);
        if (target) chosen = symbols[i];
    }
    if (!target || !chosen) {
        snprintf(error, error_size, "no dlopen entry point found (android_dlopen_ext/dlopen)");
        return 0;
    }
    void *replacement = strcmp(chosen, "android_dlopen_ext") == 0
                      ? (void *)&dlopen_ext_wrapper : (void *)&dlopen_wrapper;
    void *original = NULL;
    if (!adh_inline_hook(target, replacement, &original) || !original) {
        snprintf(error, error_size, "inline hook on %s failed", chosen);
        return 0;
    }
    pthread_mutex_lock(&g_watch_lock);
    g_watch_target = target;
    g_watch_original = original;
    snprintf(g_watch_symbol, sizeof(g_watch_symbol), "%s", chosen);
    g_watch_installed = 1;
    pthread_mutex_unlock(&g_watch_lock);
    LOGI("dlopen watch installed on %s (target=%p)", chosen, target);
    return 1;
}