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
#include "../capture/capture.h"
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
// Two slots, because there are two real entry points: 0 = dlopen, 1 = android_dlopen_ext (or the
// loader's __loader_ alias when the public name is absent). Each keeps its OWN original so the two
// trampolines never share state.
static void *g_watch_targets[2] = { NULL, NULL };
static void *g_watch_originals[2] = { NULL, NULL };
static char g_watch_symbols[2][64] = { "", "" };
static __thread int g_watch_in_wrapper = 0;

static void copy_sym_name(int slot, const char *name) {
    if (slot < 0 || slot > 1) return;
    strncpy(g_watch_symbols[slot], name, sizeof(g_watch_symbols[slot]) - 1);
    g_watch_symbols[slot][sizeof(g_watch_symbols[slot]) - 1] = 0;
}
// Module-load broadcast. Unlike the JNI_OnLoad watch (one-shot, per library name), this reports
// EVERY library that gets mapped while it is on. The initial map of an already-loaded module never
// passes here, so a VMP/抽取壳 payload that decrypts itself into a fresh mapping is exactly what
// this catches: the host can dump or hook it at its first appearance instead of noticing a new
// region in `maps` later.
static int g_module_watch = 0;

// Base/size of a just-mapped file from /proc/self/maps. Loader handles carry no address, and
// dlinfo is not available on every API level this agent supports, so the mapping itself is the
// source of truth (same rule the rest of the agent follows). A soname ("liblog.so") matches by
// basename; a full path must match exactly.
static int module_extent(const char *file, unsigned long long *base, unsigned long long *size) {
    if (!file || !file[0]) return 0;
    const char *slash = strrchr(file, '/');
    const char *want = slash ? slash + 1 : file;
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return 0;
    char line[1024];
    unsigned long long lo = 0, hi = 0;
    while (fgets(line, sizeof(line), m)) {
        unsigned long long s = 0, e = 0;
        char perms[8] = "", path[700] = "";
        if (sscanf(line, "%llx-%llx %7s %*s %*s %*s %699[^\n]", &s, &e, perms, path) < 4) continue;
        char *p = path; while (*p == ' ') p++;
        const char *ps = strrchr(p, '/');
        const char *pn = ps ? ps + 1 : p;
        if (strcmp(pn, want) != 0 && strcmp(p, file) != 0) continue;
        if (!lo || s < lo) lo = s;
        if (e > hi) hi = e;
    }
    fclose(m);
    if (!lo) return 0;
    *base = lo;
    *size = hi - lo;
    return 1;
}

static void emit_module_load(const char *file, void *handle) {
    if (!file || !file[0] || !handle) return;
    unsigned long long base = 0, size = 0;
    const int mapped = module_extent(file, &base, &size);
    char pathj[900];
    json_escape(file, pathj, sizeof(pathj));
    char json[1200];
    snprintf(json, sizeof(json),
             "{\"path\":\"%s\",\"handle\":\"0x%llx\",\"base\":\"0x%llx\",\"size\":%llu,\"mapped\":%s}",
             pathj, (unsigned long long)(uintptr_t)handle, base, size, mapped ? "true" : "false");
    adh_capture_push_text("MODULE_LOAD", json);
}

static void *watch_common(const char *file, void *handle) {
    if (!handle || g_watch_in_wrapper) return handle;
    char error[192] = "";
    g_watch_in_wrapper = 1;
    if (__atomic_load_n(&g_module_watch, __ATOMIC_RELAXED)) emit_module_load(file, handle);
    if (adh_jni_onload_on_module_loaded(file ? file : "", handle, error, sizeof(error))) {
        LOGI("dlopen watch: JNI_OnLoad patched before the VM call for %s", file ? file : "?");
    } else if (error[0]) {
        LOGI("dlopen watch: %s", error);
    }
    g_watch_in_wrapper = 0;
    return handle;
}

static void *dlopen_wrapper(const char *file, int flags) {
    dlopen_fn original = (dlopen_fn)__atomic_load_n(&g_watch_originals[0], __ATOMIC_ACQUIRE);
    if (!original) return NULL;
    void *handle = original(file, flags);
    return watch_common(file, handle);
}

static void *dlopen_ext_wrapper(const char *file, int flags, const void *info) {
    dlopen_ext_fn original = (dlopen_ext_fn)__atomic_load_n(&g_watch_originals[1], __ATOMIC_ACQUIRE);
    if (!original) return NULL;
    void *handle = original(file, flags, info);
    return watch_common(file, handle);
}

int adh_dlopen_watch_installed(void) {
    return (__atomic_load_n(&g_watch_originals[0], __ATOMIC_ACQUIRE) ||
            __atomic_load_n(&g_watch_originals[1], __ATOMIC_ACQUIRE)) ? 1 : 0;
}

// TWO entry points, not one. The VM's own load path is android_dlopen_ext, but ordinary code
// (including the agent's `load_so`, and most app JNI libraries) calls plain dlopen: hooking only
// the first entry that resolves made MODULE_LOAD blind to exactly the loads an operator triggers.
// Both wrappers keep their own original so neither trampoline is shared.
static int install_slot(int slot, const char *name, void *replacement, char *error, size_t error_size) {
    if (__atomic_load_n(&g_watch_originals[slot], __ATOMIC_ACQUIRE)) return 1;   // already hooked
    void *target = adh_resolve_sym("libdl.so", name);
    if (!target) target = dlsym(RTLD_DEFAULT, name);
    if (!target) return 0;
    void *original = NULL;
    if (!adh_inline_hook(target, replacement, &original) || !original) {
        snprintf(error, error_size, "inline hook on %s failed", name);
        return -1;
    }
    g_watch_targets[slot] = target;
    __atomic_store_n(&g_watch_originals[slot], original, __ATOMIC_RELEASE);
    copy_sym_name(slot, name);
    LOGI("dlopen watch installed on %s (target=%p)", name, target);
    return 1;
}

int adh_dlopen_watch_install(char *error, size_t error_size) {
    pthread_mutex_lock(&g_watch_lock);
    if (g_watch_originals[0] || g_watch_originals[1]) {
        pthread_mutex_unlock(&g_watch_lock);
        return 1;
    }
    pthread_mutex_unlock(&g_watch_lock);

    int ok = 0;
    // Plain dlopen first: it is what app code and the agent's own `load_so` call.
    int r0 = install_slot(0, "dlopen", (void *)&dlopen_wrapper, error, error_size);
    if (r0 < 0) return 0;
    if (r0 > 0) ok = 1;
    // The VM's namespace-aware entry; the loader's alias covers ROMs that do not export the name.
    int r1 = install_slot(1, "android_dlopen_ext", (void *)&dlopen_ext_wrapper, error, error_size);
    if (r1 == 0) r1 = install_slot(1, "__loader_android_dlopen_ext", (void *)&dlopen_ext_wrapper, error, error_size);
    if (r1 < 0) return 0;
    if (r1 > 0) ok = 1;
    if (!ok) {
        snprintf(error, error_size, "no dlopen entry point found (dlopen/android_dlopen_ext)");
        return 0;
    }
    LOGI("dlopen watch ready (dlopen=%d android_dlopen_ext=%d)",
         g_watch_originals[0] ? 1 : 0, g_watch_originals[1] ? 1 : 0);
    return 1;
}

int adh_module_watch_on(void) {
    return __atomic_load_n(&g_module_watch, __ATOMIC_ACQUIRE);
}

// Module-load broadcast: on = install the dlopen hook (once) and report every subsequent load.
// Off leaves the hook installed but inert, so re-arming does not pay a second inline patch.
void adh_cmd_module_watch(int fd, const char *id, const char *action) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    char error[192] = "";
    int ok = 1;
    if (strcmp(action, "start") == 0) {
        if (!adh_dlopen_watch_install(error, sizeof(error))) ok = 0;
        else __atomic_store_n(&g_module_watch, 1, __ATOMIC_RELEASE);
    } else if (strcmp(action, "stop") == 0) {
        __atomic_store_n(&g_module_watch, 0, __ATOMIC_RELEASE);
    } else if (strcmp(action, "status") != 0) {
        snprintf(error, sizeof(error), "module_watch requires action: start | stop | status");
        ok = 0;
    }
    char errj[256]; json_escape(error, errj, sizeof(errj));
    char out[512];
    snprintf(out, sizeof(out),
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"module_watch\",\"ok\":%s,\"action\":\"%s\","
             "\"watching\":%s,\"installed\":%s,\"error\":\"%s\"}\n",
             idj, ok ? "true" : "false", action,
             adh_module_watch_on() ? "true" : "false",
             adh_dlopen_watch_installed() ? "true" : "false", errj);
    send_line(fd, out);
    LOGI("module_watch: action=%s ok=%d watching=%d installed=%d %s",
         action, ok, adh_module_watch_on(), adh_dlopen_watch_installed(), error);
}