// JNI_OnLoad discovery/hook/invocation for already-loaded native modules.
// Load-time interception is intentionally out of scope here: this module can enumerate,
// patch, and manually invoke an exported JNI_OnLoad after the module is mapped.
#include "jni_onload.h"
#include "dlopen_watch.h"

#include "../bootstrap/agent_internal.h"
#include "../capture/capture.h"
#include "../runtime/jni.h"
#include "../hook/got.h"
#ifdef ADH_HAVE_INLINE_HOOK
#include "../hook/native_inline.h"
#endif

#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef jint (*jni_onload_fn)(JavaVM *, void *);
#define JNI_ONLOAD_MAX_MODULES 512

static pthread_mutex_t g_onload_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_onload_installed = 0;
static int g_onload_active = 0;
static void *g_onload_target = NULL;
static void *g_onload_original = NULL;
static void *g_onload_handle = NULL;
static char g_onload_module[128] = "";
static char g_onload_path[512] = "";
static unsigned long long g_onload_hits = 0;
static jint g_onload_last_ret = 0;
// Load-time watch (v4.30): armed by `jni_onload watch`, consumed by the dlopen wrapper when the
// matching module appears, so JNI_OnLoad is patched BEFORE ART calls it.
static int g_watch_armed = 0;
static int g_watch_skip_original = 0;
static jint g_watch_return_value = 0;
static char g_watch_module[128] = "";
static int g_watch_fired = 0;
static char g_watch_error[192] = "";
// Real unhook support: the bytes under the patch are snapshotted at install time and written back
// by `unhook`, so the onload hook slot is genuinely freed (the soft version kept the patch and
// blocked the next watch). Restored addresses are remembered because Dobby still believes they are
// hooked - re-hooking one is refused loudly instead of silently not patching.
static unsigned char g_onload_prologue[24];
static int g_onload_prologue_len = 0;
#define ADH_ONLOAD_RESTORED_MAX 4
static void *g_onload_restored[ADH_ONLOAD_RESTORED_MAX];
static int g_onload_restored_count = 0;

static int onload_target_restored(void *target) {
    for (int i = 0; i < g_onload_restored_count; i++) if (g_onload_restored[i] == target) return 1;
    return 0;
}
static void remember_onload_restored(void *target) {
    if (onload_target_restored(target)) return;
    if (g_onload_restored_count < ADH_ONLOAD_RESTORED_MAX) g_onload_restored[g_onload_restored_count++] = target;
}
static void snapshot_onload_prologue(void *target) {
    memcpy(g_onload_prologue, target, sizeof(g_onload_prologue));
    g_onload_prologue_len = (int)sizeof(g_onload_prologue);
}
static int restore_onload_prologue(void *target) {
    if (!target || g_onload_prologue_len <= 0) return 0;
    if (!adh_patch_code_bytes(target, g_onload_prologue, (size_t)g_onload_prologue_len)) return 0;
    remember_onload_restored(target);
    g_onload_prologue_len = 0;
    return 1;
}
static int g_onload_skip_original = 0;
static jint g_onload_return_value = 0;
static int g_onload_from_watch = 0;
static __thread int g_onload_in_wrapper = 0;

struct ModuleMatch { const char *wanted; char path[512]; uintptr_t base; int found; };

static const char *base_name(const char *path) {
    if (!path) return "";
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static int module_matches(const char *path, const char *wanted) {
    if (!path || !wanted || !wanted[0]) return 0;
    if (strchr(wanted, '/')) return strcmp(path, wanted) == 0;
    return strcmp(base_name(path), wanted) == 0;
}

static int match_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    struct ModuleMatch *m = (struct ModuleMatch *)data;
    if (!info->dlpi_name || !info->dlpi_name[0]) return 0;
    if (!module_matches(info->dlpi_name, m->wanted)) return 0;
    snprintf(m->path, sizeof(m->path), "%s", info->dlpi_name);
    m->base = (uintptr_t)info->dlpi_addr;
    m->found = 1;
    return 1;
}

static int find_module(const char *wanted, char *path, size_t path_size, uintptr_t *base) {
    struct ModuleMatch m; memset(&m, 0, sizeof(m)); m.wanted = wanted;
    dl_iterate_phdr(match_cb, &m);
    if (!m.found) return 0;
    if (path && path_size) snprintf(path, path_size, "%s", m.path);
    if (base) *base = m.base;
    return 1;
}

static int resolve_onload(const char *module, void **handle_out, void **target_out,
                          char *path_out, size_t path_size) {
    char path[512] = ""; uintptr_t base = 0;
    if (!find_module(module, path, sizeof(path), &base)) return 0;
    void *handle = dlopen(path, RTLD_NOW | RTLD_NOLOAD);
    if (!handle) handle = dlopen(path, RTLD_NOW);
    if (!handle) return 0;
    void *target = dlsym(handle, "JNI_OnLoad");
    if (!target) { dlclose(handle); return 0; }
    if (handle_out) *handle_out = handle;
    if (target_out) *target_out = target;
    if (path_out && path_size) snprintf(path_out, path_size, "%s", path);
    return 1;
}

static jint JNICALL onload_wrapper(JavaVM *vm, void *reserved) {
    jni_onload_fn original = (jni_onload_fn)g_onload_original;
    if (!original) return JNI_ERR;
    if (g_onload_in_wrapper || !g_onload_active) return original(vm, reserved);
    g_onload_in_wrapper = 1;
    __atomic_add_fetch(&g_onload_hits, 1, __ATOMIC_RELAXED);
    int skipped = g_onload_skip_original;
    jint ret = skipped ? g_onload_return_value : original(vm, reserved);
    g_onload_last_ret = ret;
    char json[768];
    snprintf(json, sizeof(json),
             "{\"module\":\"%s\",\"retval\":%d,\"hits\":%llu,\"phase\":\"%s\",\"skipped\":%s}",
             g_onload_module, (int)ret, (unsigned long long)g_onload_hits,
             g_onload_from_watch ? "load" : "manual", skipped ? "true" : "false");
    adh_capture_push_text("JNI_ONLOAD", json);
    g_onload_in_wrapper = 0;
    return ret;
}

static void send_action_result(int fd, const char *id, const char *action, int ok,
                               const char *module, const char *error, const char *extra) {
    char idj[64], actionj[32], modulej[256], errorj[512];
    json_escape(id, idj, sizeof(idj));
    json_escape(action ? action : "", actionj, sizeof(actionj));
    json_escape(module ? module : "", modulej, sizeof(modulej));
    json_escape(error ? error : "", errorj, sizeof(errorj));
    char out[2048];
    snprintf(out, sizeof(out),
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"jni_onload\",\"ok\":%s,"
             "\"action\":\"%s\",\"module\":\"%s\",\"installed\":%s,\"active\":%s,"
             "\"hits\":%llu,\"lastRet\":%d,\"target\":\"0x%llx\",\"error\":\"%s\"%s%s}\n",
             idj, ok ? "true" : "false", actionj, modulej,
             g_onload_installed ? "true" : "false", g_onload_active ? "true" : "false",
             (unsigned long long)g_onload_hits, (int)g_onload_last_ret,
             (unsigned long long)(uintptr_t)g_onload_target, errorj,
             extra && extra[0] ? "," : "", extra ? extra : "");
    send_line(fd, out);
}

struct OnloadEntry { char path[512]; uintptr_t base; };
struct PathState { struct OnloadEntry *entries; int *count; };

static int collect_module_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    struct PathState *s = (struct PathState *)data;
    if (!info->dlpi_name || !info->dlpi_name[0]) return 0;
    if (!strstr(info->dlpi_name, ".so")) return 0;
    for (int i = 0; i < *s->count; i++)
        if (strcmp(s->entries[i].path, info->dlpi_name) == 0) return 0;
    if (*s->count >= JNI_ONLOAD_MAX_MODULES) return 1;
    snprintf(s->entries[*s->count].path, sizeof(s->entries[0].path), "%s", info->dlpi_name);
    s->entries[*s->count].base = (uintptr_t)info->dlpi_addr;
    (*s->count)++;
    return 0;
}
static void list_onload_modules(int fd, const char *id) {
    static struct OnloadEntry entries[JNI_ONLOAD_MAX_MODULES];
    int count = 0;
    struct PathState state = { entries, &count };
    dl_iterate_phdr(collect_module_cb, &state);
    LOGI("jni_onload list scanned=%d", count);
    for (int i = 0; i < count; i++) {
        if (strstr(entries[i].path, "adh")) LOGI("jni_onload list path[%d]=%s", i, entries[i].path);
    }

    char *out = (char *)malloc(64 * 1024);
    if (!out) { send_oom(fd, id, "jni_onload"); return; }
    char idj[64]; json_escape(id, idj, sizeof(idj));
    size_t len = snprintf(out, 64 * 1024,
                          "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"jni_onload\",\"ok\":true,"
                          "\"action\":\"list\",\"count\":%d,\"modules\":[", idj, count);
    int found = 0;
    for (int i = 0; i < count && found < 128 && len + 1024 < 64 * 1024; i++) {
        void *handle = dlopen(entries[i].path, RTLD_NOW | RTLD_NOLOAD);
        if (!handle) continue;
        void *target = dlsym(handle, "JNI_OnLoad");
        if (target) {
            char pathj[1024], namej[256];
            json_escape(entries[i].path, pathj, sizeof(pathj));
            json_escape(base_name(entries[i].path), namej, sizeof(namej));
            len += snprintf(out + len, 64 * 1024 - len,
                            "%s{\"module\":\"%s\",\"path\":\"%s\",\"base\":\"0x%llx\",\"target\":\"0x%llx\"}",
                            found ? "," : "", namej, pathj,
                            (unsigned long long)entries[i].base, (unsigned long long)(uintptr_t)target);
            found++;
        }
        dlclose(handle);
    }
    snprintf(out + len, 64 * 1024 - len, "],\"found\":%d}\n", found);
    send_line(fd, out); free(out);
}

// Called by the dlopen watch once a newly loaded module is mapped and BEFORE the VM calls its
// JNI_OnLoad, so the patch is in place for the real load-time call. One-shot per watch command.
int adh_jni_onload_on_module_loaded(const char *path, void *handle, char *error, size_t error_size) {
#ifndef ADH_HAVE_INLINE_HOOK
    (void)path; (void)handle; (void)error; (void)error_size;
    return 0;
#else
    if (!path || !handle) return 0;
    pthread_mutex_lock(&g_onload_lock);
    int armed = g_watch_armed;
    char wanted[128];
    snprintf(wanted, sizeof(wanted), "%s", g_watch_module);
    int skip = g_watch_skip_original;
    jint ret_value = g_watch_return_value;
    pthread_mutex_unlock(&g_onload_lock);
    if (!armed) return 0;
    const char *base = base_name(path);
    int matches = strchr(wanted, '/') ? strcmp(path, wanted) == 0 : strcmp(base, wanted) == 0;
    if (!matches) return 0;
    void *target = dlsym(handle, "JNI_OnLoad");
    if (!target) {
        snprintf(error, error_size, "%s has no JNI_OnLoad", base);
        pthread_mutex_lock(&g_onload_lock);
        snprintf(g_watch_error, sizeof(g_watch_error), "%s", error);
        g_watch_armed = 0;
        pthread_mutex_unlock(&g_onload_lock);
        char miss[320];
        snprintf(miss, sizeof(miss), "{\"module\":\"%s\",\"phase\":\"watch-miss\",\"error\":\"%s\"}", base, error);
        adh_capture_push_text("JNI_ONLOAD", miss);
        return 0;
    }
    pthread_mutex_lock(&g_onload_lock);
    if (g_onload_installed && g_onload_target != target) {
        pthread_mutex_unlock(&g_onload_lock);
        snprintf(error, error_size, "another JNI_OnLoad hook is active; watch not applied to %s", base);
        pthread_mutex_lock(&g_onload_lock);
        snprintf(g_watch_error, sizeof(g_watch_error), "%s", error);
        g_watch_armed = 0;
        pthread_mutex_unlock(&g_onload_lock);
        char miss2[320];
        snprintf(miss2, sizeof(miss2), "{\"module\":\"%s\",\"phase\":\"watch-miss\",\"error\":\"%s\"}", base, error);
        adh_capture_push_text("JNI_ONLOAD", miss2);
        return 0;
    }
    g_watch_armed = 0;
    g_watch_fired = 1;
    pthread_mutex_unlock(&g_onload_lock);
    if (onload_target_restored(target)) {
        snprintf(error, error_size, "target was hard-unhooked earlier in this process: restart the target before hooking it again");
        return 0;
    }
    snapshot_onload_prologue(target);
    void *original = NULL;
    if (!adh_inline_hook(target, (void *)onload_wrapper, &original) || !original) {
        snprintf(error, error_size, "JNI_OnLoad inline hook failed for %s", base);
        return 0;
    }
    pthread_mutex_lock(&g_onload_lock);
    g_onload_handle = NULL;
    g_onload_target = target;
    g_onload_original = original;
    g_onload_installed = 1;
    g_onload_active = 1;
    g_onload_hits = 0;
    g_onload_last_ret = 0;
    g_onload_skip_original = skip;
    g_onload_return_value = ret_value;
    g_onload_from_watch = 1;
    snprintf(g_onload_module, sizeof(g_onload_module), "%s", base);
    snprintf(g_onload_path, sizeof(g_onload_path), "%s", path);
    pthread_mutex_unlock(&g_onload_lock);
    LOGI("jni_onload watch fired for %s (target=%p skip=%d)", base, target, skip);
    return 1;
#endif
}
void adh_cmd_jni_onload(int fd, const char *id, const char *action, const char *module,
                        int skip_original, int return_value) {
#ifndef ADH_HAVE_INLINE_HOOK
    (void)fd; (void)id; (void)action; (void)module;
    char out[256]; char idj[64]; json_escape(id, idj, sizeof(idj));
    snprintf(out, sizeof(out),
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"jni_onload\",\"ok\":false,"
             "\"error\":\"inline hook backend not built\"}\n", idj);
    send_line(fd, out);
#else
    if (!action || !action[0]) { send_action_result(fd, id, action, 0, module, "jni_onload requires action", ""); return; }
    if (strcmp(action, "list") == 0) { list_onload_modules(fd, id); return; }
    if (strcmp(action, "status") == 0) {
        char extra[384];
        pthread_mutex_lock(&g_onload_lock);
        snprintf(extra, sizeof(extra),
                 "\"watch\":{\"armed\":%s,\"fired\":%s,\"module\":\"%s\",\"skipOriginal\":%s,\"returnValue\":%d,\"error\":\"%s\"},\"dlopenWatch\":%d",
                 g_watch_armed ? "true" : "false", g_watch_fired ? "true" : "false", g_watch_module,
                 g_onload_skip_original ? "true" : "false", (int)g_onload_return_value, g_watch_error, adh_dlopen_watch_installed());
        pthread_mutex_unlock(&g_onload_lock);
        send_action_result(fd, id, action, 1, g_onload_module, "", extra);
        return;
    }
    if (strcmp(action, "unwatch") == 0) {
        pthread_mutex_lock(&g_onload_lock);
        g_watch_armed = 0;
        g_watch_module[0] = 0;
        pthread_mutex_unlock(&g_onload_lock);
        send_action_result(fd, id, action, 1, "", "", "\"watch\":{\"armed\":false}");
        return;
    }
    if (!module || !module[0]) { send_action_result(fd, id, action, 0, "", "jni_onload requires module", ""); return; }
    if (strcmp(action, "watch") == 0) {
        char derr[256] = "";
        if (!adh_dlopen_watch_install(derr, sizeof(derr))) {
            send_action_result(fd, id, action, 0, module, derr[0] ? derr : "dlopen watch install failed", "");
            return;
        }
        pthread_mutex_lock(&g_onload_lock);
        if (g_onload_installed && g_onload_active) {
            pthread_mutex_unlock(&g_onload_lock);
            send_action_result(fd, id, action, 0, module,
                               "a JNI_OnLoad hook is already active; unhook it before arming a new watch", "");
            return;
        }
        g_watch_armed = 1;
        g_watch_fired = 0;
        g_watch_error[0] = 0;
        g_watch_skip_original = skip_original;
        g_watch_return_value = (jint)return_value;
        snprintf(g_watch_module, sizeof(g_watch_module), "%s", module);
        int hook_installed = adh_dlopen_watch_installed();
        pthread_mutex_unlock(&g_onload_lock);
        char extra[320];
        snprintf(extra, sizeof(extra),
                 "\"watch\":{\"armed\":true,\"module\":\"%s\",\"skipOriginal\":%s,\"returnValue\":%d},\"dlopenWatch\":%d",
                 module, skip_original ? "true" : "false", return_value, hook_installed);
        send_action_result(fd, id, action, 1, module, "", extra);
        return;
    }
    if (strcmp(action, "hook") == 0) {
        char path[512] = ""; void *handle = NULL, *target = NULL;
        if (!resolve_onload(module, &handle, &target, path, sizeof(path))) {
            send_action_result(fd, id, action, 0, module, "JNI_OnLoad not found in loaded module", ""); return;
        }
        pthread_mutex_lock(&g_onload_lock);
        if (g_onload_installed && g_onload_target == target) {
            g_onload_active = 1; g_onload_hits = 0; pthread_mutex_unlock(&g_onload_lock); dlclose(handle);
            send_action_result(fd, id, action, 1, g_onload_module, "", ""); return;
        }
        if (g_onload_installed) {
            pthread_mutex_unlock(&g_onload_lock); dlclose(handle);
            send_action_result(fd, id, action, 0, module, "another JNI_OnLoad hook is active", ""); return;
        }
        pthread_mutex_unlock(&g_onload_lock);
        if (onload_target_restored(target)) {
            dlclose(handle);
            send_action_result(fd, id, action, 0, module, "target was hard-unhooked earlier in this process: restart the target before hooking it again", "");
            return;
        }
        snapshot_onload_prologue(target);
        void *original = NULL;
        if (!adh_inline_hook(target, (void *)onload_wrapper, &original) || !original) {
            dlclose(handle); send_action_result(fd, id, action, 0, module, "JNI_OnLoad inline hook failed", ""); return;
        }
        pthread_mutex_lock(&g_onload_lock);
        g_onload_handle = handle; g_onload_target = target; g_onload_original = original;
        g_onload_installed = 1; g_onload_active = 1; g_onload_hits = 0; g_onload_last_ret = 0;
        snprintf(g_onload_module, sizeof(g_onload_module), "%s", base_name(path));
        snprintf(g_onload_path, sizeof(g_onload_path), "%s", path);
        pthread_mutex_unlock(&g_onload_lock);
        send_action_result(fd, id, action, 1, g_onload_module, "", ""); return;
    }
    if (strcmp(action, "unhook") == 0) {
        pthread_mutex_lock(&g_onload_lock);
        if (!g_onload_installed || !g_onload_target) { pthread_mutex_unlock(&g_onload_lock); send_action_result(fd, id, action, 0, module, "JNI_OnLoad hook is not installed", ""); return; }
        void *hooked_target = g_onload_target;
        char hooked_module[128];
        snprintf(hooked_module, sizeof(hooked_module), "%s", g_onload_module);
        pthread_mutex_unlock(&g_onload_lock);
        if (!restore_onload_prologue(hooked_target)) {
            send_action_result(fd, id, action, 0, hooked_module, "failed to restore the original JNI_OnLoad bytes (hook stays patched)", "");
            return;
        }
        pthread_mutex_lock(&g_onload_lock);
        g_onload_installed = 0; g_onload_active = 0; g_onload_target = NULL; g_onload_original = NULL;
        g_onload_skip_original = 0; g_onload_from_watch = 0;
        pthread_mutex_unlock(&g_onload_lock);
        LOGI("jni_onload restored original bytes for %s", hooked_module);
        send_action_result(fd, id, action, 1, hooked_module, "", ""); return;
    }
    if (strcmp(action, "call") == 0) {
        char path[512] = ""; void *handle = NULL, *target = NULL;
        pthread_mutex_lock(&g_onload_lock);
        if (g_onload_installed && g_onload_target) target = g_onload_target;
        pthread_mutex_unlock(&g_onload_lock);
        if (!target && !resolve_onload(module, &handle, &target, path, sizeof(path))) {
            send_action_result(fd, id, action, 0, module, "JNI_OnLoad not found", ""); return;
        }
        int did_attach = 0; JNIEnv *env = adh_jni_attach(&did_attach); JavaVM *vm = adh_jni_get_vm();
        if (env && did_attach) adh_jni_detach(did_attach);
        if (!vm) { if (handle) dlclose(handle); send_action_result(fd, id, action, 0, module, "JavaVM unavailable", ""); return; }
        jint ret = ((jni_onload_fn)target)(vm, NULL);
        pthread_mutex_lock(&g_onload_lock); g_onload_last_ret = ret; pthread_mutex_unlock(&g_onload_lock);
        if (handle) dlclose(handle);
        char extra[128]; snprintf(extra, sizeof(extra), "\"retval\":%d", (int)ret);
        send_action_result(fd, id, action, 1, module, "", extra); return;
    }
    send_action_result(fd, id, action, 0, module, "jni_onload action must be list|hook|unhook|call|status", "");
#endif
}