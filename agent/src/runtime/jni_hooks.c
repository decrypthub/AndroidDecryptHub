// Global JNIEnv->RegisterNatives hook. The wrapper observes every native-method
// registration and forwards to the original JNI table entry. It is deliberately
// small and bounded: one JNI_NATIVE capture event per registered method (max 16/table),
// no allocation in the target while the registration lock is held.
#include "jni_hooks.h"

#include "../bootstrap/agent_internal.h"
#include "../capture/capture.h"
#include "../runtime/jni.h"
#ifdef ADH_HAVE_INLINE_HOOK
#include "../hook/native_inline.h"
#endif

#include <jni.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

typedef jint (*register_natives_fn)(JNIEnv *, jclass, const JNINativeMethod *, jint);

static pthread_mutex_t g_jni_hook_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_jni_hook_installed = 0;
static void *g_jni_hook_target = NULL;
static void *g_jni_hook_original_ptr = NULL;
static unsigned long long g_jni_hook_hits = 0;
static int g_jni_hook_last_count = 0;
static char g_jni_hook_error[256] = "";
static __thread int g_jni_hook_in_wrapper = 0;

// A registration is a one-shot event: it happens during library init, usually before capture is
// armed, so pushing it only as a capture record loses it exactly when the caller needs it (the
// field report: "hook installed, hits=6, but nothing to read"). Keep the last N registrations in a
// bounded ring here and expose them through jni_hook action:list.
#define ADH_JNI_REG_SLOTS 256
typedef struct {
    unsigned int seq;
    char cls[192];
    char method[64];
    char signature[256];
    unsigned long long fn;
} adh_jni_registration;
static adh_jni_registration g_jni_regs[ADH_JNI_REG_SLOTS];
static unsigned int g_jni_reg_seq = 0;

static void remember_registration(const char *cls, const char *method, const char *signature, void *fn) {
    unsigned int seq = __atomic_add_fetch(&g_jni_reg_seq, 1, __ATOMIC_RELAXED);
    adh_jni_registration *slot = &g_jni_regs[(seq - 1) % ADH_JNI_REG_SLOTS];
    snprintf(slot->cls, sizeof(slot->cls), "%s", cls ? cls : "");
    snprintf(slot->method, sizeof(slot->method), "%s", method ? method : "");
    snprintf(slot->signature, sizeof(slot->signature), "%s", signature ? signature : "");
    slot->fn = (unsigned long long)(uintptr_t)fn;
    __atomic_store_n(&slot->seq, seq, __ATOMIC_RELEASE);
}

static void set_jni_error(const char *message) {
    snprintf(g_jni_hook_error, sizeof(g_jni_hook_error), "%s", message ? message : "");
}

static jint JNICALL register_natives_wrapper(JNIEnv *env, jclass clazz,
                                             const JNINativeMethod *methods, jint nMethods) {
    register_natives_fn original =
        (register_natives_fn)__atomic_load_n(&g_jni_hook_original_ptr, __ATOMIC_ACQUIRE);
    if (!original) return JNI_ERR;
    if (g_jni_hook_in_wrapper) return original(env, clazz, methods, nMethods);

    g_jni_hook_in_wrapper = 1;
    __atomic_add_fetch(&g_jni_hook_hits, 1, __ATOMIC_RELAXED);
    __atomic_store_n(&g_jni_hook_last_count, nMethods > 0 ? nMethods : 0, __ATOMIC_RELAXED);

    if (methods && nMethods > 0) {
        char class_name[192];
        char class_escaped[400];
        adh_jni_class_name(env, clazz, class_name, sizeof(class_name));
        json_escape(class_name, class_escaped, sizeof(class_escaped));
        int limit = nMethods > 16 ? 16 : (int)nMethods;
        for (int i = 0; i < limit; i++) {
            char name_escaped[256], signature_escaped[256], event[1024];
            json_escape(methods[i].name ? methods[i].name : "", name_escaped, sizeof(name_escaped));
            json_escape(methods[i].signature ? methods[i].signature : "", signature_escaped,
                        sizeof(signature_escaped));
            snprintf(event, sizeof(event),
                     "{\"class\":\"%s\",\"method\":\"%s\",\"signature\":\"%s\","
                     "\"fnPtr\":\"0x%llx\",\"index\":%d,\"total\":%d}",
                     class_escaped, name_escaped, signature_escaped,
                     (unsigned long long)(uintptr_t)methods[i].fnPtr, i, (int)nMethods);
            adh_capture_push_text("JNI_NATIVE", event);
            remember_registration(class_name, methods[i].name, methods[i].signature, methods[i].fnPtr);
        }
    }

    jint result = original(env, clazz, methods, nMethods);
    g_jni_hook_in_wrapper = 0;
    return result;
}

void adh_jni_hook_install_early(void) {
#ifdef ADH_HAVE_INLINE_HOOK
    pthread_mutex_lock(&g_jni_hook_lock);
    int already = g_jni_hook_installed;
    pthread_mutex_unlock(&g_jni_hook_lock);
    if (already) return;
    int did_attach = 0;
    JNIEnv *env = adh_jni_attach(&did_attach);
    if (!env) return;
    void *target = (void *)(*env)->RegisterNatives;
    adh_jni_detach(did_attach);
    if (!target) return;
    __atomic_store_n(&g_jni_hook_original_ptr, (void *)target, __ATOMIC_RELEASE);
    void *original = NULL;
    if (!adh_inline_hook(target, (void *)register_natives_wrapper, &original) || !original) {
        __atomic_store_n(&g_jni_hook_original_ptr, NULL, __ATOMIC_RELEASE);
        return;
    }
    __atomic_store_n(&g_jni_hook_original_ptr, original, __ATOMIC_RELEASE);
    pthread_mutex_lock(&g_jni_hook_lock);
    g_jni_hook_target = target;
    g_jni_hook_installed = 1;
    g_jni_hook_hits = 0;
    g_jni_hook_last_count = 0;
    set_jni_error("");
    pthread_mutex_unlock(&g_jni_hook_lock);
#endif
}

static void send_jni_hook_result(int fd, const char *id, const char *action, int ok,
                                 const char *error) {
    char idj[64], actionj[32], errorj[512];
    json_escape(id, idj, sizeof(idj));
    json_escape(action ? action : "", actionj, sizeof(actionj));
    json_escape(error ? error : "", errorj, sizeof(errorj));
    char out[1024];
    snprintf(out, sizeof(out),
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"jni_hook\",\"ok\":%s,"
             "\"action\":\"%s\",\"installed\":%s,\"hits\":%llu,\"lastCount\":%d,"
             "\"target\":\"0x%llx\",\"error\":\"%s\"}\n",
             idj, ok ? "true" : "false", actionj,
             g_jni_hook_installed ? "true" : "false",
             (unsigned long long)g_jni_hook_hits, g_jni_hook_last_count,
             (unsigned long long)(uintptr_t)g_jni_hook_target, errorj);
    send_line(fd, out);
}

void adh_cmd_jni_hook(int fd, const char *id, const char *action) {
#ifndef ADH_HAVE_INLINE_HOOK
    (void)fd; (void)id; (void)action;
    char idj[64];
    json_escape(id, idj, sizeof(idj));
    char out[260];
    snprintf(out, sizeof(out),
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"jni_hook\",\"ok\":false,"
             "\"error\":\"inline hook backend not built\"}\n", idj);
    send_line(fd, out);
#else
    if (!action || !action[0]) {
        send_jni_hook_result(fd, id, action, 0, "jni_hook requires action: install | uninstall | status");
        return;
    }
    if (strcmp(action, "install") == 0) {
        int did_attach = 0;
        JNIEnv *env = adh_jni_attach(&did_attach);
        if (!env) {
            send_jni_hook_result(fd, id, action, 0, "no JavaVM/JNIEnv");
            return;
        }
        void *target = (void *)(*env)->RegisterNatives;
        adh_jni_detach(did_attach);
        if (!target) {
            send_jni_hook_result(fd, id, action, 0, "JNIEnv->RegisterNatives is null");
            return;
        }
        pthread_mutex_lock(&g_jni_hook_lock);
        if (g_jni_hook_installed) {
            pthread_mutex_unlock(&g_jni_hook_lock);
            send_jni_hook_result(fd, id, action, 0, "RegisterNatives hook already installed");
            return;
        }
        pthread_mutex_unlock(&g_jni_hook_lock);

        // Publish the real function entry before patching so a concurrent RegisterNatives
        // during the install window still reaches the original implementation.
        __atomic_store_n(&g_jni_hook_original_ptr, (void *)target, __ATOMIC_RELEASE);
        void *original = NULL;
        if (!adh_inline_hook(target, (void *)register_natives_wrapper, &original) || !original) {
            __atomic_store_n(&g_jni_hook_original_ptr, NULL, __ATOMIC_RELEASE);
            send_jni_hook_result(fd, id, action, 0, "inline hook installation failed");
            return;
        }
        __atomic_store_n(&g_jni_hook_original_ptr, original, __ATOMIC_RELEASE);
        pthread_mutex_lock(&g_jni_hook_lock);
        g_jni_hook_target = target;
        g_jni_hook_installed = 1;
        g_jni_hook_hits = 0;
        g_jni_hook_last_count = 0;
        set_jni_error("");
        pthread_mutex_unlock(&g_jni_hook_lock);
        send_jni_hook_result(fd, id, action, 1, "");
        return;
    }
    if (strcmp(action, "uninstall") == 0) {
        pthread_mutex_lock(&g_jni_hook_lock);
        if (!g_jni_hook_installed || !g_jni_hook_target) {
            pthread_mutex_unlock(&g_jni_hook_lock);
            send_jni_hook_result(fd, id, action, 0, "RegisterNatives hook is not installed");
            return;
        }
        void *target = g_jni_hook_target;
        pthread_mutex_unlock(&g_jni_hook_lock);
        int ok = adh_inline_unhook(target);
        pthread_mutex_lock(&g_jni_hook_lock);
        if (ok) {
            g_jni_hook_installed = 0;
            set_jni_error("");
        } else {
            set_jni_error("inline unhook failed");
        }
        pthread_mutex_unlock(&g_jni_hook_lock);
        send_jni_hook_result(fd, id, action, ok ? 1 : 0, ok ? "" : "inline unhook failed");
        return;
    }
    if (strcmp(action, "list") == 0) {
        unsigned int total = __atomic_load_n(&g_jni_reg_seq, __ATOMIC_ACQUIRE);
        unsigned int count = total < ADH_JNI_REG_SLOTS ? total : ADH_JNI_REG_SLOTS;
        size_t cap = (size_t)count * 720 + 512;
        char *out = (char *)malloc(cap);
        if (!out) { send_jni_hook_result(fd, id, action, 0, "out of memory"); return; }
        size_t len = 0;
        len += snprintf(out + len, cap - len,
                        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"jni_hook\",\"ok\":true,"
                        "\"action\":\"list\",\"installed\":%s,\"total\":%u,\"count\":%u,"
                        "\"registrations\":[",
                        id, g_jni_hook_installed ? "true" : "false", total, count);
        int written = 0;
        for (unsigned int i = 0; i < count; i++) {
            /* Oldest first: seq numbers run (total-count+1)..total. */
            unsigned int seq = total - count + 1 + i;
            adh_jni_registration *r = &g_jni_regs[(seq - 1) % ADH_JNI_REG_SLOTS];
            if (__atomic_load_n(&r->seq, __ATOMIC_ACQUIRE) != seq) continue;
            char cls_escaped[400], method_escaped[160], signature_escaped[560];
            json_escape(r->cls, cls_escaped, sizeof(cls_escaped));
            json_escape(r->method, method_escaped, sizeof(method_escaped));
            json_escape(r->signature, signature_escaped, sizeof(signature_escaped));
            len += snprintf(out + len, cap > len ? cap - len : 0,
                            "%s{\"seq\":%u,\"class\":\"%s\",\"method\":\"%s\",\"signature\":\"%s\",\"fnPtr\":\"0x%llx\"}",
                            written ? "," : "", seq, cls_escaped, method_escaped, signature_escaped, r->fn);
            written++;
        }
        len += snprintf(out + len, cap > len ? cap - len : 0, "]}\n");
        send_line(fd, out);
        free(out);
        return;
    }
    if (strcmp(action, "status") == 0) {
        send_jni_hook_result(fd, id, action, 1, g_jni_hook_error);
        return;
    }
    send_jni_hook_result(fd, id, action, 0, "jni_hook requires action: install | uninstall | status");
#endif
}