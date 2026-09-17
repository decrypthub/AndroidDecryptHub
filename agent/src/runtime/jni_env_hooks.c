// Per-entry hooks on the JNIEnv function table. In C a JNIEnv* points at a table of
// function pointers, so swapping one aligned 8-byte slot intercepts every JNI call that goes
// through that env (all envs of a VM share the table). No trampoline is involved: the saved
// slot value is the real implementation and uninstall writes it back, so this feature has
// neither a patch/UAF window nor a hard-unhook problem.
//
// Hot-path rules (a hooked entry runs on target threads, forever):
//   * every intercepted call is counted in `hits` (success or failure) and at most
//     ENV_EVENT_LIMIT records are emitted per slot; past that only `dropped` grows;
//   * anything expensive — class-name reflection, payload preview, string copy — is gated on
//     env_budget_left() so the steady-state cost of a spent slot is one atomic add;
//   * the wrappers never block or allocate: capture is written through its own try-lock ring.
// Member-ID wrappers do not touch the caller's exception state: a failed lookup is reported
// with ok=false and no reflection (calling JNI with a pending exception aborts under CheckJNI).

#include "jni_env_hooks.h"

#include "../bootstrap/agent_internal.h"
#include "../capture/capture.h"
#include "../hook/got.h"
#include "../runtime/jni.h"

#include <jni.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ENV_HOOK_MAX 9
#define ENV_EVENT_LIMIT 256
#define ENV_HEX_PREVIEW 24   // bytes of array payload echoed in one event

struct EnvHookSlot {
    const char *name;
    void **slot;              // &table-><fn>; kept after uninstall so status can show the restore
    void *original;           // saved table entry (published atomically)
    int installed;
    int active;               // atomic: wrappers forward without emitting while 0
    unsigned long long hits;
    unsigned long long dropped;
};

static struct EnvHookSlot g_env_hooks[ENV_HOOK_MAX] = {
    { "GetStringUTFChars",   NULL, NULL, 0, 0, 0, 0 },
    { "FindClass",           NULL, NULL, 0, 0, 0, 0 },
    { "GetMethodID",         NULL, NULL, 0, 0, 0, 0 },
    { "GetStaticMethodID",   NULL, NULL, 0, 0, 0, 0 },
    { "NewStringUTF",        NULL, NULL, 0, 0, 0, 0 },
    { "GetFieldID",          NULL, NULL, 0, 0, 0, 0 },
    { "GetStaticFieldID",    NULL, NULL, 0, 0, 0, 0 },
    { "GetByteArrayElements", NULL, NULL, 0, 0, 0, 0 },
    { "SetByteArrayRegion",  NULL, NULL, 0, 0, 0, 0 },
};
static pthread_mutex_t g_env_hook_lock = PTHREAD_MUTEX_INITIALIZER;
static __thread int g_env_hook_reentry = 0;
static unsigned long long g_env_hook_table = 0;

typedef const char *(*get_string_utf_chars_fn)(JNIEnv *, jstring, jboolean *);
typedef jclass (*find_class_fn)(JNIEnv *, const char *);
typedef jmethodID (*get_method_id_fn)(JNIEnv *, jclass, const char *, const char *);
typedef jstring (*new_string_utf_fn)(JNIEnv *, const char *);
typedef jbyte *(*get_byte_array_elements_fn)(JNIEnv *, jarray, jboolean *);
typedef void (*set_byte_array_region_fn)(JNIEnv *, jarray, jsize, jsize, const jbyte *);

static void *slot_original(int index) {
    return __atomic_load_n(&g_env_hooks[index].original, __ATOMIC_ACQUIRE);
}
static int slot_active(int index) {
    return __atomic_load_n(&g_env_hooks[index].active, __ATOMIC_ACQUIRE);
}
// True while the slot may still emit a record — the gate for all expensive detail work.
static int env_budget_left(int index) {
    return __atomic_load_n(&g_env_hooks[index].hits, __ATOMIC_RELAXED) < ENV_EVENT_LIMIT;
}

// Count one intercepted call and, while under budget, push one bounded record. value may be
// NULL (over budget / no detail available) and ok reports whether the JNI call succeeded.
static void env_note(int index, const char *value, int ok) {
    unsigned long long hits = __atomic_add_fetch(&g_env_hooks[index].hits, 1, __ATOMIC_RELAXED);
    if (hits > ENV_EVENT_LIMIT) {
        __atomic_add_fetch(&g_env_hooks[index].dropped, 1, __ATOMIC_RELAXED);
        return;
    }
    char valuej[768], json[1024];
    json_escape(value ? value : "", valuej, sizeof(valuej));
    snprintf(json, sizeof(json), "{\"function\":\"%s\",\"value\":\"%s\",\"ok\":%s}",
             g_env_hooks[index].name, valuej, ok ? "true" : "false");
    adh_capture_push_text("JNI_ENV", json);
}

// "<class>#<name><signature>" for methods, "<class>#<name>:<signature>" for fields. The
// no-reflection variants are used when the lookup already failed (pending exception): they
// keep the coordinates but leave the caller's exception state completely untouched.
static void detail_method_plain(const char *name, const char *sig, char *out, size_t out_size) {
    snprintf(out, out_size, "?#%s%s", name ? name : "", sig ? sig : "");
}

static void detail_field_plain(const char *name, const char *sig, char *out, size_t out_size) {
    snprintf(out, out_size, "?#%s:%s", name ? name : "", sig ? sig : "");
}

static void detail_method(JNIEnv *env, jclass clazz, const char *name, const char *sig,
                          char *out, size_t out_size) {
    char cls[192];
    adh_jni_class_name(env, clazz, cls, sizeof(cls));
    snprintf(out, out_size, "%s#%s%s", cls[0] ? cls : "?", name ? name : "", sig ? sig : "");
}

static void detail_field(JNIEnv *env, jclass clazz, const char *name, const char *sig,
                         char *out, size_t out_size) {
    char cls[192];
    adh_jni_class_name(env, clazz, cls, sizeof(cls));
    snprintf(out, out_size, "%s#%s:%s", cls[0] ? cls : "?", name ? name : "", sig ? sig : "");
}

static void hex_preview(const jbyte *data, jsize len, char *out, size_t out_size) {
    size_t used = 0;
    jsize cap = len > ENV_HEX_PREVIEW ? ENV_HEX_PREVIEW : len;
    if (!out || out_size == 0) return;
    out[0] = 0;
    if (!data || cap <= 0) return;
    for (jsize i = 0; i < cap && used + 3 < out_size; i++) {
        used += (size_t)snprintf(out + used, out_size - used, "%02x", (unsigned char)data[i]);
    }
}

static const char *GetStringUTFChars_wrapper(JNIEnv *env, jstring str, jboolean *isCopy) {
    get_string_utf_chars_fn original = (get_string_utf_chars_fn)slot_original(0);
    if (!original) return NULL;
    if (g_env_hook_reentry || !slot_active(0)) return original(env, str, isCopy);
    g_env_hook_reentry = 1;
    const char *result = original(env, str, isCopy);
    if (result && env_budget_left(0)) {
        char bounded[257];
        strncpy(bounded, result, sizeof(bounded) - 1);
        bounded[sizeof(bounded) - 1] = 0;
        env_note(0, bounded, 1);
    } else {
        env_note(0, NULL, result != NULL);
    }
    g_env_hook_reentry = 0;
    return result;
}

static jclass FindClass_wrapper(JNIEnv *env, const char *name) {
    find_class_fn original = (find_class_fn)slot_original(1);
    if (!original) return NULL;
    if (g_env_hook_reentry || !slot_active(1)) return original(env, name);
    g_env_hook_reentry = 1;
    jclass result = original(env, name);
    env_note(1, env_budget_left(1) ? name : NULL, result != NULL);
    g_env_hook_reentry = 0;
    return result;
}

static jmethodID GetMethodID_wrapper(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
    get_method_id_fn original = (get_method_id_fn)slot_original(2);
    if (!original) return NULL;
    if (g_env_hook_reentry || !slot_active(2)) return original(env, clazz, name, sig);
    g_env_hook_reentry = 1;
    jmethodID result = original(env, clazz, name, sig);
    char detail[512];
    if (!env_budget_left(2)) {
        env_note(2, NULL, 0);
    } else if ((*env)->ExceptionCheck(env)) {
        detail_method_plain(name, sig, detail, sizeof(detail));
        env_note(2, detail, 0);
    } else {
        detail_method(env, clazz, name, sig, detail, sizeof(detail));
        env_note(2, detail, 1);
    }
    g_env_hook_reentry = 0;
    return result;
}

static jmethodID GetStaticMethodID_wrapper(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
    get_method_id_fn original = (get_method_id_fn)slot_original(3);
    if (!original) return NULL;
    if (g_env_hook_reentry || !slot_active(3)) return original(env, clazz, name, sig);
    g_env_hook_reentry = 1;
    jmethodID result = original(env, clazz, name, sig);
    char detail[512];
    if (!env_budget_left(3)) {
        env_note(3, NULL, 0);
    } else if ((*env)->ExceptionCheck(env)) {
        detail_method_plain(name, sig, detail, sizeof(detail));
        env_note(3, detail, 0);
    } else {
        detail_method(env, clazz, name, sig, detail, sizeof(detail));
        env_note(3, detail, 1);
    }
    g_env_hook_reentry = 0;
    return result;
}

static jstring NewStringUTF_wrapper(JNIEnv *env, const char *chars) {
    new_string_utf_fn original = (new_string_utf_fn)slot_original(4);
    if (!original) return NULL;
    if (g_env_hook_reentry || !slot_active(4)) return original(env, chars);
    g_env_hook_reentry = 1;
    jstring result = original(env, chars);
    env_note(4, env_budget_left(4) ? chars : NULL, result != NULL);
    g_env_hook_reentry = 0;
    return result;
}

static jfieldID GetFieldID_wrapper(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
    get_method_id_fn original = (get_method_id_fn)slot_original(5);
    if (!original) return NULL;
    if (g_env_hook_reentry || !slot_active(5)) return (jfieldID)original(env, clazz, name, sig);
    g_env_hook_reentry = 1;
    jfieldID result = (jfieldID)original(env, clazz, name, sig);
    char detail[512];
    if (!env_budget_left(5)) {
        env_note(5, NULL, 0);
    } else if ((*env)->ExceptionCheck(env)) {
        detail_field_plain(name, sig, detail, sizeof(detail));
        env_note(5, detail, 0);
    } else {
        detail_field(env, clazz, name, sig, detail, sizeof(detail));
        env_note(5, detail, 1);
    }
    g_env_hook_reentry = 0;
    return result;
}

static jfieldID GetStaticFieldID_wrapper(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
    get_method_id_fn original = (get_method_id_fn)slot_original(6);
    if (!original) return NULL;
    if (g_env_hook_reentry || !slot_active(6)) return (jfieldID)original(env, clazz, name, sig);
    g_env_hook_reentry = 1;
    jfieldID result = (jfieldID)original(env, clazz, name, sig);
    char detail[512];
    if (!env_budget_left(6)) {
        env_note(6, NULL, 0);
    } else if ((*env)->ExceptionCheck(env)) {
        detail_field_plain(name, sig, detail, sizeof(detail));
        env_note(6, detail, 0);
    } else {
        detail_field(env, clazz, name, sig, detail, sizeof(detail));
        env_note(6, detail, 1);
    }
    g_env_hook_reentry = 0;
    return result;
}

// Array payloads are the interesting part (decrypted/plain buffers crossing the JNI boundary),
// so both array entries echo length + a bounded hex preview of the bytes.
static jbyte *GetByteArrayElements_wrapper(JNIEnv *env, jarray array, jboolean *isCopy) {
    get_byte_array_elements_fn original = (get_byte_array_elements_fn)slot_original(7);
    if (!original) return NULL;
    if (g_env_hook_reentry || !slot_active(7)) return original(env, array, isCopy);
    g_env_hook_reentry = 1;
    jbyte *result = original(env, array, isCopy);
    if (result && array && env_budget_left(7)) {
        jsize len = (*env)->GetArrayLength(env, array);
        char hex[2 * ENV_HEX_PREVIEW + 8], detail[96];
        hex_preview(result, len, hex, sizeof(hex));
        snprintf(detail, sizeof(detail), "len=%d hex=%s", (int)len, hex);
        env_note(7, detail, 1);
    } else {
        env_note(7, NULL, result != NULL);
    }
    g_env_hook_reentry = 0;
    return result;
}

static void SetByteArrayRegion_wrapper(JNIEnv *env, jarray array, jsize start, jsize len,
                                       const jbyte *buf) {
    set_byte_array_region_fn original = (set_byte_array_region_fn)slot_original(8);
    if (!original) return;
    if (g_env_hook_reentry || !slot_active(8)) { original(env, array, start, len, buf); return; }
    g_env_hook_reentry = 1;
    if (env_budget_left(8)) {
        char hex[2 * ENV_HEX_PREVIEW + 8], detail[128];
        hex_preview(buf, len, hex, sizeof(hex));
        snprintf(detail, sizeof(detail), "start=%d len=%d hex=%s", (int)start, (int)len, hex);
        original(env, array, start, len, buf);
        env_note(8, detail, 1);
    } else {
        original(env, array, start, len, buf);
        env_note(8, NULL, 1);
    }
    g_env_hook_reentry = 0;
}

static int env_hook_index(const char *name) {
    for (int i = 0; i < ENV_HOOK_MAX; i++) {
        if (strcmp(g_env_hooks[i].name, name) == 0) return i;
    }
    return -1;
}

// Address of the table slot for one entry. The table is const data (RELRO) in libart; the
// swap goes through adh_swap_pointer_in_ro_page, which restores the original protection.
static void **env_hook_slot(struct JNINativeInterface *table, int index) {
    switch (index) {
        case 0: return (void **)(uintptr_t)&table->GetStringUTFChars;
        case 1: return (void **)(uintptr_t)&table->FindClass;
        case 2: return (void **)(uintptr_t)&table->GetMethodID;
        case 3: return (void **)(uintptr_t)&table->GetStaticMethodID;
        case 4: return (void **)(uintptr_t)&table->NewStringUTF;
        case 5: return (void **)(uintptr_t)&table->GetFieldID;
        case 6: return (void **)(uintptr_t)&table->GetStaticFieldID;
        case 7: return (void **)(uintptr_t)&table->GetByteArrayElements;
        case 8: return (void **)(uintptr_t)&table->SetByteArrayRegion;
        default: return NULL;
    }
}

static void *env_hook_wrapper(int index) {
    switch (index) {
        case 0: return (void *)&GetStringUTFChars_wrapper;
        case 1: return (void *)&FindClass_wrapper;
        case 2: return (void *)&GetMethodID_wrapper;
        case 3: return (void *)&GetStaticMethodID_wrapper;
        case 4: return (void *)&NewStringUTF_wrapper;
        case 5: return (void *)&GetFieldID_wrapper;
        case 6: return (void *)&GetStaticFieldID_wrapper;
        case 7: return (void *)&GetByteArrayElements_wrapper;
        case 8: return (void *)&SetByteArrayRegion_wrapper;
        default: return NULL;
    }
}

// Every slot is reported, hooked or not. slotValue is the LIVE table entry read at reply time:
// installing must make it differ from original, uninstalling must make them equal again — that
// is what lets a verifier prove the table (not just a flag) was patched and restored.
static void send_env_result(int fd, const char *id, const char *action, const char *function,
                            int ok, const char *error) {
    char idj[64], actionj[32], functionj[64], errorj[256];
    json_escape(id, idj, sizeof(idj));
    json_escape(action ? action : "", actionj, sizeof(actionj));
    json_escape(function ? function : "", functionj, sizeof(functionj));
    json_escape(error ? error : "", errorj, sizeof(errorj));
    char table_perms[8] = "";
    if (g_env_hook_table) adh_perms_of_addr((void *)(uintptr_t)g_env_hook_table, table_perms, sizeof(table_perms));
    char out[4096];
    size_t len = snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"jni_env_hook\",\"ok\":%s,"
        "\"action\":\"%s\",\"function\":\"%s\",\"table\":\"0x%llx\",\"tablePerms\":\"%s\","
        "\"error\":\"%s\",\"hooks\":[",
        idj, ok ? "true" : "false", actionj, functionj, g_env_hook_table, table_perms, errorj);
    int first = 1;
    for (int i = 0; i < ENV_HOOK_MAX && len + 320 < sizeof(out); i++) {
        char slot_perms[8] = "";
        void *live = NULL;
        if (g_env_hooks[i].slot) {
            adh_perms_of_addr((void *)(uintptr_t)g_env_hooks[i].slot, slot_perms, sizeof(slot_perms));
            live = __atomic_load_n(g_env_hooks[i].slot, __ATOMIC_ACQUIRE);
        }
        len += snprintf(out + len, sizeof(out) - len,
                        "%s{\"function\":\"%s\",\"installed\":%s,\"active\":%s,"
                        "\"hits\":%llu,\"dropped\":%llu,\"entry\":\"0x%llx\",\"perms\":\"%s\","
                        "\"slotValue\":\"0x%llx\",\"original\":\"0x%llx\"}",
                        first ? "" : ",", g_env_hooks[i].name,
                        g_env_hooks[i].installed ? "true" : "false",
                        slot_active(i) ? "true" : "false",
                        g_env_hooks[i].hits, g_env_hooks[i].dropped,
                        (unsigned long long)(uintptr_t)g_env_hooks[i].slot, slot_perms,
                        (unsigned long long)(uintptr_t)live,
                        (unsigned long long)(uintptr_t)g_env_hooks[i].original);
        first = 0;
    }
    snprintf(out + len, sizeof(out) - len, "]}\n");
    send_line(fd, out);
}

void adh_cmd_jni_env_hook(int fd, const char *id, const char *action, const char *function) {
    if (!action || !action[0]) {
        send_env_result(fd, id, action, function, 0,
                        "jni_env_hook requires action: install | uninstall | status");
        return;
    }
    if (strcmp(action, "status") == 0) {
        int did_attach = 0;
        JNIEnv *env = adh_jni_attach(&did_attach);
        if (!env) {
            send_env_result(fd, id, action, function, 0, "no JavaVM/JNIEnv");
            return;
        }
        g_env_hook_table = (unsigned long long)(uintptr_t)(*env);
        adh_jni_detach(did_attach);
        send_env_result(fd, id, action, function, 1, "");
        return;
    }
    if (strcmp(action, "install") != 0 && strcmp(action, "uninstall") != 0) {
        send_env_result(fd, id, action, function, 0,
                        "action must be install|uninstall|status");
        return;
    }
    if (!function || !function[0]) {
        send_env_result(fd, id, action, function, 0, "jni_env_hook requires function");
        return;
    }
    int index = env_hook_index(function);
    if (index < 0) {
        send_env_result(fd, id, action, function, 0, "unsupported JNIEnv function");
        return;
    }

    if (strcmp(action, "uninstall") == 0) {
        pthread_mutex_lock(&g_env_hook_lock);
        if (!g_env_hooks[index].installed || !g_env_hooks[index].slot) {
            pthread_mutex_unlock(&g_env_hook_lock);
            send_env_result(fd, id, action, function, 0, "function is not hooked");
            return;
        }
        void **saved_slot = g_env_hooks[index].slot;
        void *saved_original = g_env_hooks[index].original;
        pthread_mutex_unlock(&g_env_hook_lock);

        // Deactivate first: a call already inside the wrapper then still reaches the real
        // implementation (saved_original is a stable pointer) but stops emitting events.
        __atomic_store_n(&g_env_hooks[index].active, 0, __ATOMIC_RELEASE);
        void *current = __atomic_load_n(saved_slot, __ATOMIC_ACQUIRE);
        if (current != env_hook_wrapper(index)) {
            send_env_result(fd, id, action, function, 0,
                            "JNIEnv table entry changed underneath the ADH wrapper; left untouched");
            return;
        }
        if (!adh_swap_pointer_in_ro_page(saved_slot, saved_original)) {
            __atomic_store_n(&g_env_hooks[index].active, 1, __ATOMIC_RELEASE);
            send_env_result(fd, id, action, function, 0,
                            "JNIEnv table page could not be made writable");
            return;
        }
        pthread_mutex_lock(&g_env_hook_lock);
        g_env_hooks[index].installed = 0;
        pthread_mutex_unlock(&g_env_hook_lock);
        send_env_result(fd, id, action, function, 1, "");
        return;
    }

    int did_attach = 0;
    JNIEnv *env = adh_jni_attach(&did_attach);
    if (!env) {
        send_env_result(fd, id, action, function, 0, "no JavaVM/JNIEnv");
        return;
    }
    struct JNINativeInterface *table = (struct JNINativeInterface *)(*env);
    adh_jni_detach(did_attach);
    if (!table) {
        send_env_result(fd, id, action, function, 0, "JNIEnv function table unavailable");
        return;
    }
    g_env_hook_table = (unsigned long long)(uintptr_t)table;
    void **slot = env_hook_slot(table, index);
    if (!slot) {
        send_env_result(fd, id, action, function, 0, "JNIEnv function table entry unavailable");
        return;
    }

    pthread_mutex_lock(&g_env_hook_lock);
    if (g_env_hooks[index].installed && g_env_hooks[index].slot == slot) {
        // Same entry: re-activate the existing hook instead of patching twice.
        g_env_hooks[index].hits = 0;
        g_env_hooks[index].dropped = 0;
        pthread_mutex_unlock(&g_env_hook_lock);
        __atomic_store_n(&g_env_hooks[index].active, 1, __ATOMIC_RELEASE);
        send_env_result(fd, id, action, function, 1, "");
        return;
    }
    if (g_env_hooks[index].installed) {
        pthread_mutex_unlock(&g_env_hook_lock);
        send_env_result(fd, id, action, function, 0,
                        "already hooked at a different table entry");
        return;
    }
    pthread_mutex_unlock(&g_env_hook_lock);

    void *original = __atomic_load_n(slot, __ATOMIC_ACQUIRE);
    if (!original) {
        send_env_result(fd, id, action, function, 0, "JNIEnv table entry is null");
        return;
    }
    if (original == env_hook_wrapper(index)) {
        send_env_result(fd, id, action, function, 0,
                        "JNIEnv table entry already points at the ADH wrapper");
        return;
    }
    // Publish the real entry before the swap: a call that lands in the wrapper during the
    // swap window then still reaches the original implementation.
    __atomic_store_n(&g_env_hooks[index].original, original, __ATOMIC_RELEASE);
    if (!adh_swap_pointer_in_ro_page(slot, env_hook_wrapper(index))) {
        __atomic_store_n(&g_env_hooks[index].original, NULL, __ATOMIC_RELEASE);
        send_env_result(fd, id, action, function, 0,
                        "JNIEnv table page could not be made writable");
        return;
    }
    __atomic_store_n(&g_env_hooks[index].active, 1, __ATOMIC_RELEASE);
    pthread_mutex_lock(&g_env_hook_lock);
    g_env_hooks[index].slot = slot;
    g_env_hooks[index].installed = 1;
    g_env_hooks[index].hits = 0;
    g_env_hooks[index].dropped = 0;
    pthread_mutex_unlock(&g_env_hook_lock);
    send_env_result(fd, id, action, function, 1, "");
}