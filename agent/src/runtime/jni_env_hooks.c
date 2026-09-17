// Per-entry hooks on the JNIEnv function table. In C a JNIEnv* points at a table of
// function pointers, so swapping one aligned 8-byte slot intercepts every JNI call that goes
// through that env (all envs of a VM share the table). No trampoline is involved: the saved
// slot value is the real implementation and uninstall writes it back, so this feature has
// neither a patch/UAF window nor a hard-unhook problem.
//
// Two groups of entries are hooked:
//   1. bookkeeping/ID lookups + byte arrays (fixed list below);
//   2. the Call*Method / NewObject family, in all three JNI forms. Which form a target hits
//      depends on its language: the NDK's C++ JNIEnv_ wrappers build a va_list and call the
//      "...V" table entry, C code calls the varargs entry, and generated/A-style code calls
//      the "...A" entry - so a tracer that hooks only one form sees only part of the traffic.
//      The varargs wrapper forwards to the live "...V" entry, which keeps the chain correct
//      even when both forms are hooked.
//
// Hot-path rules (a hooked entry runs on target threads, forever):
//   * every intercepted call is counted in `hits` (success or failure) and at most
//     ENV_EVENT_LIMIT records are emitted per slot; past that only `dropped` grows;
//   * anything expensive - class-name reflection, member resolution, argument rendering,
//     payload preview, string copy - is gated on env_budget_left() so a spent slot costs
//     one atomic add per call;
//   * the wrappers never block or allocate: capture goes through its own try-lock ring and
//     the member-name cache is lock-free on the read path.
// Member-ID wrappers do not touch the caller's exception state: a failed lookup is reported
// with ok=false and no reflection (calling JNI with a pending exception aborts under CheckJNI).

#include "jni_env_hooks.h"

#include "../bootstrap/agent_internal.h"
#include "../capture/capture.h"
#include "../hook/got.h"
#include "../runtime/jni.h"
#include "../runtime/jni_method_names.h"

#include <jni.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ENV_EVENT_LIMIT 256
#define ENV_HEX_PREVIEW 24     // bytes of array payload echoed in one event
#define ENV_ARG_PARAMS 6       // arguments rendered per call
#define ENV_ARG_CHARS 64       // characters per rendered argument

// ---- slot layout ----------------------------------------------------------
enum {
    ENV_SLOT_GetStringUTFChars = 0,
    ENV_SLOT_FindClass,
    ENV_SLOT_GetMethodID,
    ENV_SLOT_GetStaticMethodID,
    ENV_SLOT_NewStringUTF,
    ENV_SLOT_GetFieldID,
    ENV_SLOT_GetStaticFieldID,
    ENV_SLOT_GetByteArrayElements,
    ENV_SLOT_SetByteArrayRegion,
    ENV_FIXED_SLOTS,

    ENV_SLOT_CallObjectMethod = ENV_FIXED_SLOTS,
    ENV_SLOT_CallBooleanMethod = ENV_SLOT_CallObjectMethod + 3,
    ENV_SLOT_CallIntMethod = ENV_SLOT_CallBooleanMethod + 3,
    ENV_SLOT_CallLongMethod = ENV_SLOT_CallIntMethod + 3,
    ENV_SLOT_CallStaticObjectMethod = ENV_SLOT_CallLongMethod + 3,
    ENV_SLOT_CallStaticIntMethod = ENV_SLOT_CallStaticObjectMethod + 3,
    ENV_SLOT_NewObject = ENV_SLOT_CallStaticIntMethod + 3,
    ENV_SLOT_CallVoidMethod = ENV_SLOT_NewObject + 3,
    ENV_SLOT_CallStaticVoidMethod = ENV_SLOT_CallVoidMethod + 3,
    ENV_HOOK_MAX = ENV_SLOT_CallStaticVoidMethod + 3,
};

struct EnvHookSlot {
    const char *name;
    void **slot;              // &table-><fn>; kept after uninstall so status can show the restore
    void *original;           // saved table entry (published atomically)
    int installed;
    int active;               // atomic: wrappers forward without emitting while 0
    unsigned long long hits;
    unsigned long long dropped;
};

#define ADH_FIXED_SLOT_INITS(X) \
    X("GetStringUTFChars") X("FindClass") X("GetMethodID") X("GetStaticMethodID") \
    X("NewStringUTF") X("GetFieldID") X("GetStaticFieldID") X("GetByteArrayElements") \
    X("SetByteArrayRegion")

#define ADH_CALL_VALUE_FAMILIES(X) \
    X(CallObjectMethod,       jobject,  jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallObjectMethod) \
    X(CallBooleanMethod,      jboolean, jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallBooleanMethod) \
    X(CallIntMethod,          jint,     jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallIntMethod) \
    X(CallLongMethod,         jlong,    jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallLongMethod) \
    X(CallStaticObjectMethod, jobject,  jclass,  ADH_MEMBER_STATIC,   ENV_SLOT_CallStaticObjectMethod) \
    X(CallStaticIntMethod,    jint,     jclass,  ADH_MEMBER_STATIC,   ENV_SLOT_CallStaticIntMethod) \
    X(NewObject,              jobject,  jclass,  ADH_MEMBER_CTOR,     ENV_SLOT_NewObject)

#define ADH_CALL_VOID_FAMILIES(X) \
    X(CallVoidMethod,         jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallVoidMethod) \
    X(CallStaticVoidMethod,   jclass,  ADH_MEMBER_STATIC,   ENV_SLOT_CallStaticVoidMethod)

#define ADH_SLOT_INIT(name) { name, NULL, NULL, 0, 0, 0, 0 },
#define ADH_CALL_INITS_3(name, ret, tgt, kind, base) \
    ADH_SLOT_INIT(#name) ADH_SLOT_INIT(#name "V") ADH_SLOT_INIT(#name "A")
#define ADH_CALL_INITS(name, ret, tgt, kind, base) ADH_CALL_INITS_3(name, ret, tgt, kind, base)
#define ADH_CALL_VOID_INITS(name, tgt, kind, base) ADH_CALL_INITS_3(name, void, tgt, kind, base)

static struct EnvHookSlot g_env_hooks[ENV_HOOK_MAX] = {
    ADH_FIXED_SLOT_INITS(ADH_SLOT_INIT)
    ADH_CALL_VALUE_FAMILIES(ADH_CALL_INITS)
    ADH_CALL_VOID_FAMILIES(ADH_CALL_VOID_INITS)
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
// True while the slot may still emit a record - the gate for all expensive detail work.
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
    char valuej[1024], json[1280];
    json_escape(value ? value : "", valuej, sizeof(valuej));
    snprintf(json, sizeof(json), "{\"function\":\"%s\",\"value\":\"%s\",\"ok\":%s}",
             g_env_hooks[index].name, valuej, ok ? "true" : "false");
    adh_capture_push_text("JNI_ENV", json);
}
// ---- member-ID / array detail --------------------------------------------
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

// ---- Call* argument rendering --------------------------------------------
struct AdhCallDetail {
    char text[640];
    int ok;
};

static void append_quoted_string(JNIEnv *env, jobject obj, char *out, size_t out_size) {
    if (!obj) { snprintf(out, out_size, "null"); return; }
    const char *chars = (*env)->GetStringUTFChars(env, (jstring)obj, NULL);
    if (!chars) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        snprintf(out, out_size, "str?");
        return;
    }
    size_t w = 0;
    out[w++] = '"';
    for (size_t i = 0; chars[i] && w + 5 < out_size; i++) {
        unsigned char c = (unsigned char)chars[i];
        if (c == '"' || c == '\\') { out[w++] = '\\'; out[w++] = (char)c; }
        else if (c >= 0x20 && c < 0x7f) out[w++] = (char)c;
        else w += (size_t)snprintf(out + w, out_size - w, "\\x%02x", c);
    }
    out[w++] = '"';
    out[w] = 0;
    (*env)->ReleaseStringUTFChars(env, (jstring)obj, chars);
}

// Walk a JNI method signature and render up to ENV_ARG_PARAMS argument values. Either the
// va_list form (varargs promotion rules: sub-int -> int, float -> double) or the jvalue array
// form is used. Callers guarantee no exception is pending.
static void render_signature_args(JNIEnv *env, const char *sig, char *out, size_t out_size,
                                  int from_va, const jvalue *jargs, va_list ap) {
    size_t w = 0;
    out[0] = 0;
    if (!sig || sig[0] != '(') return;
    const char *p = sig + 1;
    int index = 0;
    int first = 1;
    while (*p && *p != ')' && index < ENV_ARG_PARAMS) {
        char desc[96];
        size_t dl = 0;
        if (*p == '[') {
            while (*p == '[' && dl + 1 < sizeof(desc)) desc[dl++] = *p++;
            if (*p == 'L') {
                while (*p && *p != ';' && dl + 1 < sizeof(desc)) desc[dl++] = *p++;
                if (*p == ';') desc[dl++] = *p++;
            } else if (*p) {
                desc[dl++] = *p++;
            }
        } else if (*p == 'L') {
            while (*p && *p != ';' && dl + 1 < sizeof(desc)) desc[dl++] = *p++;
            if (*p == ';') desc[dl++] = *p++;
        } else if (*p) {
            desc[dl++] = *p++;
        }
        desc[dl] = 0;
        char one[ENV_ARG_CHARS + 8] = "";
        char type = desc[0];
        if (type == 'L' && strcmp(desc, "Ljava/lang/String;") == 0) {
            jobject o = from_va ? va_arg(ap, jobject) : jargs[index].l;
            append_quoted_string(env, o, one, sizeof(one));
        } else if (type == 'L' || type == '[') {
            jobject o = from_va ? va_arg(ap, jobject) : jargs[index].l;
            snprintf(one, sizeof(one), "@0x%llx", (unsigned long long)(uintptr_t)o);
        } else {
            switch (type) {
                case 'Z': case 'B': case 'C': case 'S': case 'I': {
                    jint v = from_va ? va_arg(ap, jint) : jargs[index].i;
                    if (type == 'Z') snprintf(one, sizeof(one), "%s", v ? "true" : "false");
                    else snprintf(one, sizeof(one), "%d", (int)v);
                    break;
                }
                case 'J': {
                    jlong v = from_va ? va_arg(ap, jlong) : jargs[index].j;
                    snprintf(one, sizeof(one), "%lld", (long long)v);
                    break;
                }
                case 'F': case 'D': {
                    double v = from_va ? va_arg(ap, double)
                                       : (type == 'F' ? (double)jargs[index].f : jargs[index].d);
                    snprintf(one, sizeof(one), "%g", v);
                    break;
                }
                default: snprintf(one, sizeof(one), "?"); break;
            }
        }
        int written = snprintf(out + w, out_size > w ? out_size - w : 0, "%s%s",
                               first ? "" : ",", one);
        if (written < 0) break;
        w += (size_t)written;
        first = 0;
        index++;
        if (w + 8 >= out_size) break;
    }
    if (*p != ')' && index >= ENV_ARG_PARAMS) {
        size_t cur = strlen(out);
        if (cur + 5 < out_size) snprintf(out + cur, out_size - cur, ",...");
    }
}

static void call_detail_common(JNIEnv *env, int slot, jobject target, int kind, jmethodID mid,
                               struct AdhCallDetail *d, int from_va, const jvalue *jargs, va_list ap) {
    d->text[0] = 0;
    d->ok = 0;
    if (!env_budget_left(slot)) return;
    struct AdhMethodInfo info;
    adh_jni_method_info(env, target, kind, mid, &info);
    if (!info.ok) {
        snprintf(d->text, sizeof(d->text), "%s", info.label);
        return;
    }
    char args[360];
    render_signature_args(env, info.sig, args, sizeof(args), from_va, jargs, ap);
    snprintf(d->text, sizeof(d->text), "%s args(%s)", info.label, args);
    d->ok = 1;
}

static void call_detail_va(JNIEnv *env, int slot, jobject target, int kind, jmethodID mid,
                           va_list ap, struct AdhCallDetail *d) {
    va_list copy;
    va_copy(copy, ap);
    call_detail_common(env, slot, target, kind, mid, d, 1, NULL, copy);
    va_end(copy);
}

static void call_detail_a(JNIEnv *env, int slot, jobject target, int kind, jmethodID mid,
                          const jvalue *args, struct AdhCallDetail *d) {
    va_list empty;
    memset(&empty, 0, sizeof(empty));
    call_detail_common(env, slot, target, kind, mid, d, 0, args, empty);
}

static void call_emit(int slot, struct AdhCallDetail *d) {
    env_note(slot, d->text[0] ? d->text : NULL, d->ok);
}
// ---- fixed wrappers -------------------------------------------------------
static const char *GetStringUTFChars_wrapper(JNIEnv *env, jstring str, jboolean *isCopy) {
    get_string_utf_chars_fn original = (get_string_utf_chars_fn)slot_original(ENV_SLOT_GetStringUTFChars);
    if (!original) return NULL;
    if (g_env_hook_reentry || !slot_active(ENV_SLOT_GetStringUTFChars)) return original(env, str, isCopy);
    g_env_hook_reentry = 1;
    const char *result = original(env, str, isCopy);
    if (result && env_budget_left(ENV_SLOT_GetStringUTFChars)) {
        char bounded[257];
        strncpy(bounded, result, sizeof(bounded) - 1);
        bounded[sizeof(bounded) - 1] = 0;
        env_note(ENV_SLOT_GetStringUTFChars, bounded, 1);
    } else {
        env_note(ENV_SLOT_GetStringUTFChars, NULL, result != NULL);
    }
    g_env_hook_reentry = 0;
    return result;
}

static jclass FindClass_wrapper(JNIEnv *env, const char *name) {
    find_class_fn original = (find_class_fn)slot_original(ENV_SLOT_FindClass);
    if (!original) return NULL;
    if (g_env_hook_reentry || !slot_active(ENV_SLOT_FindClass)) return original(env, name);
    g_env_hook_reentry = 1;
    jclass result = original(env, name);
    env_note(ENV_SLOT_FindClass, env_budget_left(ENV_SLOT_FindClass) ? name : NULL, result != NULL);
    g_env_hook_reentry = 0;
    return result;
}

static jmethodID GetMethodID_wrapper(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
    get_method_id_fn original = (get_method_id_fn)slot_original(ENV_SLOT_GetMethodID);
    if (!original) return NULL;
    if (g_env_hook_reentry || !slot_active(ENV_SLOT_GetMethodID)) return original(env, clazz, name, sig);
    g_env_hook_reentry = 1;
    jmethodID result = original(env, clazz, name, sig);
    char detail[512];
    if (!env_budget_left(ENV_SLOT_GetMethodID)) {
        env_note(ENV_SLOT_GetMethodID, NULL, 0);
    } else if ((*env)->ExceptionCheck(env)) {
        detail_method_plain(name, sig, detail, sizeof(detail));
        env_note(ENV_SLOT_GetMethodID, detail, 0);
    } else {
        detail_method(env, clazz, name, sig, detail, sizeof(detail));
        env_note(ENV_SLOT_GetMethodID, detail, 1);
    }
    g_env_hook_reentry = 0;
    return result;
}

static jmethodID GetStaticMethodID_wrapper(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
    get_method_id_fn original = (get_method_id_fn)slot_original(ENV_SLOT_GetStaticMethodID);
    if (!original) return NULL;
    if (g_env_hook_reentry || !slot_active(ENV_SLOT_GetStaticMethodID)) return original(env, clazz, name, sig);
    g_env_hook_reentry = 1;
    jmethodID result = original(env, clazz, name, sig);
    char detail[512];
    if (!env_budget_left(ENV_SLOT_GetStaticMethodID)) {
        env_note(ENV_SLOT_GetStaticMethodID, NULL, 0);
    } else if ((*env)->ExceptionCheck(env)) {
        detail_method_plain(name, sig, detail, sizeof(detail));
        env_note(ENV_SLOT_GetStaticMethodID, detail, 0);
    } else {
        detail_method(env, clazz, name, sig, detail, sizeof(detail));
        env_note(ENV_SLOT_GetStaticMethodID, detail, 1);
    }
    g_env_hook_reentry = 0;
    return result;
}

static jstring NewStringUTF_wrapper(JNIEnv *env, const char *chars) {
    new_string_utf_fn original = (new_string_utf_fn)slot_original(ENV_SLOT_NewStringUTF);
    if (!original) return NULL;
    if (g_env_hook_reentry || !slot_active(ENV_SLOT_NewStringUTF)) return original(env, chars);
    g_env_hook_reentry = 1;
    jstring result = original(env, chars);
    env_note(ENV_SLOT_NewStringUTF, env_budget_left(ENV_SLOT_NewStringUTF) ? chars : NULL, result != NULL);
    g_env_hook_reentry = 0;
    return result;
}

static jfieldID GetFieldID_wrapper(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
    get_method_id_fn original = (get_method_id_fn)slot_original(ENV_SLOT_GetFieldID);
    if (!original) return NULL;
    if (g_env_hook_reentry || !slot_active(ENV_SLOT_GetFieldID)) return (jfieldID)original(env, clazz, name, sig);
    g_env_hook_reentry = 1;
    jfieldID result = (jfieldID)original(env, clazz, name, sig);
    char detail[512];
    if (!env_budget_left(ENV_SLOT_GetFieldID)) {
        env_note(ENV_SLOT_GetFieldID, NULL, 0);
    } else if ((*env)->ExceptionCheck(env)) {
        detail_field_plain(name, sig, detail, sizeof(detail));
        env_note(ENV_SLOT_GetFieldID, detail, 0);
    } else {
        detail_field(env, clazz, name, sig, detail, sizeof(detail));
        env_note(ENV_SLOT_GetFieldID, detail, 1);
    }
    g_env_hook_reentry = 0;
    return result;
}

static jfieldID GetStaticFieldID_wrapper(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
    get_method_id_fn original = (get_method_id_fn)slot_original(ENV_SLOT_GetStaticFieldID);
    if (!original) return NULL;
    if (g_env_hook_reentry || !slot_active(ENV_SLOT_GetStaticFieldID)) return (jfieldID)original(env, clazz, name, sig);
    g_env_hook_reentry = 1;
    jfieldID result = (jfieldID)original(env, clazz, name, sig);
    char detail[512];
    if (!env_budget_left(ENV_SLOT_GetStaticFieldID)) {
        env_note(ENV_SLOT_GetStaticFieldID, NULL, 0);
    } else if ((*env)->ExceptionCheck(env)) {
        detail_field_plain(name, sig, detail, sizeof(detail));
        env_note(ENV_SLOT_GetStaticFieldID, detail, 0);
    } else {
        detail_field(env, clazz, name, sig, detail, sizeof(detail));
        env_note(ENV_SLOT_GetStaticFieldID, detail, 1);
    }
    g_env_hook_reentry = 0;
    return result;
}

static jbyte *GetByteArrayElements_wrapper(JNIEnv *env, jarray array, jboolean *isCopy) {
    get_byte_array_elements_fn original =
        (get_byte_array_elements_fn)slot_original(ENV_SLOT_GetByteArrayElements);
    if (!original) return NULL;
    if (g_env_hook_reentry || !slot_active(ENV_SLOT_GetByteArrayElements)) return original(env, array, isCopy);
    g_env_hook_reentry = 1;
    jbyte *result = original(env, array, isCopy);
    if (result && array && env_budget_left(ENV_SLOT_GetByteArrayElements)) {
        jsize len = (*env)->GetArrayLength(env, array);
        char hex[2 * ENV_HEX_PREVIEW + 8], detail[96];
        hex_preview(result, len, hex, sizeof(hex));
        snprintf(detail, sizeof(detail), "len=%d hex=%s", (int)len, hex);
        env_note(ENV_SLOT_GetByteArrayElements, detail, 1);
    } else {
        env_note(ENV_SLOT_GetByteArrayElements, NULL, result != NULL);
    }
    g_env_hook_reentry = 0;
    return result;
}

static void SetByteArrayRegion_wrapper(JNIEnv *env, jarray array, jsize start, jsize len,
                                       const jbyte *buf) {
    set_byte_array_region_fn original =
        (set_byte_array_region_fn)slot_original(ENV_SLOT_SetByteArrayRegion);
    if (!original) return;
    if (g_env_hook_reentry || !slot_active(ENV_SLOT_SetByteArrayRegion)) {
        original(env, array, start, len, buf);
        return;
    }
    g_env_hook_reentry = 1;
    if (env_budget_left(ENV_SLOT_SetByteArrayRegion)) {
        char hex[2 * ENV_HEX_PREVIEW + 8], detail[128];
        hex_preview(buf, len, hex, sizeof(hex));
        snprintf(detail, sizeof(detail), "start=%d len=%d hex=%s", (int)start, (int)len, hex);
        original(env, array, start, len, buf);
        env_note(ENV_SLOT_SetByteArrayRegion, detail, 1);
    } else {
        original(env, array, start, len, buf);
        env_note(ENV_SLOT_SetByteArrayRegion, NULL, 1);
    }
    g_env_hook_reentry = 0;
}
// ---- Call* family wrappers (macro-generated per form) ---------------------
#define ADH_DEFINE_CALL_VALUE(NAME, RET, TGT, KIND, BASE)                                      \
    static RET NAME##_wrapper(JNIEnv *env, TGT target, jmethodID mid, ...) {                    \
        va_list ap;                                                                             \
        va_start(ap, mid);                                                                      \
        if (g_env_hook_reentry || !slot_active(BASE)) {                                         \
            RET r = (*env)->NAME##V(env, target, mid, ap);                                      \
            va_end(ap);                                                                         \
            return r;                                                                           \
        }                                                                                       \
        g_env_hook_reentry = 1;                                                                 \
        struct AdhCallDetail detail;                                                            \
        call_detail_va(env, BASE, (jobject)target, KIND, mid, ap, &detail);                     \
        RET result = (*env)->NAME##V(env, target, mid, ap);                                     \
        va_end(ap);                                                                             \
        call_emit(BASE, &detail);                                                               \
        g_env_hook_reentry = 0;                                                                 \
        return result;                                                                          \
    }                                                                                           \
    static RET NAME##V_wrapper(JNIEnv *env, TGT target, jmethodID mid, va_list ap) {            \
        RET (*original)(JNIEnv *, TGT, jmethodID, va_list) =                                    \
            (RET (*)(JNIEnv *, TGT, jmethodID, va_list))slot_original(BASE + 1);                \
        if (!original) return (RET)0;                                                           \
        if (g_env_hook_reentry || !slot_active(BASE + 1)) return original(env, target, mid, ap); \
        g_env_hook_reentry = 1;                                                                 \
        struct AdhCallDetail detail;                                                            \
        call_detail_va(env, BASE + 1, (jobject)target, KIND, mid, ap, &detail);                 \
        RET result = original(env, target, mid, ap);                                            \
        call_emit(BASE + 1, &detail);                                                           \
        g_env_hook_reentry = 0;                                                                 \
        return result;                                                                          \
    }                                                                                           \
    static RET NAME##A_wrapper(JNIEnv *env, TGT target, jmethodID mid, const jvalue *args) {    \
        RET (*original)(JNIEnv *, TGT, jmethodID, const jvalue *) =                             \
            (RET (*)(JNIEnv *, TGT, jmethodID, const jvalue *))slot_original(BASE + 2);          \
        if (!original) return (RET)0;                                                           \
        if (g_env_hook_reentry || !slot_active(BASE + 2)) return original(env, target, mid, args); \
        g_env_hook_reentry = 1;                                                                 \
        struct AdhCallDetail detail;                                                            \
        call_detail_a(env, BASE + 2, (jobject)target, KIND, mid, args, &detail);                 \
        RET result = original(env, target, mid, args);                                          \
        call_emit(BASE + 2, &detail);                                                           \
        g_env_hook_reentry = 0;                                                                 \
        return result;                                                                          \
    }

#define ADH_DEFINE_CALL_VOID(NAME, TGT, KIND, BASE)                                             \
    static void NAME##_wrapper(JNIEnv *env, TGT target, jmethodID mid, ...) {                   \
        va_list ap;                                                                             \
        va_start(ap, mid);                                                                      \
        if (g_env_hook_reentry || !slot_active(BASE)) {                                         \
            (*env)->NAME##V(env, target, mid, ap);                                              \
            va_end(ap);                                                                         \
            return;                                                                             \
        }                                                                                       \
        g_env_hook_reentry = 1;                                                                 \
        struct AdhCallDetail detail;                                                            \
        call_detail_va(env, BASE, (jobject)target, KIND, mid, ap, &detail);                     \
        (*env)->NAME##V(env, target, mid, ap);                                                  \
        va_end(ap);                                                                             \
        call_emit(BASE, &detail);                                                               \
        g_env_hook_reentry = 0;                                                                 \
    }                                                                                           \
    static void NAME##V_wrapper(JNIEnv *env, TGT target, jmethodID mid, va_list ap) {           \
        void (*original)(JNIEnv *, TGT, jmethodID, va_list) =                                   \
            (void (*)(JNIEnv *, TGT, jmethodID, va_list))slot_original(BASE + 1);               \
        if (!original) return;                                                                  \
        if (g_env_hook_reentry || !slot_active(BASE + 1)) { original(env, target, mid, ap); return; } \
        g_env_hook_reentry = 1;                                                                 \
        struct AdhCallDetail detail;                                                            \
        call_detail_va(env, BASE + 1, (jobject)target, KIND, mid, ap, &detail);                 \
        original(env, target, mid, ap);                                                         \
        call_emit(BASE + 1, &detail);                                                           \
        g_env_hook_reentry = 0;                                                                 \
    }                                                                                           \
    static void NAME##A_wrapper(JNIEnv *env, TGT target, jmethodID mid, const jvalue *args) {   \
        void (*original)(JNIEnv *, TGT, jmethodID, const jvalue *) =                            \
            (void (*)(JNIEnv *, TGT, jmethodID, const jvalue *))slot_original(BASE + 2);         \
        if (!original) return;                                                                  \
        if (g_env_hook_reentry || !slot_active(BASE + 2)) { original(env, target, mid, args); return; } \
        g_env_hook_reentry = 1;                                                                 \
        struct AdhCallDetail detail;                                                            \
        call_detail_a(env, BASE + 2, (jobject)target, KIND, mid, args, &detail);                 \
        original(env, target, mid, args);                                                       \
        call_emit(BASE + 2, &detail);                                                           \
        g_env_hook_reentry = 0;                                                                 \
    }

ADH_CALL_VALUE_FAMILIES(ADH_DEFINE_CALL_VALUE)
ADH_CALL_VOID_FAMILIES(ADH_DEFINE_CALL_VOID)
// JNIEnv table slot indices, straight from the JNINativeInterface field order in the NDK
// jni.h (the layout the JNI spec fixes). The offset check below turns "my index table drifted
// from the real ABI" into a loud install failure instead of patching a neighbouring entry.
static int env_hook_spec_index(int index) {
    switch (index) {
        case ENV_SLOT_FindClass: return 6;
        case ENV_SLOT_NewObject: return 28;
        case ENV_SLOT_NewObject + 1: return 29;
        case ENV_SLOT_NewObject + 2: return 30;
        case ENV_SLOT_GetMethodID: return 33;
        case ENV_SLOT_CallObjectMethod: return 34;
        case ENV_SLOT_CallObjectMethod + 1: return 35;
        case ENV_SLOT_CallObjectMethod + 2: return 36;
        case ENV_SLOT_CallBooleanMethod: return 37;
        case ENV_SLOT_CallBooleanMethod + 1: return 38;
        case ENV_SLOT_CallBooleanMethod + 2: return 39;
        case ENV_SLOT_CallIntMethod: return 49;
        case ENV_SLOT_CallIntMethod + 1: return 50;
        case ENV_SLOT_CallIntMethod + 2: return 51;
        case ENV_SLOT_CallLongMethod: return 52;
        case ENV_SLOT_CallLongMethod + 1: return 53;
        case ENV_SLOT_CallLongMethod + 2: return 54;
        case ENV_SLOT_CallVoidMethod: return 61;
        case ENV_SLOT_CallVoidMethod + 1: return 62;
        case ENV_SLOT_CallVoidMethod + 2: return 63;
        case ENV_SLOT_GetFieldID: return 94;
        case ENV_SLOT_GetStaticMethodID: return 113;
        case ENV_SLOT_CallStaticObjectMethod: return 114;
        case ENV_SLOT_CallStaticObjectMethod + 1: return 115;
        case ENV_SLOT_CallStaticObjectMethod + 2: return 116;
        case ENV_SLOT_CallStaticIntMethod: return 129;
        case ENV_SLOT_CallStaticIntMethod + 1: return 130;
        case ENV_SLOT_CallStaticIntMethod + 2: return 131;
        case ENV_SLOT_CallStaticVoidMethod: return 141;
        case ENV_SLOT_CallStaticVoidMethod + 1: return 142;
        case ENV_SLOT_CallStaticVoidMethod + 2: return 143;
        case ENV_SLOT_GetStaticFieldID: return 144;
        case ENV_SLOT_NewStringUTF: return 167;
        case ENV_SLOT_GetStringUTFChars: return 169;
        case ENV_SLOT_GetByteArrayElements: return 184;
        case ENV_SLOT_SetByteArrayRegion: return 208;
        default: return -1;
    }
}
// ---- slot lookup ----------------------------------------------------------
static int env_hook_index(const char *name) {
    for (int i = 0; i < ENV_HOOK_MAX; i++) {
        if (strcmp(g_env_hooks[i].name, name) == 0) return i;
    }
    return -1;
}

#define ADH_CALL_SLOT_CASES(name, ret, tgt, kind, base) \
    case base: return (void **)(uintptr_t)&table->name; \
    case base + 1: return (void **)(uintptr_t)&table->name##V; \
    case base + 2: return (void **)(uintptr_t)&table->name##A;
#define ADH_CALL_VOID_SLOT_CASES(name, tgt, kind, base) ADH_CALL_SLOT_CASES(name, void, tgt, kind, base)

static void **env_hook_slot(struct JNINativeInterface *table, int index) {
    switch (index) {
        case ENV_SLOT_GetStringUTFChars: return (void **)(uintptr_t)&table->GetStringUTFChars;
        case ENV_SLOT_FindClass: return (void **)(uintptr_t)&table->FindClass;
        case ENV_SLOT_GetMethodID: return (void **)(uintptr_t)&table->GetMethodID;
        case ENV_SLOT_GetStaticMethodID: return (void **)(uintptr_t)&table->GetStaticMethodID;
        case ENV_SLOT_NewStringUTF: return (void **)(uintptr_t)&table->NewStringUTF;
        case ENV_SLOT_GetFieldID: return (void **)(uintptr_t)&table->GetFieldID;
        case ENV_SLOT_GetStaticFieldID: return (void **)(uintptr_t)&table->GetStaticFieldID;
        case ENV_SLOT_GetByteArrayElements: return (void **)(uintptr_t)&table->GetByteArrayElements;
        case ENV_SLOT_SetByteArrayRegion: return (void **)(uintptr_t)&table->SetByteArrayRegion;
        ADH_CALL_VALUE_FAMILIES(ADH_CALL_SLOT_CASES)
        ADH_CALL_VOID_FAMILIES(ADH_CALL_VOID_SLOT_CASES)
        default: return NULL;
    }
}

#define ADH_CALL_WRAPPER_CASES(name, ret, tgt, kind, base) \
    case base: return (void *)&name##_wrapper; \
    case base + 1: return (void *)&name##V_wrapper; \
    case base + 2: return (void *)&name##A_wrapper;
#define ADH_CALL_VOID_WRAPPER_CASES(name, tgt, kind, base) ADH_CALL_WRAPPER_CASES(name, void, tgt, kind, base)

static void *env_hook_wrapper(int index) {
    switch (index) {
        case ENV_SLOT_GetStringUTFChars: return (void *)&GetStringUTFChars_wrapper;
        case ENV_SLOT_FindClass: return (void *)&FindClass_wrapper;
        case ENV_SLOT_GetMethodID: return (void *)&GetMethodID_wrapper;
        case ENV_SLOT_GetStaticMethodID: return (void *)&GetStaticMethodID_wrapper;
        case ENV_SLOT_NewStringUTF: return (void *)&NewStringUTF_wrapper;
        case ENV_SLOT_GetFieldID: return (void *)&GetFieldID_wrapper;
        case ENV_SLOT_GetStaticFieldID: return (void *)&GetStaticFieldID_wrapper;
        case ENV_SLOT_GetByteArrayElements: return (void *)&GetByteArrayElements_wrapper;
        case ENV_SLOT_SetByteArrayRegion: return (void *)&SetByteArrayRegion_wrapper;
        ADH_CALL_VALUE_FAMILIES(ADH_CALL_WRAPPER_CASES)
        ADH_CALL_VOID_FAMILIES(ADH_CALL_VOID_WRAPPER_CASES)
        default: return NULL;
    }
}

// ---- command handling -----------------------------------------------------
// Every slot is reported, hooked or not. slotValue is the LIVE table entry read at reply time:
// installing must make it differ from original, uninstalling must make them equal again - that
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
    char out[16384];
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
    // ABI guard: the address we are about to patch must be the spec-defined field for this
    // entry. A drifted index table would otherwise silently hook a neighbouring JNI function.
    int spec = env_hook_spec_index(index);
    unsigned long long slot_offset = (unsigned long long)((char *)slot - (char *)table);
    if (spec < 0 || slot_offset != (unsigned long long)spec * sizeof(void *)) {
        char guard_error[192];
        snprintf(guard_error, sizeof(guard_error),
                 "JNIEnv table layout mismatch for %s (offset %llu, spec %d) — refusing to patch",
                 function, slot_offset, spec);
        LOGE("jni_env_hook: %s", guard_error);
        send_env_result(fd, id, action, function, 0, guard_error);
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