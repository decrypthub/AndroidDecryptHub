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
// Field accessors (v4.55). Native code that reads/writes fields through the JNIEnv table is a
// large blind spot - object_set only covers the reflection path. One list drives the enum, the
// name table, the struct-field cases and the wrapper dispatch, so those four cannot drift apart;
// the numeric spec indices come from struct JNINativeInterface and are checked against the SDK
// jni.h by tools/verify_v90_jni_table_abi.sh.
#define ADH_FIELD_SLOT_LIST(X) \
    X(GetObjectField) X(GetBooleanField) X(GetByteField) X(GetCharField) X(GetShortField) X(GetIntField) X(GetLongField) X(GetFloatField) X(GetDoubleField) \
    X(SetObjectField) X(SetBooleanField) X(SetByteField) X(SetCharField) X(SetShortField) X(SetIntField) X(SetLongField) X(SetFloatField) X(SetDoubleField) \
    X(GetStaticObjectField) X(GetStaticBooleanField) X(GetStaticByteField) X(GetStaticCharField) X(GetStaticShortField) X(GetStaticIntField) X(GetStaticLongField) X(GetStaticFloatField) X(GetStaticDoubleField) \
    X(SetStaticObjectField) X(SetStaticBooleanField) X(SetStaticByteField) X(SetStaticCharField) X(SetStaticShortField) X(SetStaticIntField) X(SetStaticLongField) X(SetStaticFloatField) X(SetStaticDoubleField)

#define ADH_FIELD_ENUM_ENTRY(name) ENV_SLOT_##name,
#define ADH_FIELD_NAME_ENTRY(name) { #name, NULL, NULL, 0, 0, 0, 0, "" },
#define ADH_FIELD_SLOT_CASE(name) case ENV_SLOT_##name: return (void **)(uintptr_t)&table->name;
#define ADH_FIELD_WRAPPER_CASE(name) case ENV_SLOT_##name: return (void *)&name##_wrapper;

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
    ENV_SLOT_ReleaseByteArrayElements,
    ENV_SLOT_GetByteArrayRegion,
    ENV_SLOT_GetPrimitiveArrayCritical,
    ENV_SLOT_ReleasePrimitiveArrayCritical,
    ENV_FIXED_SLOTS,

    ENV_SLOT_CallObjectMethod = ENV_FIXED_SLOTS,
    ENV_SLOT_CallBooleanMethod = ENV_SLOT_CallObjectMethod + 3,
    ENV_SLOT_CallByteMethod = ENV_SLOT_CallBooleanMethod + 3,
    ENV_SLOT_CallCharMethod = ENV_SLOT_CallByteMethod + 3,
    ENV_SLOT_CallShortMethod = ENV_SLOT_CallCharMethod + 3,
    ENV_SLOT_CallIntMethod = ENV_SLOT_CallShortMethod + 3,
    ENV_SLOT_CallLongMethod = ENV_SLOT_CallIntMethod + 3,
    ENV_SLOT_CallFloatMethod = ENV_SLOT_CallLongMethod + 3,
    ENV_SLOT_CallDoubleMethod = ENV_SLOT_CallFloatMethod + 3,
    ENV_SLOT_CallStaticObjectMethod = ENV_SLOT_CallDoubleMethod + 3,
    ENV_SLOT_CallStaticBooleanMethod = ENV_SLOT_CallStaticObjectMethod + 3,
    ENV_SLOT_CallStaticByteMethod = ENV_SLOT_CallStaticBooleanMethod + 3,
    ENV_SLOT_CallStaticCharMethod = ENV_SLOT_CallStaticByteMethod + 3,
    ENV_SLOT_CallStaticShortMethod = ENV_SLOT_CallStaticCharMethod + 3,
    ENV_SLOT_CallStaticIntMethod = ENV_SLOT_CallStaticShortMethod + 3,
    ENV_SLOT_CallStaticLongMethod = ENV_SLOT_CallStaticIntMethod + 3,
    ENV_SLOT_CallStaticFloatMethod = ENV_SLOT_CallStaticLongMethod + 3,
    ENV_SLOT_CallStaticDoubleMethod = ENV_SLOT_CallStaticFloatMethod + 3,
    ENV_SLOT_NewObject = ENV_SLOT_CallStaticDoubleMethod + 3,
    ENV_SLOT_CallVoidMethod = ENV_SLOT_NewObject + 3,
    ENV_SLOT_CallStaticVoidMethod = ENV_SLOT_CallVoidMethod + 3,
    ENV_SLOT_CallStaticVoidMethod_end = ENV_SLOT_CallStaticVoidMethod + 3,
    ADH_FIELD_SLOT_LIST(ADH_FIELD_ENUM_ENTRY)
    ENV_HOOK_MAX,
};

struct EnvHookSlot {
    const char *name;
    void **slot;              // &table-><fn>; kept after uninstall so status can show the restore
    void *original;           // saved table entry (published atomically)
    int installed;
    int active;               // atomic: wrappers forward without emitting while 0
    unsigned long long hits;
    unsigned long long dropped;
    // Last emitted value, so status can show what a slot saw even when the capture ring has
    // already evicted the record (a busy target can push thousands of events). Benignly racy:
    // hits/dropped stay authoritative, this is a diagnostic snapshot.
    char last[192];
};

#define ADH_FIXED_SLOT_INITS(X) \
    X("GetStringUTFChars") X("FindClass") X("GetMethodID") X("GetStaticMethodID") \
    X("NewStringUTF") X("GetFieldID") X("GetStaticFieldID") X("GetByteArrayElements") \
    X("SetByteArrayRegion") X("ReleaseByteArrayElements") X("GetByteArrayRegion") \
    X("GetPrimitiveArrayCritical") X("ReleasePrimitiveArrayCritical")

#define ADH_CALL_VALUE_FAMILIES(X) \
    X(CallObjectMethod,        jobject,  jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallObjectMethod,        34) \
    X(CallBooleanMethod,       jboolean, jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallBooleanMethod,       37) \
    X(CallByteMethod,          jbyte,    jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallByteMethod,          40) \
    X(CallCharMethod,          jchar,    jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallCharMethod,          43) \
    X(CallShortMethod,         jshort,   jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallShortMethod,         46) \
    X(CallIntMethod,           jint,     jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallIntMethod,           49) \
    X(CallLongMethod,          jlong,    jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallLongMethod,          52) \
    X(CallFloatMethod,         jfloat,   jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallFloatMethod,         55) \
    X(CallDoubleMethod,        jdouble,  jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallDoubleMethod,        58) \
    X(CallStaticObjectMethod,  jobject,  jclass,  ADH_MEMBER_STATIC,   ENV_SLOT_CallStaticObjectMethod,  114) \
    X(CallStaticBooleanMethod, jboolean, jclass,  ADH_MEMBER_STATIC,   ENV_SLOT_CallStaticBooleanMethod, 117) \
    X(CallStaticByteMethod,    jbyte,    jclass,  ADH_MEMBER_STATIC,   ENV_SLOT_CallStaticByteMethod,    120) \
    X(CallStaticCharMethod,    jchar,    jclass,  ADH_MEMBER_STATIC,   ENV_SLOT_CallStaticCharMethod,    123) \
    X(CallStaticShortMethod,   jshort,   jclass,  ADH_MEMBER_STATIC,   ENV_SLOT_CallStaticShortMethod,   126) \
    X(CallStaticIntMethod,     jint,     jclass,  ADH_MEMBER_STATIC,   ENV_SLOT_CallStaticIntMethod,     129) \
    X(CallStaticLongMethod,    jlong,    jclass,  ADH_MEMBER_STATIC,   ENV_SLOT_CallStaticLongMethod,    132) \
    X(CallStaticFloatMethod,   jfloat,   jclass,  ADH_MEMBER_STATIC,   ENV_SLOT_CallStaticFloatMethod,   135) \
    X(CallStaticDoubleMethod,  jdouble,  jclass,  ADH_MEMBER_STATIC,   ENV_SLOT_CallStaticDoubleMethod,  138) \
    X(NewObject,               jobject,  jclass,  ADH_MEMBER_CTOR,     ENV_SLOT_NewObject,               28)

#define ADH_CALL_VOID_FAMILIES(X) \
    X(CallVoidMethod,       jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallVoidMethod,       61) \
    X(CallStaticVoidMethod, jclass,  ADH_MEMBER_STATIC,   ENV_SLOT_CallStaticVoidMethod, 141)

#define ADH_SLOT_INIT(name) { name, NULL, NULL, 0, 0, 0, 0, "" },
#define ADH_CALL_INITS_3(name, ret, tgt, kind, base) \
    ADH_SLOT_INIT(#name) ADH_SLOT_INIT(#name "V") ADH_SLOT_INIT(#name "A")
#define ADH_CALL_INITS(name, ret, tgt, kind, base, spec) ADH_CALL_INITS_3(name, ret, tgt, kind, base)
#define ADH_CALL_VOID_INITS(name, tgt, kind, base, spec) ADH_CALL_INITS_3(name, void, tgt, kind, base)

static struct EnvHookSlot g_env_hooks[ENV_HOOK_MAX] = {
    ADH_FIXED_SLOT_INITS(ADH_SLOT_INIT)
    ADH_CALL_VALUE_FAMILIES(ADH_CALL_INITS)
    ADH_CALL_VOID_FAMILIES(ADH_CALL_VOID_INITS)
    ADH_FIELD_SLOT_LIST(ADH_FIELD_NAME_ENTRY)
};

static pthread_mutex_t g_env_hook_lock = PTHREAD_MUTEX_INITIALIZER;
// Marks the current thread as running ADH instrumentation code (label resolution, class
// names, array-length reads). Only our own nested JNI calls are suppressed by it: the target's
// own call always runs with the flag clear, so Java->JNI callbacks made *inside* a hooked call
// are still observed. Setting it across the target call would silently hide that traffic.
static __thread int g_env_hook_in_ours = 0;
static unsigned long long g_env_hook_table = 0;

typedef const char *(*get_string_utf_chars_fn)(JNIEnv *, jstring, jboolean *);
typedef jclass (*find_class_fn)(JNIEnv *, const char *);
typedef jmethodID (*get_method_id_fn)(JNIEnv *, jclass, const char *, const char *);
typedef jstring (*new_string_utf_fn)(JNIEnv *, const char *);
typedef jbyte *(*get_byte_array_elements_fn)(JNIEnv *, jarray, jboolean *);
typedef void (*set_byte_array_region_fn)(JNIEnv *, jarray, jsize, jsize, const jbyte *);
typedef void (*release_byte_array_elements_fn)(JNIEnv *, jbyteArray, jbyte *, jint);
typedef void (*get_byte_array_region_fn)(JNIEnv *, jbyteArray, jsize, jsize, jbyte *);
typedef void *(*get_primitive_array_critical_fn)(JNIEnv *, jarray, jboolean *);
typedef void (*release_primitive_array_critical_fn)(JNIEnv *, jarray, void *, jint);

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
    snprintf(g_env_hooks[index].last, sizeof(g_env_hooks[index].last), "%s", value ? value : "");
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
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetStringUTFChars)) return original(env, str, isCopy);
    g_env_hook_in_ours = 1;
    const char *result = original(env, str, isCopy);
    if (result && env_budget_left(ENV_SLOT_GetStringUTFChars)) {
        char bounded[257];
        strncpy(bounded, result, sizeof(bounded) - 1);
        bounded[sizeof(bounded) - 1] = 0;
        env_note(ENV_SLOT_GetStringUTFChars, bounded, 1);
    } else {
        env_note(ENV_SLOT_GetStringUTFChars, NULL, result != NULL);
    }
    g_env_hook_in_ours = 0;
    return result;
}

static jclass FindClass_wrapper(JNIEnv *env, const char *name) {
    find_class_fn original = (find_class_fn)slot_original(ENV_SLOT_FindClass);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_FindClass)) return original(env, name);
    g_env_hook_in_ours = 1;
    jclass result = original(env, name);
    env_note(ENV_SLOT_FindClass, env_budget_left(ENV_SLOT_FindClass) ? name : NULL, result != NULL);
    g_env_hook_in_ours = 0;
    return result;
}

static jmethodID GetMethodID_wrapper(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
    get_method_id_fn original = (get_method_id_fn)slot_original(ENV_SLOT_GetMethodID);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetMethodID)) return original(env, clazz, name, sig);
    jmethodID result = original(env, clazz, name, sig);
    char detail[512];
    if (!env_budget_left(ENV_SLOT_GetMethodID)) {
        env_note(ENV_SLOT_GetMethodID, NULL, 0);
    } else if ((*env)->ExceptionCheck(env)) {
        detail_method_plain(name, sig, detail, sizeof(detail));
        env_note(ENV_SLOT_GetMethodID, detail, 0);
    } else {
        g_env_hook_in_ours = 1;
        detail_method(env, clazz, name, sig, detail, sizeof(detail));
        g_env_hook_in_ours = 0;
        env_note(ENV_SLOT_GetMethodID, detail, 1);
    }
    return result;
}

static jmethodID GetStaticMethodID_wrapper(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
    get_method_id_fn original = (get_method_id_fn)slot_original(ENV_SLOT_GetStaticMethodID);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetStaticMethodID)) return original(env, clazz, name, sig);
    jmethodID result = original(env, clazz, name, sig);
    char detail[512];
    if (!env_budget_left(ENV_SLOT_GetStaticMethodID)) {
        env_note(ENV_SLOT_GetStaticMethodID, NULL, 0);
    } else if ((*env)->ExceptionCheck(env)) {
        detail_method_plain(name, sig, detail, sizeof(detail));
        env_note(ENV_SLOT_GetStaticMethodID, detail, 0);
    } else {
        g_env_hook_in_ours = 1;
        detail_method(env, clazz, name, sig, detail, sizeof(detail));
        g_env_hook_in_ours = 0;
        env_note(ENV_SLOT_GetStaticMethodID, detail, 1);
    }
    return result;
}

static jstring NewStringUTF_wrapper(JNIEnv *env, const char *chars) {
    new_string_utf_fn original = (new_string_utf_fn)slot_original(ENV_SLOT_NewStringUTF);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_NewStringUTF)) return original(env, chars);
    g_env_hook_in_ours = 1;
    jstring result = original(env, chars);
    env_note(ENV_SLOT_NewStringUTF, env_budget_left(ENV_SLOT_NewStringUTF) ? chars : NULL, result != NULL);
    g_env_hook_in_ours = 0;
    return result;
}

static jfieldID GetFieldID_wrapper(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
    get_method_id_fn original = (get_method_id_fn)slot_original(ENV_SLOT_GetFieldID);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetFieldID)) return (jfieldID)original(env, clazz, name, sig);
    jfieldID result = (jfieldID)original(env, clazz, name, sig);
    char detail[512];
    if (!env_budget_left(ENV_SLOT_GetFieldID)) {
        env_note(ENV_SLOT_GetFieldID, NULL, 0);
    } else if ((*env)->ExceptionCheck(env)) {
        detail_field_plain(name, sig, detail, sizeof(detail));
        env_note(ENV_SLOT_GetFieldID, detail, 0);
    } else {
        g_env_hook_in_ours = 1;
        detail_field(env, clazz, name, sig, detail, sizeof(detail));
        g_env_hook_in_ours = 0;
        // Append the id the caller received. The field ACCESS events (Get/Set<Type>Field) carry
        // "field=0x.." but no name, so this is what lets the host join an access back to
        // "Class#name:sig" instead of reporting an opaque pointer.
        {
            size_t dl = strlen(detail);
            if (dl + 16 < sizeof(detail)) snprintf(detail + dl, sizeof(detail) - dl, " -> %p", (void *)result);
        }
        env_note(ENV_SLOT_GetFieldID, detail, 1);
    }
    return result;
}

static jfieldID GetStaticFieldID_wrapper(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
    get_method_id_fn original = (get_method_id_fn)slot_original(ENV_SLOT_GetStaticFieldID);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetStaticFieldID)) return (jfieldID)original(env, clazz, name, sig);
    jfieldID result = (jfieldID)original(env, clazz, name, sig);
    char detail[512];
    if (!env_budget_left(ENV_SLOT_GetStaticFieldID)) {
        env_note(ENV_SLOT_GetStaticFieldID, NULL, 0);
    } else if ((*env)->ExceptionCheck(env)) {
        detail_field_plain(name, sig, detail, sizeof(detail));
        env_note(ENV_SLOT_GetStaticFieldID, detail, 0);
    } else {
        g_env_hook_in_ours = 1;
        detail_field(env, clazz, name, sig, detail, sizeof(detail));
        g_env_hook_in_ours = 0;
        {
            size_t dl = strlen(detail);
            if (dl + 16 < sizeof(detail)) snprintf(detail + dl, sizeof(detail) - dl, " -> %p", (void *)result);
        }
        env_note(ENV_SLOT_GetStaticFieldID, detail, 1);
    }
    return result;
}

static jbyte *GetByteArrayElements_wrapper(JNIEnv *env, jarray array, jboolean *isCopy) {
    get_byte_array_elements_fn original =
        (get_byte_array_elements_fn)slot_original(ENV_SLOT_GetByteArrayElements);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetByteArrayElements)) return original(env, array, isCopy);
    jbyte *result = original(env, array, isCopy);
    if (result && array && env_budget_left(ENV_SLOT_GetByteArrayElements)) {
        g_env_hook_in_ours = 1;
        jsize len = (*env)->GetArrayLength(env, array);
        g_env_hook_in_ours = 0;
        char hex[2 * ENV_HEX_PREVIEW + 8], detail[96];
        hex_preview(result, len, hex, sizeof(hex));
        snprintf(detail, sizeof(detail), "len=%d hex=%s", (int)len, hex);
        env_note(ENV_SLOT_GetByteArrayElements, detail, 1);
    } else {
        env_note(ENV_SLOT_GetByteArrayElements, NULL, result != NULL);
    }
    return result;
}

static void SetByteArrayRegion_wrapper(JNIEnv *env, jarray array, jsize start, jsize len,
                                       const jbyte *buf) {
    set_byte_array_region_fn original =
        (set_byte_array_region_fn)slot_original(ENV_SLOT_SetByteArrayRegion);
    if (!original) return;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_SetByteArrayRegion)) {
        original(env, array, start, len, buf);
        return;
    }
    g_env_hook_in_ours = 1;
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
    g_env_hook_in_ours = 0;
}
// Critical arrays: JNI forbids calling other JNI functions (or blocking) between
// Get/ReleasePrimitiveArrayCritical, so the length is captured at Get time keyed by the
// returned buffer pointer and consumed at Release time. Reading the buffer at release is then
// legal and gives the in-place writeback (the usual post-decryption pattern) with no JNI call
// inside the critical section and no stale-handle guessing.
#define ENV_CRIT_SLOTS 8
struct CritEntry { void *carray; jsize len; };
static struct CritEntry g_crit[ENV_CRIT_SLOTS];
static pthread_mutex_t g_crit_lock = PTHREAD_MUTEX_INITIALIZER;

static void crit_stash(void *carray, jsize len) {
    if (!carray || len <= 0 || pthread_mutex_trylock(&g_crit_lock) != 0) return;
    int slot = -1;
    for (int i = 0; i < ENV_CRIT_SLOTS; i++) {
        if (__atomic_load_n(&g_crit[i].carray, __ATOMIC_ACQUIRE) == carray) { slot = i; break; }
        if (!g_crit[i].carray && slot < 0) slot = i;
    }
    if (slot >= 0) {
        g_crit[slot].len = len;
        __atomic_store_n(&g_crit[slot].carray, carray, __ATOMIC_RELEASE);
    }
    pthread_mutex_unlock(&g_crit_lock);
}

// Consume-on-release: an entry is cleared when its buffer is released, so a recycled pointer
// finds an empty slot instead of an old length.
static jsize crit_take(void *carray) {
    if (!carray) return 0;
    for (int i = 0; i < ENV_CRIT_SLOTS; i++) {
        if (__atomic_load_n(&g_crit[i].carray, __ATOMIC_ACQUIRE) != carray) continue;
        jsize len = g_crit[i].len;
        __atomic_store_n(&g_crit[i].carray, NULL, __ATOMIC_RELEASE);
        return len;
    }
    return 0;
}

static void ReleaseByteArrayElements_wrapper(JNIEnv *env, jbyteArray array, jbyte *elems, jint mode) {
    release_byte_array_elements_fn original =
        (release_byte_array_elements_fn)slot_original(ENV_SLOT_ReleaseByteArrayElements);
    if (!original) return;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_ReleaseByteArrayElements)) {
        original(env, array, elems, mode);
        return;
    }
    if (env_budget_left(ENV_SLOT_ReleaseByteArrayElements)) {
        char hex[2 * ENV_HEX_PREVIEW + 8], detail[160];
        g_env_hook_in_ours = 1;
        jsize len = (array && elems) ? (*env)->GetArrayLength(env, array) : 0;
        g_env_hook_in_ours = 0;
        hex_preview(elems, (mode == JNI_ABORT) ? 0 : len, hex, sizeof(hex));
        snprintf(detail, sizeof(detail), "len=%d mode=%d %s%s", (int)len, (int)mode,
                 (mode == JNI_ABORT) ? "(no copyback)" : "writeback hex=", hex);
        original(env, array, elems, mode);
        env_note(ENV_SLOT_ReleaseByteArrayElements, detail, 1);
    } else {
        original(env, array, elems, mode);
        env_note(ENV_SLOT_ReleaseByteArrayElements, NULL, 1);
    }
}

static void GetByteArrayRegion_wrapper(JNIEnv *env, jbyteArray array, jsize start, jsize len, jbyte *buf) {
    get_byte_array_region_fn original =
        (get_byte_array_region_fn)slot_original(ENV_SLOT_GetByteArrayRegion);
    if (!original) return;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetByteArrayRegion)) {
        original(env, array, start, len, buf);
        return;
    }
    original(env, array, start, len, buf);
    if (env_budget_left(ENV_SLOT_GetByteArrayRegion) && !(*env)->ExceptionCheck(env)) {
        char hex[2 * ENV_HEX_PREVIEW + 8], detail[128];
        hex_preview(buf, len, hex, sizeof(hex));
        snprintf(detail, sizeof(detail), "start=%d len=%d hex=%s", (int)start, (int)len, hex);
        env_note(ENV_SLOT_GetByteArrayRegion, detail, 1);
    } else {
        env_note(ENV_SLOT_GetByteArrayRegion, NULL, 0);
    }
}

static void *GetPrimitiveArrayCritical_wrapper(JNIEnv *env, jarray array, jboolean *isCopy) {
    get_primitive_array_critical_fn original =
        (get_primitive_array_critical_fn)slot_original(ENV_SLOT_GetPrimitiveArrayCritical);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetPrimitiveArrayCritical)) {
        return original(env, array, isCopy);
    }
    // Length must be read BEFORE the original call: once it returns we are inside the critical
    // section, where JNI forbids further JNI calls.
    jsize len = array ? (*env)->GetArrayLength(env, array) : 0;
    void *result = original(env, array, isCopy);
    if (result && len > 0) crit_stash(result, len);
    if (env_budget_left(ENV_SLOT_GetPrimitiveArrayCritical)) {
        char detail[96];
        snprintf(detail, sizeof(detail), "len=%d ptr=0x%llx isCopy=%s", (int)len,
                 (unsigned long long)(uintptr_t)result, (isCopy && *isCopy) ? "true" : "false");
        env_note(ENV_SLOT_GetPrimitiveArrayCritical, detail, result != NULL);
    } else {
        env_note(ENV_SLOT_GetPrimitiveArrayCritical, NULL, result != NULL);
    }
    return result;
}

static void ReleasePrimitiveArrayCritical_wrapper(JNIEnv *env, jarray array, void *carray, jint mode) {
    release_primitive_array_critical_fn original =
        (release_primitive_array_critical_fn)slot_original(ENV_SLOT_ReleasePrimitiveArrayCritical);
    if (!original) return;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_ReleasePrimitiveArrayCritical)) {
        original(env, array, carray, mode);
        return;
    }
    jsize len = crit_take(carray);
    if (env_budget_left(ENV_SLOT_ReleasePrimitiveArrayCritical)) {
        char hex[2 * ENV_HEX_PREVIEW + 8], detail[160];
        hex_preview((const jbyte *)carray, (mode == JNI_ABORT) ? 0 : len, hex, sizeof(hex));
        snprintf(detail, sizeof(detail), "len=%d mode=%d %s%s", (int)len, (int)mode,
                 (mode == JNI_ABORT) ? "(no copyback)" : "writeback hex=", hex);
        original(env, array, carray, mode);
        env_note(ENV_SLOT_ReleasePrimitiveArrayCritical, detail, 1);
    } else {
        original(env, array, carray, mode);
        env_note(ENV_SLOT_ReleasePrimitiveArrayCritical, NULL, 1);
    }
}
// ---- Call* family wrappers (macro-generated per form) ---------------------
#define ADH_DEFINE_CALL_VALUE(NAME, RET, TGT, KIND, BASE, SPEC)                                \
    static RET NAME##_wrapper(JNIEnv *env, TGT target, jmethodID mid, ...) {                    \
        va_list ap;                                                                             \
        va_start(ap, mid);                                                                      \
        RET (*v_original)(JNIEnv *, TGT, jmethodID, va_list) =                                  \
            (RET (*)(JNIEnv *, TGT, jmethodID, va_list))slot_original(BASE + 1);                \
        if (!slot_active(BASE)) {                                                               \
            RET r = v_original ? v_original(env, target, mid, ap)                               \
                               : (*env)->NAME##V(env, target, mid, ap);                         \
            va_end(ap);                                                                         \
            return r;                                                                           \
        }                                                                                       \
        struct AdhCallDetail detail;                                                            \
        g_env_hook_in_ours = 1;                                                                 \
        call_detail_va(env, BASE, (jobject)target, KIND, mid, ap, &detail);                     \
        g_env_hook_in_ours = 0;                                                                 \
        RET result = v_original ? v_original(env, target, mid, ap)                              \
                                : (*env)->NAME##V(env, target, mid, ap);                        \
        va_end(ap);                                                                             \
        call_emit(BASE, &detail);                                                               \
        return result;                                                                          \
    }                                                                                           \
    static RET NAME##V_wrapper(JNIEnv *env, TGT target, jmethodID mid, va_list ap) {            \
        RET (*original)(JNIEnv *, TGT, jmethodID, va_list) =                                    \
            (RET (*)(JNIEnv *, TGT, jmethodID, va_list))slot_original(BASE + 1);                \
        if (!original) return (RET)0;                                                           \
        if (g_env_hook_in_ours || !slot_active(BASE + 1)) return original(env, target, mid, ap); \
        struct AdhCallDetail detail;                                                            \
        g_env_hook_in_ours = 1;                                                                 \
        call_detail_va(env, BASE + 1, (jobject)target, KIND, mid, ap, &detail);                 \
        g_env_hook_in_ours = 0;                                                                 \
        RET result = original(env, target, mid, ap);                                            \
        call_emit(BASE + 1, &detail);                                                           \
        return result;                                                                          \
    }                                                                                           \
    static RET NAME##A_wrapper(JNIEnv *env, TGT target, jmethodID mid, const jvalue *args) {    \
        RET (*original)(JNIEnv *, TGT, jmethodID, const jvalue *) =                             \
            (RET (*)(JNIEnv *, TGT, jmethodID, const jvalue *))slot_original(BASE + 2);          \
        if (!original) return (RET)0;                                                           \
        if (g_env_hook_in_ours || !slot_active(BASE + 2)) return original(env, target, mid, args); \
        struct AdhCallDetail detail;                                                            \
        g_env_hook_in_ours = 1;                                                                 \
        call_detail_a(env, BASE + 2, (jobject)target, KIND, mid, args, &detail);                 \
        g_env_hook_in_ours = 0;                                                                 \
        RET result = original(env, target, mid, args);                                          \
        call_emit(BASE + 2, &detail);                                                           \
        return result;                                                                          \
    }

#define ADH_DEFINE_CALL_VOID(NAME, TGT, KIND, BASE, SPEC)                                       \
    static void NAME##_wrapper(JNIEnv *env, TGT target, jmethodID mid, ...) {                   \
        va_list ap;                                                                             \
        va_start(ap, mid);                                                                      \
        void (*v_original)(JNIEnv *, TGT, jmethodID, va_list) =                                 \
            (void (*)(JNIEnv *, TGT, jmethodID, va_list))slot_original(BASE + 1);               \
        if (!slot_active(BASE)) {                                                               \
            if (v_original) v_original(env, target, mid, ap);                                   \
            else (*env)->NAME##V(env, target, mid, ap);                                         \
            va_end(ap);                                                                         \
            return;                                                                             \
        }                                                                                       \
        struct AdhCallDetail detail;                                                            \
        g_env_hook_in_ours = 1;                                                                 \
        call_detail_va(env, BASE, (jobject)target, KIND, mid, ap, &detail);                     \
        g_env_hook_in_ours = 0;                                                                 \
        if (v_original) v_original(env, target, mid, ap);                                       \
        else (*env)->NAME##V(env, target, mid, ap);                                             \
        va_end(ap);                                                                             \
        call_emit(BASE, &detail);                                                               \
    }                                                                                           \
    static void NAME##V_wrapper(JNIEnv *env, TGT target, jmethodID mid, va_list ap) {           \
        void (*original)(JNIEnv *, TGT, jmethodID, va_list) =                                   \
            (void (*)(JNIEnv *, TGT, jmethodID, va_list))slot_original(BASE + 1);               \
        if (!original) return;                                                                  \
        if (g_env_hook_in_ours || !slot_active(BASE + 1)) { original(env, target, mid, ap); return; } \
        struct AdhCallDetail detail;                                                            \
        g_env_hook_in_ours = 1;                                                                 \
        call_detail_va(env, BASE + 1, (jobject)target, KIND, mid, ap, &detail);                 \
        g_env_hook_in_ours = 0;                                                                 \
        original(env, target, mid, ap);                                                         \
        call_emit(BASE + 1, &detail);                                                           \
    }                                                                                           \
    static void NAME##A_wrapper(JNIEnv *env, TGT target, jmethodID mid, const jvalue *args) {   \
        void (*original)(JNIEnv *, TGT, jmethodID, const jvalue *) =                            \
            (void (*)(JNIEnv *, TGT, jmethodID, const jvalue *))slot_original(BASE + 2);         \
        if (!original) return;                                                                  \
        if (g_env_hook_in_ours || !slot_active(BASE + 2)) { original(env, target, mid, args); return; } \
        struct AdhCallDetail detail;                                                            \
        g_env_hook_in_ours = 1;                                                                 \
        call_detail_a(env, BASE + 2, (jobject)target, KIND, mid, args, &detail);                 \
        g_env_hook_in_ours = 0;                                                                 \
        original(env, target, mid, args);                                                       \
        call_emit(BASE + 2, &detail);                                                           \
    }

ADH_CALL_VALUE_FAMILIES(ADH_DEFINE_CALL_VALUE)
ADH_CALL_VOID_FAMILIES(ADH_DEFINE_CALL_VOID)


// ---- field accessors ------------------------------------------------------
// Each wrapper forwards to the saved table entry and records one bounded event. The _Static_assert
// block at the end is compile-time proof that every wrapper has EXACTLY the JNI signature of the
// entry it replaces - a mismatch stops the build instead of crashing inside a target.
#define ADH_DEFINE_FIELD_GET_BODY(JNI_NAME, CTYPE, FMT, CAST, TARGET)                       \
static CTYPE JNICALL JNI_NAME##_wrapper(JNIEnv *env, TARGET target, jfieldID field) {       \
    typedef CTYPE (JNICALL *fn_t)(JNIEnv *, TARGET, jfieldID);                              \
    fn_t original = (fn_t)slot_original(ENV_SLOT_##JNI_NAME);                               \
    if (!original) return (CTYPE)0;                                                         \
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_##JNI_NAME)) {                          \
        return original(env, target, field);                                                \
    }                                                                                       \
    g_env_hook_in_ours = 1;                                                                 \
    CTYPE result = original(env, target, field);                                            \
    char detail[128]; detail[0] = 0;                                                        \
    if (env_budget_left(ENV_SLOT_##JNI_NAME)) {                                             \
        snprintf(detail, sizeof(detail), "field=%p value=" FMT, (void *)field, CAST(result)); \
    }                                                                                       \
    env_note(ENV_SLOT_##JNI_NAME, detail[0] ? detail : NULL, 1);                            \
    g_env_hook_in_ours = 0;                                                                 \
    return result;                                                                          \
}

#define ADH_DEFINE_FIELD_SET_BODY(JNI_NAME, CTYPE, FMT, CAST, TARGET)                       \
static void JNICALL JNI_NAME##_wrapper(JNIEnv *env, TARGET target, jfieldID field, CTYPE value) { \
    typedef void (JNICALL *fn_t)(JNIEnv *, TARGET, jfieldID, CTYPE);                        \
    fn_t original = (fn_t)slot_original(ENV_SLOT_##JNI_NAME);                               \
    if (!original) return;                                                                  \
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_##JNI_NAME)) {                          \
        original(env, target, field, value);                                                \
        return;                                                                             \
    }                                                                                       \
    g_env_hook_in_ours = 1;                                                                 \
    original(env, target, field, value);                                                    \
    char detail[128]; detail[0] = 0;                                                        \
    if (env_budget_left(ENV_SLOT_##JNI_NAME)) {                                             \
        snprintf(detail, sizeof(detail), "field=%p value=" FMT, (void *)field, CAST(value)); \
    }                                                                                       \
    env_note(ENV_SLOT_##JNI_NAME, detail[0] ? detail : NULL, 1);                            \
    g_env_hook_in_ours = 0;                                                                 \
}

#define ADH_FIELD_TYPE_ROW(NAME, CTYPE, FMT, CAST)                                          \
    ADH_DEFINE_FIELD_GET_BODY(Get##NAME##Field, CTYPE, FMT, CAST, jobject)                  \
    ADH_DEFINE_FIELD_SET_BODY(Set##NAME##Field, CTYPE, FMT, CAST, jobject)                  \
    ADH_DEFINE_FIELD_GET_BODY(GetStatic##NAME##Field, CTYPE, FMT, CAST, jclass)             \
    ADH_DEFINE_FIELD_SET_BODY(SetStatic##NAME##Field, CTYPE, FMT, CAST, jclass)

ADH_FIELD_TYPE_ROW(Object, jobject, "%p", (const void *))
ADH_FIELD_TYPE_ROW(Boolean, jboolean, "%d", (int))
ADH_FIELD_TYPE_ROW(Byte, jbyte, "%d", (int))
ADH_FIELD_TYPE_ROW(Char, jchar, "%u", (unsigned))
ADH_FIELD_TYPE_ROW(Short, jshort, "%d", (int))
ADH_FIELD_TYPE_ROW(Int, jint, "%d", (int))
ADH_FIELD_TYPE_ROW(Long, jlong, "%lld", (long long))
ADH_FIELD_TYPE_ROW(Float, jfloat, "%g", (double))
ADH_FIELD_TYPE_ROW(Double, jdouble, "%g", (double))

// Compile-time type check: each wrapper must have exactly its table entry signature.
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetObjectField), __typeof__(&GetObjectField_wrapper)), "GetObjectField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetObjectField), __typeof__(&SetObjectField_wrapper)), "SetObjectField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetStaticObjectField), __typeof__(&GetStaticObjectField_wrapper)), "GetStaticObjectField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetStaticObjectField), __typeof__(&SetStaticObjectField_wrapper)), "SetStaticObjectField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetBooleanField), __typeof__(&GetBooleanField_wrapper)), "GetBooleanField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetBooleanField), __typeof__(&SetBooleanField_wrapper)), "SetBooleanField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetStaticBooleanField), __typeof__(&GetStaticBooleanField_wrapper)), "GetStaticBooleanField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetStaticBooleanField), __typeof__(&SetStaticBooleanField_wrapper)), "SetStaticBooleanField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetByteField), __typeof__(&GetByteField_wrapper)), "GetByteField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetByteField), __typeof__(&SetByteField_wrapper)), "SetByteField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetStaticByteField), __typeof__(&GetStaticByteField_wrapper)), "GetStaticByteField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetStaticByteField), __typeof__(&SetStaticByteField_wrapper)), "SetStaticByteField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetCharField), __typeof__(&GetCharField_wrapper)), "GetCharField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetCharField), __typeof__(&SetCharField_wrapper)), "SetCharField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetStaticCharField), __typeof__(&GetStaticCharField_wrapper)), "GetStaticCharField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetStaticCharField), __typeof__(&SetStaticCharField_wrapper)), "SetStaticCharField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetShortField), __typeof__(&GetShortField_wrapper)), "GetShortField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetShortField), __typeof__(&SetShortField_wrapper)), "SetShortField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetStaticShortField), __typeof__(&GetStaticShortField_wrapper)), "GetStaticShortField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetStaticShortField), __typeof__(&SetStaticShortField_wrapper)), "SetStaticShortField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetIntField), __typeof__(&GetIntField_wrapper)), "GetIntField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetIntField), __typeof__(&SetIntField_wrapper)), "SetIntField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetStaticIntField), __typeof__(&GetStaticIntField_wrapper)), "GetStaticIntField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetStaticIntField), __typeof__(&SetStaticIntField_wrapper)), "SetStaticIntField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetLongField), __typeof__(&GetLongField_wrapper)), "GetLongField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetLongField), __typeof__(&SetLongField_wrapper)), "SetLongField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetStaticLongField), __typeof__(&GetStaticLongField_wrapper)), "GetStaticLongField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetStaticLongField), __typeof__(&SetStaticLongField_wrapper)), "SetStaticLongField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetFloatField), __typeof__(&GetFloatField_wrapper)), "GetFloatField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetFloatField), __typeof__(&SetFloatField_wrapper)), "SetFloatField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetStaticFloatField), __typeof__(&GetStaticFloatField_wrapper)), "GetStaticFloatField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetStaticFloatField), __typeof__(&SetStaticFloatField_wrapper)), "SetStaticFloatField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetDoubleField), __typeof__(&GetDoubleField_wrapper)), "GetDoubleField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetDoubleField), __typeof__(&SetDoubleField_wrapper)), "SetDoubleField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetStaticDoubleField), __typeof__(&GetStaticDoubleField_wrapper)), "GetStaticDoubleField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetStaticDoubleField), __typeof__(&SetStaticDoubleField_wrapper)), "SetStaticDoubleField_wrapper signature mismatch");

// JNIEnv table slot indices, straight from the JNINativeInterface field order in the NDK
// jni.h (the layout the JNI spec fixes). The offset check turns "my index table drifted from
// the real ABI" into a loud install failure instead of patching a neighbouring JNI function.
#define ADH_CALL_GUARD_CASES(name, ret, tgt, kind, base, spec) \
    case base: return spec; \
    case base + 1: return spec + 1; \
    case base + 2: return spec + 2;
#define ADH_CALL_VOID_GUARD_CASES(name, tgt, kind, base, spec) ADH_CALL_GUARD_CASES(name, void, tgt, kind, base, spec)

static int env_hook_spec_index(int index) {
    switch (index) {
        // field accessors (v4.55): indices verified against jni.h by tools/verify_v90_jni_table_abi.sh
        case ENV_SLOT_GetObjectField: return 95;
        case ENV_SLOT_GetBooleanField: return 96;
        case ENV_SLOT_GetByteField: return 97;
        case ENV_SLOT_GetCharField: return 98;
        case ENV_SLOT_GetShortField: return 99;
        case ENV_SLOT_GetIntField: return 100;
        case ENV_SLOT_GetLongField: return 101;
        case ENV_SLOT_GetFloatField: return 102;
        case ENV_SLOT_GetDoubleField: return 103;
        case ENV_SLOT_SetObjectField: return 104;
        case ENV_SLOT_SetBooleanField: return 105;
        case ENV_SLOT_SetByteField: return 106;
        case ENV_SLOT_SetCharField: return 107;
        case ENV_SLOT_SetShortField: return 108;
        case ENV_SLOT_SetIntField: return 109;
        case ENV_SLOT_SetLongField: return 110;
        case ENV_SLOT_SetFloatField: return 111;
        case ENV_SLOT_SetDoubleField: return 112;
        case ENV_SLOT_GetStaticObjectField: return 145;
        case ENV_SLOT_GetStaticBooleanField: return 146;
        case ENV_SLOT_GetStaticByteField: return 147;
        case ENV_SLOT_GetStaticCharField: return 148;
        case ENV_SLOT_GetStaticShortField: return 149;
        case ENV_SLOT_GetStaticIntField: return 150;
        case ENV_SLOT_GetStaticLongField: return 151;
        case ENV_SLOT_GetStaticFloatField: return 152;
        case ENV_SLOT_GetStaticDoubleField: return 153;
        case ENV_SLOT_SetStaticObjectField: return 154;
        case ENV_SLOT_SetStaticBooleanField: return 155;
        case ENV_SLOT_SetStaticByteField: return 156;
        case ENV_SLOT_SetStaticCharField: return 157;
        case ENV_SLOT_SetStaticShortField: return 158;
        case ENV_SLOT_SetStaticIntField: return 159;
        case ENV_SLOT_SetStaticLongField: return 160;
        case ENV_SLOT_SetStaticFloatField: return 161;
        case ENV_SLOT_SetStaticDoubleField: return 162;
        case ENV_SLOT_FindClass: return 6;
        case ENV_SLOT_GetMethodID: return 33;
        ADH_CALL_VALUE_FAMILIES(ADH_CALL_GUARD_CASES)
        ADH_CALL_VOID_FAMILIES(ADH_CALL_VOID_GUARD_CASES)
        case ENV_SLOT_GetFieldID: return 94;
        case ENV_SLOT_GetStaticMethodID: return 113;
        case ENV_SLOT_GetStaticFieldID: return 144;
        case ENV_SLOT_NewStringUTF: return 167;
        case ENV_SLOT_GetStringUTFChars: return 169;
        case ENV_SLOT_GetByteArrayElements: return 184;
        case ENV_SLOT_ReleaseByteArrayElements: return 192;
        case ENV_SLOT_GetByteArrayRegion: return 200;
        case ENV_SLOT_SetByteArrayRegion: return 208;
        case ENV_SLOT_GetPrimitiveArrayCritical: return 222;
        case ENV_SLOT_ReleasePrimitiveArrayCritical: return 223;
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

#define ADH_CALL_SLOT_CASES(name, ret, tgt, kind, base, spec) \
    case base: return (void **)(uintptr_t)&table->name; \
    case base + 1: return (void **)(uintptr_t)&table->name##V; \
    case base + 2: return (void **)(uintptr_t)&table->name##A;
#define ADH_CALL_VOID_SLOT_CASES(name, tgt, kind, base, spec) ADH_CALL_SLOT_CASES(name, void, tgt, kind, base, spec)

static void **env_hook_slot(struct JNINativeInterface *table, int index) {
    switch (index) {
        case ENV_SLOT_GetStringUTFChars: return (void **)(uintptr_t)&table->GetStringUTFChars;
        case ENV_SLOT_FindClass: return (void **)(uintptr_t)&table->FindClass;
        case ENV_SLOT_GetMethodID: return (void **)(uintptr_t)&table->GetMethodID;
        case ENV_SLOT_GetStaticMethodID: return (void **)(uintptr_t)&table->GetStaticMethodID;
        case ENV_SLOT_NewStringUTF: return (void **)(uintptr_t)&table->NewStringUTF;
        case ENV_SLOT_GetFieldID: return (void **)(uintptr_t)&table->GetFieldID;
        case ENV_SLOT_GetStaticFieldID: return (void **)(uintptr_t)&table->GetStaticFieldID;
        ADH_FIELD_SLOT_LIST(ADH_FIELD_SLOT_CASE)
        case ENV_SLOT_GetByteArrayElements: return (void **)(uintptr_t)&table->GetByteArrayElements;
        case ENV_SLOT_SetByteArrayRegion: return (void **)(uintptr_t)&table->SetByteArrayRegion;
        case ENV_SLOT_ReleaseByteArrayElements: return (void **)(uintptr_t)&table->ReleaseByteArrayElements;
        case ENV_SLOT_GetByteArrayRegion: return (void **)(uintptr_t)&table->GetByteArrayRegion;
        case ENV_SLOT_GetPrimitiveArrayCritical: return (void **)(uintptr_t)&table->GetPrimitiveArrayCritical;
        case ENV_SLOT_ReleasePrimitiveArrayCritical: return (void **)(uintptr_t)&table->ReleasePrimitiveArrayCritical;
        ADH_CALL_VALUE_FAMILIES(ADH_CALL_SLOT_CASES)
        ADH_CALL_VOID_FAMILIES(ADH_CALL_VOID_SLOT_CASES)
        default: return NULL;
    }
}

#define ADH_CALL_WRAPPER_CASES(name, ret, tgt, kind, base, spec) \
    case base: return (void *)&name##_wrapper; \
    case base + 1: return (void *)&name##V_wrapper; \
    case base + 2: return (void *)&name##A_wrapper;
#define ADH_CALL_VOID_WRAPPER_CASES(name, tgt, kind, base, spec) ADH_CALL_WRAPPER_CASES(name, void, tgt, kind, base, spec)

static void *env_hook_wrapper(int index) {
    switch (index) {
        case ENV_SLOT_GetStringUTFChars: return (void *)&GetStringUTFChars_wrapper;
        case ENV_SLOT_FindClass: return (void *)&FindClass_wrapper;
        case ENV_SLOT_GetMethodID: return (void *)&GetMethodID_wrapper;
        case ENV_SLOT_GetStaticMethodID: return (void *)&GetStaticMethodID_wrapper;
        case ENV_SLOT_NewStringUTF: return (void *)&NewStringUTF_wrapper;
        case ENV_SLOT_GetFieldID: return (void *)&GetFieldID_wrapper;
        case ENV_SLOT_GetStaticFieldID: return (void *)&GetStaticFieldID_wrapper;
        ADH_FIELD_SLOT_LIST(ADH_FIELD_WRAPPER_CASE)
        case ENV_SLOT_GetByteArrayElements: return (void *)&GetByteArrayElements_wrapper;
        case ENV_SLOT_SetByteArrayRegion: return (void *)&SetByteArrayRegion_wrapper;
        case ENV_SLOT_ReleaseByteArrayElements: return (void *)&ReleaseByteArrayElements_wrapper;
        case ENV_SLOT_GetByteArrayRegion: return (void *)&GetByteArrayRegion_wrapper;
        case ENV_SLOT_GetPrimitiveArrayCritical: return (void *)&GetPrimitiveArrayCritical_wrapper;
        case ENV_SLOT_ReleasePrimitiveArrayCritical: return (void *)&ReleasePrimitiveArrayCritical_wrapper;
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
                            int ok, int applied, int failed, const char *error) {
    char idj[64], actionj[32], functionj[96], errorj[384];
    json_escape(id, idj, sizeof(idj));
    json_escape(action ? action : "", actionj, sizeof(actionj));
    json_escape(function ? function : "", functionj, sizeof(functionj));
    json_escape(error ? error : "", errorj, sizeof(errorj));
    char table_perms[8] = "";
    if (g_env_hook_table) adh_perms_of_addr((void *)(uintptr_t)g_env_hook_table, table_perms, sizeof(table_perms));
    char out[32768];
    size_t len = snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"jni_env_hook\",\"ok\":%s,"
        "\"action\":\"%s\",\"function\":\"%s\",\"applied\":%d,\"failed\":%d,"
        "\"table\":\"0x%llx\",\"tablePerms\":\"%s\",\"error\":\"%s\",\"hooks\":[",
        idj, ok ? "true" : "false", actionj, functionj, applied, failed,
        g_env_hook_table, table_perms, errorj);
    int first = 1;
    for (int i = 0; i < ENV_HOOK_MAX && len + 340 < sizeof(out); i++) {
        char slot_perms[8] = "";
        char lastj[512];
        json_escape(g_env_hooks[i].last, lastj, sizeof(lastj));
        void *live = NULL;
        if (g_env_hooks[i].slot) {
            adh_perms_of_addr((void *)(uintptr_t)g_env_hooks[i].slot, slot_perms, sizeof(slot_perms));
            live = __atomic_load_n(g_env_hooks[i].slot, __ATOMIC_ACQUIRE);
        }
        len += snprintf(out + len, sizeof(out) - len,
                        "%s{\"function\":\"%s\",\"installed\":%s,\"active\":%s,"
                        "\"hits\":%llu,\"dropped\":%llu,\"entry\":\"0x%llx\",\"perms\":\"%s\","
                        "\"slotValue\":\"0x%llx\",\"original\":\"0x%llx\",\"last\":\"%s\"}",
                        first ? "" : ",", g_env_hooks[i].name,
                        g_env_hooks[i].installed ? "true" : "false",
                        slot_active(i) ? "true" : "false",
                        g_env_hooks[i].hits, g_env_hooks[i].dropped,
                        (unsigned long long)(uintptr_t)g_env_hooks[i].slot, slot_perms,
                        (unsigned long long)(uintptr_t)live,
                        (unsigned long long)(uintptr_t)g_env_hooks[i].original, lastj);
        first = 0;
    }
    snprintf(out + len, sizeof(out) - len, "]}\n");
    send_line(fd, out);
}

// Restore one slot's original entry. Fail-loud: refuse if the entry no longer points at our
// wrapper (somebody else patched it), and stay active if the page cannot be made writable.
static int env_hook_uninstall_index(int index, char *error, size_t error_size) {
    pthread_mutex_lock(&g_env_hook_lock);
    if (!g_env_hooks[index].installed || !g_env_hooks[index].slot) {
        pthread_mutex_unlock(&g_env_hook_lock);
        snprintf(error, error_size, "%s is not hooked", g_env_hooks[index].name);
        return 0;
    }
    void **saved_slot = g_env_hooks[index].slot;
    void *saved_original = g_env_hooks[index].original;
    pthread_mutex_unlock(&g_env_hook_lock);

    // Deactivate first: a call already inside the wrapper then still reaches the real
    // implementation (saved_original is a stable pointer) but stops emitting events.
    __atomic_store_n(&g_env_hooks[index].active, 0, __ATOMIC_RELEASE);
    void *current = __atomic_load_n(saved_slot, __ATOMIC_ACQUIRE);
    if (current != env_hook_wrapper(index)) {
        snprintf(error, error_size, "%s: table entry changed underneath the hook wrapper; left untouched",
                 g_env_hooks[index].name);
        return 0;
    }
    if (!adh_swap_pointer_in_ro_page(saved_slot, saved_original)) {
        __atomic_store_n(&g_env_hooks[index].active, 1, __ATOMIC_RELEASE);
        snprintf(error, error_size, "%s: table page could not be made writable", g_env_hooks[index].name);
        return 0;
    }
    pthread_mutex_lock(&g_env_hook_lock);
    g_env_hooks[index].installed = 0;
    pthread_mutex_unlock(&g_env_hook_lock);
    return 1;
}

// Patch one slot. The JNIEnv table lives in libart's RELRO segment, so the swap goes through
// adh_swap_pointer_in_ro_page() and the ABI guard below refuses to touch a drifted offset.
static int env_hook_install_index(int index, char *error, size_t error_size) {
    int did_attach = 0;
    JNIEnv *env = adh_jni_attach(&did_attach);
    if (!env) {
        snprintf(error, error_size, "no JavaVM/JNIEnv");
        return 0;
    }
    struct JNINativeInterface *table = (struct JNINativeInterface *)(*env);
    adh_jni_detach(did_attach);
    if (!table) {
        snprintf(error, error_size, "JNIEnv function table unavailable");
        return 0;
    }
    g_env_hook_table = (unsigned long long)(uintptr_t)table;
    void **slot = env_hook_slot(table, index);
    if (!slot) {
        snprintf(error, error_size, "%s: table entry unavailable", g_env_hooks[index].name);
        return 0;
    }
    int spec = env_hook_spec_index(index);
    unsigned long long slot_offset = (unsigned long long)((char *)slot - (char *)table);
    if (spec < 0 || slot_offset != (unsigned long long)spec * sizeof(void *)) {
        snprintf(error, error_size, "%s: JNIEnv table layout mismatch (offset %llu, spec %d) - refusing to patch",
                 g_env_hooks[index].name, slot_offset, spec);
        LOGE("jni_env_hook: %s", error);
        return 0;
    }

    pthread_mutex_lock(&g_env_hook_lock);
    if (g_env_hooks[index].installed && g_env_hooks[index].slot == slot) {
        // Same entry: re-activate the existing hook instead of patching twice.
        g_env_hooks[index].hits = 0;
        g_env_hooks[index].dropped = 0;
        pthread_mutex_unlock(&g_env_hook_lock);
        __atomic_store_n(&g_env_hooks[index].active, 1, __ATOMIC_RELEASE);
        return 1;
    }
    if (g_env_hooks[index].installed) {
        pthread_mutex_unlock(&g_env_hook_lock);
        snprintf(error, error_size, "%s is already hooked at a different table entry", g_env_hooks[index].name);
        return 0;
    }
    pthread_mutex_unlock(&g_env_hook_lock);

    void *original = __atomic_load_n(slot, __ATOMIC_ACQUIRE);
    if (!original) {
        snprintf(error, error_size, "%s: table entry is null", g_env_hooks[index].name);
        return 0;
    }
    if (original == env_hook_wrapper(index)) {
        snprintf(error, error_size, "%s: entry already points at the hook wrapper", g_env_hooks[index].name);
        return 0;
    }
    // Publish the real entry before the swap: a call that lands in the wrapper during the
    // swap window then still reaches the original implementation.
    __atomic_store_n(&g_env_hooks[index].original, original, __ATOMIC_RELEASE);
    if (!adh_swap_pointer_in_ro_page(slot, env_hook_wrapper(index))) {
        __atomic_store_n(&g_env_hooks[index].original, NULL, __ATOMIC_RELEASE);
        snprintf(error, error_size, "%s: table page could not be made writable", g_env_hooks[index].name);
        return 0;
    }
    __atomic_store_n(&g_env_hooks[index].active, 1, __ATOMIC_RELEASE);
    pthread_mutex_lock(&g_env_hook_lock);
    g_env_hooks[index].slot = slot;
    g_env_hooks[index].installed = 1;
    g_env_hooks[index].hits = 0;
    g_env_hooks[index].dropped = 0;
    pthread_mutex_unlock(&g_env_hook_lock);
    return 1;
}

void adh_cmd_jni_env_hook(int fd, const char *id, const char *action, const char *function) {
    if (!action || !action[0]) {
        send_env_result(fd, id, action, function, 0, 0, 0,
                        "jni_env_hook requires action: install | uninstall | status");
        return;
    }
    if (strcmp(action, "status") == 0) {
        int did_attach = 0;
        JNIEnv *env = adh_jni_attach(&did_attach);
        if (!env) {
            send_env_result(fd, id, action, function, 0, 0, 0, "no JavaVM/JNIEnv");
            return;
        }
        g_env_hook_table = (unsigned long long)(uintptr_t)(*env);
        adh_jni_detach(did_attach);
        send_env_result(fd, id, action, function, 1, 0, 0, "");
        return;
    }
    if (strcmp(action, "install") != 0 && strcmp(action, "uninstall") != 0) {
        send_env_result(fd, id, action, function, 0, 0, 0, "action must be install|uninstall|status");
        return;
    }
    if (!function || !function[0]) {
        send_env_result(fd, id, action, function, 0, 0, 0, "jni_env_hook requires function");
        return;
    }

    // Wildcards so dozens of table entries stay operable in one call:
    //   "*" / "all"   every slot
    //   "Call*"       prefix   (all three forms of a Call family)
    //   "*Field"      suffix   (the 36 field accessors in one call)
    //   "*Field*"     contains (the field ID lookups AND the accessors - what the field digest needs)
    // Reports how many were applied and the first failure, never a silent skip.
    int wildcard = 0, suffix_only = 0, contains = 0;
    const char *pat = function;
    size_t pat_len = strlen(function);
    if (strcmp(function, "all") == 0 || strcmp(function, "*") == 0) {
        wildcard = 1;
        pat = "";
        pat_len = 0;
    } else if (pat_len && pat[0] == '*') {
        wildcard = 1;
        pat++;
        pat_len--;
        if (pat_len && pat[pat_len - 1] == '*') { contains = 1; pat_len--; }   // trim the trailing star too
        else suffix_only = 1;
    } else if (pat_len && pat[pat_len - 1] == '*') {
        wildcard = 1;
        pat_len--;
    }

    int applying = strcmp(action, "install") == 0;
    int applied = 0, failed = 0, matched = 0;
    char first_error[320] = "";
    if (!wildcard) {
        int index = env_hook_index(function);
        if (index < 0) {
            send_env_result(fd, id, action, function, 0, 0, 0, "unsupported JNIEnv function");
            return;
        }
        matched = 1;
        char error[320] = "";
        int ok = applying ? env_hook_install_index(index, error, sizeof(error))
                          : env_hook_uninstall_index(index, error, sizeof(error));
        if (ok) applied = 1; else { failed = 1; snprintf(first_error, sizeof(first_error), "%s", error); }
    } else {
        for (int i = 0; i < ENV_HOOK_MAX; i++) {
            const char *n = g_env_hooks[i].name;
            size_t nlen = strlen(n);
            int hit = 0;
            if (!pat_len) hit = 1;                                             // "all" / "*" / "**"
            else if (suffix_only) hit = nlen >= pat_len && strncmp(n + nlen - pat_len, pat, pat_len) == 0;
            else if (contains) {
                for (size_t o = 0; o + pat_len <= nlen && !hit; o++) {
                    if (strncmp(n + o, pat, pat_len) == 0) hit = 1;
                }
            } else hit = strncmp(n, pat, pat_len) == 0;                        // prefix
            if (!hit) continue;
            matched++;
            char error[320] = "";
            int ok = applying ? env_hook_install_index(i, error, sizeof(error))
                              : env_hook_uninstall_index(i, error, sizeof(error));
            if (ok) applied++;
            else {
                failed++;
                if (!first_error[0]) snprintf(first_error, sizeof(first_error), "%s", error);
            }
        }
        if (matched == 0) {
            send_env_result(fd, id, action, function, 0, 0, 0, "no JNIEnv function matches that pattern");
            return;
        }
    }
    send_env_result(fd, id, action, function, (failed == 0) ? 1 : 0, applied, failed, first_error);
}