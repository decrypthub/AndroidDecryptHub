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
#include <limits.h>
#include <math.h>
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
#define ADH_FIELD_NAME_ENTRY(name) { #name, NULL, NULL, 0, 0, 0, 0, "", 0, 0, 0.0 },
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
    // v4.72: the rest of the Get/Release<Type>ArrayElements family (Byte landed in v4.19).
    // Get pins an array's elements - isCopy says whether the target got a private copy, which
    // decides whether a later Release has to copy back - and Release is where those writes land,
    // or get thrown away (JNI_ABORT).
    ENV_SLOT_GetBooleanArrayElements,
    ENV_SLOT_ReleaseBooleanArrayElements,
    ENV_SLOT_GetCharArrayElements,
    ENV_SLOT_ReleaseCharArrayElements,
    ENV_SLOT_GetShortArrayElements,
    ENV_SLOT_ReleaseShortArrayElements,
    ENV_SLOT_GetIntArrayElements,
    ENV_SLOT_ReleaseIntArrayElements,
    ENV_SLOT_GetLongArrayElements,
    ENV_SLOT_ReleaseLongArrayElements,
    ENV_SLOT_GetFloatArrayElements,
    ENV_SLOT_ReleaseFloatArrayElements,
    ENV_SLOT_GetDoubleArrayElements,
    ENV_SLOT_ReleaseDoubleArrayElements,
    ENV_SLOT_GetPrimitiveArrayCritical,
    ENV_SLOT_ReleasePrimitiveArrayCritical,
    // v4.63: the "native pulls Java data into its own buffer / hands Java a native buffer" entries.
    // Fingerprint code reads Java strings into native memory, and native crypto passes payloads to
    // Java through a direct ByteBuffer - both were invisible.
    ENV_SLOT_GetStringRegion,
    ENV_SLOT_GetStringUTFRegion,
    // v4.65: the "pin the Java string, then release it" pair - the other common way native code
    // reads a Java string (a direct pointer instead of a copy).
    ENV_SLOT_GetStringChars,
    ENV_SLOT_ReleaseStringChars,
    // v4.67: exception flow + VM handle. Anti-analysis code uses exceptions as control flow, so
    // "which exception was raised and who cleared it" is a real signal; GetJavaVM hands the target
    // the VM handle it would need for anything more invasive.
    ENV_SLOT_Throw,
    ENV_SLOT_ThrowNew,
    ENV_SLOT_ExceptionOccurred,
    ENV_SLOT_ExceptionDescribe,
    ENV_SLOT_ExceptionClear,
    ENV_SLOT_GetJavaVM,
    // v4.68: reference lifecycle. Which references the target creates and frees (and whether it
    // leaks a global ref, or keeps a local frame open) is a concrete analysis signal - and these are
    // the entries every JNI library touches.
    ENV_SLOT_PushLocalFrame,
    ENV_SLOT_PopLocalFrame,
    ENV_SLOT_NewLocalRef,
    ENV_SLOT_DeleteLocalRef,
    ENV_SLOT_NewGlobalRef,
    ENV_SLOT_DeleteGlobalRef,
    ENV_SLOT_IsSameObject,
    ENV_SLOT_EnsureLocalCapacity,
    // v4.69: type introspection, monitors, weak globals and GetVersion. Anti-tamper code asks type
    // questions (superclass / assignable / instance-of / ref type) and takes monitors; a weak-global
    // pair plus GetVersion complete the "what does the target ask the VM" picture.
    ENV_SLOT_GetVersion,
    ENV_SLOT_DefineClass,
    ENV_SLOT_GetSuperclass,
    ENV_SLOT_IsAssignableFrom,
    ENV_SLOT_GetObjectClass,
    ENV_SLOT_IsInstanceOf,
    ENV_SLOT_MonitorEnter,
    ENV_SLOT_MonitorExit,
    ENV_SLOT_NewWeakGlobalRef,
    ENV_SLOT_DeleteWeakGlobalRef,
    ENV_SLOT_GetObjectRefType,
    // v4.70: the rest of the array-region family (Byte was already hooked). These are the bulk
    // data movement entries: Get*ArrayRegion lifts an array into native memory, Set* writes one
    // back, and the event carries a bounded preview of the first elements.
    ENV_SLOT_GetBooleanArrayRegion,
    ENV_SLOT_SetBooleanArrayRegion,
    ENV_SLOT_GetCharArrayRegion,
    ENV_SLOT_SetCharArrayRegion,
    ENV_SLOT_GetShortArrayRegion,
    ENV_SLOT_SetShortArrayRegion,
    ENV_SLOT_GetIntArrayRegion,
    ENV_SLOT_SetIntArrayRegion,
    ENV_SLOT_GetLongArrayRegion,
    ENV_SLOT_SetLongArrayRegion,
    ENV_SLOT_GetFloatArrayRegion,
    ENV_SLOT_SetFloatArrayRegion,
    ENV_SLOT_GetDoubleArrayRegion,
    ENV_SLOT_SetDoubleArrayRegion,
    ENV_SLOT_NewDirectByteBuffer,
    ENV_SLOT_GetDirectBufferAddress,
    ENV_SLOT_GetDirectBufferCapacity,
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
    // v4.58 write override for one Set<Type>Field slot: the wrapper stores override_i/override_d
    // instead of the caller's value and the event reports requested -> applied. Only the numeric and
    // boolean field types can be overridden (an object value would need a reference we do not have).
    int override_active;
    long long override_i;
    double override_d;
};

#define ADH_FIXED_SLOT_INITS(X) \
    X("GetStringUTFChars") X("FindClass") X("GetMethodID") X("GetStaticMethodID") \
    X("NewStringUTF") X("GetFieldID") X("GetStaticFieldID") X("GetByteArrayElements") \
    X("SetByteArrayRegion") X("ReleaseByteArrayElements") X("GetByteArrayRegion") \
    X("GetBooleanArrayElements") X("ReleaseBooleanArrayElements") \
    X("GetCharArrayElements") X("ReleaseCharArrayElements") \
    X("GetShortArrayElements") X("ReleaseShortArrayElements") \
    X("GetIntArrayElements") X("ReleaseIntArrayElements") \
    X("GetLongArrayElements") X("ReleaseLongArrayElements") \
    X("GetFloatArrayElements") X("ReleaseFloatArrayElements") \
    X("GetDoubleArrayElements") X("ReleaseDoubleArrayElements") \
    X("GetPrimitiveArrayCritical") X("ReleasePrimitiveArrayCritical") \
    X("GetStringRegion") X("GetStringUTFRegion") X("GetStringChars") X("ReleaseStringChars") \
    X("Throw") X("ThrowNew") X("ExceptionOccurred") X("ExceptionDescribe") X("ExceptionClear") \
    X("GetJavaVM") X("PushLocalFrame") X("PopLocalFrame") X("NewLocalRef") X("DeleteLocalRef") \
    X("NewGlobalRef") X("DeleteGlobalRef") X("IsSameObject") X("EnsureLocalCapacity") \
    X("GetVersion") X("DefineClass") X("GetSuperclass") X("IsAssignableFrom") X("GetObjectClass") \
    X("IsInstanceOf") X("MonitorEnter") X("MonitorExit") X("NewWeakGlobalRef") \
    X("DeleteWeakGlobalRef") X("GetObjectRefType") \
    X("GetBooleanArrayRegion") \
    X("SetBooleanArrayRegion") \
    X("GetCharArrayRegion") \
    X("SetCharArrayRegion") \
    X("GetShortArrayRegion") \
    X("SetShortArrayRegion") \
    X("GetIntArrayRegion") \
    X("SetIntArrayRegion") \
    X("GetLongArrayRegion") \
    X("SetLongArrayRegion") \
    X("GetFloatArrayRegion") \
    X("SetFloatArrayRegion") \
    X("GetDoubleArrayRegion") \
    X("SetDoubleArrayRegion") \
    X("NewDirectByteBuffer") \
    X("GetDirectBufferAddress") X("GetDirectBufferCapacity")

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

#define ADH_SLOT_INIT(name) { name, NULL, NULL, 0, 0, 0, 0, "", 0, 0, 0.0 },
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

typedef jfieldID (JNICALL *get_field_id_fn)(JNIEnv *, jclass, const char *, const char *);

static jfieldID GetFieldID_wrapper(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
    get_field_id_fn original = (get_field_id_fn)slot_original(ENV_SLOT_GetFieldID);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetFieldID)) return (jfieldID)original(env, clazz, name, sig);
    jfieldID result = (jfieldID)original(env, clazz, name, sig);
    char detail[512];
    if (!env_budget_left(ENV_SLOT_GetFieldID)) {
        // The CALL may have succeeded: the budget only decided that we skip the expensive detail.
        // Saying ok=false here made a successful lookup look like a failed one downstream.
        env_note(ENV_SLOT_GetFieldID, "<budget spent>", result != NULL);
    } else if (result == NULL || (*env)->ExceptionCheck(env)) {
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
    get_field_id_fn original = (get_field_id_fn)slot_original(ENV_SLOT_GetStaticFieldID);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetStaticFieldID)) return (jfieldID)original(env, clazz, name, sig);
    jfieldID result = (jfieldID)original(env, clazz, name, sig);
    char detail[512];
    if (!env_budget_left(ENV_SLOT_GetStaticFieldID)) {
        env_note(ENV_SLOT_GetStaticFieldID, "<budget spent>", result != NULL);
    } else if (result == NULL || (*env)->ExceptionCheck(env)) {
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

#define ADH_DEFINE_FIELD_SET_BODY(JNI_NAME, CTYPE, FMT, CAST, TARGET, OV)                   \
static void JNICALL JNI_NAME##_wrapper(JNIEnv *env, TARGET target, jfieldID field, CTYPE value) { \
    typedef void (JNICALL *fn_t)(JNIEnv *, TARGET, jfieldID, CTYPE);                        \
    fn_t original = (fn_t)slot_original(ENV_SLOT_##JNI_NAME);                               \
    if (!original) return;                                                                  \
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_##JNI_NAME)) {                          \
        original(env, target, field, value);                                                \
        return;                                                                             \
    }                                                                                       \
    CTYPE requested = value;                                                                \
    long long ov_i = 0; double ov_d = 0; int override_on = 0;                               \
    if (__atomic_load_n(&g_env_hooks[ENV_SLOT_##JNI_NAME].override_active, __ATOMIC_ACQUIRE)) { \
        ov_i = g_env_hooks[ENV_SLOT_##JNI_NAME].override_i;                                 \
        ov_d = g_env_hooks[ENV_SLOT_##JNI_NAME].override_d;                                 \
        (void)ov_i; (void)ov_d;   /* only one of them feeds OV, per field type */            \
        value = (OV);                                                                       \
        override_on = 1;                                                                    \
    }                                                                                       \
    g_env_hook_in_ours = 1;                                                                 \
    original(env, target, field, value);                                                    \
    char detail[192]; detail[0] = 0;                                                        \
    if (env_budget_left(ENV_SLOT_##JNI_NAME)) {                                             \
        if (override_on) {                                                                  \
            snprintf(detail, sizeof(detail), "field=%p value=" FMT " requested=" FMT,       \
                     (void *)field, CAST(value), CAST(requested));                          \
        } else {                                                                            \
            snprintf(detail, sizeof(detail), "field=%p value=" FMT, (void *)field, CAST(value)); \
        }                                                                                   \
    }                                                                                       \
    env_note(ENV_SLOT_##JNI_NAME, detail[0] ? detail : NULL, 1);                            \
    g_env_hook_in_ours = 0;                                                                 \
}

#define ADH_FIELD_TYPE_ROW(NAME, CTYPE, FMT, CAST, OV)                                      \
    ADH_DEFINE_FIELD_GET_BODY(Get##NAME##Field, CTYPE, FMT, CAST, jobject)                  \
    ADH_DEFINE_FIELD_SET_BODY(Set##NAME##Field, CTYPE, FMT, CAST, jobject, OV)              \
    ADH_DEFINE_FIELD_GET_BODY(GetStatic##NAME##Field, CTYPE, FMT, CAST, jclass)             \
    ADH_DEFINE_FIELD_SET_BODY(SetStatic##NAME##Field, CTYPE, FMT, CAST, jclass, OV)

ADH_FIELD_TYPE_ROW(Object, jobject, "%p", (const void *), (jobject)0)      // object writes cannot be overridden
ADH_FIELD_TYPE_ROW(Boolean, jboolean, "%d", (int), (jboolean)ov_i)
ADH_FIELD_TYPE_ROW(Byte, jbyte, "%d", (int), (jbyte)ov_i)
ADH_FIELD_TYPE_ROW(Char, jchar, "%u", (unsigned), (jchar)ov_i)
ADH_FIELD_TYPE_ROW(Short, jshort, "%d", (int), (jshort)ov_i)
ADH_FIELD_TYPE_ROW(Int, jint, "%d", (int), (jint)ov_i)
ADH_FIELD_TYPE_ROW(Long, jlong, "%lld", (long long), (jlong)ov_i)
ADH_FIELD_TYPE_ROW(Float, jfloat, "%g", (double), (jfloat)ov_d)
ADH_FIELD_TYPE_ROW(Double, jdouble, "%g", (double), (jdouble)ov_d)

// ---- v4.63: string region + direct buffer entries ---------------------------
// GetStringRegion/GetStringUTFRegion copy a Java string INTO a native buffer (how native fingerprint
// code lifts values out of Java), so the event carries a bounded preview of what was copied. The
// direct-buffer trio is how native code hands a payload to Java (or looks one up), so the event
// carries the address and capacity.
static void GetStringRegion_wrapper(JNIEnv *env, jstring str, jsize start, jsize len, jchar *buf) {
    typedef void (JNICALL *fn_t)(JNIEnv *, jstring, jsize, jsize, jchar *);
    fn_t original = (fn_t)slot_original(ENV_SLOT_GetStringRegion);
    if (!original) return;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetStringRegion)) { original(env, str, start, len, buf); return; }
    g_env_hook_in_ours = 1;
    original(env, str, start, len, buf);
    // A failed copy (out-of-range start/len throws and leaves buf UNTOUCHED) must not be
    // reported as data the target lifted out of Java: reading buf here would put uninitialized
    // memory into the event with ok=1.
    int failed = (*env)->ExceptionCheck(env) ? 1 : 0;
    char detail[220]; detail[0] = 0;
    if (failed) {
        snprintf(detail, sizeof(detail), "string=%p start=%d len=%d <copy failed, buffer untouched>", (void *)str, (int)start, (int)len);
    } else if (env_budget_left(ENV_SLOT_GetStringRegion)) {
        char preview[80] = "";
        size_t p = 0;
        if (buf && len > 0) {
            for (jsize i = 0; i < len && i < 24 && p + 2 < sizeof(preview); i++) {
                jchar c = buf[i];
                preview[p++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
            }
            preview[p] = 0;
        }
        snprintf(detail, sizeof(detail), "string=%p start=%d len=%d text=\"%s\"", (void *)str, (int)start, (int)len, preview);
    }
    env_note(ENV_SLOT_GetStringRegion, detail[0] ? detail : NULL, !failed && buf != NULL);
    g_env_hook_in_ours = 0;
}

static void GetStringUTFRegion_wrapper(JNIEnv *env, jstring str, jsize start, jsize len, char *buf) {
    typedef void (JNICALL *fn_t)(JNIEnv *, jstring, jsize, jsize, char *);
    fn_t original = (fn_t)slot_original(ENV_SLOT_GetStringUTFRegion);
    if (!original) return;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetStringUTFRegion)) { original(env, str, start, len, buf); return; }
    g_env_hook_in_ours = 1;
    original(env, str, start, len, buf);
    // A failed copy (out-of-range start/len throws and leaves buf UNTOUCHED) must not be
    // reported as data the target lifted out of Java: reading buf here would put uninitialized
    // memory into the event with ok=1.
    int failed = (*env)->ExceptionCheck(env) ? 1 : 0;
    char detail[220]; detail[0] = 0;
    if (failed) {
        snprintf(detail, sizeof(detail), "string=%p start=%d len=%d <copy failed, buffer untouched>", (void *)str, (int)start, (int)len);
    } else if (env_budget_left(ENV_SLOT_GetStringUTFRegion)) {
        char preview[96] = "";
        size_t p = 0;
        if (buf && len > 0) {
            for (jsize i = 0; i < len && i < 48 && p + 2 < sizeof(preview); i++) {
                char c = buf[i];
                preview[p++] = (c >= 0x20 && c < 0x7f) ? c : '.';
            }
            preview[p] = 0;
        }
        snprintf(detail, sizeof(detail), "string=%p start=%d len=%d text=\"%s\"", (void *)str, (int)start, (int)len, preview);
    }
    env_note(ENV_SLOT_GetStringUTFRegion, detail[0] ? detail : NULL, !failed && buf != NULL);
    g_env_hook_in_ours = 0;
}

static jobject NewDirectByteBuffer_wrapper(JNIEnv *env, void *address, jlong capacity) {
    typedef jobject (JNICALL *fn_t)(JNIEnv *, void *, jlong);
    fn_t original = (fn_t)slot_original(ENV_SLOT_NewDirectByteBuffer);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_NewDirectByteBuffer)) return original(env, address, capacity);
    g_env_hook_in_ours = 1;
    jobject result = original(env, address, capacity);
    char detail[128]; detail[0] = 0;
    if (env_budget_left(ENV_SLOT_NewDirectByteBuffer)) {
        snprintf(detail, sizeof(detail), "address=%p capacity=%lld result=%p", address, (long long)capacity, (void *)result);
    }
    env_note(ENV_SLOT_NewDirectByteBuffer, detail[0] ? detail : NULL, result != NULL);
    g_env_hook_in_ours = 0;
    return result;
}

static void *GetDirectBufferAddress_wrapper(JNIEnv *env, jobject buf) {
    typedef void *(JNICALL *fn_t)(JNIEnv *, jobject);
    fn_t original = (fn_t)slot_original(ENV_SLOT_GetDirectBufferAddress);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetDirectBufferAddress)) return original(env, buf);
    g_env_hook_in_ours = 1;
    void *address = original(env, buf);
    char detail[128]; detail[0] = 0;
    if (env_budget_left(ENV_SLOT_GetDirectBufferAddress)) {
        snprintf(detail, sizeof(detail), "buffer=%p address=%p", (void *)buf, address);
    }
    env_note(ENV_SLOT_GetDirectBufferAddress, detail[0] ? detail : NULL, address != NULL);
    g_env_hook_in_ours = 0;
    return address;
}

static jlong GetDirectBufferCapacity_wrapper(JNIEnv *env, jobject buf) {
    typedef jlong (JNICALL *fn_t)(JNIEnv *, jobject);
    fn_t original = (fn_t)slot_original(ENV_SLOT_GetDirectBufferCapacity);
    if (!original) return -1;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetDirectBufferCapacity)) return original(env, buf);
    g_env_hook_in_ours = 1;
    jlong capacity = original(env, buf);
    char detail[128]; detail[0] = 0;
    if (env_budget_left(ENV_SLOT_GetDirectBufferCapacity)) {
        // capacity 0 is both "a legal empty direct buffer" and what some VMs answer for a non-direct
        // buffer: say so explicitly instead of letting the reader guess.
        if (capacity == 0) {
            snprintf(detail, sizeof(detail), "buffer=%p capacity=0 (empty direct buffer or not a direct buffer)", (void *)buf);
        } else {
            snprintf(detail, sizeof(detail), "buffer=%p capacity=%lld", (void *)buf, (long long)capacity);
        }
    }
    env_note(ENV_SLOT_GetDirectBufferCapacity, detail[0] ? detail : NULL, capacity >= 0);
    g_env_hook_in_ours = 0;
    return capacity;
}

static const jchar *GetStringChars_wrapper(JNIEnv *env, jstring str, jboolean *is_copy) {
    typedef const jchar *(JNICALL *fn_t)(JNIEnv *, jstring, jboolean *);
    fn_t original = (fn_t)slot_original(ENV_SLOT_GetStringChars);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetStringChars)) return original(env, str, is_copy);
    g_env_hook_in_ours = 1;
    const jchar *chars = original(env, str, is_copy);
    int failed = (*env)->ExceptionCheck(env) ? 1 : 0;   // never read a pointer a failed call returned
    char detail[220]; detail[0] = 0;
    if (failed) {
        snprintf(detail, sizeof(detail), "string=%p <pin failed>", (void *)str);
    } else if (env_budget_left(ENV_SLOT_GetStringChars)) {
        char preview[80] = "";
        if (chars) {
            size_t p = 0;
            for (int i = 0; i < 24 && p + 2 < sizeof(preview); i++) {
                jchar c = chars[i];
                if (c == 0) break;                       // bounded by the string's own terminator
                preview[p++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
            }
            preview[p] = 0;
        }
        snprintf(detail, sizeof(detail), "string=%p isCopy=%s text=\"%s\"",
                 (void *)str, (is_copy && *is_copy) ? "true" : "false", preview);
    }
    env_note(ENV_SLOT_GetStringChars, detail[0] ? detail : NULL, !failed && chars != NULL);
    g_env_hook_in_ours = 0;
    return chars;
}

static void ReleaseStringChars_wrapper(JNIEnv *env, jstring str, const jchar *chars) {
    typedef void (JNICALL *fn_t)(JNIEnv *, jstring, const jchar *);
    fn_t original = (fn_t)slot_original(ENV_SLOT_ReleaseStringChars);
    if (!original) return;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_ReleaseStringChars)) { original(env, str, chars); return; }
    g_env_hook_in_ours = 1;
    original(env, str, chars);
    char detail[128]; detail[0] = 0;
    if (env_budget_left(ENV_SLOT_ReleaseStringChars)) {
        snprintf(detail, sizeof(detail), "string=%p chars=%p", (void *)str, (const void *)chars);
    }
    env_note(ENV_SLOT_ReleaseStringChars, detail[0] ? detail : NULL, 1);
    g_env_hook_in_ours = 0;
}

// ---- v4.67: exception flow + VM handle --------------------------------------
// ExceptionOccurred is called exactly WHEN an exception is pending, so none of these wrappers may make
// JNI calls that require a clear exception state: the name lookups are gated on "no pending exception
// at entry" and ExceptionOccurred reports only the pointer.
static jint Throw_wrapper(JNIEnv *env, jthrowable obj) {
    typedef jint (JNICALL *fn_t)(JNIEnv *, jthrowable);
    fn_t original = (fn_t)slot_original(ENV_SLOT_Throw);
    if (!original) return JNI_ERR;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_Throw)) return original(env, obj);
    char detail[220] = "";
    if (env_budget_left(ENV_SLOT_Throw)) {
        char cls[160] = "";
        if (!(*env)->ExceptionCheck(env) && obj) {
            jclass c = (*env)->GetObjectClass(env, obj);
            if (c) adh_jni_class_name(env, c, cls, sizeof(cls));
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        }
        snprintf(detail, sizeof(detail), "throwable=%p class=%s", (void *)obj, cls[0] ? cls : "?");
    }
    g_env_hook_in_ours = 1;
    jint rc = original(env, obj);
    g_env_hook_in_ours = 0;
    env_note(ENV_SLOT_Throw, detail[0] ? detail : NULL, rc == JNI_OK);
    return rc;
}

static jint ThrowNew_wrapper(JNIEnv *env, jclass clazz, const char *message) {
    typedef jint (JNICALL *fn_t)(JNIEnv *, jclass, const char *);
    fn_t original = (fn_t)slot_original(ENV_SLOT_ThrowNew);
    if (!original) return JNI_ERR;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_ThrowNew)) return original(env, clazz, message);
    char detail[280] = "";
    if (env_budget_left(ENV_SLOT_ThrowNew)) {
        char cls[160] = "";
        if (!(*env)->ExceptionCheck(env) && clazz) {
            adh_jni_class_name(env, clazz, cls, sizeof(cls));
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        }
        char msg[96] = "";
        if (message) {
            size_t p = 0;
            for (size_t i = 0; message[i] && p + 2 < sizeof(msg); i++) {
                char c = message[i];
                msg[p++] = (c >= 0x20 && c < 0x7f) ? c : '.';
            }
            msg[p] = 0;
        }
        snprintf(detail, sizeof(detail), "class=%s message=\"%s\"", cls[0] ? cls : "?", msg);
    }
    g_env_hook_in_ours = 1;
    jint rc = original(env, clazz, message);
    g_env_hook_in_ours = 0;
    env_note(ENV_SLOT_ThrowNew, detail[0] ? detail : NULL, rc == JNI_OK);
    return rc;
}

static jthrowable ExceptionOccurred_wrapper(JNIEnv *env) {
    typedef jthrowable (JNICALL *fn_t)(JNIEnv *);
    fn_t original = (fn_t)slot_original(ENV_SLOT_ExceptionOccurred);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_ExceptionOccurred)) return original(env);
    g_env_hook_in_ours = 1;
    jthrowable ex = original(env);
    g_env_hook_in_ours = 0;
    char detail[128];
    snprintf(detail, sizeof(detail), "throwable=%p", (void *)ex);
    env_note(ENV_SLOT_ExceptionOccurred, env_budget_left(ENV_SLOT_ExceptionOccurred) ? detail : NULL, ex != NULL);
    return ex;
}

static void ExceptionDescribe_wrapper(JNIEnv *env) {
    typedef void (JNICALL *fn_t)(JNIEnv *);
    fn_t original = (fn_t)slot_original(ENV_SLOT_ExceptionDescribe);
    if (!original) return;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_ExceptionDescribe)) { original(env); return; }
    g_env_hook_in_ours = 1;
    original(env);
    g_env_hook_in_ours = 0;
    env_note(ENV_SLOT_ExceptionDescribe, env_budget_left(ENV_SLOT_ExceptionDescribe) ? "describe" : NULL, 1);
}

static void ExceptionClear_wrapper(JNIEnv *env) {
    typedef void (JNICALL *fn_t)(JNIEnv *);
    fn_t original = (fn_t)slot_original(ENV_SLOT_ExceptionClear);
    if (!original) return;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_ExceptionClear)) { original(env); return; }
    g_env_hook_in_ours = 1;
    original(env);
    g_env_hook_in_ours = 0;
    env_note(ENV_SLOT_ExceptionClear, env_budget_left(ENV_SLOT_ExceptionClear) ? "cleared" : NULL, 1);
}

static jint GetJavaVM_wrapper(JNIEnv *env, JavaVM **vm) {
    typedef jint (JNICALL *fn_t)(JNIEnv *, JavaVM **);
    fn_t original = (fn_t)slot_original(ENV_SLOT_GetJavaVM);
    if (!original) return JNI_ERR;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetJavaVM)) return original(env, vm);
    g_env_hook_in_ours = 1;
    jint rc = original(env, vm);
    g_env_hook_in_ours = 0;
    char detail[96];
    snprintf(detail, sizeof(detail), "vm=%p", (void *)(vm ? *vm : NULL));
    env_note(ENV_SLOT_GetJavaVM, env_budget_left(ENV_SLOT_GetJavaVM) ? detail : NULL, rc == JNI_OK);
    return rc;
}

// ---- v4.68: reference lifecycle ---------------------------------------------
// Pointer-in/pointer-out entries: the detail is the reference and its identity, which is what makes
// "who allocated this global ref and never freed it" answerable from the capture stream.
static jint PushLocalFrame_wrapper(JNIEnv *env, jint capacity) {
    typedef jint (JNICALL *fn_t)(JNIEnv *, jint);
    fn_t original = (fn_t)slot_original(ENV_SLOT_PushLocalFrame);
    if (!original) return JNI_ERR;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_PushLocalFrame)) return original(env, capacity);
    g_env_hook_in_ours = 1;
    jint rc = original(env, capacity);
    g_env_hook_in_ours = 0;
    char detail[96];
    snprintf(detail, sizeof(detail), "capacity=%d", (int)capacity);
    env_note(ENV_SLOT_PushLocalFrame, env_budget_left(ENV_SLOT_PushLocalFrame) ? detail : NULL, rc == JNI_OK);
    return rc;
}

static jobject PopLocalFrame_wrapper(JNIEnv *env, jobject result) {
    typedef jobject (JNICALL *fn_t)(JNIEnv *, jobject);
    fn_t original = (fn_t)slot_original(ENV_SLOT_PopLocalFrame);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_PopLocalFrame)) return original(env, result);
    g_env_hook_in_ours = 1;
    jobject out = original(env, result);
    g_env_hook_in_ours = 0;
    char detail[128];
    snprintf(detail, sizeof(detail), "result=%p -> %p", (void *)result, (void *)out);
    env_note(ENV_SLOT_PopLocalFrame, env_budget_left(ENV_SLOT_PopLocalFrame) ? detail : NULL, 1);
    return out;
}

static jobject NewLocalRef_wrapper(JNIEnv *env, jobject ref) {
    typedef jobject (JNICALL *fn_t)(JNIEnv *, jobject);
    fn_t original = (fn_t)slot_original(ENV_SLOT_NewLocalRef);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_NewLocalRef)) return original(env, ref);
    g_env_hook_in_ours = 1;
    jobject out = original(env, ref);
    g_env_hook_in_ours = 0;
    char detail[128];
    snprintf(detail, sizeof(detail), "ref=%p -> %p", (void *)ref, (void *)out);
    env_note(ENV_SLOT_NewLocalRef, env_budget_left(ENV_SLOT_NewLocalRef) ? detail : NULL, out != NULL);
    return out;
}

static void DeleteLocalRef_wrapper(JNIEnv *env, jobject ref) {
    typedef void (JNICALL *fn_t)(JNIEnv *, jobject);
    fn_t original = (fn_t)slot_original(ENV_SLOT_DeleteLocalRef);
    if (!original) return;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_DeleteLocalRef)) { original(env, ref); return; }
    g_env_hook_in_ours = 1;
    original(env, ref);
    g_env_hook_in_ours = 0;
    char detail[96];
    snprintf(detail, sizeof(detail), "ref=%p", (void *)ref);
    env_note(ENV_SLOT_DeleteLocalRef, env_budget_left(ENV_SLOT_DeleteLocalRef) ? detail : NULL, 1);
}

static jobject NewGlobalRef_wrapper(JNIEnv *env, jobject ref) {
    typedef jobject (JNICALL *fn_t)(JNIEnv *, jobject);
    fn_t original = (fn_t)slot_original(ENV_SLOT_NewGlobalRef);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_NewGlobalRef)) return original(env, ref);
    g_env_hook_in_ours = 1;
    jobject out = original(env, ref);
    g_env_hook_in_ours = 0;
    char detail[128];
    snprintf(detail, sizeof(detail), "ref=%p -> %p", (void *)ref, (void *)out);
    env_note(ENV_SLOT_NewGlobalRef, env_budget_left(ENV_SLOT_NewGlobalRef) ? detail : NULL, out != NULL);
    return out;
}

static void DeleteGlobalRef_wrapper(JNIEnv *env, jobject ref) {
    typedef void (JNICALL *fn_t)(JNIEnv *, jobject);
    fn_t original = (fn_t)slot_original(ENV_SLOT_DeleteGlobalRef);
    if (!original) return;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_DeleteGlobalRef)) { original(env, ref); return; }
    g_env_hook_in_ours = 1;
    original(env, ref);
    g_env_hook_in_ours = 0;
    char detail[96];
    snprintf(detail, sizeof(detail), "ref=%p", (void *)ref);
    env_note(ENV_SLOT_DeleteGlobalRef, env_budget_left(ENV_SLOT_DeleteGlobalRef) ? detail : NULL, 1);
}

static jboolean IsSameObject_wrapper(JNIEnv *env, jobject a, jobject b) {
    typedef jboolean (JNICALL *fn_t)(JNIEnv *, jobject, jobject);
    fn_t original = (fn_t)slot_original(ENV_SLOT_IsSameObject);
    if (!original) return JNI_FALSE;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_IsSameObject)) return original(env, a, b);
    g_env_hook_in_ours = 1;
    jboolean same = original(env, a, b);
    g_env_hook_in_ours = 0;
    char detail[128];
    snprintf(detail, sizeof(detail), "a=%p b=%p same=%s", (void *)a, (void *)b, same ? "true" : "false");
    env_note(ENV_SLOT_IsSameObject, env_budget_left(ENV_SLOT_IsSameObject) ? detail : NULL, 1);
    return same;
}

static jint EnsureLocalCapacity_wrapper(JNIEnv *env, jint capacity) {
    typedef jint (JNICALL *fn_t)(JNIEnv *, jint);
    fn_t original = (fn_t)slot_original(ENV_SLOT_EnsureLocalCapacity);
    if (!original) return JNI_ERR;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_EnsureLocalCapacity)) return original(env, capacity);
    g_env_hook_in_ours = 1;
    jint rc = original(env, capacity);
    g_env_hook_in_ours = 0;
    char detail[96];
    snprintf(detail, sizeof(detail), "capacity=%d", (int)capacity);
    env_note(ENV_SLOT_EnsureLocalCapacity, env_budget_left(ENV_SLOT_EnsureLocalCapacity) ? detail : NULL, rc == JNI_OK);
    return rc;
}

// ---- v4.69: type introspection / monitors / weak globals / GetVersion -------
static jint GetVersion_wrapper(JNIEnv *env) {
    typedef jint (JNICALL *fn_t)(JNIEnv *);
    fn_t original = (fn_t)slot_original(ENV_SLOT_GetVersion);
    if (!original) return 0;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetVersion)) return original(env);
    g_env_hook_in_ours = 1;
    jint v = original(env);
    g_env_hook_in_ours = 0;
    char detail[64];
    snprintf(detail, sizeof(detail), "version=0x%x", (unsigned)v);
    env_note(ENV_SLOT_GetVersion, env_budget_left(ENV_SLOT_GetVersion) ? detail : NULL, 1);
    return v;
}

static jclass DefineClass_wrapper(JNIEnv *env, const char *name, jobject loader, const jbyte *buf, jsize len) {
    typedef jclass (JNICALL *fn_t)(JNIEnv *, const char *, jobject, const jbyte *, jsize);
    fn_t original = (fn_t)slot_original(ENV_SLOT_DefineClass);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_DefineClass)) return original(env, name, loader, buf, len);
    g_env_hook_in_ours = 1;
    jclass cls = original(env, name, loader, buf, len);
    g_env_hook_in_ours = 0;
    char detail[220]; detail[0] = 0;
    if (env_budget_left(ENV_SLOT_DefineClass)) {
        char nm[96] = "";
        if (name) { size_t p = 0; for (size_t i = 0; name[i] && p + 2 < sizeof(nm); i++) { char c = name[i]; nm[p++] = (c >= 0x20 && c < 0x7f) ? c : '.'; } nm[p] = 0; }
        snprintf(detail, sizeof(detail), "name=\"%s\" loader=%p bytes=%d class=%p", nm, (void *)loader, (int)len, (void *)cls);
    }
    env_note(ENV_SLOT_DefineClass, detail[0] ? detail : NULL, cls != NULL);
    return cls;
}

static jclass GetSuperclass_wrapper(JNIEnv *env, jclass clazz) {
    typedef jclass (JNICALL *fn_t)(JNIEnv *, jclass);
    fn_t original = (fn_t)slot_original(ENV_SLOT_GetSuperclass);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetSuperclass)) return original(env, clazz);
    g_env_hook_in_ours = 1;
    jclass sup = original(env, clazz);
    g_env_hook_in_ours = 0;
    char detail[260] = "";
    if (env_budget_left(ENV_SLOT_GetSuperclass) && !(*env)->ExceptionCheck(env)) {
        char a[96] = "", b[96] = "";
        if (clazz) adh_jni_class_name(env, clazz, a, sizeof(a));
        if (sup) adh_jni_class_name(env, sup, b, sizeof(b));
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        snprintf(detail, sizeof(detail), "class=%s -> %s", a[0] ? a : "?", b[0] ? b : "(none)");
    }
    env_note(ENV_SLOT_GetSuperclass, detail[0] ? detail : NULL, 1);
    return sup;
}

static jboolean IsAssignableFrom_wrapper(JNIEnv *env, jclass a, jclass b) {
    typedef jboolean (JNICALL *fn_t)(JNIEnv *, jclass, jclass);
    fn_t original = (fn_t)slot_original(ENV_SLOT_IsAssignableFrom);
    if (!original) return JNI_FALSE;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_IsAssignableFrom)) return original(env, a, b);
    g_env_hook_in_ours = 1;
    jboolean r = original(env, a, b);
    g_env_hook_in_ours = 0;
    char detail[220]; detail[0] = 0;
    if (env_budget_left(ENV_SLOT_IsAssignableFrom)) {
        char na[96] = "", nb[96] = "";
        if (a) adh_jni_class_name(env, a, na, sizeof(na));
        if (b) adh_jni_class_name(env, b, nb, sizeof(nb));
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        snprintf(detail, sizeof(detail), "%s <- %s = %s", na[0] ? na : "?", nb[0] ? nb : "?", r ? "true" : "false");
    }
    env_note(ENV_SLOT_IsAssignableFrom, detail[0] ? detail : NULL, 1);
    return r;
}

static jclass GetObjectClass_wrapper(JNIEnv *env, jobject obj) {
    typedef jclass (JNICALL *fn_t)(JNIEnv *, jobject);
    fn_t original = (fn_t)slot_original(ENV_SLOT_GetObjectClass);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetObjectClass)) return original(env, obj);
    g_env_hook_in_ours = 1;
    jclass cls = original(env, obj);
    g_env_hook_in_ours = 0;
    char detail[220] = "";
    if (env_budget_left(ENV_SLOT_GetObjectClass)) {
        char name[96] = "";
        if (cls) adh_jni_class_name(env, cls, name, sizeof(name));
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        snprintf(detail, sizeof(detail), "obj=%p class=%s", (void *)obj, name[0] ? name : "?");
    }
    env_note(ENV_SLOT_GetObjectClass, detail[0] ? detail : NULL, cls != NULL);
    return cls;
}

static jboolean IsInstanceOf_wrapper(JNIEnv *env, jobject obj, jclass clazz) {
    typedef jboolean (JNICALL *fn_t)(JNIEnv *, jobject, jclass);
    fn_t original = (fn_t)slot_original(ENV_SLOT_IsInstanceOf);
    if (!original) return JNI_FALSE;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_IsInstanceOf)) return original(env, obj, clazz);
    g_env_hook_in_ours = 1;
    jboolean r = original(env, obj, clazz);
    g_env_hook_in_ours = 0;
    char detail[220] = "";
    if (env_budget_left(ENV_SLOT_IsInstanceOf)) {
        char name[96] = "";
        if (clazz) adh_jni_class_name(env, clazz, name, sizeof(name));
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        snprintf(detail, sizeof(detail), "obj=%p class=%s = %s", (void *)obj, name[0] ? name : "?", r ? "true" : "false");
    }
    env_note(ENV_SLOT_IsInstanceOf, detail[0] ? detail : NULL, 1);
    return r;
}

static jint MonitorEnter_wrapper(JNIEnv *env, jobject obj) {
    typedef jint (JNICALL *fn_t)(JNIEnv *, jobject);
    fn_t original = (fn_t)slot_original(ENV_SLOT_MonitorEnter);
    if (!original) return JNI_ERR;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_MonitorEnter)) return original(env, obj);
    g_env_hook_in_ours = 1;
    jint rc = original(env, obj);
    g_env_hook_in_ours = 0;
    char detail[96];
    snprintf(detail, sizeof(detail), "monitor=%p", (void *)obj);
    env_note(ENV_SLOT_MonitorEnter, env_budget_left(ENV_SLOT_MonitorEnter) ? detail : NULL, rc == JNI_OK);
    return rc;
}

static jint MonitorExit_wrapper(JNIEnv *env, jobject obj) {
    typedef jint (JNICALL *fn_t)(JNIEnv *, jobject);
    fn_t original = (fn_t)slot_original(ENV_SLOT_MonitorExit);
    if (!original) return JNI_ERR;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_MonitorExit)) return original(env, obj);
    g_env_hook_in_ours = 1;
    jint rc = original(env, obj);
    g_env_hook_in_ours = 0;
    char detail[96];
    snprintf(detail, sizeof(detail), "monitor=%p", (void *)obj);
    env_note(ENV_SLOT_MonitorExit, env_budget_left(ENV_SLOT_MonitorExit) ? detail : NULL, rc == JNI_OK);
    return rc;
}

static jweak NewWeakGlobalRef_wrapper(JNIEnv *env, jobject obj) {
    typedef jweak (JNICALL *fn_t)(JNIEnv *, jobject);
    fn_t original = (fn_t)slot_original(ENV_SLOT_NewWeakGlobalRef);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_NewWeakGlobalRef)) return original(env, obj);
    g_env_hook_in_ours = 1;
    jweak out = original(env, obj);
    g_env_hook_in_ours = 0;
    char detail[128];
    snprintf(detail, sizeof(detail), "obj=%p -> weak=%p", (void *)obj, (void *)out);
    env_note(ENV_SLOT_NewWeakGlobalRef, env_budget_left(ENV_SLOT_NewWeakGlobalRef) ? detail : NULL, out != NULL);
    return out;
}

static void DeleteWeakGlobalRef_wrapper(JNIEnv *env, jweak ref) {
    typedef void (JNICALL *fn_t)(JNIEnv *, jweak);
    fn_t original = (fn_t)slot_original(ENV_SLOT_DeleteWeakGlobalRef);
    if (!original) return;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_DeleteWeakGlobalRef)) { original(env, ref); return; }
    g_env_hook_in_ours = 1;
    original(env, ref);
    g_env_hook_in_ours = 0;
    char detail[96];
    snprintf(detail, sizeof(detail), "weak=%p", (void *)ref);
    env_note(ENV_SLOT_DeleteWeakGlobalRef, env_budget_left(ENV_SLOT_DeleteWeakGlobalRef) ? detail : NULL, 1);
}

static jobjectRefType GetObjectRefType_wrapper(JNIEnv *env, jobject obj) {
    typedef jobjectRefType (JNICALL *fn_t)(JNIEnv *, jobject);
    fn_t original = (fn_t)slot_original(ENV_SLOT_GetObjectRefType);
    if (!original) return JNIInvalidRefType;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetObjectRefType)) return original(env, obj);
    g_env_hook_in_ours = 1;
    jobjectRefType t = original(env, obj);
    g_env_hook_in_ours = 0;
    const char *tn = t == JNILocalRefType ? "local" : t == JNIGlobalRefType ? "global"
                   : t == JNIWeakGlobalRefType ? "weak" : "invalid";
    char detail[96];
    snprintf(detail, sizeof(detail), "obj=%p type=%s", (void *)obj, tn);
    env_note(ENV_SLOT_GetObjectRefType, env_budget_left(ENV_SLOT_GetObjectRefType) ? detail : NULL, t != JNIInvalidRefType);
    return t;
}


// ---- v4.70: the rest of the array-region family ------------------------------
// Get lifts array data into native memory, Set writes native data back into a Java array; both
// events carry a bounded preview of the first elements. A failed call (exception) leaves the buffer
// untouched, so the preview is skipped in that case (the lesson from the string-region batch).
#define ADH_DEFINE_ARRAY_REGION(JNI_NAME, CTYPE, BUFPTR, FMT, CAST)                                  \
static void JNI_NAME##_wrapper(JNIEnv *env, jarray arr, jsize start, jsize len, BUFPTR buf) { \
    typedef void (JNICALL *fn_t)(JNIEnv *, jarray, jsize, jsize, BUFPTR);                     \
    fn_t original = (fn_t)slot_original(ENV_SLOT_##JNI_NAME);                                \
    if (!original) return;                                                                   \
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_##JNI_NAME)) {                           \
        original(env, arr, start, len, buf);                                                 \
        return;                                                                              \
    }                                                                                        \
    g_env_hook_in_ours = 1;                                                                  \
    original(env, arr, start, len, buf);                                                     \
    g_env_hook_in_ours = 0;                                                                  \
    int failed = (*env)->ExceptionCheck(env) ? 1 : 0;                                        \
    char detail[220]; detail[0] = 0;                                                         \
    if (!failed && env_budget_left(ENV_SLOT_##JNI_NAME)) {                                   \
        char preview[96] = "";                                                               \
        size_t p = 0;                                                                        \
        if (buf && len > 0) {                                                                \
            for (jsize i = 0; i < len && i < 4 && p + 24 < sizeof(preview); i++) {            \
                p += (size_t)snprintf(preview + p, sizeof(preview) - p, "%s" FMT,            \
                                      i ? "," : "", CAST(buf[i]));                           \
            }                                                                                \
        }                                                                                    \
        snprintf(detail, sizeof(detail), "array=%p start=%d len=%d first=[%s]",               \
                 (void *)arr, (int)start, (int)len, preview);                                \
    } else if (failed) {                                                                     \
        snprintf(detail, sizeof(detail), "array=%p start=%d len=%d <call failed>",            \
                 (void *)arr, (int)start, (int)len);                                         \
    }                                                                                        \
    /* A zero-length region call with a NULL buffer is a legal no-op, not a failure. */       \
    env_note(ENV_SLOT_##JNI_NAME, detail[0] ? detail : NULL,                                 \
             !failed && (buf != NULL || len == 0));                                          \
}

ADH_DEFINE_ARRAY_REGION(GetBooleanArrayRegion, jboolean, jboolean *, "%d", (int))
ADH_DEFINE_ARRAY_REGION(SetBooleanArrayRegion, jboolean, const jboolean *, "%d", (int))
ADH_DEFINE_ARRAY_REGION(GetCharArrayRegion, jchar, jchar *, "%u", (unsigned))
ADH_DEFINE_ARRAY_REGION(SetCharArrayRegion, jchar, const jchar *, "%u", (unsigned))
ADH_DEFINE_ARRAY_REGION(GetShortArrayRegion, jshort, jshort *, "%d", (int))
ADH_DEFINE_ARRAY_REGION(SetShortArrayRegion, jshort, const jshort *, "%d", (int))
ADH_DEFINE_ARRAY_REGION(GetIntArrayRegion, jint, jint *, "%d", (int))
ADH_DEFINE_ARRAY_REGION(SetIntArrayRegion, jint, const jint *, "%d", (int))
ADH_DEFINE_ARRAY_REGION(GetLongArrayRegion, jlong, jlong *, "%lld", (long long))
ADH_DEFINE_ARRAY_REGION(SetLongArrayRegion, jlong, const jlong *, "%lld", (long long))
ADH_DEFINE_ARRAY_REGION(GetFloatArrayRegion, jfloat, jfloat *, "%g", (double))
ADH_DEFINE_ARRAY_REGION(SetFloatArrayRegion, jfloat, const jfloat *, "%g", (double))
ADH_DEFINE_ARRAY_REGION(GetDoubleArrayRegion, jdouble, jdouble *, "%g", (double))
ADH_DEFINE_ARRAY_REGION(SetDoubleArrayRegion, jdouble, const jdouble *, "%g", (double))

// v4.72 fixture-free family: Get/Release<Type>ArrayElements. Get hands the target a pointer to the
// array data (a copy or the real thing - isCopy says which) and Release is where the target's
// writes either land (mode copyback / commit) or are dropped (mode abort). The length comes from
// GetArrayLength, and ONLY when no exception is pending: querying it while one is pending is
// illegal JNI (the CheckJNI lesson from the exception batch). The preview is read while the buffer
// is still valid - before the release call - so an abort honestly shows what was discarded.
#define ADH_DEFINE_ARRAY_ELEMENTS(JNI_NAME, CTYPE, FMT, CAST)                                       \
static CTYPE *JNI_NAME##_wrapper(JNIEnv *env, jarray arr, jboolean *isCopy) {                    \
    typedef CTYPE *(JNICALL *fn_t)(JNIEnv *, jarray, jboolean *);                                \
    fn_t original = (fn_t)slot_original(ENV_SLOT_##JNI_NAME);                                    \
    if (!original) return NULL;                                                                  \
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_##JNI_NAME)) return original(env, arr, isCopy); \
    CTYPE *elems = original(env, arr, isCopy);                                                   \
    int failed = (*env)->ExceptionCheck(env) ? 1 : 0;                                            \
    char detail[220]; detail[0] = 0;                                                             \
    if (failed) {                                                                                \
        snprintf(detail, sizeof(detail), "array=%p <call failed>", (void *)arr);                 \
    } else if (elems && arr && env_budget_left(ENV_SLOT_##JNI_NAME)) {                           \
        g_env_hook_in_ours = 1;                                                                  \
        int len = (int)(*env)->GetArrayLength(env, arr);                                         \
        g_env_hook_in_ours = 0;                                                                  \
        char preview[96] = "";                                                                   \
        size_t p = 0;                                                                            \
        for (int i = 0; i < len && i < 4 && p + 24 < sizeof(preview); i++) {                     \
            p += (size_t)snprintf(preview + p, sizeof(preview) - p, "%s" FMT,                    \
                                  i ? "," : "", CAST(elems[i]));                                 \
        }                                                                                        \
        snprintf(detail, sizeof(detail), "array=%p len=%d elements=%p isCopy=%d first=[%s]",     \
                 (void *)arr, len, (void *)elems, isCopy ? (int)*isCopy : -1, preview);          \
    }                                                                                            \
    env_note(ENV_SLOT_##JNI_NAME, detail[0] ? detail : NULL, !failed && elems != NULL);          \
    return elems;                                                                                \
}

#define ADH_DEFINE_ARRAY_ELEMENTS_RELEASE(JNI_NAME, CTYPE, FMT, CAST)                               \
static void JNI_NAME##_wrapper(JNIEnv *env, jarray arr, CTYPE *elems, jint mode) {               \
    typedef void (JNICALL *fn_t)(JNIEnv *, jarray, CTYPE *, jint);                               \
    fn_t original = (fn_t)slot_original(ENV_SLOT_##JNI_NAME);                                    \
    if (!original) return;                                                                       \
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_##JNI_NAME)) {                               \
        original(env, arr, elems, mode);                                                         \
        return;                                                                                  \
    }                                                                                            \
    char detail[220]; detail[0] = 0;                                                             \
    if (env_budget_left(ENV_SLOT_##JNI_NAME)) {                                                  \
        int len = -1;                                                                            \
        if (arr && !(*env)->ExceptionCheck(env)) {                                               \
            g_env_hook_in_ours = 1;                                                              \
            len = (int)(*env)->GetArrayLength(env, arr);                                         \
            g_env_hook_in_ours = 0;                                                              \
        }                                                                                        \
        const char *mode_name = mode == 0 ? "copyback"                                              \
                              : mode == 1 ? "commit"                                                \
                              : mode == 2 ? "abort" : "unknown";                                    \
        char preview[96] = "";                                                                   \
        size_t p = 0;                                                                            \
        for (int i = 0; i < len && i < 4 && p + 24 < sizeof(preview); i++) {                     \
            p += (size_t)snprintf(preview + p, sizeof(preview) - p, "%s" FMT,                    \
                                  i ? "," : "", CAST(elems[i]));                                 \
        }                                                                                        \
        snprintf(detail, sizeof(detail), "array=%p len=%d elements=%p mode=%d(%s) first=[%s]",   \
                 (void *)arr, len, (void *)elems, (int)mode, mode_name,                          \
                 elems ? preview : "");                                                          \
    }                                                                                            \
    original(env, arr, elems, mode);                                                             \
    env_note(ENV_SLOT_##JNI_NAME, detail[0] ? detail : NULL, elems != NULL);                     \
}

ADH_DEFINE_ARRAY_ELEMENTS(GetBooleanArrayElements, jboolean, "%d", (int))
ADH_DEFINE_ARRAY_ELEMENTS_RELEASE(ReleaseBooleanArrayElements, jboolean, "%d", (int))
ADH_DEFINE_ARRAY_ELEMENTS(GetCharArrayElements, jchar, "%u", (unsigned))
ADH_DEFINE_ARRAY_ELEMENTS_RELEASE(ReleaseCharArrayElements, jchar, "%u", (unsigned))
ADH_DEFINE_ARRAY_ELEMENTS(GetShortArrayElements, jshort, "%d", (int))
ADH_DEFINE_ARRAY_ELEMENTS_RELEASE(ReleaseShortArrayElements, jshort, "%d", (int))
ADH_DEFINE_ARRAY_ELEMENTS(GetIntArrayElements, jint, "%d", (int))
ADH_DEFINE_ARRAY_ELEMENTS_RELEASE(ReleaseIntArrayElements, jint, "%d", (int))
ADH_DEFINE_ARRAY_ELEMENTS(GetLongArrayElements, jlong, "%lld", (long long))
ADH_DEFINE_ARRAY_ELEMENTS_RELEASE(ReleaseLongArrayElements, jlong, "%lld", (long long))
ADH_DEFINE_ARRAY_ELEMENTS(GetFloatArrayElements, jfloat, "%g", (double))
ADH_DEFINE_ARRAY_ELEMENTS_RELEASE(ReleaseFloatArrayElements, jfloat, "%g", (double))
ADH_DEFINE_ARRAY_ELEMENTS(GetDoubleArrayElements, jdouble, "%g", (double))
ADH_DEFINE_ARRAY_ELEMENTS_RELEASE(ReleaseDoubleArrayElements, jdouble, "%g", (double))

// Compile-time type check: each wrapper must have exactly its table entry signature.
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetBooleanArrayElements), __typeof__(&GetBooleanArrayElements_wrapper)), "GetBooleanArrayElements_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->ReleaseBooleanArrayElements), __typeof__(&ReleaseBooleanArrayElements_wrapper)), "ReleaseBooleanArrayElements_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetCharArrayElements), __typeof__(&GetCharArrayElements_wrapper)), "GetCharArrayElements_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->ReleaseCharArrayElements), __typeof__(&ReleaseCharArrayElements_wrapper)), "ReleaseCharArrayElements_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetShortArrayElements), __typeof__(&GetShortArrayElements_wrapper)), "GetShortArrayElements_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->ReleaseShortArrayElements), __typeof__(&ReleaseShortArrayElements_wrapper)), "ReleaseShortArrayElements_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetIntArrayElements), __typeof__(&GetIntArrayElements_wrapper)), "GetIntArrayElements_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->ReleaseIntArrayElements), __typeof__(&ReleaseIntArrayElements_wrapper)), "ReleaseIntArrayElements_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetLongArrayElements), __typeof__(&GetLongArrayElements_wrapper)), "GetLongArrayElements_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->ReleaseLongArrayElements), __typeof__(&ReleaseLongArrayElements_wrapper)), "ReleaseLongArrayElements_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetFloatArrayElements), __typeof__(&GetFloatArrayElements_wrapper)), "GetFloatArrayElements_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->ReleaseFloatArrayElements), __typeof__(&ReleaseFloatArrayElements_wrapper)), "ReleaseFloatArrayElements_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetDoubleArrayElements), __typeof__(&GetDoubleArrayElements_wrapper)), "GetDoubleArrayElements_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->ReleaseDoubleArrayElements), __typeof__(&ReleaseDoubleArrayElements_wrapper)), "ReleaseDoubleArrayElements_wrapper signature mismatch");

// Compile-time type check: each wrapper must have exactly its table entry signature.
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetBooleanArrayRegion), __typeof__(&GetBooleanArrayRegion_wrapper)), "GetBooleanArrayRegion_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetBooleanArrayRegion), __typeof__(&SetBooleanArrayRegion_wrapper)), "SetBooleanArrayRegion_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetCharArrayRegion), __typeof__(&GetCharArrayRegion_wrapper)), "GetCharArrayRegion_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetCharArrayRegion), __typeof__(&SetCharArrayRegion_wrapper)), "SetCharArrayRegion_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetShortArrayRegion), __typeof__(&GetShortArrayRegion_wrapper)), "GetShortArrayRegion_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetShortArrayRegion), __typeof__(&SetShortArrayRegion_wrapper)), "SetShortArrayRegion_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetIntArrayRegion), __typeof__(&GetIntArrayRegion_wrapper)), "GetIntArrayRegion_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetIntArrayRegion), __typeof__(&SetIntArrayRegion_wrapper)), "SetIntArrayRegion_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetLongArrayRegion), __typeof__(&GetLongArrayRegion_wrapper)), "GetLongArrayRegion_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetLongArrayRegion), __typeof__(&SetLongArrayRegion_wrapper)), "SetLongArrayRegion_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetFloatArrayRegion), __typeof__(&GetFloatArrayRegion_wrapper)), "GetFloatArrayRegion_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetFloatArrayRegion), __typeof__(&SetFloatArrayRegion_wrapper)), "SetFloatArrayRegion_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetDoubleArrayRegion), __typeof__(&GetDoubleArrayRegion_wrapper)), "GetDoubleArrayRegion_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetDoubleArrayRegion), __typeof__(&SetDoubleArrayRegion_wrapper)), "SetDoubleArrayRegion_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetVersion), __typeof__(&GetVersion_wrapper)), "GetVersion_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->DefineClass), __typeof__(&DefineClass_wrapper)), "DefineClass_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetSuperclass), __typeof__(&GetSuperclass_wrapper)), "GetSuperclass_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->IsAssignableFrom), __typeof__(&IsAssignableFrom_wrapper)), "IsAssignableFrom_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetObjectClass), __typeof__(&GetObjectClass_wrapper)), "GetObjectClass_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->IsInstanceOf), __typeof__(&IsInstanceOf_wrapper)), "IsInstanceOf_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->MonitorEnter), __typeof__(&MonitorEnter_wrapper)), "MonitorEnter_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->MonitorExit), __typeof__(&MonitorExit_wrapper)), "MonitorExit_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->NewWeakGlobalRef), __typeof__(&NewWeakGlobalRef_wrapper)), "NewWeakGlobalRef_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->DeleteWeakGlobalRef), __typeof__(&DeleteWeakGlobalRef_wrapper)), "DeleteWeakGlobalRef_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetObjectRefType), __typeof__(&GetObjectRefType_wrapper)), "GetObjectRefType_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->PushLocalFrame), __typeof__(&PushLocalFrame_wrapper)), "PushLocalFrame_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->PopLocalFrame), __typeof__(&PopLocalFrame_wrapper)), "PopLocalFrame_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->NewLocalRef), __typeof__(&NewLocalRef_wrapper)), "NewLocalRef_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->DeleteLocalRef), __typeof__(&DeleteLocalRef_wrapper)), "DeleteLocalRef_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->NewGlobalRef), __typeof__(&NewGlobalRef_wrapper)), "NewGlobalRef_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->DeleteGlobalRef), __typeof__(&DeleteGlobalRef_wrapper)), "DeleteGlobalRef_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->IsSameObject), __typeof__(&IsSameObject_wrapper)), "IsSameObject_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->EnsureLocalCapacity), __typeof__(&EnsureLocalCapacity_wrapper)), "EnsureLocalCapacity_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->Throw), __typeof__(&Throw_wrapper)), "Throw_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->ThrowNew), __typeof__(&ThrowNew_wrapper)), "ThrowNew_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->ExceptionOccurred), __typeof__(&ExceptionOccurred_wrapper)), "ExceptionOccurred_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->ExceptionDescribe), __typeof__(&ExceptionDescribe_wrapper)), "ExceptionDescribe_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->ExceptionClear), __typeof__(&ExceptionClear_wrapper)), "ExceptionClear_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetJavaVM), __typeof__(&GetJavaVM_wrapper)), "GetJavaVM_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetStringChars), __typeof__(&GetStringChars_wrapper)), "GetStringChars_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->ReleaseStringChars), __typeof__(&ReleaseStringChars_wrapper)), "ReleaseStringChars_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetStringRegion), __typeof__(&GetStringRegion_wrapper)), "GetStringRegion_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetStringUTFRegion), __typeof__(&GetStringUTFRegion_wrapper)), "GetStringUTFRegion_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->NewDirectByteBuffer), __typeof__(&NewDirectByteBuffer_wrapper)), "NewDirectByteBuffer_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetDirectBufferAddress), __typeof__(&GetDirectBufferAddress_wrapper)), "GetDirectBufferAddress_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetDirectBufferCapacity), __typeof__(&GetDirectBufferCapacity_wrapper)), "GetDirectBufferCapacity_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetFieldID), __typeof__(&GetFieldID_wrapper)), "GetFieldID_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetStaticFieldID), __typeof__(&GetStaticFieldID_wrapper)), "GetStaticFieldID_wrapper signature mismatch");
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
        // v4.72: the rest of the elements family.
        case ENV_SLOT_GetBooleanArrayElements: return 183;
        case ENV_SLOT_ReleaseBooleanArrayElements: return 191;
        case ENV_SLOT_GetCharArrayElements: return 185;
        case ENV_SLOT_ReleaseCharArrayElements: return 193;
        case ENV_SLOT_GetShortArrayElements: return 186;
        case ENV_SLOT_ReleaseShortArrayElements: return 194;
        case ENV_SLOT_GetIntArrayElements: return 187;
        case ENV_SLOT_ReleaseIntArrayElements: return 195;
        case ENV_SLOT_GetLongArrayElements: return 188;
        case ENV_SLOT_ReleaseLongArrayElements: return 196;
        case ENV_SLOT_GetFloatArrayElements: return 189;
        case ENV_SLOT_ReleaseFloatArrayElements: return 197;
        case ENV_SLOT_GetDoubleArrayElements: return 190;
        case ENV_SLOT_ReleaseDoubleArrayElements: return 198;
        case ENV_SLOT_GetByteArrayRegion: return 200;
        case ENV_SLOT_SetByteArrayRegion: return 208;
        case ENV_SLOT_GetPrimitiveArrayCritical: return 222;
        case ENV_SLOT_GetStringRegion: return 220;
        case ENV_SLOT_GetBooleanArrayRegion: return 199;
        case ENV_SLOT_SetBooleanArrayRegion: return 207;
        case ENV_SLOT_GetCharArrayRegion: return 201;
        case ENV_SLOT_SetCharArrayRegion: return 209;
        case ENV_SLOT_GetShortArrayRegion: return 202;
        case ENV_SLOT_SetShortArrayRegion: return 210;
        case ENV_SLOT_GetIntArrayRegion: return 203;
        case ENV_SLOT_SetIntArrayRegion: return 211;
        case ENV_SLOT_GetLongArrayRegion: return 204;
        case ENV_SLOT_SetLongArrayRegion: return 212;
        case ENV_SLOT_GetFloatArrayRegion: return 205;
        case ENV_SLOT_SetFloatArrayRegion: return 213;
        case ENV_SLOT_GetDoubleArrayRegion: return 206;
        case ENV_SLOT_SetDoubleArrayRegion: return 214;
        case ENV_SLOT_GetVersion: return 4;
        case ENV_SLOT_DefineClass: return 5;
        case ENV_SLOT_GetSuperclass: return 10;
        case ENV_SLOT_IsAssignableFrom: return 11;
        case ENV_SLOT_GetObjectClass: return 31;
        case ENV_SLOT_IsInstanceOf: return 32;
        case ENV_SLOT_MonitorEnter: return 217;
        case ENV_SLOT_MonitorExit: return 218;
        case ENV_SLOT_NewWeakGlobalRef: return 226;
        case ENV_SLOT_DeleteWeakGlobalRef: return 227;
        case ENV_SLOT_GetObjectRefType: return 232;
        case ENV_SLOT_PushLocalFrame: return 19;
        case ENV_SLOT_PopLocalFrame: return 20;
        case ENV_SLOT_NewLocalRef: return 25;
        case ENV_SLOT_DeleteLocalRef: return 23;
        case ENV_SLOT_NewGlobalRef: return 21;
        case ENV_SLOT_DeleteGlobalRef: return 22;
        case ENV_SLOT_IsSameObject: return 24;
        case ENV_SLOT_EnsureLocalCapacity: return 26;
        case ENV_SLOT_Throw: return 13;
        case ENV_SLOT_ThrowNew: return 14;
        case ENV_SLOT_ExceptionOccurred: return 15;
        case ENV_SLOT_ExceptionDescribe: return 16;
        case ENV_SLOT_ExceptionClear: return 17;
        case ENV_SLOT_GetJavaVM: return 219;
        case ENV_SLOT_GetStringChars: return 165;
        case ENV_SLOT_ReleaseStringChars: return 166;
        case ENV_SLOT_GetStringUTFRegion: return 221;
        case ENV_SLOT_NewDirectByteBuffer: return 229;
        case ENV_SLOT_GetDirectBufferAddress: return 230;
        case ENV_SLOT_GetDirectBufferCapacity: return 231;
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
        case ENV_SLOT_GetBooleanArrayElements: return (void **)(uintptr_t)&table->GetBooleanArrayElements;
        case ENV_SLOT_ReleaseBooleanArrayElements: return (void **)(uintptr_t)&table->ReleaseBooleanArrayElements;
        case ENV_SLOT_GetCharArrayElements: return (void **)(uintptr_t)&table->GetCharArrayElements;
        case ENV_SLOT_ReleaseCharArrayElements: return (void **)(uintptr_t)&table->ReleaseCharArrayElements;
        case ENV_SLOT_GetShortArrayElements: return (void **)(uintptr_t)&table->GetShortArrayElements;
        case ENV_SLOT_ReleaseShortArrayElements: return (void **)(uintptr_t)&table->ReleaseShortArrayElements;
        case ENV_SLOT_GetIntArrayElements: return (void **)(uintptr_t)&table->GetIntArrayElements;
        case ENV_SLOT_ReleaseIntArrayElements: return (void **)(uintptr_t)&table->ReleaseIntArrayElements;
        case ENV_SLOT_GetLongArrayElements: return (void **)(uintptr_t)&table->GetLongArrayElements;
        case ENV_SLOT_ReleaseLongArrayElements: return (void **)(uintptr_t)&table->ReleaseLongArrayElements;
        case ENV_SLOT_GetFloatArrayElements: return (void **)(uintptr_t)&table->GetFloatArrayElements;
        case ENV_SLOT_ReleaseFloatArrayElements: return (void **)(uintptr_t)&table->ReleaseFloatArrayElements;
        case ENV_SLOT_GetDoubleArrayElements: return (void **)(uintptr_t)&table->GetDoubleArrayElements;
        case ENV_SLOT_ReleaseDoubleArrayElements: return (void **)(uintptr_t)&table->ReleaseDoubleArrayElements;
        case ENV_SLOT_GetByteArrayRegion: return (void **)(uintptr_t)&table->GetByteArrayRegion;
        case ENV_SLOT_GetPrimitiveArrayCritical: return (void **)(uintptr_t)&table->GetPrimitiveArrayCritical;
        case ENV_SLOT_GetBooleanArrayRegion: return (void **)(uintptr_t)&table->GetBooleanArrayRegion;
        case ENV_SLOT_SetBooleanArrayRegion: return (void **)(uintptr_t)&table->SetBooleanArrayRegion;
        case ENV_SLOT_GetCharArrayRegion: return (void **)(uintptr_t)&table->GetCharArrayRegion;
        case ENV_SLOT_SetCharArrayRegion: return (void **)(uintptr_t)&table->SetCharArrayRegion;
        case ENV_SLOT_GetShortArrayRegion: return (void **)(uintptr_t)&table->GetShortArrayRegion;
        case ENV_SLOT_SetShortArrayRegion: return (void **)(uintptr_t)&table->SetShortArrayRegion;
        case ENV_SLOT_GetIntArrayRegion: return (void **)(uintptr_t)&table->GetIntArrayRegion;
        case ENV_SLOT_SetIntArrayRegion: return (void **)(uintptr_t)&table->SetIntArrayRegion;
        case ENV_SLOT_GetLongArrayRegion: return (void **)(uintptr_t)&table->GetLongArrayRegion;
        case ENV_SLOT_SetLongArrayRegion: return (void **)(uintptr_t)&table->SetLongArrayRegion;
        case ENV_SLOT_GetFloatArrayRegion: return (void **)(uintptr_t)&table->GetFloatArrayRegion;
        case ENV_SLOT_SetFloatArrayRegion: return (void **)(uintptr_t)&table->SetFloatArrayRegion;
        case ENV_SLOT_GetDoubleArrayRegion: return (void **)(uintptr_t)&table->GetDoubleArrayRegion;
        case ENV_SLOT_SetDoubleArrayRegion: return (void **)(uintptr_t)&table->SetDoubleArrayRegion;
        case ENV_SLOT_GetVersion: return (void **)(uintptr_t)&table->GetVersion;
        case ENV_SLOT_DefineClass: return (void **)(uintptr_t)&table->DefineClass;
        case ENV_SLOT_GetSuperclass: return (void **)(uintptr_t)&table->GetSuperclass;
        case ENV_SLOT_IsAssignableFrom: return (void **)(uintptr_t)&table->IsAssignableFrom;
        case ENV_SLOT_GetObjectClass: return (void **)(uintptr_t)&table->GetObjectClass;
        case ENV_SLOT_IsInstanceOf: return (void **)(uintptr_t)&table->IsInstanceOf;
        case ENV_SLOT_MonitorEnter: return (void **)(uintptr_t)&table->MonitorEnter;
        case ENV_SLOT_MonitorExit: return (void **)(uintptr_t)&table->MonitorExit;
        case ENV_SLOT_NewWeakGlobalRef: return (void **)(uintptr_t)&table->NewWeakGlobalRef;
        case ENV_SLOT_DeleteWeakGlobalRef: return (void **)(uintptr_t)&table->DeleteWeakGlobalRef;
        case ENV_SLOT_GetObjectRefType: return (void **)(uintptr_t)&table->GetObjectRefType;
        case ENV_SLOT_PushLocalFrame: return (void **)(uintptr_t)&table->PushLocalFrame;
        case ENV_SLOT_PopLocalFrame: return (void **)(uintptr_t)&table->PopLocalFrame;
        case ENV_SLOT_NewLocalRef: return (void **)(uintptr_t)&table->NewLocalRef;
        case ENV_SLOT_DeleteLocalRef: return (void **)(uintptr_t)&table->DeleteLocalRef;
        case ENV_SLOT_NewGlobalRef: return (void **)(uintptr_t)&table->NewGlobalRef;
        case ENV_SLOT_DeleteGlobalRef: return (void **)(uintptr_t)&table->DeleteGlobalRef;
        case ENV_SLOT_IsSameObject: return (void **)(uintptr_t)&table->IsSameObject;
        case ENV_SLOT_EnsureLocalCapacity: return (void **)(uintptr_t)&table->EnsureLocalCapacity;
        case ENV_SLOT_Throw: return (void **)(uintptr_t)&table->Throw;
        case ENV_SLOT_ThrowNew: return (void **)(uintptr_t)&table->ThrowNew;
        case ENV_SLOT_ExceptionOccurred: return (void **)(uintptr_t)&table->ExceptionOccurred;
        case ENV_SLOT_ExceptionDescribe: return (void **)(uintptr_t)&table->ExceptionDescribe;
        case ENV_SLOT_ExceptionClear: return (void **)(uintptr_t)&table->ExceptionClear;
        case ENV_SLOT_GetJavaVM: return (void **)(uintptr_t)&table->GetJavaVM;
        case ENV_SLOT_GetStringChars: return (void **)(uintptr_t)&table->GetStringChars;
        case ENV_SLOT_ReleaseStringChars: return (void **)(uintptr_t)&table->ReleaseStringChars;
        case ENV_SLOT_GetStringRegion: return (void **)(uintptr_t)&table->GetStringRegion;
        case ENV_SLOT_GetStringUTFRegion: return (void **)(uintptr_t)&table->GetStringUTFRegion;
        case ENV_SLOT_NewDirectByteBuffer: return (void **)(uintptr_t)&table->NewDirectByteBuffer;
        case ENV_SLOT_GetDirectBufferAddress: return (void **)(uintptr_t)&table->GetDirectBufferAddress;
        case ENV_SLOT_GetDirectBufferCapacity: return (void **)(uintptr_t)&table->GetDirectBufferCapacity;
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
        case ENV_SLOT_GetBooleanArrayElements: return (void *)&GetBooleanArrayElements_wrapper;
        case ENV_SLOT_ReleaseBooleanArrayElements: return (void *)&ReleaseBooleanArrayElements_wrapper;
        case ENV_SLOT_GetCharArrayElements: return (void *)&GetCharArrayElements_wrapper;
        case ENV_SLOT_ReleaseCharArrayElements: return (void *)&ReleaseCharArrayElements_wrapper;
        case ENV_SLOT_GetShortArrayElements: return (void *)&GetShortArrayElements_wrapper;
        case ENV_SLOT_ReleaseShortArrayElements: return (void *)&ReleaseShortArrayElements_wrapper;
        case ENV_SLOT_GetIntArrayElements: return (void *)&GetIntArrayElements_wrapper;
        case ENV_SLOT_ReleaseIntArrayElements: return (void *)&ReleaseIntArrayElements_wrapper;
        case ENV_SLOT_GetLongArrayElements: return (void *)&GetLongArrayElements_wrapper;
        case ENV_SLOT_ReleaseLongArrayElements: return (void *)&ReleaseLongArrayElements_wrapper;
        case ENV_SLOT_GetFloatArrayElements: return (void *)&GetFloatArrayElements_wrapper;
        case ENV_SLOT_ReleaseFloatArrayElements: return (void *)&ReleaseFloatArrayElements_wrapper;
        case ENV_SLOT_GetDoubleArrayElements: return (void *)&GetDoubleArrayElements_wrapper;
        case ENV_SLOT_ReleaseDoubleArrayElements: return (void *)&ReleaseDoubleArrayElements_wrapper;
        case ENV_SLOT_GetByteArrayRegion: return (void *)&GetByteArrayRegion_wrapper;
        case ENV_SLOT_GetPrimitiveArrayCritical: return (void *)&GetPrimitiveArrayCritical_wrapper;
        case ENV_SLOT_GetBooleanArrayRegion: return (void *)&GetBooleanArrayRegion_wrapper;
        case ENV_SLOT_SetBooleanArrayRegion: return (void *)&SetBooleanArrayRegion_wrapper;
        case ENV_SLOT_GetCharArrayRegion: return (void *)&GetCharArrayRegion_wrapper;
        case ENV_SLOT_SetCharArrayRegion: return (void *)&SetCharArrayRegion_wrapper;
        case ENV_SLOT_GetShortArrayRegion: return (void *)&GetShortArrayRegion_wrapper;
        case ENV_SLOT_SetShortArrayRegion: return (void *)&SetShortArrayRegion_wrapper;
        case ENV_SLOT_GetIntArrayRegion: return (void *)&GetIntArrayRegion_wrapper;
        case ENV_SLOT_SetIntArrayRegion: return (void *)&SetIntArrayRegion_wrapper;
        case ENV_SLOT_GetLongArrayRegion: return (void *)&GetLongArrayRegion_wrapper;
        case ENV_SLOT_SetLongArrayRegion: return (void *)&SetLongArrayRegion_wrapper;
        case ENV_SLOT_GetFloatArrayRegion: return (void *)&GetFloatArrayRegion_wrapper;
        case ENV_SLOT_SetFloatArrayRegion: return (void *)&SetFloatArrayRegion_wrapper;
        case ENV_SLOT_GetDoubleArrayRegion: return (void *)&GetDoubleArrayRegion_wrapper;
        case ENV_SLOT_SetDoubleArrayRegion: return (void *)&SetDoubleArrayRegion_wrapper;
        case ENV_SLOT_GetVersion: return (void *)&GetVersion_wrapper;
        case ENV_SLOT_DefineClass: return (void *)&DefineClass_wrapper;
        case ENV_SLOT_GetSuperclass: return (void *)&GetSuperclass_wrapper;
        case ENV_SLOT_IsAssignableFrom: return (void *)&IsAssignableFrom_wrapper;
        case ENV_SLOT_GetObjectClass: return (void *)&GetObjectClass_wrapper;
        case ENV_SLOT_IsInstanceOf: return (void *)&IsInstanceOf_wrapper;
        case ENV_SLOT_MonitorEnter: return (void *)&MonitorEnter_wrapper;
        case ENV_SLOT_MonitorExit: return (void *)&MonitorExit_wrapper;
        case ENV_SLOT_NewWeakGlobalRef: return (void *)&NewWeakGlobalRef_wrapper;
        case ENV_SLOT_DeleteWeakGlobalRef: return (void *)&DeleteWeakGlobalRef_wrapper;
        case ENV_SLOT_GetObjectRefType: return (void *)&GetObjectRefType_wrapper;
        case ENV_SLOT_PushLocalFrame: return (void *)&PushLocalFrame_wrapper;
        case ENV_SLOT_PopLocalFrame: return (void *)&PopLocalFrame_wrapper;
        case ENV_SLOT_NewLocalRef: return (void *)&NewLocalRef_wrapper;
        case ENV_SLOT_DeleteLocalRef: return (void *)&DeleteLocalRef_wrapper;
        case ENV_SLOT_NewGlobalRef: return (void *)&NewGlobalRef_wrapper;
        case ENV_SLOT_DeleteGlobalRef: return (void *)&DeleteGlobalRef_wrapper;
        case ENV_SLOT_IsSameObject: return (void *)&IsSameObject_wrapper;
        case ENV_SLOT_EnsureLocalCapacity: return (void *)&EnsureLocalCapacity_wrapper;
        case ENV_SLOT_Throw: return (void *)&Throw_wrapper;
        case ENV_SLOT_ThrowNew: return (void *)&ThrowNew_wrapper;
        case ENV_SLOT_ExceptionOccurred: return (void *)&ExceptionOccurred_wrapper;
        case ENV_SLOT_ExceptionDescribe: return (void *)&ExceptionDescribe_wrapper;
        case ENV_SLOT_ExceptionClear: return (void *)&ExceptionClear_wrapper;
        case ENV_SLOT_GetJavaVM: return (void *)&GetJavaVM_wrapper;
        case ENV_SLOT_GetStringChars: return (void *)&GetStringChars_wrapper;
        case ENV_SLOT_ReleaseStringChars: return (void *)&ReleaseStringChars_wrapper;
        case ENV_SLOT_GetStringRegion: return (void *)&GetStringRegion_wrapper;
        case ENV_SLOT_GetStringUTFRegion: return (void *)&GetStringUTFRegion_wrapper;
        case ENV_SLOT_NewDirectByteBuffer: return (void *)&NewDirectByteBuffer_wrapper;
        case ENV_SLOT_GetDirectBufferAddress: return (void *)&GetDirectBufferAddress_wrapper;
        case ENV_SLOT_GetDirectBufferCapacity: return (void *)&GetDirectBufferCapacity_wrapper;
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
    pthread_mutex_lock(&g_env_hook_lock);
    for (int i = 0; i < ENV_HOOK_MAX && len + 380 < sizeof(out); i++) {
        char slot_perms[8] = "";
        char lastj[512];
        json_escape(g_env_hooks[i].last, lastj, sizeof(lastj));
        // A running write override must be visible in status - otherwise the operator cannot tell
        // whether a Set<Type>Field hook is still rewriting values.
        char ovbuf[48] = "";
        if (g_env_hooks[i].override_active) {
            if ((double)g_env_hooks[i].override_i == g_env_hooks[i].override_d) snprintf(ovbuf, sizeof(ovbuf), "%lld", g_env_hooks[i].override_i);
            else snprintf(ovbuf, sizeof(ovbuf), "%g", g_env_hooks[i].override_d);
        }
        const char *ovjson = g_env_hooks[i].override_active ? ovbuf : "null";
        void *live = NULL;
        if (g_env_hooks[i].slot) {
            adh_perms_of_addr((void *)(uintptr_t)g_env_hooks[i].slot, slot_perms, sizeof(slot_perms));
            live = __atomic_load_n(g_env_hooks[i].slot, __ATOMIC_ACQUIRE);
        }
        len += snprintf(out + len, sizeof(out) - len,
                        "%s{\"function\":\"%s\",\"installed\":%s,\"active\":%s,"
                        "\"hits\":%llu,\"dropped\":%llu,\"entry\":\"0x%llx\",\"perms\":\"%s\","
                        "\"slotValue\":\"0x%llx\",\"original\":\"0x%llx\",\"override\":%s,\"last\":\"%s\"}",
                        first ? "" : ",", g_env_hooks[i].name,
                        g_env_hooks[i].installed ? "true" : "false",
                        slot_active(i) ? "true" : "false",
                        g_env_hooks[i].hits, g_env_hooks[i].dropped,
                        (unsigned long long)(uintptr_t)g_env_hooks[i].slot, slot_perms,
                        (unsigned long long)(uintptr_t)live,
                        (unsigned long long)(uintptr_t)g_env_hooks[i].original,
                        g_env_hooks[i].override_active ? ovjson : "null", lastj);
        first = 0;
    }
    pthread_mutex_unlock(&g_env_hook_lock);
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
    __atomic_store_n(&g_env_hooks[index].override_active, 0, __ATOMIC_RELEASE);   // a removed hook must not keep rewriting writes
    pthread_mutex_unlock(&g_env_hook_lock);
    return 1;
}

// Patch one slot. The JNIEnv table lives in libart's RELRO segment, so the swap goes through
// adh_swap_pointer_in_ro_page() and the ABI guard below refuses to touch a drifted offset.
static int env_hook_install_index(int index, int override_active, long long override_i, double override_d,
                                  char *error, size_t error_size) {
    // Validate the override BEFORE touching the table: it only makes sense for one Set*Field slot.
    if (override_active) {
        const char *name = g_env_hooks[index].name;
        int is_set_field = strncmp(name, "Set", 3) == 0 && strstr(name, "Field") != NULL;
        if (!is_set_field) {
            snprintf(error, error_size, "setValue applies to a Set<Type>Field slot, not %s", name);
            return 0;
        }
        if (strstr(name, "Object") != NULL) {
            snprintf(error, error_size, "setValue cannot override %s: an object value would need a reference the agent does not hold", name);
            return 0;
        }
        // Range-check against the TARGET type: silently writing (jboolean)300 == 0 would be exactly
        // the kind of "it said ok but the field did not get what I asked for" this tool must not do.
        const char *type = (strncmp(name, "SetStatic", 9) == 0) ? name + 9
                         : (strncmp(name, "Set", 3) == 0) ? name + 3 : NULL;
        int in_range = 0;
        const char *range = "";
        if (type && strcmp(type, "BooleanField") == 0) { in_range = (override_i == 0 || override_i == 1); range = "0 or 1"; }
        else if (type && strcmp(type, "ByteField") == 0) { in_range = (override_i >= -128 && override_i <= 127); range = "-128..127"; }
        else if (type && strcmp(type, "CharField") == 0) { in_range = (override_i >= 0 && override_i <= 65535); range = "0..65535"; }
        else if (type && strcmp(type, "ShortField") == 0) { in_range = (override_i >= -32768 && override_i <= 32767); range = "-32768..32767"; }
        else if (type && strcmp(type, "IntField") == 0) { in_range = (override_i >= INT_MIN && override_i <= INT_MAX); range = "the int range"; }
        else if (type && strcmp(type, "LongField") == 0) { in_range = 1; }
        else if (type && (strcmp(type, "FloatField") == 0 || strcmp(type, "DoubleField") == 0)) { in_range = isfinite(override_d) ? 1 : 0; range = "a finite number"; }
        else { in_range = 0; range = "(unknown field type)"; }
        if (!in_range) {
            snprintf(error, error_size, "setValue for %s must be %s (got %lld / %g)", name, range, override_i, override_d);
            return 0;
        }
    }
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
        g_env_hooks[index].override_i = override_i;
        g_env_hooks[index].override_d = override_d;
        // Release AFTER the values so a wrapper that sees the flag with an acquire load also sees them.
        __atomic_store_n(&g_env_hooks[index].override_active, override_active ? 1 : 0, __ATOMIC_RELEASE);
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
    g_env_hooks[index].override_i = override_i;
    g_env_hooks[index].override_d = override_d;
    __atomic_store_n(&g_env_hooks[index].override_active, override_active ? 1 : 0, __ATOMIC_RELEASE);
    g_env_hooks[index].hits = 0;
    g_env_hooks[index].dropped = 0;
    pthread_mutex_unlock(&g_env_hook_lock);
    return 1;
}

void adh_cmd_jni_env_hook(int fd, const char *id, const char *action, const char *function,
                          int override_active, long long override_i, double override_d) {
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

    if (override_active && wildcard) {
        send_env_result(fd, id, action, function, 0, 0, 0, "setValue needs a single Set<Type>Field slot (no wildcard pattern)");
        return;
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
        int ok = applying ? env_hook_install_index(index, override_active, override_i, override_d, error, sizeof(error))
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
            int ok = applying ? env_hook_install_index(i, 0, 0, 0, error, sizeof(error))
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