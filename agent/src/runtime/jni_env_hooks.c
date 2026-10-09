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
// Fixed-slot dispatch cases, generated from the same list as the enum and the name table: which
// field a case returns and which wrapper it installs can no longer be paired by hand. A mismatched
// pair with identical signatures (two ID lookups, two Get/Set field entries) used to be invisible
// to the asserts, the layout check and the offset check alike.
#define ADH_FIXED_SLOT_CASE(name) case ENV_SLOT_##name: return (void **)(uintptr_t)&table->name;
#define ADH_FIXED_WRAPPER_CASE(name) case ENV_SLOT_##name: return (void *)&name##_wrapper;

// The fixed slots: ONE list drives the enum values, the installable-name table and the name
// mapping the layout self-check compares them against, all in the same order. Adding a slot in
// one place and forgetting another can no longer produce a hook that patches the neighbouring
// entry (the failure the field family lived with).
#define ADH_FIXED_SLOT_LIST(X) \
    X(GetStringUTFChars) X(FindClass) X(GetMethodID) X(GetStaticMethodID) \
    X(NewStringUTF) X(GetFieldID) X(GetStaticFieldID) X(GetByteArrayElements) \
    X(SetByteArrayRegion) X(ReleaseByteArrayElements) X(GetByteArrayRegion) X(GetBooleanArrayElements) \
    X(ReleaseBooleanArrayElements) X(GetCharArrayElements) X(ReleaseCharArrayElements) X(GetShortArrayElements) \
    X(ReleaseShortArrayElements) X(GetIntArrayElements) X(ReleaseIntArrayElements) X(GetLongArrayElements) \
    X(ReleaseLongArrayElements) X(GetFloatArrayElements) X(ReleaseFloatArrayElements) X(GetDoubleArrayElements) \
    X(ReleaseDoubleArrayElements) X(GetArrayLength) X(NewObjectArray) X(GetObjectArrayElement) \
    X(SetObjectArrayElement) X(AllocObject) X(NewBooleanArray) X(NewByteArray) \
    X(NewCharArray) X(NewShortArray) X(NewIntArray) X(NewLongArray) \
    X(NewFloatArray) X(NewDoubleArray) X(GetPrimitiveArrayCritical) X(ReleasePrimitiveArrayCritical) \
    X(GetStringRegion) X(GetStringUTFRegion) X(GetStringChars) X(ReleaseStringChars) \
    X(NewString) X(GetStringLength) X(GetStringUTFLength) X(ReleaseStringUTFChars) \
    X(GetStringCritical) X(ReleaseStringCritical) X(FromReflectedMethod) X(FromReflectedField) \
    X(ToReflectedMethod) X(ToReflectedField) X(UnregisterNatives) X(FatalError) \
    X(ExceptionCheck) X(Throw) X(ThrowNew) X(ExceptionOccurred) \
    X(ExceptionDescribe) X(ExceptionClear) X(GetJavaVM) X(PushLocalFrame) \
    X(PopLocalFrame) X(NewLocalRef) X(DeleteLocalRef) X(NewGlobalRef) \
    X(DeleteGlobalRef) X(IsSameObject) X(EnsureLocalCapacity) X(GetVersion) \
    X(DefineClass) X(GetSuperclass) X(IsAssignableFrom) X(GetObjectClass) \
    X(IsInstanceOf) X(MonitorEnter) X(MonitorExit) X(NewWeakGlobalRef) \
    X(DeleteWeakGlobalRef) X(GetObjectRefType) X(GetBooleanArrayRegion) X(SetBooleanArrayRegion) \
    X(GetCharArrayRegion) X(SetCharArrayRegion) X(GetShortArrayRegion) X(SetShortArrayRegion) \
    X(GetIntArrayRegion) X(SetIntArrayRegion) X(GetLongArrayRegion) X(SetLongArrayRegion) \
    X(GetFloatArrayRegion) X(SetFloatArrayRegion) X(GetDoubleArrayRegion) X(SetDoubleArrayRegion) \
    X(NewDirectByteBuffer) X(GetDirectBufferAddress) X(GetDirectBufferCapacity)

#define ADH_FIXED_ENUM_ENTRY(name) ENV_SLOT_##name,

enum {
    // The fixed slots, in table order, straight from ADH_FIXED_SLOT_LIST: the enum values ARE the
    // table indices, so deriving both from one list is what keeps name lookup and dispatch aligned.
    ADH_FIXED_SLOT_LIST(ADH_FIXED_ENUM_ENTRY)
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
    // v4.76: CallNonvirtual* - the three JNI forms with an explicit class, i.e. the caller names
    // the implementation to run instead of letting the receiver's runtime class decide.
    ENV_SLOT_CallNonvirtualObjectMethod = ENV_SLOT_CallStaticVoidMethod + 3,
    ENV_SLOT_CallNonvirtualBooleanMethod = ENV_SLOT_CallNonvirtualObjectMethod + 3,
    ENV_SLOT_CallNonvirtualByteMethod = ENV_SLOT_CallNonvirtualBooleanMethod + 3,
    ENV_SLOT_CallNonvirtualCharMethod = ENV_SLOT_CallNonvirtualByteMethod + 3,
    ENV_SLOT_CallNonvirtualShortMethod = ENV_SLOT_CallNonvirtualCharMethod + 3,
    ENV_SLOT_CallNonvirtualIntMethod = ENV_SLOT_CallNonvirtualShortMethod + 3,
    ENV_SLOT_CallNonvirtualLongMethod = ENV_SLOT_CallNonvirtualIntMethod + 3,
    ENV_SLOT_CallNonvirtualFloatMethod = ENV_SLOT_CallNonvirtualLongMethod + 3,
    ENV_SLOT_CallNonvirtualDoubleMethod = ENV_SLOT_CallNonvirtualFloatMethod + 3,
    ENV_SLOT_CallNonvirtualVoidMethod = ENV_SLOT_CallNonvirtualDoubleMethod + 3,
    // Name the V/A forms of the last family instead of leaving them as bare arithmetic: the field
    // block follows and must start at CallNonvirtualVoidMethodA + 1. The old "*_end" arithmetic
    // anchor consumed an enum value without a matching table entry, which pushed every field slot
    // one index past its table position; the assert block further down pins the layout now.
    ENV_SLOT_CallNonvirtualVoidMethodV,
    ENV_SLOT_CallNonvirtualVoidMethodA,
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

// v4.76: the CallNonvirtual* family. Same three JNI forms as Call*, plus an explicit jclass that
// names the implementation to run (the receiver's runtime class is bypassed on purpose). The
// wrappers therefore take (env, obj, clazz, mid, ...) and the event adds "via=<class>".
#define ADH_CALLNV_VALUE_FAMILIES(X) \
    X(CallNonvirtualObjectMethod, jobject, jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallNonvirtualObjectMethod,  64) \
    X(CallNonvirtualBooleanMethod, jboolean, jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallNonvirtualBooleanMethod,  67) \
    X(CallNonvirtualByteMethod, jbyte, jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallNonvirtualByteMethod,  70) \
    X(CallNonvirtualCharMethod, jchar, jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallNonvirtualCharMethod,  73) \
    X(CallNonvirtualShortMethod, jshort, jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallNonvirtualShortMethod,  76) \
    X(CallNonvirtualIntMethod,  jint, jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallNonvirtualIntMethod,  79) \
    X(CallNonvirtualLongMethod, jlong, jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallNonvirtualLongMethod,  82) \
    X(CallNonvirtualFloatMethod, jfloat, jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallNonvirtualFloatMethod,  85) \
    X(CallNonvirtualDoubleMethod, jdouble, jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallNonvirtualDoubleMethod,  88) \

#define ADH_CALLNV_VOID_FAMILIES(X) \
    X(CallNonvirtualVoidMethod, jobject, ADH_MEMBER_INSTANCE, ENV_SLOT_CallNonvirtualVoidMethod, 91)

#define ADH_SLOT_INIT(name) { name, NULL, NULL, 0, 0, 0, 0, "", 0, 0, 0.0 },
#define ADH_FIXED_INIT(name) ADH_SLOT_INIT(#name)
#define ADH_CALL_INITS_3(name, ret, tgt, kind, base) \
    ADH_SLOT_INIT(#name) ADH_SLOT_INIT(#name "V") ADH_SLOT_INIT(#name "A")
#define ADH_CALL_INITS(name, ret, tgt, kind, base, spec) ADH_CALL_INITS_3(name, ret, tgt, kind, base)
#define ADH_CALL_VOID_INITS(name, tgt, kind, base, spec) ADH_CALL_INITS_3(name, void, tgt, kind, base)
#define ADH_CALLNV_INITS(name, ret, tgt, kind, base, spec) ADH_CALL_INITS_3(name, ret, tgt, kind, base)
#define ADH_CALLNV_VOID_INITS(name, tgt, kind, base, spec) ADH_CALL_INITS_3(name, void, tgt, kind, base)

static struct EnvHookSlot g_env_hooks[] = {
    ADH_FIXED_SLOT_LIST(ADH_FIXED_INIT)
    ADH_CALL_VALUE_FAMILIES(ADH_CALL_INITS)
    ADH_CALL_VOID_FAMILIES(ADH_CALL_VOID_INITS)
    ADH_CALLNV_VALUE_FAMILIES(ADH_CALLNV_INITS)
    ADH_CALLNV_VOID_FAMILIES(ADH_CALLNV_VOID_INITS)
    ADH_FIELD_SLOT_LIST(ADH_FIELD_NAME_ENTRY)
};
// The table is indexed by the ENV_SLOT_* enumerators, so its size must be exactly the enum
// value that follows them: an unsized array plus this assert turns "the enum and the table
// drifted apart" into one clear compile error instead of silent truncation.
_Static_assert(sizeof(g_env_hooks) / sizeof(g_env_hooks[0]) == ENV_HOOK_MAX,
               "g_env_hooks must have exactly ENV_HOOK_MAX entries");
_Static_assert(ENV_SLOT_SetStaticDoubleField == ENV_HOOK_MAX - 1,
               "the field accessors are the last group in the table, so the last field slot must be the"
               " last enum value before ENV_HOOK_MAX (a drifting base would land on the wrong slot)");
// A total-size check alone cannot see a shifted layout: in the broken version the table and the enum
// agreed on the count while every field slot sat one index too high. These pin the group BASES to the
// positions the table actually has (fixed slots, then the Call families, then the field block).
_Static_assert(ENV_SLOT_CallObjectMethod == ENV_FIXED_SLOTS,
               "the Call families start right after the fixed slots");
_Static_assert(ENV_SLOT_CallNonvirtualObjectMethod == ENV_SLOT_CallStaticVoidMethod + 3,
               "the CallNonvirtual families start where the CallStaticVoid family ends");
_Static_assert(ENV_SLOT_GetObjectField == ENV_SLOT_CallNonvirtualVoidMethod + 3,
               "the field accessor block starts exactly where the last CallNonvirtual family ends");
_Static_assert(ENV_SLOT_SetStaticDoubleField == ENV_SLOT_GetObjectField + 35,
               "the field list must stay at 36 entries, one table entry each");

static pthread_mutex_t g_env_hook_lock = PTHREAD_MUTEX_INITIALIZER;
// Marks the current thread as running ADH instrumentation code (label resolution, class
// names, array-length reads). Only our own nested JNI calls are suppressed by it: the target's
// own call always runs with the flag clear, so Java->JNI callbacks made *inside* a hooked call
// are still observed. Setting it across the target call would silently hide that traffic.
static __thread int g_env_hook_in_ours = 0;

// ADH's own JNI work (class-name resolution, loader lookups, command paths) must not be recorded as
// target behaviour when the corresponding slots are hooked. Helpers that do such work set this flag
// around themselves; the enter/leave pair restores the previous value, so a helper called from inside
// a wrapper (where the flag is already set) behaves exactly like one called from a command path.
int adh_jni_ours_enter(void) {
    int previous = g_env_hook_in_ours;
    g_env_hook_in_ours = 1;
    return previous;
}

void adh_jni_ours_leave(int previous) {
    g_env_hook_in_ours = previous;
}
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

// ADH's own exception checks must NOT go through the (possibly hooked) table entry. If the
// ExceptionCheck slot is installed, every ADH-side call would otherwise be recorded as target
// behaviour - wrong attribution - and re-entering the wrapper from instrumentation paths is pure
// noise. The saved original is used once the slot has been installed, the live entry otherwise;
// both are the real function. Shared with the rest of the agent (jni_env_hooks.h) so no module
// has to remember this rule.
jboolean adh_jni_exception_check(JNIEnv *env) {
    if (!env || !(*env)->ExceptionCheck) return 0;
    jboolean (*original)(JNIEnv *) = (jboolean (*)(JNIEnv *))slot_original(ENV_SLOT_ExceptionCheck);
    if (original) return original(env) ? 1 : 0;
    return (*env)->ExceptionCheck(env) ? 1 : 0;
}

// ExceptionClear is a hookable table entry too: ADH clearing an exception it caused (or parking one
// while it resolves a name) must not look like target behaviour either.
void adh_jni_exception_clear(JNIEnv *env) {
    if (!env || !(*env)->ExceptionClear) return;
    void (*original)(JNIEnv *) = (void (*)(JNIEnv *))slot_original(ENV_SLOT_ExceptionClear);
    if (original) { original(env); return; }
    (*env)->ExceptionClear(env);
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
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
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
    } else if (adh_jni_exception_check(env)) {
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
    } else if (adh_jni_exception_check(env)) {
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
    } else if (result == NULL || adh_jni_exception_check(env)) {
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
    } else if (result == NULL || adh_jni_exception_check(env)) {
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
    if (env_budget_left(ENV_SLOT_GetByteArrayRegion) && !adh_jni_exception_check(env)) {
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
        if (g_env_hook_in_ours || !slot_active(BASE)) {                                        \
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
        if (g_env_hook_in_ours || !slot_active(BASE)) {                                        \
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

// ---- v4.76: CallNonvirtual* ----------------------------------------------------------------
// The caller passes the class explicitly, so the receiver's runtime class does not decide which
// implementation runs. That is worth a field of its own in the event: the label already says which
// member was called, " via=<class>" says which implementation the caller asked for.
static void callnv_add_via(JNIEnv *env, jclass clazz, struct AdhCallDetail *d) {
    if (!clazz || !d->text[0]) return;
    char cls[192];
    adh_jni_class_name(env, clazz, cls, sizeof(cls));
    size_t used = strlen(d->text);
    if (used + 8 < sizeof(d->text))
        snprintf(d->text + used, sizeof(d->text) - used, " via=%s", cls[0] ? cls : "?");
}

#define ADH_DEFINE_CALLNV_VALUE(NAME, RET, BASE)                                                   \
    static RET NAME##_wrapper(JNIEnv *env, jobject obj, jclass clazz, jmethodID mid, ...) {        \
        va_list ap;                                                                                \
        va_start(ap, mid);                                                                         \
        RET (*v_original)(JNIEnv *, jobject, jclass, jmethodID, va_list) =                          \
            (RET (*)(JNIEnv *, jobject, jclass, jmethodID, va_list))slot_original(BASE + 1);        \
        if (g_env_hook_in_ours || !slot_active(BASE)) {                                             \
            RET r = v_original ? v_original(env, obj, clazz, mid, ap)                               \
                               : (*env)->NAME##V(env, obj, clazz, mid, ap);                         \
            va_end(ap);                                                                             \
            return r;                                                                               \
        }                                                                                           \
        struct AdhCallDetail detail;                                                                \
        g_env_hook_in_ours = 1;                                                                     \
        call_detail_va(env, BASE, obj, ADH_MEMBER_INSTANCE, mid, ap, &detail);                      \
        callnv_add_via(env, clazz, &detail);                                                        \
        g_env_hook_in_ours = 0;                                                                     \
        RET result = v_original ? v_original(env, obj, clazz, mid, ap)                              \
                                : (*env)->NAME##V(env, obj, clazz, mid, ap);                        \
        va_end(ap);                                                                                 \
        call_emit(BASE, &detail);                                                                   \
        return result;                                                                              \
    }                                                                                               \
    static RET NAME##V_wrapper(JNIEnv *env, jobject obj, jclass clazz, jmethodID mid, va_list ap) {  \
        RET (*original)(JNIEnv *, jobject, jclass, jmethodID, va_list) =                            \
            (RET (*)(JNIEnv *, jobject, jclass, jmethodID, va_list))slot_original(BASE + 1);        \
        if (!original) return (RET)0;                                                               \
        if (g_env_hook_in_ours || !slot_active(BASE + 1))                                           \
            return original(env, obj, clazz, mid, ap);                                              \
        struct AdhCallDetail detail;                                                                \
        g_env_hook_in_ours = 1;                                                                     \
        call_detail_va(env, BASE + 1, obj, ADH_MEMBER_INSTANCE, mid, ap, &detail);                  \
        callnv_add_via(env, clazz, &detail);                                                        \
        g_env_hook_in_ours = 0;                                                                     \
        RET result = original(env, obj, clazz, mid, ap);                                            \
        call_emit(BASE + 1, &detail);                                                               \
        return result;                                                                              \
    }                                                                                               \
    static RET NAME##A_wrapper(JNIEnv *env, jobject obj, jclass clazz, jmethodID mid,               \
                               const jvalue *args) {                                                \
        RET (*original)(JNIEnv *, jobject, jclass, jmethodID, const jvalue *) =                     \
            (RET (*)(JNIEnv *, jobject, jclass, jmethodID, const jvalue *))slot_original(BASE + 2); \
        if (!original) return (RET)0;                                                               \
        if (g_env_hook_in_ours || !slot_active(BASE + 2))                                           \
            return original(env, obj, clazz, mid, args);                                            \
        struct AdhCallDetail detail;                                                                \
        g_env_hook_in_ours = 1;                                                                     \
        call_detail_a(env, BASE + 2, obj, ADH_MEMBER_INSTANCE, mid, args, &detail);                 \
        callnv_add_via(env, clazz, &detail);                                                        \
        g_env_hook_in_ours = 0;                                                                     \
        RET result = original(env, obj, clazz, mid, args);                                          \
        call_emit(BASE + 2, &detail);                                                               \
        return result;                                                                              \
    }

#define ADH_DEFINE_CALLNV_VOID(NAME, BASE)                                                         \
    static void NAME##_wrapper(JNIEnv *env, jobject obj, jclass clazz, jmethodID mid, ...) {       \
        va_list ap;                                                                                \
        va_start(ap, mid);                                                                         \
        void (*v_original)(JNIEnv *, jobject, jclass, jmethodID, va_list) =                        \
            (void (*)(JNIEnv *, jobject, jclass, jmethodID, va_list))slot_original(BASE + 1);       \
        if (g_env_hook_in_ours || !slot_active(BASE)) {                                            \
            if (v_original) v_original(env, obj, clazz, mid, ap);                                  \
            else (*env)->NAME##V(env, obj, clazz, mid, ap);                                        \
            va_end(ap);                                                                            \
            return;                                                                                \
        }                                                                                          \
        struct AdhCallDetail detail;                                                               \
        g_env_hook_in_ours = 1;                                                                    \
        call_detail_va(env, BASE, obj, ADH_MEMBER_INSTANCE, mid, ap, &detail);                     \
        callnv_add_via(env, clazz, &detail);                                                       \
        g_env_hook_in_ours = 0;                                                                    \
        if (v_original) v_original(env, obj, clazz, mid, ap);                                      \
        else (*env)->NAME##V(env, obj, clazz, mid, ap);                                            \
        va_end(ap);                                                                                \
        call_emit(BASE, &detail);                                                                  \
    }                                                                                              \
    static void NAME##V_wrapper(JNIEnv *env, jobject obj, jclass clazz, jmethodID mid, va_list ap) {\
        void (*original)(JNIEnv *, jobject, jclass, jmethodID, va_list) =                          \
            (void (*)(JNIEnv *, jobject, jclass, jmethodID, va_list))slot_original(BASE + 1);       \
        if (!original) return;                                                                     \
        if (g_env_hook_in_ours || !slot_active(BASE + 1)) { original(env, obj, clazz, mid, ap); return; } \
        struct AdhCallDetail detail;                                                               \
        g_env_hook_in_ours = 1;                                                                    \
        call_detail_va(env, BASE + 1, obj, ADH_MEMBER_INSTANCE, mid, ap, &detail);                 \
        callnv_add_via(env, clazz, &detail);                                                       \
        g_env_hook_in_ours = 0;                                                                    \
        original(env, obj, clazz, mid, ap);                                                        \
        call_emit(BASE + 1, &detail);                                                              \
    }                                                                                              \
    static void NAME##A_wrapper(JNIEnv *env, jobject obj, jclass clazz, jmethodID mid,             \
                                const jvalue *args) {                                              \
        void (*original)(JNIEnv *, jobject, jclass, jmethodID, const jvalue *) =                   \
            (void (*)(JNIEnv *, jobject, jclass, jmethodID, const jvalue *))slot_original(BASE + 2);\
        if (!original) return;                                                                     \
        if (g_env_hook_in_ours || !slot_active(BASE + 2)) { original(env, obj, clazz, mid, args); return; } \
        struct AdhCallDetail detail;                                                               \
        g_env_hook_in_ours = 1;                                                                    \
        call_detail_a(env, BASE + 2, obj, ADH_MEMBER_INSTANCE, mid, args, &detail);                \
        callnv_add_via(env, clazz, &detail);                                                       \
        g_env_hook_in_ours = 0;                                                                    \
        original(env, obj, clazz, mid, args);                                                      \
        call_emit(BASE + 2, &detail);                                                              \
    }

// The family list carries (name, ret, target, kind, base, spec); the NV wrappers need only
// (name, ret, base) because the extra jclass is fixed by the JNI signature.
#define ADH_DEFINE_CALLNV_VALUE_ENTRY(name, ret, tgt, kind, base, spec) ADH_DEFINE_CALLNV_VALUE(name, ret, base)
#define ADH_DEFINE_CALLNV_VOID_ENTRY(name, tgt, kind, base, spec) ADH_DEFINE_CALLNV_VOID(name, base)

ADH_CALLNV_VALUE_FAMILIES(ADH_DEFINE_CALLNV_VALUE_ENTRY)
ADH_CALLNV_VOID_FAMILIES(ADH_DEFINE_CALLNV_VOID_ENTRY)

#define ADH_CALL_ASSERT_3(name)                                                                 \
    _Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->name), \
                   __typeof__(&name##_wrapper)), "family wrapper signature mismatch");          \
    _Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->name##V), \
                   __typeof__(&name##V_wrapper)), "family V wrapper signature mismatch");       \
    _Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->name##A), \
                   __typeof__(&name##A_wrapper)), "family A wrapper signature mismatch");

// Every Call* / CallNonvirtual* family gets the same compile-time proof the fixed slots, the field
// accessors and the array families already have: the wrappers are cast to void* at install time, so a
// signature mismatch would only surface when the target calls the entry.
#define ADH_CALL_ASSERT_VALUE(name, ret, tgt, kind, base, spec) ADH_CALL_ASSERT_3(name)
#define ADH_CALL_ASSERT_VOID(name, tgt, kind, base, spec) ADH_CALL_ASSERT_3(name)
ADH_CALL_VALUE_FAMILIES(ADH_CALL_ASSERT_VALUE)
ADH_CALL_VOID_FAMILIES(ADH_CALL_ASSERT_VOID)
ADH_CALLNV_VALUE_FAMILIES(ADH_CALL_ASSERT_VALUE)
ADH_CALLNV_VOID_FAMILIES(ADH_CALL_ASSERT_VOID)

// ---- layout self-check ----------------------------------------------------
// The enum values ARE the table indices (name lookup returns a table position and every switch is
// keyed by the enum), so a drift between the two installs the NEIGHBOURING entry while the reply
// still shows the requested name - exactly how the field family looked installed for months. This
// mapping is generated from the same lists that build the enum and the table; comparing the two
// turns any such drift into a refusal instead of a hook on the wrong function.
#define ADH_ENUM_NAME_CASE(name) case ENV_SLOT_##name: return #name;
#define ADH_FAMILY_NAME_CASES(name, ret, tgt, kind, base, spec) \
    case base: return #name; case base + 1: return #name "V"; case base + 2: return #name "A";
#define ADH_FAMILY_VOID_NAME_CASES(name, tgt, kind, base, spec) \
    ADH_FAMILY_NAME_CASES(name, void, tgt, kind, base, spec)

static const char *env_slot_name(int index) {
    switch (index) {
        ADH_FIXED_SLOT_LIST(ADH_ENUM_NAME_CASE)
        ADH_CALL_VALUE_FAMILIES(ADH_FAMILY_NAME_CASES)
        ADH_CALL_VOID_FAMILIES(ADH_FAMILY_VOID_NAME_CASES)
        ADH_CALLNV_VALUE_FAMILIES(ADH_FAMILY_NAME_CASES)
        ADH_CALLNV_VOID_FAMILIES(ADH_FAMILY_VOID_NAME_CASES)
        ADH_FIELD_SLOT_LIST(ADH_ENUM_NAME_CASE)
        default: return NULL;
    }
}

static int env_hook_layout_ok(char *error, size_t error_size) {
    for (int i = 0; i < ENV_HOOK_MAX; i++) {
        const char *expect = env_slot_name(i);
        if (!expect || strcmp(expect, g_env_hooks[i].name) != 0) {
            snprintf(error, error_size,
                     "JNIEnv slot table layout mismatch at %d: the enum names it %s, the table has %s - refusing to patch anything",
                     i, expect ? expect : "(none)", g_env_hooks[i].name);
            return 0;
        }
    }
    return 1;
}

static int g_env_layout_state = 0;              // 0 = unchecked, 1 = ok, -1 = mismatch
static char g_env_layout_error[224];

static int env_hook_layout_ready(char *error, size_t error_size) {
    int state = __atomic_load_n(&g_env_layout_state, __ATOMIC_ACQUIRE);
    if (state == 0) {
        int ok = env_hook_layout_ok(g_env_layout_error, sizeof(g_env_layout_error));
        __atomic_store_n(&g_env_layout_state, ok ? 1 : -1, __ATOMIC_RELEASE);
        state = ok ? 1 : -1;
    }
    if (state < 0) { snprintf(error, error_size, "%s", g_env_layout_error); return 0; }
    return 1;
}


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
    int failed = adh_jni_exception_check(env) ? 1 : 0;
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
    int failed = adh_jni_exception_check(env) ? 1 : 0;
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
    // Length first, while we may still call other entries: the JNI spec promises neither that the
    // buffer we are about to receive is NUL-terminated nor any particular layout, so the preview is
    // bounded by the real element count instead of by a terminator we would be guessing at.
    // The query itself must not look like target behaviour (and must not leave an exception behind
    // if the string is bogus - our clear only removes the copy our own query produced).
    int str_len = -1;
    if (str && env_budget_left(ENV_SLOT_GetStringChars) && !adh_jni_exception_check(env)) {
        g_env_hook_in_ours = 1;
        str_len = (int)(*env)->GetStringLength(env, str);
        g_env_hook_in_ours = 0;
        if (adh_jni_exception_check(env)) { adh_jni_exception_clear(env); str_len = -1; }
    }
    g_env_hook_in_ours = 1;
    const jchar *chars = original(env, str, is_copy);
    int failed = adh_jni_exception_check(env) ? 1 : 0;   // never read a pointer a failed call returned
    char detail[220]; detail[0] = 0;
    if (failed) {
        snprintf(detail, sizeof(detail), "string=%p <pin failed>", (void *)str);
    } else if (env_budget_left(ENV_SLOT_GetStringChars)) {
        char preview[80] = "";
        if (chars) {
            size_t p = 0;
            for (int i = 0; i < 24 && i < str_len && p + 2 < sizeof(preview); i++) {
                jchar c = chars[i];
                if (c == 0) break;                       // stop at an embedded NUL as well
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

// v4.77: string construction and the two length queries. NewString's input is the caller's own
// buffer, so a bounded preview of it costs nothing and shows what the target built.
static jstring NewString_wrapper(JNIEnv *env, const jchar *unicode, jsize len) {
    typedef jstring (JNICALL *fn_t)(JNIEnv *, const jchar *, jsize);
    fn_t original = (fn_t)slot_original(ENV_SLOT_NewString);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_NewString)) return original(env, unicode, len);
    jstring result = original(env, unicode, len);
    int failed = adh_jni_exception_check(env) ? 1 : 0;
    char detail[220]; detail[0] = 0;
    if (failed) snprintf(detail, sizeof(detail), "len=%d <call failed>", (int)len);
    else if (env_budget_left(ENV_SLOT_NewString)) {
        char preview[80] = "";
        if (unicode && len > 0) {
            size_t p = 0;
            for (jsize i = 0; i < len && i < 24 && p + 2 < sizeof(preview); i++)
                preview[p++] = (unicode[i] >= 0x20 && unicode[i] < 0x7f) ? (char)unicode[i] : '.';
            preview[p] = 0;
        }
        snprintf(detail, sizeof(detail), "len=%d text=\"%s\" -> %p", (int)len, preview, (void *)result);
    }
    env_note(ENV_SLOT_NewString, detail[0] ? detail : NULL, !failed && result != NULL);
    return result;
}

#define ADH_DEFINE_STRING_LENGTH(JNI_NAME)                                                      \
static jsize JNI_NAME##_wrapper(JNIEnv *env, jstring str) {                                     \
    typedef jsize (JNICALL *fn_t)(JNIEnv *, jstring);                                           \
    fn_t original = (fn_t)slot_original(ENV_SLOT_##JNI_NAME);                                   \
    if (!original) return 0;                                                                    \
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_##JNI_NAME)) return original(env, str);     \
    jsize len = original(env, str);                                                             \
    int failed = adh_jni_exception_check(env) ? 1 : 0;                                           \
    char detail[128]; detail[0] = 0;                                                            \
    if (failed) snprintf(detail, sizeof(detail), "string=%p <call failed>", (void *)str);       \
    else if (env_budget_left(ENV_SLOT_##JNI_NAME))                                              \
        snprintf(detail, sizeof(detail), "string=%p len=%d", (void *)str, (int)len);            \
    env_note(ENV_SLOT_##JNI_NAME, detail[0] ? detail : NULL, !failed);                          \
    return len;                                                                                 \
}

ADH_DEFINE_STRING_LENGTH(GetStringLength)
ADH_DEFINE_STRING_LENGTH(GetStringUTFLength)

static void ReleaseStringUTFChars_wrapper(JNIEnv *env, jstring str, const char *utf) {
    typedef void (JNICALL *fn_t)(JNIEnv *, jstring, const char *);
    fn_t original = (fn_t)slot_original(ENV_SLOT_ReleaseStringUTFChars);
    if (!original) return;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_ReleaseStringUTFChars)) {
        original(env, str, utf);
        return;
    }
    if (env_budget_left(ENV_SLOT_ReleaseStringUTFChars)) {
        char detail[128];
        snprintf(detail, sizeof(detail), "string=%p chars=%p", (void *)str, (const void *)utf);
        original(env, str, utf);
        env_note(ENV_SLOT_ReleaseStringUTFChars, detail, 1);
    } else {
        original(env, str, utf);
        env_note(ENV_SLOT_ReleaseStringUTFChars, NULL, 1);
    }
}

// GetStringCritical hands out a pinned pointer that must be released before ANY other JNI call, so
// this wrapper does not call ExceptionCheck/GetStringLength after it (that would break the critical
// section the target just entered): a NULL result is the only failure signal it needs, and the
// preview is a bounded read of the buffer that is already in hand. The same rule makes
// ReleaseStringCritical a plain pair of pointers.
static const jchar *GetStringCritical_wrapper(JNIEnv *env, jstring str, jboolean *is_copy) {
    typedef const jchar *(JNICALL *fn_t)(JNIEnv *, jstring, jboolean *);
    fn_t original = (fn_t)slot_original(ENV_SLOT_GetStringCritical);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetStringCritical)) return original(env, str, is_copy);
    // The length has to come BEFORE the pin: once GetStringCritical has run we are inside the
    // critical section and may not call another JNI function. That is also the only safe way to
    // bound the preview - the spec does not promise the pinned buffer is NUL-terminated.
    int str_len = -1;
    if (str && env_budget_left(ENV_SLOT_GetStringCritical) && !adh_jni_exception_check(env)) {
        g_env_hook_in_ours = 1;
        str_len = (int)(*env)->GetStringLength(env, str);
        g_env_hook_in_ours = 0;
        if (adh_jni_exception_check(env)) { adh_jni_exception_clear(env); str_len = -1; }
    }
    const jchar *chars = original(env, str, is_copy);
    char detail[220]; detail[0] = 0;
    if (!chars) {
        snprintf(detail, sizeof(detail), "string=%p <pin failed>", (void *)str);
    } else if (env_budget_left(ENV_SLOT_GetStringCritical)) {
        char preview[80] = "";
        size_t p = 0;
        for (int i = 0; i < 24 && i < str_len && p + 2 < sizeof(preview); i++) {
            jchar c = chars[i];
            if (c == 0) break;                       // stop at an embedded NUL as well
            preview[p++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
        }
        preview[p] = 0;
        snprintf(detail, sizeof(detail), "string=%p isCopy=%s text=\"%s\"",
                 (void *)str, (is_copy && *is_copy) ? "true" : "false", preview);
    }
    env_note(ENV_SLOT_GetStringCritical, detail[0] ? detail : NULL, chars != NULL);
    return chars;
}

static void ReleaseStringCritical_wrapper(JNIEnv *env, jstring str, const jchar *cstring) {
    typedef void (JNICALL *fn_t)(JNIEnv *, jstring, const jchar *);
    fn_t original = (fn_t)slot_original(ENV_SLOT_ReleaseStringCritical);
    if (!original) return;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_ReleaseStringCritical)) {
        original(env, str, cstring);
        return;
    }
    char detail[128]; detail[0] = 0;
    if (env_budget_left(ENV_SLOT_ReleaseStringCritical))
        snprintf(detail, sizeof(detail), "string=%p chars=%p", (void *)str, (const void *)cstring);
    original(env, str, cstring);
    env_note(ENV_SLOT_ReleaseStringCritical, detail[0] ? detail : NULL, 1);
}

// v4.78: the reflection bridge. The id in the event is the join key: the host already turns ids
// into Class#name:sig from the GetMethodID/GetFieldID events, so a reflected call site stops being
// invisible without this wrapper having to resolve a member name itself.
static jmethodID FromReflectedMethod_wrapper(JNIEnv *env, jobject method) {
    typedef jmethodID (JNICALL *fn_t)(JNIEnv *, jobject);
    fn_t original = (fn_t)slot_original(ENV_SLOT_FromReflectedMethod);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_FromReflectedMethod)) return original(env, method);
    jmethodID mid = original(env, method);
    int failed = adh_jni_exception_check(env) ? 1 : 0;
    char detail[160]; detail[0] = 0;
    if (failed) snprintf(detail, sizeof(detail), "reflect=%p <call failed>", (void *)method);
    else if (env_budget_left(ENV_SLOT_FromReflectedMethod))
        snprintf(detail, sizeof(detail), "reflect=%p -> mid=%p", (void *)method, (void *)mid);
    env_note(ENV_SLOT_FromReflectedMethod, detail[0] ? detail : NULL, !failed);
    return mid;
}

static jfieldID FromReflectedField_wrapper(JNIEnv *env, jobject field) {
    typedef jfieldID (JNICALL *fn_t)(JNIEnv *, jobject);
    fn_t original = (fn_t)slot_original(ENV_SLOT_FromReflectedField);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_FromReflectedField)) return original(env, field);
    jfieldID fid = original(env, field);
    int failed = adh_jni_exception_check(env) ? 1 : 0;
    char detail[160]; detail[0] = 0;
    if (failed) snprintf(detail, sizeof(detail), "reflect=%p <call failed>", (void *)field);
    else if (env_budget_left(ENV_SLOT_FromReflectedField))
        snprintf(detail, sizeof(detail), "reflect=%p -> fid=%p", (void *)field, (void *)fid);
    env_note(ENV_SLOT_FromReflectedField, detail[0] ? detail : NULL, !failed);
    return fid;
}

static jobject ToReflectedMethod_wrapper(JNIEnv *env, jclass clazz, jmethodID mid, jboolean is_static) {
    typedef jobject (JNICALL *fn_t)(JNIEnv *, jclass, jmethodID, jboolean);
    fn_t original = (fn_t)slot_original(ENV_SLOT_ToReflectedMethod);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_ToReflectedMethod))
        return original(env, clazz, mid, is_static);
    jobject result = original(env, clazz, mid, is_static);
    int failed = adh_jni_exception_check(env) ? 1 : 0;
    char detail[320]; detail[0] = 0;
    if (failed) snprintf(detail, sizeof(detail), "mid=%p <call failed>", (void *)mid);
    else if (env_budget_left(ENV_SLOT_ToReflectedMethod)) {
        char cls[192];
        g_env_hook_in_ours = 1;
        adh_jni_class_name(env, clazz, cls, sizeof(cls));
        g_env_hook_in_ours = 0;
        snprintf(detail, sizeof(detail), "class=%s mid=%p static=%d -> %p",
                 cls[0] ? cls : "?", (void *)mid, is_static ? 1 : 0, (void *)result);
    }
    env_note(ENV_SLOT_ToReflectedMethod, detail[0] ? detail : NULL, !failed && result != NULL);
    return result;
}

static jobject ToReflectedField_wrapper(JNIEnv *env, jclass clazz, jfieldID fid, jboolean is_static) {
    typedef jobject (JNICALL *fn_t)(JNIEnv *, jclass, jfieldID, jboolean);
    fn_t original = (fn_t)slot_original(ENV_SLOT_ToReflectedField);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_ToReflectedField))
        return original(env, clazz, fid, is_static);
    jobject result = original(env, clazz, fid, is_static);
    int failed = adh_jni_exception_check(env) ? 1 : 0;
    char detail[320]; detail[0] = 0;
    if (failed) snprintf(detail, sizeof(detail), "fid=%p <call failed>", (void *)fid);
    else if (env_budget_left(ENV_SLOT_ToReflectedField)) {
        char cls[192];
        g_env_hook_in_ours = 1;
        adh_jni_class_name(env, clazz, cls, sizeof(cls));
        g_env_hook_in_ours = 0;
        snprintf(detail, sizeof(detail), "class=%s fid=%p static=%d -> %p",
                 cls[0] ? cls : "?", (void *)fid, is_static ? 1 : 0, (void *)result);
    }
    env_note(ENV_SLOT_ToReflectedField, detail[0] ? detail : NULL, !failed && result != NULL);
    return result;
}

// Returns 0 when the class' native bindings were dropped; anything else (or a throw) is a failure.
static jint UnregisterNatives_wrapper(JNIEnv *env, jclass clazz) {
    typedef jint (JNICALL *fn_t)(JNIEnv *, jclass);
    fn_t original = (fn_t)slot_original(ENV_SLOT_UnregisterNatives);
    if (!original) return -1;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_UnregisterNatives)) return original(env, clazz);
    jint result = original(env, clazz);
    int failed = adh_jni_exception_check(env) ? 1 : 0;
    char detail[320]; detail[0] = 0;
    if (failed) snprintf(detail, sizeof(detail), "class=%p <call failed>", (void *)clazz);
    else if (env_budget_left(ENV_SLOT_UnregisterNatives)) {
        char cls[192];
        g_env_hook_in_ours = 1;
        adh_jni_class_name(env, clazz, cls, sizeof(cls));
        g_env_hook_in_ours = 0;
        snprintf(detail, sizeof(detail), "class=%s -> %d", cls[0] ? cls : "?", (int)result);
    }
    env_note(ENV_SLOT_UnregisterNatives, detail[0] ? detail : NULL, !failed && result == 0);
    return result;
}

// v4.79: FatalError is the VM's last word before the process goes down and (per the JNI spec) it
// never returns, so there is no "after the call" - the message is the argument and the event is
// written first. Caveat worth stating: the capture ring is drained by the host loop and the process
// may die before that happens, so this event is best effort.
static void FatalError_wrapper(JNIEnv *env, const char *msg) {
    typedef void (JNICALL *fn_t)(JNIEnv *, const char *);
    fn_t original = (fn_t)slot_original(ENV_SLOT_FatalError);
    if (!original) return;
    if (!g_env_hook_in_ours && slot_active(ENV_SLOT_FatalError)) {
        char bounded[160] = "";
        if (msg) {
            size_t n = strnlen(msg, sizeof(bounded) - 1);
            memcpy(bounded, msg, n);
            bounded[n] = 0;
        }
        char detail[200];
        snprintf(detail, sizeof(detail), "msg=\"%s\"", bounded);
        env_note(ENV_SLOT_FatalError, detail, 1);
    }
    original(env, msg);
}

// v4.79: the target's own ExceptionCheck - the signal that says "this code path expects a throwable
// here". ADH's instrumentation never reaches this wrapper (adh_jni_exception_check() uses the saved
// original), so what is recorded is the target's behaviour. It is also the hottest entry in the
// table, so install it deliberately: the per-slot budget caps the events at ENV_EVENT_LIMIT and the
// slot keeps counting hits/dropped afterwards.
static jboolean ExceptionCheck_wrapper(JNIEnv *env) {
    typedef jboolean (JNICALL *fn_t)(JNIEnv *);
    fn_t original = (fn_t)slot_original(ENV_SLOT_ExceptionCheck);
    if (!original) return JNI_FALSE;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_ExceptionCheck)) return original(env);
    jboolean pending = original(env);
    if (env_budget_left(ENV_SLOT_ExceptionCheck))
        env_note(ENV_SLOT_ExceptionCheck, pending ? "pending=true" : "pending=false", 1);
    else
        env_note(ENV_SLOT_ExceptionCheck, NULL, 1);
    return pending;
}

// Compile-time type check: the last two entries must match theirs exactly too.
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->FatalError), __typeof__(&FatalError_wrapper)), "FatalError_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->ExceptionCheck), __typeof__(&ExceptionCheck_wrapper)), "ExceptionCheck_wrapper signature mismatch");

// Compile-time type check: the reflection bridge and UnregisterNatives must match their entries.
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->FromReflectedMethod), __typeof__(&FromReflectedMethod_wrapper)), "FromReflectedMethod_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->FromReflectedField), __typeof__(&FromReflectedField_wrapper)), "FromReflectedField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->ToReflectedMethod), __typeof__(&ToReflectedMethod_wrapper)), "ToReflectedMethod_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->ToReflectedField), __typeof__(&ToReflectedField_wrapper)), "ToReflectedField_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->UnregisterNatives), __typeof__(&UnregisterNatives_wrapper)), "UnregisterNatives_wrapper signature mismatch");

// Compile-time type check: the six new string wrappers must match their table entries exactly.
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->NewString), __typeof__(&NewString_wrapper)), "NewString_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetStringLength), __typeof__(&GetStringLength_wrapper)), "GetStringLength_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetStringUTFLength), __typeof__(&GetStringUTFLength_wrapper)), "GetStringUTFLength_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->ReleaseStringUTFChars), __typeof__(&ReleaseStringUTFChars_wrapper)), "ReleaseStringUTFChars_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetStringCritical), __typeof__(&GetStringCritical_wrapper)), "GetStringCritical_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->ReleaseStringCritical), __typeof__(&ReleaseStringCritical_wrapper)), "ReleaseStringCritical_wrapper signature mismatch");

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
        if (!adh_jni_exception_check(env) && obj) {
            jclass c = (*env)->GetObjectClass(env, obj);
            if (c) adh_jni_class_name(env, c, cls, sizeof(cls));
            if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
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
        if (!adh_jni_exception_check(env) && clazz) {
            adh_jni_class_name(env, clazz, cls, sizeof(cls));
            if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
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
    if (env_budget_left(ENV_SLOT_GetSuperclass) && !adh_jni_exception_check(env)) {
        char a[96] = "", b[96] = "";
        if (clazz) adh_jni_class_name(env, clazz, a, sizeof(a));
        if (sup) adh_jni_class_name(env, sup, b, sizeof(b));
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
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
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
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
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
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
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
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
    int failed = adh_jni_exception_check(env) ? 1 : 0;                                        \
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
    int failed = adh_jni_exception_check(env) ? 1 : 0;                                            \
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
        if (arr && !adh_jni_exception_check(env)) {                                               \
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

// ---- v4.75: creation, length, object arrays and AllocObject --------------------------------
// The eight primitive array constructors share one shape (len in, array out). A length that is
// rejected (negative) throws, and so does an allocation failure - both are reported as failed
// rather than as a mysterious 0x0 result.
#define ADH_DEFINE_NEW_ARRAY(JNI_NAME)                                                      \
static jobject JNI_NAME##_wrapper(JNIEnv *env, jsize len) {                                 \
    typedef jobject (JNICALL *fn_t)(JNIEnv *, jsize);                                       \
    fn_t original = (fn_t)slot_original(ENV_SLOT_##JNI_NAME);                               \
    if (!original) return NULL;                                                             \
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_##JNI_NAME)) return original(env, len); \
    jobject result = original(env, len);                                                    \
    int failed = adh_jni_exception_check(env) ? 1 : 0;                                       \
    char detail[128]; detail[0] = 0;                                                        \
    if (failed) snprintf(detail, sizeof(detail), "len=%d <call failed>", (int)len);         \
    else if (env_budget_left(ENV_SLOT_##JNI_NAME))                                          \
        snprintf(detail, sizeof(detail), "len=%d -> %p", (int)len, (void *)result);         \
    env_note(ENV_SLOT_##JNI_NAME, detail[0] ? detail : NULL, !failed && result != NULL);    \
    return result;                                                                          \
}

ADH_DEFINE_NEW_ARRAY(NewBooleanArray)
ADH_DEFINE_NEW_ARRAY(NewByteArray)
ADH_DEFINE_NEW_ARRAY(NewCharArray)
ADH_DEFINE_NEW_ARRAY(NewShortArray)
ADH_DEFINE_NEW_ARRAY(NewIntArray)
ADH_DEFINE_NEW_ARRAY(NewLongArray)
ADH_DEFINE_NEW_ARRAY(NewFloatArray)
ADH_DEFINE_NEW_ARRAY(NewDoubleArray)

static jsize GetArrayLength_wrapper(JNIEnv *env, jarray arr) {
    typedef jsize (JNICALL *fn_t)(JNIEnv *, jarray);
    fn_t original = (fn_t)slot_original(ENV_SLOT_GetArrayLength);
    if (!original) return 0;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetArrayLength)) return original(env, arr);
    jsize len = original(env, arr);
    int failed = adh_jni_exception_check(env) ? 1 : 0;
    char detail[128]; detail[0] = 0;
    if (failed) snprintf(detail, sizeof(detail), "array=%p <call failed>", (void *)arr);
    else if (env_budget_left(ENV_SLOT_GetArrayLength))
        snprintf(detail, sizeof(detail), "array=%p len=%d", (void *)arr, (int)len);
    env_note(ENV_SLOT_GetArrayLength, detail[0] ? detail : NULL, !failed);
    return len;
}

static jobject NewObjectArray_wrapper(JNIEnv *env, jsize len, jclass elem_class, jobject initial) {
    typedef jobject (JNICALL *fn_t)(JNIEnv *, jsize, jclass, jobject);
    fn_t original = (fn_t)slot_original(ENV_SLOT_NewObjectArray);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_NewObjectArray))
        return original(env, len, elem_class, initial);
    jobject result = original(env, len, elem_class, initial);
    int failed = adh_jni_exception_check(env) ? 1 : 0;
    char detail[320]; detail[0] = 0;
    if (failed) snprintf(detail, sizeof(detail), "len=%d <call failed>", (int)len);
    else if (env_budget_left(ENV_SLOT_NewObjectArray)) {
        char cls[192];
        g_env_hook_in_ours = 1;
        adh_jni_class_name(env, elem_class, cls, sizeof(cls));
        g_env_hook_in_ours = 0;
        snprintf(detail, sizeof(detail), "len=%d elem=%s initial=%p -> %p",
                 (int)len, cls[0] ? cls : "?", (void *)initial, (void *)result);
    }
    env_note(ENV_SLOT_NewObjectArray, detail[0] ? detail : NULL, !failed && result != NULL);
    return result;
}

// A NULL element is legal (it is just a null entry), so ok tracks the exception state and the text
// says which of the two it was - an out-of-range index throws and must not look like a null read.
static jobject GetObjectArrayElement_wrapper(JNIEnv *env, jobjectArray arr, jsize index) {
    typedef jobject (JNICALL *fn_t)(JNIEnv *, jobjectArray, jsize);
    fn_t original = (fn_t)slot_original(ENV_SLOT_GetObjectArrayElement);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_GetObjectArrayElement))
        return original(env, arr, index);
    jobject result = original(env, arr, index);
    int failed = adh_jni_exception_check(env) ? 1 : 0;
    char detail[192]; detail[0] = 0;
    if (failed) snprintf(detail, sizeof(detail), "array=%p index=%d <call failed>", (void *)arr, (int)index);
    else if (env_budget_left(ENV_SLOT_GetObjectArrayElement))
        snprintf(detail, sizeof(detail), "array=%p index=%d -> %p%s",
                 (void *)arr, (int)index, (void *)result, result ? "" : " (null element)");
    env_note(ENV_SLOT_GetObjectArrayElement, detail[0] ? detail : NULL, !failed);
    return result;
}

static void SetObjectArrayElement_wrapper(JNIEnv *env, jobjectArray arr, jsize index, jobject value) {
    typedef void (JNICALL *fn_t)(JNIEnv *, jobjectArray, jsize, jobject);
    fn_t original = (fn_t)slot_original(ENV_SLOT_SetObjectArrayElement);
    if (!original) return;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_SetObjectArrayElement)) {
        original(env, arr, index, value);
        return;
    }
    original(env, arr, index, value);
    int failed = adh_jni_exception_check(env) ? 1 : 0;
    char detail[192]; detail[0] = 0;
    if (failed) snprintf(detail, sizeof(detail), "array=%p index=%d value=%p <call failed>",
                         (void *)arr, (int)index, (void *)value);
    else if (env_budget_left(ENV_SLOT_SetObjectArrayElement))
        snprintf(detail, sizeof(detail), "array=%p index=%d value=%p",
                 (void *)arr, (int)index, (void *)value);
    env_note(ENV_SLOT_SetObjectArrayElement, detail[0] ? detail : NULL, !failed);
}

static jobject AllocObject_wrapper(JNIEnv *env, jclass clazz) {
    typedef jobject (JNICALL *fn_t)(JNIEnv *, jclass);
    fn_t original = (fn_t)slot_original(ENV_SLOT_AllocObject);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_AllocObject)) return original(env, clazz);
    jobject result = original(env, clazz);
    int failed = adh_jni_exception_check(env) ? 1 : 0;
    char detail[320]; detail[0] = 0;
    if (failed) snprintf(detail, sizeof(detail), "class=%p <call failed>", (void *)clazz);
    else if (env_budget_left(ENV_SLOT_AllocObject)) {
        char cls[192];
        g_env_hook_in_ours = 1;
        adh_jni_class_name(env, clazz, cls, sizeof(cls));
        g_env_hook_in_ours = 0;
        snprintf(detail, sizeof(detail), "class=%s -> %p", cls[0] ? cls : "?", (void *)result);
    }
    env_note(ENV_SLOT_AllocObject, detail[0] ? detail : NULL, !failed && result != NULL);
    return result;
}

// Compile-time type check: each wrapper must have exactly its table entry signature.
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->AllocObject), __typeof__(&AllocObject_wrapper)), "AllocObject_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetArrayLength), __typeof__(&GetArrayLength_wrapper)), "GetArrayLength_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->NewObjectArray), __typeof__(&NewObjectArray_wrapper)), "NewObjectArray_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->GetObjectArrayElement), __typeof__(&GetObjectArrayElement_wrapper)), "GetObjectArrayElement_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->SetObjectArrayElement), __typeof__(&SetObjectArrayElement_wrapper)), "SetObjectArrayElement_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->NewBooleanArray), __typeof__(&NewBooleanArray_wrapper)), "NewBooleanArray_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->NewByteArray), __typeof__(&NewByteArray_wrapper)), "NewByteArray_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->NewCharArray), __typeof__(&NewCharArray_wrapper)), "NewCharArray_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->NewShortArray), __typeof__(&NewShortArray_wrapper)), "NewShortArray_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->NewIntArray), __typeof__(&NewIntArray_wrapper)), "NewIntArray_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->NewLongArray), __typeof__(&NewLongArray_wrapper)), "NewLongArray_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->NewFloatArray), __typeof__(&NewFloatArray_wrapper)), "NewFloatArray_wrapper signature mismatch");
_Static_assert(__builtin_types_compatible_p(__typeof__(((struct JNINativeInterface *)0)->NewDoubleArray), __typeof__(&NewDoubleArray_wrapper)), "NewDoubleArray_wrapper signature mismatch");
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
        ADH_CALLNV_VALUE_FAMILIES(ADH_CALL_GUARD_CASES)
        ADH_CALLNV_VOID_FAMILIES(ADH_CALL_VOID_GUARD_CASES)
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
        // v4.75: creation / length / object arrays / AllocObject.
        case ENV_SLOT_AllocObject: return 27;
        case ENV_SLOT_GetArrayLength: return 171;
        case ENV_SLOT_NewObjectArray: return 172;
        case ENV_SLOT_GetObjectArrayElement: return 173;
        case ENV_SLOT_SetObjectArrayElement: return 174;
        case ENV_SLOT_NewBooleanArray: return 175;
        case ENV_SLOT_NewByteArray: return 176;
        case ENV_SLOT_NewCharArray: return 177;
        case ENV_SLOT_NewShortArray: return 178;
        case ENV_SLOT_NewIntArray: return 179;
        case ENV_SLOT_NewLongArray: return 180;
        case ENV_SLOT_NewFloatArray: return 181;
        case ENV_SLOT_NewDoubleArray: return 182;
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
        // v4.77: the rest of the string family.
        case ENV_SLOT_NewString: return 163;
        case ENV_SLOT_GetStringLength: return 164;
        case ENV_SLOT_GetStringUTFLength: return 168;
        case ENV_SLOT_ReleaseStringUTFChars: return 170;
        case ENV_SLOT_GetStringCritical: return 224;
        case ENV_SLOT_ReleaseStringCritical: return 225;
        // v4.78: reflection bridge + UnregisterNatives.
        case ENV_SLOT_FromReflectedMethod: return 7;
        case ENV_SLOT_FromReflectedField: return 8;
        case ENV_SLOT_ToReflectedMethod: return 9;
        case ENV_SLOT_ToReflectedField: return 12;
        case ENV_SLOT_UnregisterNatives: return 216;
        // v4.79: the last two.
        case ENV_SLOT_FatalError: return 18;
        case ENV_SLOT_ExceptionCheck: return 228;
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
        ADH_FIXED_SLOT_LIST(ADH_FIXED_SLOT_CASE)
        ADH_FIELD_SLOT_LIST(ADH_FIELD_SLOT_CASE)
        ADH_CALL_VALUE_FAMILIES(ADH_CALL_SLOT_CASES)
        ADH_CALL_VOID_FAMILIES(ADH_CALL_VOID_SLOT_CASES)
        ADH_CALLNV_VALUE_FAMILIES(ADH_CALL_SLOT_CASES)
        ADH_CALLNV_VOID_FAMILIES(ADH_CALL_VOID_SLOT_CASES)
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
        ADH_FIXED_SLOT_LIST(ADH_FIXED_WRAPPER_CASE)
        ADH_FIELD_SLOT_LIST(ADH_FIELD_WRAPPER_CASE)
        ADH_CALL_VALUE_FAMILIES(ADH_CALL_WRAPPER_CASES)
        ADH_CALL_VOID_FAMILIES(ADH_CALL_VOID_WRAPPER_CASES)
        ADH_CALLNV_VALUE_FAMILIES(ADH_CALL_WRAPPER_CASES)
        ADH_CALLNV_VOID_FAMILIES(ADH_CALL_VOID_WRAPPER_CASES)
        default: return NULL;
    }
}

// ---- command handling -----------------------------------------------------

// ---- slot filters ---------------------------------------------------------
// `function` doubles as a pattern for action:status, with the same language the install path uses
// (exact name, prefix, "*suffix", "*contains*", "all"/"*") plus the keyword "installed" for the
// slots that are hooked right now. One parser for both paths, so they cannot drift apart.
struct EnvNameFilter {
    const char *pat;
    size_t pat_len;
    int wildcard;
    int suffix_only;
    int contains;
    int installed_only;
};

static void env_filter_parse(const char *function, struct EnvNameFilter *f) {
    memset(f, 0, sizeof(*f));
    f->pat = function ? function : "";
    f->pat_len = strlen(f->pat);
    if (f->pat_len && strcmp(f->pat, "installed") == 0) {
        f->wildcard = 1;
        f->installed_only = 1;
        f->pat = "";
        f->pat_len = 0;
        return;
    }
    if (f->pat_len == 0 || strcmp(f->pat, "all") == 0 || strcmp(f->pat, "*") == 0) {
        f->wildcard = 1;
        f->pat = "";
        f->pat_len = 0;
        return;
    }
    if (f->pat[0] == '*') {
        f->wildcard = 1;
        f->pat++;
        f->pat_len--;
        if (f->pat_len && f->pat[f->pat_len - 1] == '*') { f->contains = 1; f->pat_len--; }
        else f->suffix_only = 1;
    } else if (f->pat[f->pat_len - 1] == '*') {
        f->wildcard = 1;
        f->pat_len--;
    }
}

static int env_filter_match(const struct EnvNameFilter *f, const char *name) {
    if (!f->wildcard) return strcmp(name, f->pat) == 0;
    if (f->pat_len == 0) return 1;                                  // all / * / installed
    size_t nlen = strlen(name);
    if (f->suffix_only) return nlen >= f->pat_len && strncmp(name + nlen - f->pat_len, f->pat, f->pat_len) == 0;
    if (f->contains) {
        for (size_t o = 0; o + f->pat_len <= nlen; o++) {
            if (strncmp(name + o, f->pat, f->pat_len) == 0) return 1;
        }
        return 0;
    }
    return strncmp(name, f->pat, f->pat_len) == 0;                   // prefix
}
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
    // Same 128 KB buffer as action:status, and the same honesty rule: a slot list that does not fit
    // must say so (total/emitted/truncated) instead of looking like the whole table. The old 32 KB
    // buffer silently dropped 69 of the 228 slots, so a caller counting installed entries saw 159.
    static char out[128 * 1024];              // command handling is serial; agent frames carry up to FRAME_MAX
    size_t len = snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"jni_env_hook\",\"ok\":%s,"
        "\"action\":\"%s\",\"function\":\"%s\",\"applied\":%d,\"failed\":%d,"
        "\"table\":\"0x%llx\",\"tablePerms\":\"%s\",\"error\":\"%s\",\"hooks\":[",
        idj, ok ? "true" : "false", actionj, functionj, applied, failed,
        g_env_hook_table, table_perms, errorj);
    int first = 1, emitted = 0;
    pthread_mutex_lock(&g_env_hook_lock);
    for (int i = 0; i < ENV_HOOK_MAX && len + 900 < sizeof(out); i++) {
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
        emitted++;
    }
    pthread_mutex_unlock(&g_env_hook_lock);
    snprintf(out + len, sizeof(out) - len, "],\"total\":%d,\"emitted\":%d,\"truncated\":%s}\n",
             ENV_HOOK_MAX, emitted, emitted < ENV_HOOK_MAX ? "true" : "false");
    send_line(fd, out);
}

// The status reply says how much of the table it is showing. The list is filtered by `function`
// and, if it still does not fit the frame buffer, clipped - and both facts are in the reply
// (total/matched/emitted/truncated), because a partial slot list that claims to be complete is
// worse than no list at all: a verifier would read "not installed" out of a missing entry.
static void send_env_status(int fd, const char *id, const char *function, const struct EnvNameFilter *filter) {
    static char out[128 * 1024];              // command handling is serial; agent frames carry up to FRAME_MAX
    char idj[64], functionj[96];
    json_escape(id, idj, sizeof(idj));
    json_escape(function ? function : "", functionj, sizeof(functionj));
    char table_perms[8] = "";
    if (g_env_hook_table) adh_perms_of_addr((void *)(uintptr_t)g_env_hook_table, table_perms, sizeof(table_perms));

    // Pass 1: count what matches, so the header can state it even when the list is clipped.
    int matched = 0;
    for (int i = 0; i < ENV_HOOK_MAX; i++) {
        if (filter->installed_only && !g_env_hooks[i].installed) continue;
        if (env_filter_match(filter, g_env_hooks[i].name)) matched++;
    }

    // Status stays available even when the layout is broken - that is exactly when an operator
    // needs to see the table - but it has to SAY so instead of looking healthy.
    char layout_error[224] = "";
    int layout_ok = env_hook_layout_ready(layout_error, sizeof(layout_error));
    char layout_errorj[256] = "";
    if (!layout_ok) json_escape(layout_error, layout_errorj, sizeof(layout_errorj));
    size_t len = snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"jni_env_hook\",\"ok\":true,"
        "\"action\":\"status\",\"function\":\"%s\",\"applied\":0,\"failed\":0,"
        "\"total\":%d,\"matched\":%d,\"layout\":\"%s\",\"layoutError\":\"%s\","
        "\"table\":\"0x%llx\",\"tablePerms\":\"%s\",\"error\":\"\",\"hooks\":[",
        idj, functionj, ENV_HOOK_MAX, matched, layout_ok ? "ok" : "mismatch", layout_errorj,
        g_env_hook_table, table_perms);

    // Pass 2: emit what fits. A slot that does not fit is NOT reported as absent - the header
    // carries matched vs emitted so the caller knows the list was clipped.
    int emitted = 0, first = 1;
    pthread_mutex_lock(&g_env_hook_lock);
    for (int i = 0; i < ENV_HOOK_MAX; i++) {
        if (filter->installed_only && !g_env_hooks[i].installed) continue;
        if (!env_filter_match(filter, g_env_hooks[i].name)) continue;
        if (len + 900 >= sizeof(out)) continue;
        char slot_perms[8] = "";
        char lastj[512];
        json_escape(g_env_hooks[i].last, lastj, sizeof(lastj));
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
        emitted++;
    }
    pthread_mutex_unlock(&g_env_hook_lock);
    // emitted/truncated are only known now, so they travel after the list instead of forcing a
    // rewrite of the header (the header states total+matched, which are known up front).
    snprintf(out + len, sizeof(out) - len, "],\"emitted\":%d,\"truncated\":%s}\n",
             emitted, (emitted == matched) ? "false" : "true");
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
    // A slot whose wrapper is missing must never be installed: adh_swap_pointer_in_ro_page()
    // accepts a NULL replacement, and a NULL in ART's JNIEnv table is a jump through NULL on the
    // target's next call to that entry - a crash, not a fail-loud refusal.
    void *wrapper = env_hook_wrapper(index);
    if (!wrapper) {
        snprintf(error, error_size, "%s: no wrapper for this slot - refusing to patch", g_env_hooks[index].name);
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
        // Same entry: re-activate the existing hook instead of patching twice - but only while the
        // entry still points at OUR wrapper. If something else replaced it, flipping the flag would
        // make the reply claim a hook that is no longer in the table.
        if (__atomic_load_n(slot, __ATOMIC_ACQUIRE) != wrapper) {
            pthread_mutex_unlock(&g_env_hook_lock);
            snprintf(error, error_size, "%s: table entry no longer points at the hook wrapper; refusing to re-activate",
                     g_env_hooks[index].name);
            return 0;
        }
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
    if (original == wrapper) {
        snprintf(error, error_size, "%s: entry already points at the hook wrapper", g_env_hooks[index].name);
        return 0;
    }
    // Publish the real entry before the swap: a call that lands in the wrapper during the
    // swap window then still reaches the original implementation.
    __atomic_store_n(&g_env_hooks[index].original, original, __ATOMIC_RELEASE);
    if (!adh_swap_pointer_in_ro_page(slot, wrapper)) {
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
        struct EnvNameFilter status_filter;
        env_filter_parse(function, &status_filter);
        send_env_status(fd, id, function, &status_filter);
        return;
    }
    if (strcmp(action, "install") != 0 && strcmp(action, "uninstall") != 0) {
        send_env_result(fd, id, action, function, 0, 0, 0, "action must be install|uninstall|status");
        return;
    }
    // Never patch a table whose enum/name layout does not line up: the patch would land on the
    // neighbouring entry while the reply still named the requested one.
    {
        char layout_error[224];
        if (!env_hook_layout_ready(layout_error, sizeof(layout_error))) {
            send_env_result(fd, id, action, function, 0, 0, 0, layout_error);
            return;
        }
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
    struct EnvNameFilter filter;
    env_filter_parse(function, &filter);
    int wildcard = filter.wildcard;
    if (filter.installed_only) {
        send_env_result(fd, id, action, function, 0, 0, 0,
                        "\"installed\" is a status filter; install/uninstall need a slot name or pattern");
        return;
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
            if (!env_filter_match(&filter, n)) continue;
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
