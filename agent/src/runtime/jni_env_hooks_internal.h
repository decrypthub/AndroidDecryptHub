#ifndef ADH_JNI_ENV_HOOKS_INTERNAL_H
#define ADH_JNI_ENV_HOOKS_INTERNAL_H

// Shared internals for the JNIEnv hook implementation, split across
// jni_env_{fixed,calls,fields,string,misc,objects}.c. Not a public header:
// everything here exists so the family TUs can share the slot tables,
// dispatch macros and detail/emit helpers.

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
// entry (the failure the field family lived with). Per-version history: docs/PROGRESS.md.
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

struct AdhCallDetail {
    char text[640];
    int ok;
};

extern struct EnvHookSlot g_env_hooks[];
extern __thread int g_env_hook_in_ours;
void call_detail_a(JNIEnv *env, int slot, jobject target, int kind, jmethodID mid, const jvalue *args, struct AdhCallDetail *d);
void call_detail_va(JNIEnv *env, int slot, jobject target, int kind, jmethodID mid, va_list ap, struct AdhCallDetail *d);
void call_emit(int slot, struct AdhCallDetail *d);
void detail_field(JNIEnv *env, jclass clazz, const char *name, const char *sig, char *out, size_t out_size);
void detail_field_plain(const char *name, const char *sig, char *out, size_t out_size);
void detail_method(JNIEnv *env, jclass clazz, const char *name, const char *sig, char *out, size_t out_size);
void detail_method_plain(const char *name, const char *sig, char *out, size_t out_size);
int env_budget_left(int index);
void env_note(int index, const char *value, int ok);
void hex_preview(const jbyte *data, jsize len, char *out, size_t out_size);
int slot_active(int index);
void * slot_original(int index);

/* wrapper functions live in the family TUs; dispatch takes their address.
   Signatures come from the matching JNINativeInterface member so the layout
   self-check's __typeof__ comparisons still hold. */
#define ADH_DECL_W1(name) __typeof__(*((struct JNINativeInterface *)0)->name) name##_wrapper;
#define ADH_DECL_W3(name, ...) \
    __typeof__(*((struct JNINativeInterface *)0)->name) name##_wrapper; \
    __typeof__(*((struct JNINativeInterface *)0)->name##V) name##V_wrapper; \
    __typeof__(*((struct JNINativeInterface *)0)->name##A) name##A_wrapper;
ADH_FIXED_SLOT_LIST(ADH_DECL_W1)
ADH_FIELD_SLOT_LIST(ADH_DECL_W1)
ADH_CALL_VALUE_FAMILIES(ADH_DECL_W3)
ADH_CALL_VOID_FAMILIES(ADH_DECL_W3)
ADH_CALLNV_VALUE_FAMILIES(ADH_DECL_W3)
ADH_CALLNV_VOID_FAMILIES(ADH_DECL_W3)
#undef ADH_DECL_W1
#undef ADH_DECL_W3

#endif
