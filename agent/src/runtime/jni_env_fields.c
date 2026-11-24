// ---- JNIEnv hook implementation (split from jni_env_hooks.c) ------------
#include "jni_env_hooks_internal.h"

// ---- field accessors ------------------------------------------------------
// Each wrapper forwards to the saved table entry and records one bounded event. The _Static_assert
// block at the end is compile-time proof that every wrapper has EXACTLY the JNI signature of the
// entry it replaces - a mismatch stops the build instead of crashing inside a target.
#define ADH_DEFINE_FIELD_GET_BODY(JNI_NAME, CTYPE, FMT, CAST, TARGET)                       \
 CTYPE JNICALL JNI_NAME##_wrapper(JNIEnv *env, TARGET target, jfieldID field) {       \
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
 void JNICALL JNI_NAME##_wrapper(JNIEnv *env, TARGET target, jfieldID field, CTYPE value) { \
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

