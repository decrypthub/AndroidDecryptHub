// ---- JNIEnv hook implementation (split from jni_env_hooks.c) ------------
#include "jni_env_hooks_internal.h"

// ---- Call* family wrappers (macro-generated per form) ---------------------
#define ADH_DEFINE_CALL_VALUE(NAME, RET, TGT, KIND, BASE, SPEC)                                \
     RET NAME##_wrapper(JNIEnv *env, TGT target, jmethodID mid, ...) {                    \
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
     RET NAME##V_wrapper(JNIEnv *env, TGT target, jmethodID mid, va_list ap) {            \
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
     RET NAME##A_wrapper(JNIEnv *env, TGT target, jmethodID mid, const jvalue *args) {    \
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
     void NAME##_wrapper(JNIEnv *env, TGT target, jmethodID mid, ...) {                   \
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
     void NAME##V_wrapper(JNIEnv *env, TGT target, jmethodID mid, va_list ap) {           \
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
     void NAME##A_wrapper(JNIEnv *env, TGT target, jmethodID mid, const jvalue *args) {   \
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
     RET NAME##_wrapper(JNIEnv *env, jobject obj, jclass clazz, jmethodID mid, ...) {        \
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
     RET NAME##V_wrapper(JNIEnv *env, jobject obj, jclass clazz, jmethodID mid, va_list ap) {  \
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
     RET NAME##A_wrapper(JNIEnv *env, jobject obj, jclass clazz, jmethodID mid,               \
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
     void NAME##_wrapper(JNIEnv *env, jobject obj, jclass clazz, jmethodID mid, ...) {       \
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
     void NAME##V_wrapper(JNIEnv *env, jobject obj, jclass clazz, jmethodID mid, va_list ap) {\
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
     void NAME##A_wrapper(JNIEnv *env, jobject obj, jclass clazz, jmethodID mid,             \
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

