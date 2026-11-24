// ---- JNIEnv hook implementation (split from jni_env_hooks.c) ------------
#include "jni_env_hooks_internal.h"

// ---- v4.67: exception flow + VM handle --------------------------------------
// ExceptionOccurred is called exactly WHEN an exception is pending, so none of these wrappers may make
// JNI calls that require a clear exception state: the name lookups are gated on "no pending exception
// at entry" and ExceptionOccurred reports only the pointer.
 jint Throw_wrapper(JNIEnv *env, jthrowable obj) {
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

 jint ThrowNew_wrapper(JNIEnv *env, jclass clazz, const char *message) {
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

 jthrowable ExceptionOccurred_wrapper(JNIEnv *env) {
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

 void ExceptionDescribe_wrapper(JNIEnv *env) {
    typedef void (JNICALL *fn_t)(JNIEnv *);
    fn_t original = (fn_t)slot_original(ENV_SLOT_ExceptionDescribe);
    if (!original) return;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_ExceptionDescribe)) { original(env); return; }
    g_env_hook_in_ours = 1;
    original(env);
    g_env_hook_in_ours = 0;
    env_note(ENV_SLOT_ExceptionDescribe, env_budget_left(ENV_SLOT_ExceptionDescribe) ? "describe" : NULL, 1);
}

 void ExceptionClear_wrapper(JNIEnv *env) {
    typedef void (JNICALL *fn_t)(JNIEnv *);
    fn_t original = (fn_t)slot_original(ENV_SLOT_ExceptionClear);
    if (!original) return;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_ExceptionClear)) { original(env); return; }
    g_env_hook_in_ours = 1;
    original(env);
    g_env_hook_in_ours = 0;
    env_note(ENV_SLOT_ExceptionClear, env_budget_left(ENV_SLOT_ExceptionClear) ? "cleared" : NULL, 1);
}

 jint GetJavaVM_wrapper(JNIEnv *env, JavaVM **vm) {
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
 jint PushLocalFrame_wrapper(JNIEnv *env, jint capacity) {
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

 jobject PopLocalFrame_wrapper(JNIEnv *env, jobject result) {
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

 jobject NewLocalRef_wrapper(JNIEnv *env, jobject ref) {
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

 void DeleteLocalRef_wrapper(JNIEnv *env, jobject ref) {
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

 jobject NewGlobalRef_wrapper(JNIEnv *env, jobject ref) {
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

 void DeleteGlobalRef_wrapper(JNIEnv *env, jobject ref) {
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

 jboolean IsSameObject_wrapper(JNIEnv *env, jobject a, jobject b) {
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

 jint EnsureLocalCapacity_wrapper(JNIEnv *env, jint capacity) {
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
 jint GetVersion_wrapper(JNIEnv *env) {
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

 jclass DefineClass_wrapper(JNIEnv *env, const char *name, jobject loader, const jbyte *buf, jsize len) {
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

 jclass GetSuperclass_wrapper(JNIEnv *env, jclass clazz) {
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

 jboolean IsAssignableFrom_wrapper(JNIEnv *env, jclass a, jclass b) {
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

 jclass GetObjectClass_wrapper(JNIEnv *env, jobject obj) {
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

 jboolean IsInstanceOf_wrapper(JNIEnv *env, jobject obj, jclass clazz) {
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

 jint MonitorEnter_wrapper(JNIEnv *env, jobject obj) {
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

 jint MonitorExit_wrapper(JNIEnv *env, jobject obj) {
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

 jweak NewWeakGlobalRef_wrapper(JNIEnv *env, jobject obj) {
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

 void DeleteWeakGlobalRef_wrapper(JNIEnv *env, jweak ref) {
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

 jobjectRefType GetObjectRefType_wrapper(JNIEnv *env, jobject obj) {
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
 void JNI_NAME##_wrapper(JNIEnv *env, jarray arr, jsize start, jsize len, BUFPTR buf) { \
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
 CTYPE *JNI_NAME##_wrapper(JNIEnv *env, jarray arr, jboolean *isCopy) {                    \
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
 void JNI_NAME##_wrapper(JNIEnv *env, jarray arr, CTYPE *elems, jint mode) {               \
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

