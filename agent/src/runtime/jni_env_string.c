// ---- JNIEnv hook implementation (split from jni_env_hooks.c) ------------
#include "jni_env_hooks_internal.h"

// ---- v4.63: string region + direct buffer entries ---------------------------
// GetStringRegion/GetStringUTFRegion copy a Java string INTO a native buffer (how native fingerprint
// code lifts values out of Java), so the event carries a bounded preview of what was copied. The
// direct-buffer trio is how native code hands a payload to Java (or looks one up), so the event
// carries the address and capacity.
 void GetStringRegion_wrapper(JNIEnv *env, jstring str, jsize start, jsize len, jchar *buf) {
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

 void GetStringUTFRegion_wrapper(JNIEnv *env, jstring str, jsize start, jsize len, char *buf) {
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

 jobject NewDirectByteBuffer_wrapper(JNIEnv *env, void *address, jlong capacity) {
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

 void *GetDirectBufferAddress_wrapper(JNIEnv *env, jobject buf) {
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

 jlong GetDirectBufferCapacity_wrapper(JNIEnv *env, jobject buf) {
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

 const jchar *GetStringChars_wrapper(JNIEnv *env, jstring str, jboolean *is_copy) {
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
 jstring NewString_wrapper(JNIEnv *env, const jchar *unicode, jsize len) {
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
 jsize JNI_NAME##_wrapper(JNIEnv *env, jstring str) {                                     \
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

 void ReleaseStringUTFChars_wrapper(JNIEnv *env, jstring str, const char *utf) {
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
 const jchar *GetStringCritical_wrapper(JNIEnv *env, jstring str, jboolean *is_copy) {
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

 void ReleaseStringCritical_wrapper(JNIEnv *env, jstring str, const jchar *cstring) {
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
 jmethodID FromReflectedMethod_wrapper(JNIEnv *env, jobject method) {
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

 jfieldID FromReflectedField_wrapper(JNIEnv *env, jobject field) {
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

 jobject ToReflectedMethod_wrapper(JNIEnv *env, jclass clazz, jmethodID mid, jboolean is_static) {
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

 jobject ToReflectedField_wrapper(JNIEnv *env, jclass clazz, jfieldID fid, jboolean is_static) {
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
 jint UnregisterNatives_wrapper(JNIEnv *env, jclass clazz) {
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
 void FatalError_wrapper(JNIEnv *env, const char *msg) {
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
 jboolean ExceptionCheck_wrapper(JNIEnv *env) {
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

 void ReleaseStringChars_wrapper(JNIEnv *env, jstring str, const jchar *chars) {
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

