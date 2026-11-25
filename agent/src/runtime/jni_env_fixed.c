// ---- JNIEnv hook implementation (split from jni_env_hooks.c) ------------
#include "jni_env_hooks_internal.h"

// ---- fixed wrappers -------------------------------------------------------
 const char *GetStringUTFChars_wrapper(JNIEnv *env, jstring str, jboolean *isCopy) {
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

 jclass FindClass_wrapper(JNIEnv *env, const char *name) {
    find_class_fn original = (find_class_fn)slot_original(ENV_SLOT_FindClass);
    if (!original) return NULL;
    if (g_env_hook_in_ours || !slot_active(ENV_SLOT_FindClass)) return original(env, name);
    g_env_hook_in_ours = 1;
    jclass result = original(env, name);
    env_note(ENV_SLOT_FindClass, env_budget_left(ENV_SLOT_FindClass) ? name : NULL, result != NULL);
    g_env_hook_in_ours = 0;
    return result;
}

 jmethodID GetMethodID_wrapper(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
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

 jmethodID GetStaticMethodID_wrapper(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
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

 jstring NewStringUTF_wrapper(JNIEnv *env, const char *chars) {
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

 jfieldID GetFieldID_wrapper(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
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

 jfieldID GetStaticFieldID_wrapper(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
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

 jbyte *GetByteArrayElements_wrapper(JNIEnv *env, jarray array, jboolean *isCopy) {
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

 void SetByteArrayRegion_wrapper(JNIEnv *env, jarray array, jsize start, jsize len,
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

 void ReleaseByteArrayElements_wrapper(JNIEnv *env, jbyteArray array, jbyte *elems, jint mode) {
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

 void GetByteArrayRegion_wrapper(JNIEnv *env, jbyteArray array, jsize start, jsize len, jbyte *buf) {
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

 void *GetPrimitiveArrayCritical_wrapper(JNIEnv *env, jarray array, jboolean *isCopy) {
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

 void ReleasePrimitiveArrayCritical_wrapper(JNIEnv *env, jarray array, void *carray, jint mode) {
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
