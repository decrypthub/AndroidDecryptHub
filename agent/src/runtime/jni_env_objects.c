// ---- JNIEnv hook implementation (split from jni_env_hooks.c) ------------
#include "jni_env_hooks_internal.h"

// ---- v4.75: creation, length, object arrays and AllocObject --------------------------------
// The eight primitive array constructors share one shape (len in, array out). A length that is
// rejected (negative) throws, and so does an allocation failure - both are reported as failed
// rather than as a mysterious 0x0 result.
#define ADH_DEFINE_NEW_ARRAY(JNI_NAME)                                                      \
 jobject JNI_NAME##_wrapper(JNIEnv *env, jsize len) {                                 \
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

 jsize GetArrayLength_wrapper(JNIEnv *env, jarray arr) {
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

 jobject NewObjectArray_wrapper(JNIEnv *env, jsize len, jclass elem_class, jobject initial) {
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
 jobject GetObjectArrayElement_wrapper(JNIEnv *env, jobjectArray arr, jsize index) {
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

 void SetObjectArrayElement_wrapper(JNIEnv *env, jobjectArray arr, jsize index, jobject value) {
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

 jobject AllocObject_wrapper(JNIEnv *env, jclass clazz) {
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
