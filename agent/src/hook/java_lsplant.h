// C-ABI shim over LSPlant (ART Java-method hook). agent_main.c (pure C) calls these;
// all C++ / LSPlant / JNI-object work lives in java_lsplant.cpp. See tools/fetch_lsplant.sh.
#ifndef IDH_JAVA_LSPLANT_H
#define IDH_JAVA_LSPLANT_H
#include <jni.h>
#ifdef __cplusplus
extern "C" {
#endif

// Initialize LSPlant once (idempotent). Returns 1 on success, 0 on failure (fail-loud;
// e.g. an ART symbol not found on this ROM). Never crashes on failure.
int idh_javahook_init(JNIEnv *env);

// Hook target_method (a java.lang.reflect.Method/Executable). hooker_object is an instance
// that holds the backup; callback_method is its reflect.Method `Object callback(Object[])`.
// Returns the backup method (local ref) to invoke the original, or NULL on failure.
jobject idh_javahook_hook(JNIEnv *env, jobject target_method, jobject hooker_object, jobject callback_method);

int idh_javahook_unhook(JNIEnv *env, jobject target_method);   // 1 ok, 0 fail
int idh_javahook_is_hooked(JNIEnv *env, jobject method);       // 1 hooked, 0 not

#ifdef __cplusplus
}
#endif
#endif
