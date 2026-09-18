// C-ABI shim over LSPlant (ART Java-method hook).
//
// The agent bootstrap is C; all C++/LSPlant/JNI-object work lives in java_lsplant.cpp.
// LSPlant is compiled into libadh_agent.so only when tools/fetch_lsplant.sh has prepared
// the pinned third-party sources and CMake detects them. Nothing initializes LSPlant at
// startup: adh_javahook_init() is called only by an explicit command.
#ifndef ADH_AGENT_JAVA_LSPLANT_H
#define ADH_AGENT_JAVA_LSPLANT_H

#include <jni.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 1 when the LSPlant backend is compiled into this agent, 0 otherwise.
int adh_javahook_available(void);

// Initialize LSPlant once (idempotent). Returns 1 on success, 0 on failure.
// Never initializes at JNI_OnLoad; the caller decides when to expose the backend.
int adh_javahook_init(JNIEnv *env);

// Last initialization error, or "" when no error was recorded.
const char *adh_javahook_last_error(void);

// Hook target_method (a java.lang.reflect.Method/Executable). hooker_object is an instance
// that holds the backup field; callback_method is its reflect.Method `Object callback(Object[])`.
// Returns the backup method (local ref) to invoke the original, or NULL on failure.
jobject adh_javahook_hook(JNIEnv *env, jobject target_method, jobject hooker_object, jobject callback_method);

int adh_javahook_unhook(JNIEnv *env, jobject target_method);   // 1 ok, 0 fail
int adh_javahook_is_hooked(JNIEnv *env, jobject method);       // 1 hooked, 0 not
// Generic multi-hook command surface used by agent_main.c. These functions resolve each
// target through the app ClassLoader; params is a comma-separated list of Java type names
// (for example "java.lang.String,int"). Hooks are bounded and have stable numeric ids;
// hook_id_out receives the id of a newly installed hook.
// capture_stack=1 makes every hook event carry the bounded caller chain captured at the hit.
int adh_javahook_hook_method(JNIEnv *env, const char *class_name, const char *method_name,
                             const char *params, int skip_original, const char *override_return, int arg_index, const char *arg_value,
                             int capture_stack, int *hook_id_out, char *error, size_t error_size); // 1 ok, 0 fail
// Hook every method of a class in one call (name/params filters are optional; "*"/empty = any).
// Returns the number installed and fills hook_ids_out (bounded by hook_ids_cap); matched_out reports
// how many methods matched, so a truncated result is visible instead of silently partial.
#define ADH_JAVA_HOOK_MAX 16
int adh_javahook_hook_all(JNIEnv *env, const char *class_name, const char *method_name,
                          const char *params, int skip_original, const char *override_return,
                          int arg_index, const char *arg_value, int capture_stack,
                          int max_hooks, int *hook_ids_out, int hook_ids_cap,
                          int *matched_out, int *collect_capped_out, char *error, size_t error_size);
int adh_javahook_unhook_id(JNIEnv *env, int hook_id, char *error, size_t error_size); // id=0 unhooks all; 1 ok, 0 fail
int adh_javahook_status_json(JNIEnv *env, char *out, size_t out_size);            // 1 ok, 0 fail

#ifdef __cplusplus
}
#endif

#endif