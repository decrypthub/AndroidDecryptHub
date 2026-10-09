#ifndef ADH_AGENT_RUNTIME_JNI_ENV_HOOKS_H
#define ADH_AGENT_RUNTIME_JNI_ENV_HOOKS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jni.h>

// Exception state check that never travels through the (possibly hooked) JNIEnv table entry:
// the agent is attached to the same VM as the target, so its own JNI traffic must not be recorded
// as target behaviour. Use this everywhere inside ADH instead of (*env)->ExceptionCheck(env).
jboolean adh_jni_exception_check(JNIEnv *env);
void adh_jni_exception_clear(JNIEnv *env);

// Mark the current thread as running ADH's own JNI work (see jni_env_hooks.c). enter returns
// the previous state, leave restores it - always pair them, even on early returns.
int adh_jni_ours_enter(void);
void adh_jni_ours_leave(int previous);

// Per-entry hooks on the JNIEnv function table. In C a JNIEnv* points at a table of
// function pointers, so one aligned slot swap intercepts every JNI call that goes through
// that env. No trampoline is involved: the saved slot value is the real implementation, so
// uninstall writes the original entry back (no UAF window, clean restore).
// action: install | uninstall | status, function: GetStringUTFChars | FindClass |
// GetMethodID | GetStaticMethodID | NewStringUTF | GetFieldID | GetStaticFieldID |
// GetByteArrayElements | SetByteArrayRegion.
// Method/field-ID events name the owning class; array events carry length + a bounded
// hex preview of the payload.
// Events are emitted as bounded JNI_ENV capture records.
// override_* apply to ONE Set<Type>Field slot: when active the wrapper writes the given value
// instead of the caller's, and the event reports both (requested -> applied).
void adh_cmd_jni_env_hook(int fd, const char *id, const char *action, const char *function,
                          int override_active, long long override_i, double override_d);

#ifdef __cplusplus
}
#endif

#endif