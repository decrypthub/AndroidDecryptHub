#ifndef ADH_AGENT_RUNTIME_JNI_ENV_HOOKS_H
#define ADH_AGENT_RUNTIME_JNI_ENV_HOOKS_H

#ifdef __cplusplus
extern "C" {
#endif

// Per-entry hooks on the JNIEnv function table. In C a JNIEnv* points at a table of
// function pointers, so one aligned slot swap intercepts every JNI call that goes through
// that env. No trampoline is involved: the saved slot value is the real implementation, so
// uninstall writes the original entry back (no UAF window, clean restore).
// action: install | uninstall | status, function: GetStringUTFChars | FindClass |
// GetMethodID | GetStaticMethodID | NewStringUTF.
// Events are emitted as bounded JNI_ENV capture records.
void adh_cmd_jni_env_hook(int fd, const char *id, const char *action, const char *function);

#ifdef __cplusplus
}
#endif

#endif