#ifndef ADH_AGENT_RUNTIME_JNI_HOOKS_H
#define ADH_AGENT_RUNTIME_JNI_HOOKS_H

#ifdef __cplusplus
extern "C" {
#endif

// Install/uninstall/status for the global JNIEnv->RegisterNatives hook.
// Each registration emits a JNI_NATIVE capture event with class/method/signature/fnPtr.
void adh_cmd_jni_hook(int fd, const char *id, const char *action);
// Install the same hook during agent bootstrap (gated by the caller on dh.jni_early=1), so
// registrations that happen before the first host command are still recorded.
void adh_jni_hook_install_early(void);

#ifdef __cplusplus
}
#endif

#endif