#ifndef ADH_AGENT_RUNTIME_JNI_ONLOAD_H
#define ADH_AGENT_RUNTIME_JNI_ONLOAD_H

#ifdef __cplusplus
extern "C" {
#endif

// Enumerate/hook/invoke the JNI_OnLoad exported by an already-loaded module.
// action: list | hook | unhook | call | status; module is required except for list/status.
void adh_cmd_jni_onload(int fd, const char *id, const char *action, const char *module);

#ifdef __cplusplus
}
#endif

#endif