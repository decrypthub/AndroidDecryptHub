#ifndef ADH_AGENT_RUNTIME_JNI_ONLOAD_H
#define ADH_AGENT_RUNTIME_JNI_ONLOAD_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Enumerate/hook/invoke the JNI_OnLoad exported by an already-loaded module.
// action: list | hook | unhook | call | status | watch | unwatch; module is required except for
// list/status. `watch` arms a one-shot load-time watch: the dlopen wrapper patches the matching
// module's JNI_OnLoad as soon as it is mapped, before the VM calls it.
void adh_cmd_jni_onload(int fd, const char *id, const char *action, const char *module,
                        int skip_original, int return_value);

// Called by the dlopen watch after a module is mapped (see runtime/dlopen_watch.c).
int adh_jni_onload_on_module_loaded(const char *path, void *handle, char *error, size_t error_size);

#ifdef __cplusplus
}
#endif

#endif