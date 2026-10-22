#ifndef ADH_AGENT_RUNTIME_DLOPEN_WATCH_H
#define ADH_AGENT_RUNTIME_DLOPEN_WATCH_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Watches runtime library loads so a JNI_OnLoad can be patched BEFORE the VM calls it.
//
// Install hooking one of the process's dlopen entry points (libdl's android_dlopen_ext, falling
// back to dlopen / the linker's __loader_android_dlopen_ext). The wrapper calls the original,
// then offers the freshly mapped module to the jni_onload watch, and returns the handle untouched.
// Installed lazily - only a `jni_onload watch` command arms it, so the default agent footprint is
// unchanged.
int adh_dlopen_watch_install(char *error, size_t error_size);
int adh_dlopen_watch_installed(void);

// Module-load broadcast (opt-in). `start` installs the same dlopen hook if needed and makes the
// wrapper emit a MODULE_LOAD capture event for every library mapped afterwards: path, handle,
// base, size. This is what catches a payload that decrypts itself into a fresh mapping after the
// process started - the JNI_OnLoad watch is one-shot and per-name, this one reports all of them.
void adh_cmd_module_watch(int fd, const char *id, const char *action);
int adh_module_watch_on(void);

#ifdef __cplusplus
}
#endif

#endif