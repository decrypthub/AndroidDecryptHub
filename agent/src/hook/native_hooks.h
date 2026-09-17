#ifndef ADH_AGENT_NATIVE_HOOKS_H
#define ADH_AGENT_NATIVE_HOOKS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Install a native hook. mode is "got" (module+symbol) or "inline" (module+symbol or addr).
// On success returns 1 and stores the hook id in *hook_id_out.
int adh_native_hook_install(const char *mode, const char *module, const char *symbol,
                            const char *addr, int *hook_id_out,
                            char *error, size_t error_size);
int adh_native_hook_unhook(int hook_id, char *error, size_t error_size);
int adh_native_hook_status_json(char *out, size_t out_size);

// Called by the fixed arm64 stubs. Observation-only and non-blocking.
void adh_native_hook_record(uint64_t *regs, int hook_id);

#ifdef __cplusplus
}
#endif

#endif