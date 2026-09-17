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
                            const char *addr, int skip_original, int return_set,
                            uint64_t return_value, int arg_index, uint64_t arg_value,
                            int *hook_id_out, char *error, size_t error_size);
// hard=1 destroys the inline patch (DobbyDestroy) after a quiesce window and frees the slot;
// hard=0 keeps the soft-unhook semantics (stub stays installed but inactive).
int adh_native_hook_unhook(int hook_id, int hard, char *error, size_t error_size);
int adh_native_hook_status_json(char *out, size_t out_size);

// Called by the fixed arm64 stubs. Observation-only and non-blocking.
uint64_t adh_native_hook_record(uint64_t *regs, int hook_id);

#ifdef __cplusplus
}
#endif

#endif