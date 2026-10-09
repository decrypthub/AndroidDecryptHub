#ifndef ADH_AGENT_SLOT_HOOKS_H
#define ADH_AGENT_SLOT_HOOKS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Pointer-slot ("vtable") hooking.
//
// C++ virtual dispatch and many callback tables call a function through a POINTER stored in data:
//     ldr x0, [xObj]        ; vptr
//     ldr x8, [x0, #off]    ; slot value = the function
//     blr x8
// Neither the callee's prologue nor any call site has to change: the slot value is replaced with a
// thunk. That makes this the third "entry never touched" backend (after mode=got and mode=sites) and
// the only one that covers INDIRECT dispatch, which is exactly how hardened apps reach their crypto.
//
// scope selects which data to search: "module" (default: the target's own read-only/readable data),
// "all" file-backed readable mappings except our own and memfds, or one module name/basename.
// Only 8-byte-aligned values equal to the target are candidates; every hit is reported with its
// module and mapping permissions so a false positive is visible rather than silent.
//
// Honest limits: a slot that the target rebuilds at runtime is not tracked; writable slots can be
// rewritten by the target at any time; the slot bytes themselves are of course visible to anyone
// checking that table (the FUNCTION still is not); values reached through pointer arithmetic we do
// not model (e.g. hand-rolled jump tables built at runtime) are out of scope.
// allow_writable=0 (the default the Host uses) skips slots in writable mappings: a writable word that
// merely equals the target is as likely to be a constant as a call target. 1 includes them.
int adh_slot_hook_apply(int slot, void *target, int max_slots, const char *scope,
                        int allow_writable, char *error, size_t error_size);
int adh_slot_hook_revert(int slot, char *error, size_t error_size);
int adh_slot_hook_count(int slot);
void *adh_slot_hook_page(int slot);
void adh_slot_hook_slots_json(int slot, char *out, size_t out_size, size_t *used);

#ifdef __cplusplus
}
#endif

#endif
