#ifndef ADH_AGENT_SITE_HOOKS_H
#define ADH_AGENT_SITE_HOOKS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Call-site hooking ("sites" mode).
//
// An entry-based inline hook rewrites the target function's first bytes, which any app can see by
// comparing its own prologue with the copy it took at startup (the sandbox audit reports exactly
// that as prologueDiffers/entryBranchesOutside). This backend never writes the function: it patches
// the B/BL instructions that CALL it, so the prologue stays byte-identical - and because the patch
// is the agent's own (not Dobby's state machine), install/unhook are reversible and repeatable.
//
// Scope: "module" (default) scans only the target's own module; "all" scans every file-backed
// executable mapping of the process (the operator can also pass a module name/basename to scan just
// that one). Each site is rewritten to a hand-encoded arm64 thunk on a memfd page that is allocated
// within +-128 MB of THAT site (BL reach), so sites in different modules get their own page.
//
// The thunk saves x0-x9/x29/x30/x18/q0-q7 in the same 256-byte layout the entry stubs use, calls
// adh_native_hook_record_site() (events, hit counters and integer argument rewrite come for free),
// reloads the registers, calls the real function and returns its result.
//
// Honest limits: direct B/BL only (indirect calls, function pointers and vtables need the GOT or
// entry backend); the patch keeps the site's instruction FORM (b stays b, bl stays bl) because a
// tail call patched with a BL makes the thunk return into the callee body and the target spins at
// its own entry; bounded number of sites per hook; the CALLER bytes are of course visible to anyone
// checking those; skipOriginal/returnValue are refused because the return register bank depends on
// the target.
int adh_site_hook_apply(int slot, void *target, int max_sites, const char *scope,
                        char *error, size_t error_size);
int adh_site_hook_revert(int slot, char *error, size_t error_size);
int adh_site_hook_count(int slot);
// JSON fragment (name/value pairs) describing the last revert that had to keep a thunk page mapped.
void adh_site_hook_last_revert_json(char *out, size_t out_size);
// Base of the first thunk page (what status shows as the "replacement"), or NULL when idle.
void *adh_site_hook_page(int slot);
// Write one thunk (same verified emitter the sites backend uses) into `page`. Returns the number of
// bytes written, or 0 when the layout self-check fails. Used by pointer-slot (vtable) hooking too:
// a slot is entered through a pointer, so its thunk has no BL-range constraint.
int adh_site_thunk_write(void *page, void *recorder, void *original, int hook_slot);

// Appends the site list (per site: address, form, module, original/current instruction, thunk, page)
// to out, continuing from *used.
void adh_site_hook_sites_json(int slot, char *out, size_t out_size, size_t *used);

#ifdef __cplusplus
}
#endif

#endif
