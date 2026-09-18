#ifndef ADH_AGENT_SITE_HOOKS_H
#define ADH_AGENT_SITE_HOOKS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Call-site hooking ("sites" mode).
//
// The entry-based inline hook rewrites the target function's first bytes, which any app can see by
// comparing its own prologue against the copy it took at startup (the sandbox audit does exactly
// that: prologueDiffers/entryBranchesOutside). This backend leaves the FUNCTION untouched and
// patches the BL call sites instead: the target's prologue stays byte-identical, and because the
// patch is ours (not Dobby's state machine) install/unhook are fully reversible and repeatable.
//
// How it works: every BL that calls the target is rewritten to a thunk we emit on a page allocated
// within +-128 MB of the module (BL range). The thunk saves the argument registers into the same
// 256-byte frame layout the entry stubs use, calls adh_native_hook_record_site() (so events, hit
// counters, integer argument rewrite and skip/return replacement all behave like a normal hook),
// reloads the registers, calls the real function, and returns its result untouched.
//
// Honest limits: only direct BL sites inside the target module are covered (indirect calls, PLT
// calls and other modules need the GOT or entry backend); a bounded number of sites per hook;
// the rewritten CALLER bytes are of course visible to anyone checking those.
int adh_site_hook_apply(int slot, void *target, int max_sites, char *error, size_t error_size);
int adh_site_hook_revert(int slot, char *error, size_t error_size);
int adh_site_hook_count(int slot);
// Base of the thunk page (the "replacement" the status shows) or NULL when not installed.
void *adh_site_hook_page(int slot);
// Appends one JSON object with the site list to out (already used bytes in *used).
void adh_site_hook_sites_json(int slot, char *out, size_t out_size, size_t *used);

#ifdef __cplusplus
}
#endif

#endif
