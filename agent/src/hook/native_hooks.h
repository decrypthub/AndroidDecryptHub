#ifndef ADH_AGENT_NATIVE_HOOKS_H
#define ADH_AGENT_NATIVE_HOOKS_H

#include <stddef.h>
#include <stdint.h>

// Upper bound of the per-hook event throttle window (ms). One definition for the whole agent
// (install clamp, command parser and status echo all use it); anything larger is effectively a
// "log nothing useful" setting, so it is clamped instead of rejected and the effective value is
// echoed back in status. The host mirrors this number in daemon/src/native_hook_args.ts.
#define ADH_NATIVE_THROTTLE_MAX_MS 60000

#ifdef __cplusplus
extern "C" {
#endif

// Install a native hook. mode is "got" (module+symbol), "inline" (module+symbol or addr) or
// "sites" (module+symbol: rewrite the B/BL call sites instead of the function entry, so the target
// prologue stays byte-identical; max_sites bounds how many call sites are patched and sites_scope
// selects where to look: "module" (default), "all" file-backed modules, or one module name/basename).
// On success returns 1 and stores the hook id in *hook_id_out.
// want_backtrace=1 makes every event carry the caller chain captured AT THE HIT (x30 + the x29
// chain walked inside the thread's own stack) so the host can symbolize it without reading a stack
// that has already been reused. Off by default: it costs a few stack loads per hit.
// throttle_ms>0 keeps at most ONE event per hook per window; every hit inside the window is counted
// instead of emitted (the next event reports how many it stands for, status reports the running
// total), so a hot site such as read/write/futex cannot flood the capture ring and a thinned log is
// never mistaken for a quiet target. The throttle suppresses EVENTS ONLY: the argument/return
// rewrite and the "do not call the original" answer are applied to throttled hits as well. Values
// are clamped to 0..60000 ms (0 = every hit emits), and status echoes the effective value.
int adh_native_hook_install(const char *mode, const char *module, const char *symbol,
                            const char *addr, int skip_original, int return_set,
                            uint64_t return_value, int arg_index, uint64_t arg_value,
                            int max_sites, const char *sites_scope, int allow_writable_slots,
                            int want_backtrace, int throttle_ms, int *hook_id_out, char *error,
                            size_t error_size);
// hard=1 destroys the inline patch (DobbyDestroy) after a quiesce window and frees the slot;
// hard=0 keeps the soft-unhook semantics (stub stays installed but inactive).
int adh_native_hook_unhook(int hook_id, int hard, char *error, size_t error_size);
int adh_native_hook_status_json(char *out, size_t out_size);

// Called by the fixed arm64 stubs. Observation-only and non-blocking.
uint64_t adh_native_hook_record(uint64_t *regs, int hook_id);
// Called by the site thunks: same recording, but the return value means "do not call the original"
// (set for skipOriginal and for returnSet, which both answer from the saved frame).
uint64_t adh_native_hook_record_site(uint64_t *regs, int hook_id);
// Hit counter of one slot (used by the site backend's quiesce window).
unsigned long long adh_native_hook_hits(int hook_id);

#ifdef __cplusplus
}
#endif

#endif