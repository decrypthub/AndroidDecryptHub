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
// mem_spec is an optional hit-time memory window list. "auto" copies 64 bytes from
// each of x0-x8 that is a readable pointer (integers are skipped, at most 4 windows).
// An explicit list is "x0:64" or "x0+16:32,x2:64" (registers x0-x8 only). Empty means
// no copy. Caps match daemon/src/native_hook_args.ts: at most 4 windows, each 1..1024
// bytes, 4096 bytes total, offset 0..65535. The copy happens on the hit thread BEFORE
// the original runs, and only for hits that emit an event. A bad spec refuses the install.
//
// The ceiling used to be 192 bytes per window and 512 total, which turned out to be the wrong
// number for the case that matters: a signature preimage ("POST /path " + a body hash + the
// remaining arguments) is 1.5-2 KB, so the ONE buffer worth reading was the one the tool could not
// show. A bigger cap costs nothing until somebody asks for it - the copy is bounded by the spec the
// caller wrote, and the per-hit static cost is a 4 KB array.
// Up to six windows, but the TOTAL (4 KB) is the binding guard: a structure worth reading is often five
// or six pointers deep (a formatter descriptor carries a literal pool, an argument vector, a compiled
// program and a register bank in four separate allocations), and four windows could not express that -
// which forced a choice between "copy the bank" and "copy the argument vector", and a half-copied
// descriptor is worse than no descriptor.
#define ADH_MEM_WIN_MAX 6
#define ADH_MEM_WIN_LEN 1024
#define ADH_MEM_WIN_TOTAL 4096
#define ADH_MEM_WIN_OFF_MAX 65535

// Hard ceiling of concurrent native hooks. Lives here (not native_hooks.cpp) so the hello `caps`
// message cannot advertise a different number than the install path enforces.
#define ADH_NATIVE_MAX_HOOKS 16
// Hit-time pointer write: at most this many bytes copied into one x0-x8 argument per hit.
#define ADH_HOOK_WRITE_MAX 256

// after_spec is an optional POST-CALL memory window, same syntax as mem_spec ("x0:256" or
// "x0+16:32"), at most ONE window of 1..512 bytes. It is copied after the original returns, which is
// the only way to see what a function WROTE: a compressor's output buffer, a decrypted plaintext, a
// PRG's keystream. An empty spec keeps the fast path (a tail jump to the original); a non-empty one
// switches that hook to a stub that calls the original, records, and returns its value unchanged.
#define ADH_MEM_AFTER_MAX 512

int adh_native_hook_install(const char *mode, const char *module, const char *symbol,
                            const char *addr, int skip_original, int return_set,
                            uint64_t return_value, int arg_index, uint64_t arg_value,
                            int max_sites, const char *sites_scope, int allow_writable_slots,
                            int want_backtrace, int throttle_ms, const char *mem_spec,
                            int write_reg, int write_off, const char *write_hex,
                            int set_errno, const char *after_spec, const char *filter_spec,
                            int *hook_id_out, char *error, size_t error_size);
// hard=1 destroys the inline patch (DobbyDestroy) after a quiesce window and frees the slot;
// hard=0 keeps the soft-unhook semantics (stub stays installed but inactive).
int adh_native_hook_unhook(int hook_id, int hard, char *error, size_t error_size);
// "Is this address currently carrying one of our inline patches?" - answers for a SOFT-UNHOOKED hook
// too, because that state keeps the Dobby branch in the prologue on purpose (reactivation without a
// Dobby call). The instruction tracer has to know: QBDI follows that branch into the trampoline and
// the run never comes back to the emulator (measured: it ended at pc=0x2a and the target died with
// SIGBUS). Returns 1 and fills the id/active pair when found.
int adh_native_hook_at(uint64_t addr, int *hook_id_out, int *active_out);
int adh_native_hook_status_json(char *out, size_t out_size);

// Called by the fixed arm64 stubs. Observation-only and non-blocking.
// seq_out (may be NULL) receives the seq of the mem record this hit pushed, so a post-call copy can
// carry the SAME seq and stay joinable on (hookId, seq).
uint64_t adh_native_hook_record(uint64_t *regs, int hook_id, uint64_t *seq_out);
// Called by the site thunks: same recording, but the return value means "do not call the original"
// (set for skipOriginal and for returnSet, which both answer from the saved frame).
uint64_t adh_native_hook_record_site(uint64_t *regs, int hook_id);
// Hit counter of one slot (used by the site backend's quiesce window).
unsigned long long adh_native_hook_hits(int hook_id);

#ifdef __cplusplus
}
#endif

#endif