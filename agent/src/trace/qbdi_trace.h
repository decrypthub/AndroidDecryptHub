#ifndef ADH_AGENT_QBDI_TRACE_H
#define ADH_AGENT_QBDI_TRACE_H

#include <stddef.h>
#include <stdint.h>

// Called from native_hooks.cpp (C++) and trace/commands.c (C): without this the C++ callers link
// against mangled names that the C definitions never provide.
#ifdef __cplusplus
extern "C" {
#endif

int adh_qbdi_trace(void *func, const unsigned long long *args, int argc, char *out, int out_size);
// Explicit command-thread collection. One bounded recording is retained until released/replaced;
// replies carry metadata only, and qbdi_read retrieves <=128 instructions per page.
int adh_qbdi_trace_paged(void *func, const unsigned long long *args, int argc,
                         int budget, int time_ms, int capacity, char *out, int out_size);
int adh_qbdi_read(unsigned long long trace_id, int offset, int limit, int release,
                  char *out, int out_size);

// --- in-hook trace -------------------------------------------------------------------------------
//
// "Capture the arguments, then trace afterwards" is not possible on a target whose frames are
// request-scoped: by the time a second command runs, the descriptor/bank/program the hook saw has
// been released (measured on libjdg: three separate routes died that way). The only moment the state
// is live is the hit itself, so the trace has to run INSIDE the hook callback, on the target thread.
//
// What that costs is stated here rather than hidden:
//   * the traced function is EXECUTED by the emulator (that is what a trace is), so a hooked function
//     runs twice per hit - once under QBDI, once for real. Harmless for a formatter/hasher; a
//     function with side effects (allocation, I/O, a counter in the target) must not be traced.
//   * it runs on a VIRTUAL stack (QBDI's), so stack-passed arguments (x8 and beyond) and reads of
//     caller stack slots see the virtual stack, not the caller's. Register arguments are exact.
//   * FPR state is not seeded: do not in-hook trace a function whose arguments are float/vector.
//   * the QBDI VM is PER THREAD (pthread_getspecific). A global lock would serialise the target's
//     threads, which is exactly the "agent must not slow the target down" line we do not cross.
//   * a hook that hits from inside another trace (a traced function calling a hooked function) is
//     refused as "reentrant": one VM cannot run twice.

// Summary limits. `first` is the documented "show me the first N instructions" window, and the
// mnemonic histogram is the one-line answer to "what does this function mostly do".
#define ADH_QTRACE_SUM_FIRST 32
#define ADH_QTRACE_SUM_MNEM 16
#define ADH_QTRACE_TEXT_MAX 48
#define ADH_QTRACE_MNEM_MAX 12
// Ceiling for traceInsns. A hit stops the target thread for the whole run, so the request is bounded
// (the instruction budget is the first guard, not the only one). The ceiling itself is a policy number,
// not a technical one: 4096 was too small to reach past a parser into the code that follows it, and the
// wall clock (300 ms) is what actually protects the target - whichever binds first stops the run.
#define ADH_QTRACE_INHOOK_MAX 65536
// Wall clock per in-hook run. Short on purpose: this runs on a target thread at a function entry.
#define ADH_QTRACE_INHOOK_TIME_MS 300
// How many writes a single watched range may report per hit. A range that is written in a loop is worth
// seeing a few times; past this the count says so instead of the list growing without bound.
#define ADH_QTRACE_WATCH_MAX 8

// Memory-write watch for ONE range, armed only for the duration of an in-hook run.
//
// This is the software replacement for a hardware watchpoint: `perf_event_open(PERF_TYPE_BREAKPOINT)` is
// denied to app domains on the devices we use (errno 13), so "who wrote this buffer" had no answer at all -
// an instruction trace alone knows which code ran, never which store landed where. QBDI can report the
// memory accesses of every executed instruction, so the same question becomes a fact: this pc, this
// address, this value.
typedef struct {
    int count;                  // writes matched inside [lo, hi)
    int truncated;              // more than ADH_QTRACE_WATCH_MAX writes were seen
    char error[64];             // set when the watch could not be armed (never silently ignored)
    uint64_t lo, hi;            // the range as resolved on the hit thread
    struct {
        uint64_t pc;            // the instruction that wrote
        uint64_t addr;          // the address it wrote
        uint64_t value;         // what it wrote (little-endian, up to 8 bytes)
        int size;
        char insn[ADH_QTRACE_TEXT_MAX + 1];
    } hits[ADH_QTRACE_WATCH_MAX];
} qbdi_watch_t;

// stop_reason values (documented set; the device gate accepts exactly these):
//   completed           the run reached the return address (or QBDI ended it at the function's return)
//   instruction-budget  the instruction budget stopped it
//   time-budget         the wall clock stopped it
//   ran-away            the next instruction was outside every executable mapping (QBDI would have
//                       executed it faithfully; measured on a flattened module: SIGBUS at pc=0x2a)
//   left-range          execution left the instrumented module (a call into code we did not
//                       instrument); the trace is valid up to the transfer
//   did-not-run         QBDI executed nothing (the start address was not instrumentable)
//   reentrant           the hit happened inside another run on the same thread
typedef struct {
    int ok;                          // 1 = a run happened (even if a guard stopped it early)
    char error[96];                  // set when ok == 0
    int insns;                       // the budget that was requested
    int seen;                        // instructions actually executed
    int capped;                      // first[] / mnemonics[] were clipped by the summary limits
    const char *stop_reason;         // one of the values above
    uint64_t start_pc;               // where the run started (the traceFrom / entry address)
    uint64_t stop_pc;                // where it stopped (last pc for a guard, return address otherwise)
    int first_n;
    struct {
        uint64_t addr;
        char text[ADH_QTRACE_TEXT_MAX + 1];
    } first[ADH_QTRACE_SUM_FIRST];
    int mnem_n;
    struct {
        char mnemonic[ADH_QTRACE_MNEM_MAX];
        int count;
    } mnemonics[ADH_QTRACE_SUM_MNEM];
} qbdi_summary_t;

// Run from an arbitrary pc with the hit's registers, on the current thread's VM.
// gpr layout: [0..8] = x0..x8, [9] = x29 (fp), [10] = x30 (lr), [11] = x18.
// Returns the number of instructions executed, or -1 when no run happened (out->error says why).
int adh_qbdi_run_from(uint64_t pc, const uint64_t *gpr, int budget, int time_ms, qbdi_summary_t *out);

// Same, but also names the module to instrument when the start pc is NOT inside one (the Dobby
// trampoline of an inline hook lives in an anonymous executable page, so the function's own module
// has to be added explicitly - otherwise the run stops the moment the trampoline branches back into
// the function).
int adh_qbdi_run_from_ex(uint64_t pc, const uint64_t *gpr, int budget, int time_ms,
                         uint64_t instrument_hint, qbdi_summary_t *out);

// Same as _ex, plus a WRITE watch on [watch_lo, watch_hi) for the duration of this run only (the
// per-thread VM outlives the run, so the instrumentation is removed again before returning). Writes seen
// while executing fill *watch; the run itself is not shortened by them.
int adh_qbdi_run_from_watch(uint64_t pc, const uint64_t *gpr, int budget, int time_ms,
                            uint64_t instrument_hint, uint64_t watch_lo, uint64_t watch_hi,
                            qbdi_summary_t *out, qbdi_watch_t *watch);

// Reset a watch to "nothing seen" and clear its range.
void adh_qbdi_watch_reset(qbdi_watch_t *w);

// Render a watch as the JSON OBJECT a NATIVE_HOOK event carries under "traceWatch". Returns the length
// written, or -1 when it does not fit.
int adh_qbdi_watch_json(const qbdi_watch_t *w, char *out, size_t cap);

// Reset a summary to "no run yet" (insns/seen zero, stop_reason NULL).
void adh_qbdi_summary_reset(qbdi_summary_t *s);

// Render the summary as the JSON OBJECT a NATIVE_HOOK event carries under "trace". Writes at most
// cap bytes (including NUL); returns the length written, or -1 when it does not fit (the caller then
// emits a compact refusal instead of a half-written object).
int adh_qbdi_summary_json(const qbdi_summary_t *s, char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif
