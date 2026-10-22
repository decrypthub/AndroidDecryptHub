// QBDI instruction-level dynamic trace (module I.3). QBDI is loaded at RUNTIME via
// dlopen (keeps the base agent independent of the 6.5MB libQBDI.so — trace works if
// it's bundled, degrades gracefully if not). Headers used for types only.
#include "qbdi_trace.h"
#include "../hook/native_hooks.h"

#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
// clock_gettime + CLOCK_MONOTONIC need the POSIX feature level declared before <time.h>; without it the
// wall-clock bound below would silently fail to compile into the agent.
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <time.h>
#include "QBDI/Options.h"
#include "QBDI/State.h"
#include "QBDI/Callback.h"
#include "QBDI/InstAnalysis.h"
#include "QBDI/VM_C.h"

typedef void (*p_initVM_t)(VMInstanceRef *, const char *, const char **, Options);
typedef void (*p_terminateVM_t)(VMInstanceRef);
typedef GPRState *(*p_getGPRState_t)(VMInstanceRef);
typedef bool (*p_allocStack_t)(GPRState *, uint32_t, uint8_t **);
typedef bool (*p_addMod_t)(VMInstanceRef, rword);
typedef uint32_t (*p_addCodeCB_t)(VMInstanceRef, InstPosition, InstCallback, void *, int);
typedef bool (*p_call_t)(VMInstanceRef, rword *, rword, uint32_t, ...);
typedef const InstAnalysis *(*p_getInstAnalysis_t)(VMInstanceRef, AnalysisType);
typedef void (*p_alignedFree_t)(void *);

static p_getInstAnalysis_t f_getInstAnalysis = NULL;

#define QTRACE_MAX 8192
struct QInsn { unsigned long long addr; char text[56]; };
static struct QInsn g_qtrace[QTRACE_MAX];
static int g_nqtrace = 0;
// Set when the instruction cap stopped collection: a clipped trace must say so, because the
// digest of a clipped trace looks exactly like the digest of a short one.
static int g_qtrace_capped = 0;

// --- runaway guard -----------------------------------------------------------------------------
//
// A traced function can hand control to an address that is not code. Measured on a flattened,
// obfuscated module (com.jingdong.app.mall / libjdg.so): the run ended at pc=0x2a and the PROCESS
// died with SIGBUS BUS_ADRALN - QBDI executes whatever address it is handed, faithfully. Nothing in
// the trace machinery noticed, so the first symptom was a tombstone.
//
// The guard is ours to implement: the process's executable mappings are snapshotted once, and every
// instrumented instruction's address is checked against them before it runs. An address outside them
// stops the VM and is reported (stopReason:"ran-away" + stopPc), which turns "trace killed the
// target" into "trace refused; here is where it tried to jump". The second bound is a hard
// instruction budget: the collection cap alone never stopped EXECUTION, so a long function ran to
// the end and the host timed out with nothing to show.
struct ExecRange { unsigned long long lo, hi; };
static struct ExecRange *g_exec = NULL;
static int g_exec_n = 0;
static int g_runaway = 0;
static unsigned long long g_runaway_pc = 0;
static unsigned long long g_seen = 0;
static int g_budget_hit = 0;
static int g_time_hit = 0;
static unsigned long long g_deadline_ms = 0;

#define ADH_QTRACE_BUDGET 200000
// Wall-clock bound. The instruction budget bounds the WORK, not the TIME: a synchronous interpreter
// under QBDI was measured holding the command channel for the full 60 s client timeout with the budget
// never reached, which the caller can only read as "timed out" - it cannot tell "still running" from
// "hung". A time bound turns that into a reported verdict instead of a mystery.
#define ADH_QTRACE_TIME_MS 4000

static unsigned long long monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (unsigned long long)ts.tv_sec * 1000ull + (unsigned long long)(ts.tv_nsec / 1000000);
}

static void load_exec_ranges(void) {
    free(g_exec);
    g_exec = NULL;
    g_exec_n = 0;
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return;
    char line[512];
    int cap = 0, n = 0;
    while (fgets(line, sizeof(line), m)) {
        unsigned long long lo = 0, hi = 0;
        char perms[8] = {0};
        if (sscanf(line, "%llx-%llx %7s", &lo, &hi, perms) != 3) continue;
        if (hi <= lo || perms[2] != 'x') continue;
        if (n == cap) {
            int ncap = cap ? cap * 2 : 256;
            struct ExecRange *p = (struct ExecRange *)realloc(g_exec, (size_t)ncap * sizeof(*p));
            if (!p) break;
            g_exec = p;
            cap = ncap;
        }
        g_exec[n].lo = lo;
        g_exec[n].hi = hi;
        n++;
    }
    fclose(m);
    g_exec_n = n;   // /proc/self/maps is ascending by address, so this array is already sorted
}

static int exec_contains(unsigned long long pc) {
    int lo = 0, hi = g_exec_n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (pc < g_exec[mid].lo) hi = mid - 1;
        else if (pc >= g_exec[mid].hi) lo = mid + 1;
        else return 1;
    }
    return 0;
}

static VMAction qbdi_insn_cb(VMInstanceRef vm, GPRState *gpr, FPRState *fpr, void *data) {
    (void)gpr; (void)fpr; (void)data;
    if (++g_seen > ADH_QTRACE_BUDGET) {
        g_budget_hit = 1;
        return QBDI_STOP;
    }
    // Checked every 256 instructions: clock_gettime per instruction would dominate the trace itself.
    if ((g_seen & 0xff) == 0 && g_deadline_ms && monotonic_ms() >= g_deadline_ms) {
        g_time_hit = 1;
        return QBDI_STOP;
    }
    const InstAnalysis *a = NULL;
    unsigned long long pc = 0;
    if (f_getInstAnalysis) {
        a = f_getInstAnalysis(vm, QBDI_ANALYSIS_INSTRUCTION | QBDI_ANALYSIS_DISASSEMBLY);
        if (a) pc = (unsigned long long)a->address;
    }
    if (pc && g_exec_n > 0 && !exec_contains(pc)) {
        g_runaway = 1;
        g_runaway_pc = pc;
        return QBDI_STOP;
    }
    if (g_nqtrace >= QTRACE_MAX) {
        g_qtrace_capped = 1;
        return QBDI_CONTINUE;
    }
    if (a) {
        struct QInsn *r = &g_qtrace[g_nqtrace++];
        r->addr = (unsigned long long)a->address;
        const char *s = a->disassembly ? a->disassembly : (a->mnemonic ? a->mnemonic : "");
        int o = 0; for (; s[o] && o < (int)sizeof(r->text) - 1; o++) { char c = s[o]; r->text[o] = (c == '"' || c == '\\' || c < 0x20) ? ' ' : c; }
        r->text[o] = 0;
    }
    return QBDI_CONTINUE;
}

// Trace `func` (invoked with no args) via QBDI. Writes JSON FIELDS (no outer braces)
// into out — the caller wraps them in the cmdResult object. Returns insn count / -1.
int adh_qbdi_trace(void *func, const unsigned long long *args, int argc, char *out, int outsz) {
    // Refuse a target that still carries one of our own inline patches. A SOFT unhook leaves the
    // Dobby branch in the prologue by design (that is what makes reactivation free), so the first
    // bytes QBDI sees are a jump into the hook trampoline in an anonymous executable page. QBDI
    // follows it, and the run never returns to the emulator: measured on libjdg, the trace ended at
    // pc=0x2a and the target died with SIGBUS BUS_ADRALN - with a tombstone that says nothing about
    // the real cause. Failing here names it.
    int hooked_id = 0, hooked_active = 0;
    if (adh_native_hook_at((uint64_t)(uintptr_t)func, &hooked_id, &hooked_active)) {
        snprintf(out, outsz,
                 "\"ok\":false,\"error\":\"refusing to trace: this address carries an ADH inline hook "
                 "(id %d, %s). A soft unhook leaves the Dobby branch in the prologue, so the tracer "
                 "follows it into the trampoline and the run never returns (measured: SIGBUS at "
                 "pc=0x2a, target killed). Hard-unhook it, or restart the target, then trace.\","
                 "\"hookedId\":%d,\"hookedActive\":%s",
                 hooked_id, hooked_active ? "active" : "soft-unhooked",
                 hooked_id, hooked_active ? "true" : "false");
        return -1;
    }
    // One trace at a time, and every guard counter starts clean: a leftover `capped`/`runaway` from a
    // previous call would be reported against this one, which is worse than not reporting at all.
    g_nqtrace = 0;
    g_qtrace_capped = 0;
    g_runaway = 0;
    g_runaway_pc = 0;
    g_seen = 0;
    g_budget_hit = 0;
    g_time_hit = 0;
    g_deadline_ms = monotonic_ms() + ADH_QTRACE_TIME_MS;
    load_exec_ranges();
    void *h = dlopen("libQBDI.so", RTLD_NOW);
    if (!h) { snprintf(out, outsz, "\"ok\":false,\"error\":\"libQBDI.so not available (dlopen)\""); return -1; }
    p_initVM_t f_init = (p_initVM_t)dlsym(h, "qbdi_initVM");
    p_terminateVM_t f_term = (p_terminateVM_t)dlsym(h, "qbdi_terminateVM");
    p_getGPRState_t f_gpr = (p_getGPRState_t)dlsym(h, "qbdi_getGPRState");
    p_allocStack_t f_alloc = (p_allocStack_t)dlsym(h, "qbdi_allocateVirtualStack");
    p_addMod_t f_addmod = (p_addMod_t)dlsym(h, "qbdi_addInstrumentedModuleFromAddr");
    p_addCodeCB_t f_addcb = (p_addCodeCB_t)dlsym(h, "qbdi_addCodeCB");
    p_call_t f_call = (p_call_t)dlsym(h, "qbdi_call");
    p_alignedFree_t f_free = (p_alignedFree_t)dlsym(h, "qbdi_alignedFree");
    f_getInstAnalysis = (p_getInstAnalysis_t)dlsym(h, "qbdi_getInstAnalysis");
    if (!f_init || !f_gpr || !f_alloc || !f_addmod || !f_addcb || !f_call || !f_getInstAnalysis) {
        snprintf(out, outsz, "\"ok\":false,\"error\":\"qbdi symbols missing\"");
        f_getInstAnalysis = NULL;
        dlclose(h);
        return -1;
    }

    g_nqtrace = 0;
    g_qtrace_capped = 0;
    VMInstanceRef vm = NULL;
    f_init(&vm, NULL, NULL, (Options)0);
    // Every step is checked: running on a half-initialised VM used to be reported as
    // "ok:true, count:0", which the digest could only describe as "nothing was executed".
    if (!vm) { snprintf(out, outsz, "\"ok\":false,\"error\":\"qbdi_initVM failed\""); f_getInstAnalysis = NULL; (void)dlclose(h); return -1; }
    GPRState *st = f_gpr(vm);
    if (!st) { snprintf(out, outsz, "\"ok\":false,\"error\":\"qbdi_getGPRState failed\""); if (f_term) f_term(vm); f_getInstAnalysis = NULL; (void)dlclose(h); return -1; }
    uint8_t *stack = NULL;
    if (!f_alloc(st, 0x100000, &stack) || !stack) { snprintf(out, outsz, "\"ok\":false,\"error\":\"qbdi_allocateVirtualStack failed\""); if (f_term) f_term(vm); f_getInstAnalysis = NULL; (void)dlclose(h); return -1; }
    if (!f_addmod(vm, (rword)(uintptr_t)func)) { snprintf(out, outsz, "\"ok\":false,\"error\":\"qbdi_addInstrumentedModuleFromAddr failed (module not instrumentable?)\""); if (f_free) f_free(stack); if (f_term) f_term(vm); f_getInstAnalysis = NULL; (void)dlclose(h); return -1; }
    // QBDI event IDs are opaque; zero is a valid ID (and commonly the first
    // callback registered on a fresh VM). Only the documented sentinel means
    // registration failed.
    uint32_t cb_id = f_addcb(vm, QBDI_PREINST, qbdi_insn_cb, NULL, 0);
    if (cb_id == QBDI_INVALID_EVENTID) { snprintf(out, outsz, "\"ok\":false,\"error\":\"qbdi_addCodeCB failed\""); if (f_free) f_free(stack); if (f_term) f_term(vm); f_getInstAnalysis = NULL; (void)dlclose(h); return -1; }
    rword ret = 0;
    if (argc < 0) argc = 0;
    if (argc > 8) argc = 8;
    switch (argc) {
        case 0: f_call(vm, &ret, (rword)(uintptr_t)func, 0); break;
        case 1: f_call(vm, &ret, (rword)(uintptr_t)func, 1, (rword)args[0]); break;
        case 2: f_call(vm, &ret, (rword)(uintptr_t)func, 2, (rword)args[0], (rword)args[1]); break;
        case 3: f_call(vm, &ret, (rword)(uintptr_t)func, 3, (rword)args[0], (rword)args[1], (rword)args[2]); break;
        case 4: f_call(vm, &ret, (rword)(uintptr_t)func, 4, (rword)args[0], (rword)args[1], (rword)args[2], (rword)args[3]); break;
        case 5: f_call(vm, &ret, (rword)(uintptr_t)func, 5, (rword)args[0], (rword)args[1], (rword)args[2], (rword)args[3], (rword)args[4]); break;
        case 6: f_call(vm, &ret, (rword)(uintptr_t)func, 6, (rword)args[0], (rword)args[1], (rword)args[2], (rword)args[3], (rword)args[4], (rword)args[5]); break;
        case 7: f_call(vm, &ret, (rword)(uintptr_t)func, 7, (rword)args[0], (rword)args[1], (rword)args[2], (rword)args[3], (rword)args[4], (rword)args[5], (rword)args[6]); break;
        default: f_call(vm, &ret, (rword)(uintptr_t)func, 8, (rword)args[0], (rword)args[1], (rword)args[2], (rword)args[3], (rword)args[4], (rword)args[5], (rword)args[6], (rword)args[7]); break;
    }
    int n = g_nqtrace;
    if (f_free && stack) f_free(stack);
    if (f_term) f_term(vm);
    f_getInstAnalysis = NULL;
    (void)dlclose(h);

    // Decide how many records the reply can carry BEFORE writing the header: the record text is
    // bounded (56 bytes) so a conservative per-record estimate is enough, and the counters then
    // describe exactly the list that follows. (The old code wrote count = everything it had seen and
    // stopped emitting when the buffer filled, so the reply claimed instructions it did not carry.)
    const int PER_RECORD = 120;                       // bounded text + addr + punctuation + slack
    int fits = n;
    const int headroom = 96;                          // header + closing brackets
    if (outsz > headroom && fits > (outsz - headroom) / PER_RECORD) fits = (outsz - headroom) / PER_RECORD;
    if (fits < 0) fits = 0;
    int truncated = g_qtrace_capped || fits < n ? 1 : 0;
    // A stopped run has no trustworthy return value: say so instead of handing back whatever x0 held
    // when the VM was halted. `stopReason` is the fact the caller acts on.
    const char *stop_reason = g_runaway ? "ran-away"
                             : g_time_hit ? "time-budget"
                             : g_budget_hit ? "instruction-budget" : "completed";
    int retval_valid = !g_runaway && !g_budget_hit && !g_time_hit;
    int o = snprintf(out, outsz,
                     "\"ok\":true,\"retval\":%llu,\"retvalValid\":%s,\"stopReason\":\"%s\","
                     "\"stopPc\":\"0x%llx\",\"budget\":%d,\"timeBudgetMs\":%d,\"execRanges\":%d,"
                     "\"count\":%d,\"seen\":%d,\"cap\":%d,\"truncated\":%s,\"insns\":[",
                     (unsigned long long)ret, retval_valid ? "true" : "false", stop_reason,
                     g_runaway_pc, ADH_QTRACE_BUDGET, ADH_QTRACE_TIME_MS, g_exec_n,
                     fits, n, QTRACE_MAX, truncated ? "true" : "false");
    if (o < 0 || o >= outsz) {
        snprintf(out, (size_t)(outsz > 0 ? outsz : 0), "\"ok\":false,\"error\":\"trace reply buffer too small for the header\"");
        return -1;
    }
    int emitted = 0;
    for (int i = 0; i < fits && o > 0 && o < outsz - 100; i++, emitted++)
        o += snprintf(out + o, outsz - o, "%s{\"addr\":\"%llx\",\"text\":\"%s\"}", i ? "," : "", g_qtrace[i].addr, g_qtrace[i].text);
    if (emitted < fits) truncated = 1;                // belt and braces: the array is the truth
    if (emitted < fits) {
        char fix[64];
        const char *at = strstr(out, "\"count\":");
        if (at) {
            char *list = strstr((char *)at, "\"insns\":[");
            if (list) {
                int flen = snprintf(fix, sizeof(fix), "\"count\":%d,\"seen\":%d,\"cap\":%d,\"truncated\":true,\"insns\":[",
                                    emitted, n, QTRACE_MAX);
                size_t after = (size_t)(list - out) + strlen("\"insns\":[");
                memmove(out + (size_t)(at - out) + (size_t)flen, out + after, strlen(out + after) + 1);
                memcpy(out + (size_t)(at - out), fix, (size_t)flen);
                o = (int)strlen(out);
            }
        }
    }
    snprintf(out + o, outsz - o, "]");
    return emitted;
}
