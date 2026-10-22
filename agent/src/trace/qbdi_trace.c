// QBDI instruction-level dynamic trace (module I.3). QBDI is loaded at RUNTIME via dlopen (keeps the
// base agent independent of the 6.5MB libQBDI.so — trace works if it's bundled, degrades gracefully if
// not). Headers used for types only.
//
// Two entry points share one run engine and one set of guards:
//   adh_qbdi_trace()      standalone call of a function from the command thread (trace_digest), VM
//                         created per call and the library unloaded again afterwards;
//   adh_qbdi_run_from()   in-hook run from an arbitrary pc on the TARGET thread, with a per-thread
//                         resident VM (see qbdi_trace.h for why, and what it costs).
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "qbdi_trace.h"
#include "../hook/native_hooks.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
typedef void (*p_addRange_t)(VMInstanceRef, rword, rword);
typedef uint32_t (*p_addCodeCB_t)(VMInstanceRef, InstPosition, InstCallback, void *, int);
typedef bool (*p_run_t)(VMInstanceRef, rword, rword);
typedef bool (*p_call_t)(VMInstanceRef, rword *, rword, uint32_t, ...);
typedef const InstAnalysis *(*p_getInstAnalysis_t)(VMInstanceRef, AnalysisType);
typedef void (*p_alignedFree_t)(void *);

// One resolved library. Both paths resolve the same symbol set; only the lifetime of the handle
// differs (the standalone path unloads, the in-hook path keeps it because a per-thread VM must stay
// valid between hits).
struct QbdiApi {
    void *handle;
    p_initVM_t initVM;
    p_terminateVM_t terminateVM;
    p_getGPRState_t getGPRState;
    p_allocStack_t allocateVirtualStack;
    p_addMod_t addInstrumentedModuleFromAddr;
    p_addRange_t addInstrumentedRange;
    p_addCodeCB_t addCodeCB;
    p_run_t run;
    p_call_t call;
    p_getInstAnalysis_t getInstAnalysis;
    p_alignedFree_t alignedFree;
};

static int api_load(struct QbdiApi *api, const char *libname, char *err, size_t errsz) {
    memset(api, 0, sizeof(*api));
    api->handle = dlopen(libname, RTLD_NOW);
    if (!api->handle) {
        snprintf(err, errsz, "%s not available (dlopen)", libname);
        return 0;
    }
    api->initVM = (p_initVM_t)dlsym(api->handle, "qbdi_initVM");
    api->terminateVM = (p_terminateVM_t)dlsym(api->handle, "qbdi_terminateVM");
    api->getGPRState = (p_getGPRState_t)dlsym(api->handle, "qbdi_getGPRState");
    api->allocateVirtualStack = (p_allocStack_t)dlsym(api->handle, "qbdi_allocateVirtualStack");
    api->addInstrumentedModuleFromAddr = (p_addMod_t)dlsym(api->handle, "qbdi_addInstrumentedModuleFromAddr");
    api->addInstrumentedRange = (p_addRange_t)dlsym(api->handle, "qbdi_addInstrumentedRange");
    api->addCodeCB = (p_addCodeCB_t)dlsym(api->handle, "qbdi_addCodeCB");
    api->run = (p_run_t)dlsym(api->handle, "qbdi_run");
    api->call = (p_call_t)dlsym(api->handle, "qbdi_call");
    api->getInstAnalysis = (p_getInstAnalysis_t)dlsym(api->handle, "qbdi_getInstAnalysis");
    api->alignedFree = (p_alignedFree_t)dlsym(api->handle, "qbdi_alignedFree");
    if (!api->initVM || !api->terminateVM || !api->getGPRState || !api->allocateVirtualStack ||
        !api->addInstrumentedModuleFromAddr || !api->addInstrumentedRange || !api->addCodeCB ||
        !api->run || !api->call || !api->getInstAnalysis || !api->alignedFree) {
        snprintf(err, errsz, "qbdi symbols missing");
        (void)dlclose(api->handle);
        api->handle = NULL;
        return 0;
    }
    return 1;
}

// --- executable-range snapshot -------------------------------------------------------------------
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
//
// The snapshot is now IMMUTABLE once published (a single pointer swap) because in-hook runs read it
// concurrently on target threads: the old free-and-rebuild in place would have pulled the array out
// from under a run on another thread. A rebuild happens only when the requested address is not
// covered (a module loaded after the snapshot); old snapshots are never freed, so the cost is bounded
// by "how often new code appears".
struct ExecRange { unsigned long long lo, hi; };
struct ExecMap { int n; struct ExecRange r[1]; };

static struct ExecMap *g_exec_map = NULL;      // published with release/acquire
static pthread_mutex_t g_exec_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_exec_error = 0;                   // 1 = /proc/self/maps could not be read

static struct ExecMap *build_exec_map(void) {
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return NULL;
    int cap = 256, n = 0;
    struct ExecMap *map = (struct ExecMap *)malloc(sizeof(struct ExecMap) + (size_t)(cap - 1) * sizeof(struct ExecRange));
    if (!map) { (void)fclose(m); return NULL; }
    char line[512];
    while (fgets(line, sizeof(line), m)) {
        unsigned long long lo = 0, hi = 0;
        char perms[8] = {0};
        if (sscanf(line, "%llx-%llx %7s", &lo, &hi, perms) != 3) continue;
        if (hi <= lo || perms[2] != 'x') continue;
        if (n == cap) {
            int ncap = cap * 2;
            struct ExecMap *p = (struct ExecMap *)realloc(map, sizeof(struct ExecMap) + (size_t)(ncap - 1) * sizeof(struct ExecRange));
            if (!p) break;
            map = p;
            cap = ncap;
        }
        map->r[n].lo = lo;
        map->r[n].hi = hi;
        n++;
    }
    (void)fclose(m);
    map->n = n;   // /proc/self/maps is ascending by address, so this array is already sorted
    return map;
}

static int exec_contains(const struct ExecMap *map, unsigned long long pc) {
    if (!map) return 0;
    int lo = 0, hi = map->n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (pc < map->r[mid].lo) hi = mid - 1;
        else if (pc >= map->r[mid].hi) lo = mid + 1;
        else return 1;
    }
    return 0;
}

static struct ExecMap *exec_map_current(void) {
    return __atomic_load_n(&g_exec_map, __ATOMIC_ACQUIRE);
}

// The snapshot covering `pc`, rebuilt only when it does not cover it.
static struct ExecMap *exec_map_for(unsigned long long pc) {
    struct ExecMap *map = exec_map_current();
    if (map && map->n > 0 && exec_contains(map, pc)) return map;
    pthread_mutex_lock(&g_exec_lock);
    map = exec_map_current();
    if (!map || map->n == 0 || !exec_contains(map, pc)) {
        struct ExecMap *built = build_exec_map();
        if (built && built->n > 0) {
            __atomic_store_n(&g_exec_map, built, __ATOMIC_RELEASE);
            map = built;
        } else if (built) {
            free(built);
            g_exec_error = 1;
        } else {
            g_exec_error = 1;
        }
    }
    pthread_mutex_unlock(&g_exec_lock);
    return map;
}

// --- run engine ----------------------------------------------------------------------------------

#define QTRACE_MAX 8192
struct QInsn { unsigned long long addr; char text[56]; };
// Standalone collection buffer. Kept for the command-thread path only: an in-hook run fills a small
// summary instead, because 512 KB of static array is not something to hand to every target thread.
static struct QInsn g_qtrace[QTRACE_MAX];

// Hard bound for the standalone path. The collector cap alone never stopped execution.
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

// How many distinct mnemonics the histogram tracks before it starts counting "clipped". 32 slots for
// at most 16 reported names: the ones that do not make the top 16 still have to be counted, otherwise
// a clipped histogram would silently attribute the remainder to nobody.
#define QTRACE_MNEM_SLOTS 32

struct RunCtx {
    const struct QbdiApi *api;
    struct ExecMap *map;
    int budget;
    unsigned long long deadline_ms;      // 0 = no wall-clock bound
    unsigned long long stop_pc;          // "the function returned here" (0 = none)
    unsigned long long seen;
    unsigned long long last_pc;
    unsigned long long runaway_pc;
    int budget_hit, time_hit, runaway, returned, capped;
    // Standalone sink.
    struct QInsn *insns;
    int max_insns;
    int n_insns;
    // In-hook sink.
    qbdi_summary_t *sum;
    struct { char name[ADH_QTRACE_MNEM_MAX]; int count; } mnem[QTRACE_MNEM_SLOTS];
    int nmnem;
};

// Copy instruction text into a bounded, JSON-safe field: quotes, backslashes and every non-printable
// byte become spaces, so a disassembly that contains a string literal cannot break the record.
static void sanitize_text(char *dst, size_t cap, const char *src) {
    size_t o = 0;
    if (!dst || cap == 0) return;
    if (src) {
        for (; src[o] && o + 1 < cap; o++) {
            unsigned char ch = (unsigned char)src[o];
            dst[o] = (ch < 0x20 || ch >= 0x7f) ? ' ' : (char)ch;
        }
    }
    dst[o] = 0;
}

static void mnemonic_count(struct RunCtx *c, const char *mnemonic) {
    if (!c->sum) return;
    const char *name = mnemonic ? mnemonic : "?";
    for (int i = 0; i < c->nmnem; i++) {
        if (strncmp(c->mnem[i].name, name, sizeof(c->mnem[i].name) - 1) == 0) {
            c->mnem[i].count++;
            return;
        }
    }
    if (c->nmnem < QTRACE_MNEM_SLOTS) {
        sanitize_text(c->mnem[c->nmnem].name, sizeof(c->mnem[c->nmnem].name), name);
        c->mnem[c->nmnem].count = 1;
        c->nmnem++;
    } else {
        c->sum->capped = 1;
    }
}

// One instrumented instruction. Every guard lives here so both paths get the same three bounds.
static VMAction run_step(struct RunCtx *c, VMInstanceRef vm) {
    if (!c) return QBDI_STOP;
    // Instruction budget. `seen` counts instructions actually EXECUTED, so a stop at the budget
    // reports exactly the budget instead of "budget + 1".
    if ((int)c->seen >= c->budget) {
        c->budget_hit = 1;
        return QBDI_STOP;
    }
    c->seen++;
    // Wall clock, checked every 256 instructions: clock_gettime per instruction would dominate the
    // trace itself. A run shorter than that cannot be slow enough to matter.
    if (c->deadline_ms && (c->seen & 0xff) == 0 && monotonic_ms() >= c->deadline_ms) {
        c->time_hit = 1;
        return QBDI_STOP;
    }
    const InstAnalysis *a = NULL;
    unsigned long long pc = 0;
    if (c->api && c->api->getInstAnalysis) {
        a = c->api->getInstAnalysis(vm, QBDI_ANALYSIS_INSTRUCTION | QBDI_ANALYSIS_DISASSEMBLY);
        if (a) pc = (unsigned long long)a->address;
    }
    if (pc) {
        // The function returned: stop BEFORE executing the caller's next instruction. QBDI itself may
        // also stop at the return, but relying on that alone made "did it complete" a guess.
        if (c->stop_pc && pc == c->stop_pc) {
            c->returned = 1;
            return QBDI_STOP;
        }
        // The guard is skipped only when the snapshot could not be read at all (the standalone path
        // still runs then, and the reply reports execRanges:0 so the missing guard is visible).
        if (c->map && c->map->n > 0 && !exec_contains(c->map, pc)) {
            c->runaway = 1;
            c->runaway_pc = pc;
            return QBDI_STOP;
        }
        c->last_pc = pc;
    }
    if (c->sum) {
        // QBDI's disassembly text starts with a space ("  ldr x0, [x1, #8]"), so every consumer here
        // trims before using it: taking the first token of the raw string yields an EMPTY mnemonic,
        // which showed up as a correctly-sized trace with an empty histogram.
        const char *text = a ? ((a->disassembly && a->disassembly[0]) ? a->disassembly : a->mnemonic) : NULL;
        while (text && (*text == ' ' || *text == '\t')) text++;
        if (c->sum->first_n < ADH_QTRACE_SUM_FIRST) {
            int i = c->sum->first_n++;
            c->sum->first[i].addr = pc;
            sanitize_text(c->sum->first[i].text, sizeof(c->sum->first[i].text), text);
        } else {
            c->sum->capped = 1;
        }
        // a->mnemonic is the LLVM MC opcode name (LDRWui, ADDWrs), which is not what a person reads
        // in the listing; the first token of the disassembly is. Falls back to the opcode name when
        // the disassembly was not requested/failed.
        char mnem[ADH_QTRACE_MNEM_MAX];
        int k = 0;
        while (text && text[k] && text[k] != ' ' && text[k] != '\t' && k < (int)sizeof(mnem) - 1) {
            mnem[k] = text[k];
            k++;
        }
        mnem[k] = 0;
        if (k > 0) mnemonic_count(c, mnem);
    } else if (c->insns) {
        if (c->n_insns >= c->max_insns) {
            c->capped = 1;
        } else {
            struct QInsn *r = &c->insns[c->n_insns++];
            r->addr = pc;
            const char *s = a && a->disassembly ? a->disassembly : (a && a->mnemonic ? a->mnemonic : "");
            sanitize_text(r->text, sizeof(r->text), s);
        }
    }
    return QBDI_CONTINUE;
}

// Two wrappers because QBDI hands the registration's data pointer back: the standalone path stores
// its RunCtx there, the in-hook path stores the thread VM (whose `run` points at the current ctx).
static VMAction qbdi_insn_cb(VMInstanceRef vm, GPRState *gpr, FPRState *fpr, void *data) {
    (void)gpr; (void)fpr;
    return run_step((struct RunCtx *)data, vm);
}

struct ThreadVM {
    const struct QbdiApi *api;
    VMInstanceRef vm;
    GPRState *gpr;
    uint8_t *stack;
    struct RunCtx *run;   // current run, NULL when idle
};

static VMAction qbdi_insn_cb_tv(VMInstanceRef vm, GPRState *gpr, FPRState *fpr, void *data) {
    (void)gpr; (void)fpr;
    struct ThreadVM *tv = (struct ThreadVM *)data;
    return tv ? run_step(tv->run, vm) : QBDI_STOP;
}

// Re-entrancy: one VM cannot run twice, and a traced function may itself call a hooked function.
// Thread-local, not a lock - the recorder must never serialise two target threads.
static __thread int t_qbdi_depth = 0;

// Virtual stack for an in-hook run. The traced function must NOT execute on the target thread's real
// stack: our own C frame (and the hook stub's saved registers) live below the current sp, so a
// function writing its prologue at the hit-time sp would overwrite them. 256 KB is far more than a
// formatter/hasher needs, and it is virtual memory until touched.
#define ADH_QTRACE_VSTACK 0x40000u

// --- per-thread VM (in-hook path) ----------------------------------------------------------------
//
// The VM has to survive between hits (building one per hit would cost more than the trace), and it
// must be per THREAD: a global VM plus a global lock would put every hitting thread behind one mutex
// inside the target's own call path.
static pthread_key_t g_tv_key;
static pthread_once_t g_tv_key_once = PTHREAD_ONCE_INIT;
static int g_tv_key_ok = 0;

static void tv_destroy(void *p) {
    struct ThreadVM *tv = (struct ThreadVM *)p;
    if (!tv) return;
    if (tv->stack && tv->api && tv->api->alignedFree) tv->api->alignedFree(tv->stack);
    if (tv->vm && tv->api && tv->api->terminateVM) tv->api->terminateVM(tv->vm);
    if (tv->api) {
        if (tv->api->handle) (void)dlclose(tv->api->handle);
        free((void *)tv->api);
    }
    free(tv);
}

static void tv_key_init(void) {
    g_tv_key_ok = pthread_key_create(&g_tv_key, tv_destroy) == 0;
}

static struct ThreadVM *thread_vm(char *err, size_t errsz) {
    pthread_once(&g_tv_key_once, tv_key_init);
    if (!g_tv_key_ok) {
        snprintf(err, errsz, "pthread_key_create failed for the per-thread QBDI VM");
        return NULL;
    }
    struct ThreadVM *tv = (struct ThreadVM *)pthread_getspecific(g_tv_key);
    if (tv) return tv;

    struct QbdiApi *api = (struct QbdiApi *)calloc(1, sizeof(*api));
    if (!api) {
        snprintf(err, errsz, "out of memory allocating the QBDI API table");
        return NULL;
    }
    if (!api_load(api, "libQBDI.so", err, errsz)) {
        free(api);
        return NULL;
    }
    tv = (struct ThreadVM *)calloc(1, sizeof(*tv));
    if (!tv) {
        (void)dlclose(api->handle);
        free(api);
        snprintf(err, errsz, "out of memory allocating the per-thread QBDI VM");
        return NULL;
    }
    tv->api = api;
    api->initVM(&tv->vm, NULL, NULL, (Options)0);
    if (!tv->vm) {
        snprintf(err, errsz, "qbdi_initVM failed");
        goto fail;
    }
    tv->gpr = api->getGPRState(tv->vm);
    if (!tv->gpr) {
        snprintf(err, errsz, "qbdi_getGPRState failed");
        goto fail;
    }
    if (!api->allocateVirtualStack(tv->gpr, ADH_QTRACE_VSTACK, &tv->stack) || !tv->stack) {
        snprintf(err, errsz, "qbdi_allocateVirtualStack failed");
        goto fail;
    }
    if (api->addCodeCB(tv->vm, QBDI_PREINST, qbdi_insn_cb_tv, tv, 0) == QBDI_INVALID_EVENTID) {
        snprintf(err, errsz, "qbdi_addCodeCB failed");
        goto fail;
    }
    if (pthread_setspecific(g_tv_key, tv) != 0) {
        snprintf(err, errsz, "pthread_setspecific failed for the per-thread QBDI VM");
        goto fail;
    }
    return tv;
fail:
    // The destructor owns nothing yet, so free the pieces here; a half-initialised VM must never be
    // reached by a later hit (it would be reported as "ok, 0 instructions").
    if (tv->stack && api->alignedFree) api->alignedFree(tv->stack);
    if (tv->vm) api->terminateVM(tv->vm);
    (void)dlclose(api->handle);
    free(api);
    free(tv);
    return NULL;
}

// --- in-hook run ---------------------------------------------------------------------------------

void adh_qbdi_summary_reset(qbdi_summary_t *s) {
    if (!s) return;
    memset(s, 0, sizeof(*s));
    s->stop_reason = "";
}

// Top-16-by-count view of the histogram. Insertion sort over at most 32 entries: the callback path
// must not allocate, and there is nothing asymptotic to win here.
static void summary_from_ctx(const struct RunCtx *c, qbdi_summary_t *out) {
    int order[QTRACE_MNEM_SLOTS];
    int n = c->nmnem;
    if (n > QTRACE_MNEM_SLOTS) n = QTRACE_MNEM_SLOTS;
    for (int i = 0; i < n; i++) order[i] = i;
    for (int i = 1; i < n; i++) {
        int v = order[i];
        int j = i - 1;
        while (j >= 0 && (c->mnem[order[j]].count < c->mnem[v].count ||
                          (c->mnem[order[j]].count == c->mnem[v].count && strcmp(c->mnem[order[j]].name, c->mnem[v].name) > 0))) {
            order[j + 1] = order[j];
            j--;
        }
        order[j + 1] = v;
    }
    int emit = n < ADH_QTRACE_SUM_MNEM ? n : ADH_QTRACE_SUM_MNEM;
    out->mnem_n = emit;
    for (int i = 0; i < emit; i++) {
        snprintf(out->mnemonics[i].mnemonic, sizeof(out->mnemonics[i].mnemonic), "%s", c->mnem[order[i]].name);
        out->mnemonics[i].count = c->mnem[order[i]].count;
    }
    out->capped = c->capped || out->mnem_n < n;
}

int adh_qbdi_run_from(uint64_t pc, const uint64_t *gpr, int budget, int time_ms, qbdi_summary_t *out) {
    return adh_qbdi_run_from_ex(pc, gpr, budget, time_ms, pc, out);
}

int adh_qbdi_run_from_ex(uint64_t pc, const uint64_t *gpr, int budget, int time_ms,
                         uint64_t instrument_hint, qbdi_summary_t *out) {
    if (!out) return -1;
    adh_qbdi_summary_reset(out);
    out->insns = budget;
    out->start_pc = pc;
    if (!gpr) {
        snprintf(out->error, sizeof(out->error), "no register set supplied");
        out->stop_reason = "did-not-run";
        return -1;
    }
    if (budget <= 0 || budget > ADH_QTRACE_INHOOK_MAX) {
        snprintf(out->error, sizeof(out->error), "traceInsns must be 1..%d (got %d)", ADH_QTRACE_INHOOK_MAX, budget);
        out->stop_reason = "did-not-run";
        return -1;
    }
    if (pc == 0) {
        snprintf(out->error, sizeof(out->error), "start address is null");
        out->stop_reason = "did-not-run";
        return -1;
    }
    if (t_qbdi_depth) {
        snprintf(out->error, sizeof(out->error), "already tracing on this thread (a traced function called a hooked one)");
        out->stop_reason = "reentrant";
        return -1;
    }
    struct ExecMap *map = exec_map_for(pc);
    if (!map || map->n == 0) {
        snprintf(out->error, sizeof(out->error), "no executable mapping snapshot (%s)", g_exec_error ? "/proc/self/maps unreadable" : "empty");
        out->stop_reason = "did-not-run";
        return -1;
    }
    if (!exec_contains(map, pc)) {
        snprintf(out->error, sizeof(out->error), "start address 0x%llx is not in an executable mapping", (unsigned long long)pc);
        out->stop_reason = "did-not-run";
        return -1;
    }
    struct ThreadVM *tv = thread_vm(out->error, sizeof(out->error));
    if (!tv) {
        out->stop_reason = "did-not-run";
        return -1;
    }
    const struct QbdiApi *api = tv->api;
    // Instrument the code the run will execute. The START address decides how: normally it is inside
    // a module; an inline hook's Dobby trampoline lives in an anonymous executable page, so that page
    // is added explicitly. The module holding the real function is added as well when the caller named
    // one, otherwise the run would end the instant the trampoline branches back into the function.
    // (Getting this order wrong is invisible until the run reports "executed nothing": asking QBDI to
    // instrument the HINT first answers true, so the trampoline page was never added.)
    if (!api->addInstrumentedModuleFromAddr(tv->vm, (rword)pc)) {
        uint64_t page = pc & ~(uint64_t)0xfff;
        api->addInstrumentedRange(tv->vm, (rword)page, (rword)(page + 0x1000));
    }
    if (instrument_hint && instrument_hint != pc)
        (void)api->addInstrumentedModuleFromAddr(tv->vm, (rword)instrument_hint);

    // Seed the hit's registers. x29/x30/x18 are passed in because they are what the callee would
    // actually see (frame pointer, return address, platform register). x9-x17 and x19-x28 are
    // callee-saved/scratch and must not carry stale values from a previous run: a function is
    // entitled to treat them as its own once it saved them.
    GPRState *st = tv->gpr;
    st->x0 = (rword)gpr[0]; st->x1 = (rword)gpr[1]; st->x2 = (rword)gpr[2]; st->x3 = (rword)gpr[3];
    st->x4 = (rword)gpr[4]; st->x5 = (rword)gpr[5]; st->x6 = (rword)gpr[6]; st->x7 = (rword)gpr[7];
    st->x8 = (rword)gpr[8];
    st->x9 = st->x10 = st->x11 = st->x12 = st->x13 = st->x14 = st->x15 = 0;
    st->x16 = st->x17 = 0;
    st->x18 = (rword)gpr[11];
    st->x19 = st->x20 = st->x21 = st->x22 = st->x23 = st->x24 = st->x25 = st->x26 = 0;
    st->x27 = st->x28 = 0;
    st->x29 = (rword)gpr[9];
    st->lr = (rword)gpr[10];
    st->sp = (rword)(((uintptr_t)tv->stack + ADH_QTRACE_VSTACK - 64) & ~(uintptr_t)15);
    st->nzcv = 0;
    st->pc = (rword)pc;

    struct RunCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.api = api;
    ctx.map = map;
    ctx.budget = budget;
    ctx.stop_pc = (unsigned long long)gpr[10];
    ctx.deadline_ms = monotonic_ms() + (unsigned long long)(time_ms > 0 ? time_ms : ADH_QTRACE_INHOOK_TIME_MS);
    ctx.sum = out;
    out->first_n = 0;
    out->mnem_n = 0;
    out->capped = 0;
    tv->run = &ctx;
    t_qbdi_depth++;
    bool ran = api->run(tv->vm, (rword)pc, 0);
    t_qbdi_depth--;
    tv->run = NULL;

    unsigned long long endpc = (unsigned long long)tv->gpr->pc;
    // The VM may not write the state back after a stop; a "pc" that is still the start address is
    // silence, not evidence, so it must not become the reported stopPc.
    if (endpc == pc) endpc = 0;
    out->seen = (int)ctx.seen;
    out->ok = (ctx.seen > 0 || ran) ? 1 : 0;
    if (ctx.runaway) {
        out->stop_reason = "ran-away";
        out->stop_pc = ctx.runaway_pc;
    } else if (ctx.time_hit) {
        out->stop_reason = "time-budget";
        out->stop_pc = ctx.last_pc;
    } else if (ctx.budget_hit) {
        out->stop_reason = "instruction-budget";
        out->stop_pc = ctx.last_pc;
    } else if (ctx.returned || (ctx.stop_pc && endpc == ctx.stop_pc)) {
        out->stop_reason = "completed";
        out->stop_pc = ctx.stop_pc;
        out->ok = 1;
    } else if (!ran && ctx.seen == 0) {
        out->stop_reason = "did-not-run";
        snprintf(out->error, sizeof(out->error),
                 "QBDI executed nothing at 0x%llx (the start address is not instrumentable)",
                 (unsigned long long)pc);
    } else if (endpc && !exec_contains(map, endpc)) {
        // Execution left for a mapping we did not instrument (a call into another module). The trace
        // is valid up to the transfer, and saying "left-range" keeps it from being read as "done".
        out->stop_reason = "left-range";
        out->stop_pc = endpc;
    } else {
        out->stop_reason = "completed";
        out->stop_pc = endpc ? endpc : ctx.last_pc;
    }
    summary_from_ctx(&ctx, out);
    return (int)ctx.seen;
}

// --- summary JSON --------------------------------------------------------------------------------

// JSON-safe snippet: sanitize_text already removed quotes/backslashes/control bytes.
int adh_qbdi_summary_json(const qbdi_summary_t *s, char *out, size_t cap) {
    if (!s || !out || cap < 96) return -1;
    const char *reason = (s->stop_reason && s->stop_reason[0]) ? s->stop_reason : "did-not-run";
    char errbuf[sizeof(s->error)];
    sanitize_text(errbuf, sizeof(errbuf), s->error);
    size_t off = 0;
    int n;
    if (errbuf[0]) {
        // Why there is no run is part of the answer: "did-not-run" without a reason is a dead end.
        n = snprintf(out, cap,
                     "{\"insns\":%d,\"seen\":%d,\"stopReason\":\"%s\",\"start\":\"0x%llx\",\"stopPc\":\"0x%llx\","
                     "\"capped\":%s,\"error\":\"%s\",\"mnemonics\":[",
                     s->insns, s->seen, reason, (unsigned long long)s->start_pc,
                     (unsigned long long)s->stop_pc, s->capped ? "true" : "false", errbuf);
    } else {
        n = snprintf(out, cap,
                     "{\"insns\":%d,\"seen\":%d,\"stopReason\":\"%s\",\"start\":\"0x%llx\",\"stopPc\":\"0x%llx\","
                     "\"capped\":%s,\"mnemonics\":[",
                     s->insns, s->seen, reason, (unsigned long long)s->start_pc,
                     (unsigned long long)s->stop_pc, s->capped ? "true" : "false");
    }
    if (n < 0) return -1;
    off = (size_t)n;
    for (int i = 0; i < s->mnem_n && off + 1 < cap; i++) {
        n = snprintf(out + off, cap - off, "%s{\"mnemonic\":\"%s\",\"count\":%d}",
                     i ? "," : "", s->mnemonics[i].mnemonic, s->mnemonics[i].count);
        if (n < 0 || (size_t)n >= cap - off) goto compact;
        off += (size_t)n;
    }
    n = snprintf(out + off, cap - off, "],\"first\":[");
    if (n < 0 || (size_t)n >= cap - off) goto compact;
    off += (size_t)n;
    for (int i = 0; i < s->first_n && off + 1 < cap; i++) {
        n = snprintf(out + off, cap - off, "%s\"0x%llx: %s\"",
                     i ? "," : "", (unsigned long long)s->first[i].addr, s->first[i].text);
        if (n < 0 || (size_t)n >= cap - off) goto compact;
        off += (size_t)n;
    }
    n = snprintf(out + off, cap - off, "]}");
    if (n < 0 || (size_t)n >= cap - off) goto compact;
    off += (size_t)n;
    return (int)off;
compact:
    // The instruction list is the part worth showing even when the whole object does not fit: a
    // clipped trace must arrive with the counts it kept, not as a broken record.
    n = snprintf(out, cap, "{\"insns\":%d,\"seen\":%d,\"stopReason\":\"%s\",\"start\":\"0x%llx\","
                           "\"stopPc\":\"0x%llx\",\"capped\":true,\"clipped\":true}",
                 s->insns, s->seen, reason, (unsigned long long)s->start_pc, (unsigned long long)s->stop_pc);
    return (n > 0 && (size_t)n < cap) ? n : -1;
}

// --- standalone trace (command thread) -----------------------------------------------------------

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
    // One trace at a time per thread, and every guard counter starts clean: a leftover
    // `capped`/`runaway` from a previous call would be reported against this one, which is worse than
    // not reporting at all.
    if (t_qbdi_depth) {
        snprintf(out, outsz, "\"ok\":false,\"error\":\"a trace is already running on this thread\"");
        return -1;
    }
    struct ExecMap *map = exec_map_for((unsigned long long)(uintptr_t)func);
    struct QbdiApi api;
    char apierr[128];
    if (!api_load(&api, "libQBDI.so", apierr, sizeof(apierr))) {
        snprintf(out, outsz, "\"ok\":false,\"error\":\"%s\"", apierr);
        return -1;
    }
    struct RunCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.api = &api;
    ctx.map = map;
    ctx.budget = ADH_QTRACE_BUDGET;
    ctx.deadline_ms = monotonic_ms() + ADH_QTRACE_TIME_MS;
    ctx.insns = g_qtrace;
    ctx.max_insns = QTRACE_MAX;

    VMInstanceRef vm = NULL;
    api.initVM(&vm, NULL, NULL, (Options)0);
    // Every step is checked: running on a half-initialised VM used to be reported as
    // "ok:true, count:0", which the digest could only describe as "nothing was executed".
    if (!vm) { snprintf(out, outsz, "\"ok\":false,\"error\":\"qbdi_initVM failed\""); (void)dlclose(api.handle); return -1; }
    GPRState *st = api.getGPRState(vm);
    if (!st) { snprintf(out, outsz, "\"ok\":false,\"error\":\"qbdi_getGPRState failed\""); api.terminateVM(vm); (void)dlclose(api.handle); return -1; }
    uint8_t *stack = NULL;
    if (!api.allocateVirtualStack(st, 0x100000, &stack) || !stack) {
        snprintf(out, outsz, "\"ok\":false,\"error\":\"qbdi_allocateVirtualStack failed\"");
        api.terminateVM(vm); (void)dlclose(api.handle); return -1;
    }
    if (!api.addInstrumentedModuleFromAddr(vm, (rword)(uintptr_t)func)) {
        snprintf(out, outsz, "\"ok\":false,\"error\":\"qbdi_addInstrumentedModuleFromAddr failed (module not instrumentable?)\"");
        api.alignedFree(stack); api.terminateVM(vm); (void)dlclose(api.handle); return -1;
    }
    // QBDI event IDs are opaque; zero is a valid ID (and commonly the first callback registered on a
    // fresh VM). Only the documented sentinel means registration failed.
    if (api.addCodeCB(vm, QBDI_PREINST, qbdi_insn_cb, &ctx, 0) == QBDI_INVALID_EVENTID) {
        snprintf(out, outsz, "\"ok\":false,\"error\":\"qbdi_addCodeCB failed\"");
        api.alignedFree(stack); api.terminateVM(vm); (void)dlclose(api.handle); return -1;
    }
    rword ret = 0;
    if (argc < 0) argc = 0;
    if (argc > 8) argc = 8;
    t_qbdi_depth++;
    switch (argc) {
        case 0: api.call(vm, &ret, (rword)(uintptr_t)func, 0); break;
        case 1: api.call(vm, &ret, (rword)(uintptr_t)func, 1, (rword)args[0]); break;
        case 2: api.call(vm, &ret, (rword)(uintptr_t)func, 2, (rword)args[0], (rword)args[1]); break;
        case 3: api.call(vm, &ret, (rword)(uintptr_t)func, 3, (rword)args[0], (rword)args[1], (rword)args[2]); break;
        case 4: api.call(vm, &ret, (rword)(uintptr_t)func, 4, (rword)args[0], (rword)args[1], (rword)args[2], (rword)args[3]); break;
        case 5: api.call(vm, &ret, (rword)(uintptr_t)func, 5, (rword)args[0], (rword)args[1], (rword)args[2], (rword)args[3], (rword)args[4]); break;
        case 6: api.call(vm, &ret, (rword)(uintptr_t)func, 6, (rword)args[0], (rword)args[1], (rword)args[2], (rword)args[3], (rword)args[4], (rword)args[5]); break;
        case 7: api.call(vm, &ret, (rword)(uintptr_t)func, 7, (rword)args[0], (rword)args[1], (rword)args[2], (rword)args[3], (rword)args[4], (rword)args[5], (rword)args[6]); break;
        default: api.call(vm, &ret, (rword)(uintptr_t)func, 8, (rword)args[0], (rword)args[1], (rword)args[2], (rword)args[3], (rword)args[4], (rword)args[5], (rword)args[6], (rword)args[7]); break;
    }
    t_qbdi_depth--;
    int n = ctx.n_insns;
    api.alignedFree(stack);
    api.terminateVM(vm);
    (void)dlclose(api.handle);

    // Decide how many records the reply can carry BEFORE writing the header: the record text is
    // bounded (56 bytes) so a conservative per-record estimate is enough, and the counters then
    // describe exactly the list that follows. (The old code wrote count = everything it had seen and
    // stopped emitting when the buffer filled, so the reply claimed instructions it did not carry.)
    const int PER_RECORD = 120;                       // bounded text + addr + punctuation + slack
    int fits = n;
    const int headroom = 96;                          // header + closing brackets
    if (outsz > headroom && fits > (outsz - headroom) / PER_RECORD) fits = (outsz - headroom) / PER_RECORD;
    if (fits < 0) fits = 0;
    int truncated = ctx.capped || fits < n ? 1 : 0;
    // A stopped run has no trustworthy return value: say so instead of handing back whatever x0 held
    // when the VM was halted. `stopReason` is the fact the caller acts on.
    const char *stop_reason = ctx.runaway ? "ran-away"
                             : ctx.time_hit ? "time-budget"
                             : ctx.budget_hit ? "instruction-budget" : "completed";
    int retval_valid = !ctx.runaway && !ctx.budget_hit && !ctx.time_hit;
    int o = snprintf(out, outsz,
                     "\"ok\":true,\"retval\":%llu,\"retvalValid\":%s,\"stopReason\":\"%s\","
                     "\"stopPc\":\"0x%llx\",\"budget\":%d,\"timeBudgetMs\":%d,\"execRanges\":%d,"
                     "\"count\":%d,\"seen\":%d,\"cap\":%d,\"truncated\":%s,\"insns\":[",
                     (unsigned long long)ret, retval_valid ? "true" : "false", stop_reason,
                     ctx.runaway_pc, ADH_QTRACE_BUDGET, ADH_QTRACE_TIME_MS, map ? map->n : 0,
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
