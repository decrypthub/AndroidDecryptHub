// QBDI instruction-level dynamic trace (module I.3). QBDI is loaded at RUNTIME via
// dlopen (keeps the base agent independent of the 6.5MB libQBDI.so — trace works if
// it's bundled, degrades gracefully if not). Headers used for types only.
#include "qbdi_trace.h"

#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
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

static VMAction qbdi_insn_cb(VMInstanceRef vm, GPRState *gpr, FPRState *fpr, void *data) {
    (void)gpr; (void)fpr; (void)data;
    if (g_nqtrace < QTRACE_MAX && f_getInstAnalysis) {
        const InstAnalysis *a = f_getInstAnalysis(vm, QBDI_ANALYSIS_INSTRUCTION | QBDI_ANALYSIS_DISASSEMBLY);
        if (a) {
            struct QInsn *r = &g_qtrace[g_nqtrace++];
            r->addr = (unsigned long long)a->address;
            const char *s = a->disassembly ? a->disassembly : (a->mnemonic ? a->mnemonic : "");
            int o = 0; for (; s[o] && o < (int)sizeof(r->text) - 1; o++) { char c = s[o]; r->text[o] = (c == '"' || c == '\\' || c < 0x20) ? ' ' : c; }
            r->text[o] = 0;
        }
    }
    return QBDI_CONTINUE;
}

// Trace `func` (invoked with no args) via QBDI. Writes JSON FIELDS (no outer braces)
// into out — the caller wraps them in the cmdResult object. Returns insn count / -1.
int adh_qbdi_trace(void *func, const unsigned long long *args, int argc, char *out, int outsz) {
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
    VMInstanceRef vm = NULL;
    f_init(&vm, NULL, NULL, (Options)0);
    GPRState *st = f_gpr(vm);
    uint8_t *stack = NULL;
    f_alloc(st, 0x100000, &stack);
    f_addmod(vm, (rword)(uintptr_t)func);
    f_addcb(vm, QBDI_PREINST, qbdi_insn_cb, NULL, 0);
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

    int o = snprintf(out, outsz, "\"ok\":true,\"retval\":%llu,\"count\":%d,\"insns\":[", (unsigned long long)ret, n);
    for (int i = 0; i < n && o < outsz - 100; i++)
        o += snprintf(out + o, outsz - o, "%s{\"addr\":\"%llx\",\"text\":\"%s\"}", i ? "," : "", g_qtrace[i].addr, g_qtrace[i].text);
    snprintf(out + o, outsz - o, "]");
    return n;
}
