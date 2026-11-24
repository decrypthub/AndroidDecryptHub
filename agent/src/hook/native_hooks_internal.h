#ifndef ADH_NATIVE_HOOKS_INTERNAL_H
#define ADH_NATIVE_HOOKS_INTERNAL_H

// Shared internals for the native-hook pipeline, split across
// native_hooks_{spec,record,stubs}.cpp. Holds the context layout, shared
// state and cross-TU helpers; not a public header.

// Unified native hook manager: GOT or arm64 inline hook, with a fixed register-capture
// stub per slot. The recorder only formats a bounded JSON event and pushes it into the
// existing capture ring; no allocation or blocking happens on the target thread.
#include "native_hooks.h"
#include "native_event_budget.h"
#include "hw_watch.h"
#include "got.h"
#include "native_inline.h"
#include "site_hooks.h"
#include "slot_hooks.h"
#include "../capture/capture.h"
#include "../trace/qbdi_trace.h"

#include <android/log.h>
#include <atomic>
#include <cerrno>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <string>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

// Hit-time window fallback only. Declared here so this file does not include agent_internal.h
// (that header defines its own LOGI/TAG). Opening /proc/self/mem is the second choice: the
// first choice, process_vm_readv, does not fault and does not install a SIGSEGV handler.
extern "C" int adh_mem_fd(void);

#define TAG "rt.hook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// bootstrap/util.c + bootstrap/mem.c live in C translation units and agent_internal.h is not
// included here (its logging macros are already defined), so declare the two helpers we need.
extern "C" int hex2bytes(const char *hex, unsigned char *out, int maxlen);
extern "C" int adh_mem_write_checked(unsigned long long addr, const void *src, size_t len);

// ADH_NATIVE_MAX_HOOKS lives in native_hooks.h: the hello `caps` message and the install path must
// not be able to advertise/enforce two different ceilings.
// Caller frames captured at the hit (x30 + the x29 chain). 8 covers ordinary call depth without
// growing the event; the host symbolizes them and reports the count it actually got.

#define ADH_NATIVE_BT_MAX 8
#define ADH_TRACE_JSON_MAX 3584
// ADH_NATIVE_THROTTLE_MAX_MS (the window ceiling) lives in native_hooks.h so the install clamp, the
// command parser in agent_main.c and this file cannot drift apart.

struct NativeHookContext {
    int id;
    int active;              // 0 inactive/unused, 1 observing, 2 installation reserved
    int used;                // physical slot consumed; exposed slots never move to a different target
    int unhook_pending;      // original sites restored, but outstanding callbacks still own this slot
    int retired;             // permanent generation: a pre-entry thread may still reach the old thunk
    int exposed;
    int patches_restored;
    int mode;                // 0 got, 1 inline
    void *target;
    void *original;
    void *replacement;
    char module[128];
    char symbol[128];
    uintptr_t address;
    int skip_original;
    int return_set;
    uint64_t return_value;
    int arg_index;
    uint64_t arg_value;
    int want_backtrace;      // capture the caller chain in each event (opt-in, per hook)
    int throttle_ms;         // 0 = every hit emits; >0 = at most one event per window (per hook)
    int max_events;          // 0 = unlimited capture admission; never changes replacement behavior
    int sample_every;        // 1 = every selected hit; N = first and every Nth matching hit
    int tid_filter;          // 0 = any thread; like register filter, unmatched calls run untouched
    uint64_t return_address; // 0 = any caller; otherwise exact entry x30
    // Hit-time memory windows (x0-x8 + offset). Copied on the hitting thread before the
    // original runs. Empty when the install did not ask. Written before active=1 is published.
    struct {
        int reg;
        int offset;
        int len;
        int deref;      // 1 = follow the pointer at (reg+offset), 2 = follow a pointer inside an
                        // earlier window's copy (see from_win)
        int from_win;   // 1-based earlier window holding the pointer when deref == 2
        // An ABSOLUTE window names the address itself ("0x7443113690:32"). That is the only way to ask
        // "what does this memory hold NOW" for a buffer learned earlier (a signature's value slot, a
        // kernel structure, a decrypted blob): at the next hit no register still points at it.
        int absolute;
        unsigned long long abs_addr;
    } mem_win[ADH_MEM_WIN_MAX];
    int mem_nwin;
    char mem_spec[96];
    // Post-call memory window (optional): copied AFTER the original returns, so the caller sees what
    // the function wrote. after_arg == -1 means off. A non-empty spec makes the install pick the
    // after-stub, which calls the original instead of tail-jumping to it.
    int after_arg;
    int after_off;
    int after_len;
    char after_spec[64];
    // Hit-time register filter (optional). filter_reg < 0 means off; otherwise the hit is recorded
    // ONLY when regs[filter_reg] == filter_val. Needed because one shared dispatch site serves
    // hundreds of calls per signing (measured: 422 through the host-call thunk) while the capture
    // ring holds 128: without a filter the interesting call is usually already evicted.
    int filter_reg;
    unsigned long long filter_val;
    char filter_spec[48];
    // Hit-time pointer write (optional). write_arg == -1 means off; otherwise the bytes are copied
    // into *(regs[write_arg] + write_off) BEFORE the original runs, and only when the whole range
    // sits in a writable mapping (adh_mem_write_checked): a bad pointer must never fault the target.
    // This is what makes an out-parameter check failable - __system_property_get(name, buf),
    // access()'s errno buffer, a decrypted-key buffer handed in by the caller - without patching
    // code. Published before active=1 is stored.
    int write_arg;
    int write_off;
    int write_len;
    unsigned char write_bytes[ADH_HOOK_WRITE_MAX];
    int write_ok;                // last hit: 1 = the copy landed, 0 = refused/unmapped
    // Errno neutralization (optional). A check like access()/faccessat() answers with TWO values:
    // the return code and errno. Rewriting only the return leaves the detector with the real errno
    // ("EACCES") and some of them branch on it. Set on the hit thread on every hit; meaningful with
    // skipOriginal:true, because a running original overwrites errno with its own result.
    int errno_set;               // 0 = off, otherwise the value written to *__errno_location()
    // In-hook instruction trace (opt-in). trace_insns is the instruction budget per emitted event;
    // trace_from_reg is -1 (= start at the hooked entry) or the STUB's saved-register index of the
    // register holding the code address to start from (x0-x9 -> 0-9, x29 -> 10, x30 -> 11).
    // Published before active=1, read with a relaxed load on the hit thread.
    int trace_insns;
    int trace_from_reg;
    char trace_from[ADH_TRACE_FROM_MAX];
    // Write watch for the in-hook run (opt-in). watch_reg < 0 = off; otherwise [reg+off] (deref once when
    // watch_deref) is the watched base and watch_len its size. Resolved at the hit, so the caller names a
    // register, not an address that would be stale by then.
    int watch_reg;
    int watch_off;
    int watch_len;
    int watch_deref;
    int watch_abs;                 // 1 = the range IS watch_abs_addr (learned from an earlier hit)
    unsigned long long watch_abs_addr;
    char watch_spec[48];
    int patched;             // inline stub remains installed (soft unhook / reactivation)
    unsigned char prologue[24];   // original bytes captured before the inline patch
    int prologue_len;             // 0 when not captured / not an inline hook
    int site_count;               // mode 2: how many call sites were rewritten (mode 3: slots patched)
    char sites_scope[48];         // mode 2: where they were searched ("module" / "all" / a module name)
    // mode 0 mechanism facts. A GOT hook reports address == target == original (all three are the
    // slot's pre-patch VALUE), so without these the caller cannot tell which slot was rewritten or
    // whether the write left the page protection weakened.
    uintptr_t slot_addr;          // the relocation slot we rewrote (0 = not a got hook)
    char slot_perms_before[8];    // that slot page's permissions before the write ("" = unknown)
    uint64_t installed_at_ms;     // when this hook was (re)activated
};



// buffer can be a whole payload), so that is the one argument.
struct WinSpec {
    int reg;
    int off;
    int len;
    // A window may also name an ABSOLUTE address ("0x7443113690:32"). That is what a write watch needs
    // when the buffer was learned from a previous hit (an address, not a register): the whole point is to
    // ask "who writes THIS", and the answer must not depend on some register still holding it.
    int absolute;
    unsigned long long abs_addr;
    // 0 = plain window, 1 = follow one pointer from (reg+off), 2 = follow a pointer held INSIDE an
    // earlier window's bytes ("@#2+8:256": take window 2's copy, read the u64 at +8 in it, and copy the
    // window from THAT address).
    //
    // Why the second form has to exist: one level is not enough for the structures that matter. The
    // measured case is a printf-style formatter whose descriptor (+0x18) points at an argument VECTOR,
    // and the vector's slots point at the values being rendered. `@x2+24` reaches the vector, and then
    // the values are one hop further - unreachable, because a plain deref can only start at a register.
    // Chaining from a window's own bytes makes the second hop expressible without inventing a second
    // grammar.
    int deref;
    int from_win;   // 1-based index of the earlier window that holds the pointer (deref == 2)
};

size_t adh_json_append(char *out, size_t cap, size_t off, const char *format, ...);
uint64_t adh_mono_ns(void);
extern "C" int adh_native_hook_at(uint64_t addr, int *hook_id_out, int *active_out);
extern AdhNativeEventBudget g_native_hook_budget[ADH_NATIVE_MAX_HOOKS];
extern std::atomic<uint64_t> g_native_hook_first_hit_ms[ADH_NATIVE_MAX_HOOKS];
extern std::atomic<unsigned long long> g_native_hook_hits[ADH_NATIVE_MAX_HOOKS];
extern std::atomic<unsigned long long> g_native_hook_inflight[ADH_NATIVE_MAX_HOOKS];
extern std::atomic<unsigned long long> g_native_hook_mem_seq[ADH_NATIVE_MAX_HOOKS];
extern "C" void * g_native_hook_originals[ADH_NATIVE_MAX_HOOKS];
extern std::atomic<int> g_native_hook_slot_ids[ADH_NATIVE_MAX_HOOKS];
extern std::atomic<uint64_t> g_native_hook_throttle_last_ns[ADH_NATIVE_MAX_HOOKS];
extern std::atomic<unsigned long long> g_native_hook_throttled_reported[ADH_NATIVE_MAX_HOOKS];
extern std::atomic<unsigned long long> g_native_hook_throttled_total[ADH_NATIVE_MAX_HOOKS];
extern NativeHookContext g_native_hooks[ADH_NATIVE_MAX_HOOKS];
const char * kind_name(int hook_id);
void set_error(char *error, size_t error_size, const char *format, ...);
uint64_t wall_ms();
int format_window(char *buf, size_t n, const WinSpec *w);
void hex_encode(const unsigned char *bytes, int n, char *out);
int hook_mem_copy(uint64_t addr, unsigned char *dst, int n);
int parse_mem_spec(const char *spec, int *regs, int *offsets, int *lens, int *derefs, int *froms, unsigned long long *abs_addrs, int *is_abs, int *nout, char *canon, size_t canon_sz, char *error, size_t error_size);
int parse_window(const char **pp, int max_len, const char *label, WinSpec *w, char *error, size_t error_size);
int trace_from_stub_index(const char *spec, char *canon, size_t canon_size);
void * after_stub_for_id(int id);
void * stub_for_id(int id);
struct NativeRecorderLease {
    int slot;
    explicit NativeRecorderLease(int s) : slot(s) { g_native_hook_inflight[slot].fetch_add(1, std::memory_order_acquire); }
    ~NativeRecorderLease() { g_native_hook_inflight[slot].fetch_sub(1, std::memory_order_release); }
};
struct NativeErrnoGuard {
    int saved;
    NativeErrnoGuard() : saved(errno) {}
    ~NativeErrnoGuard() { errno = saved; }
};

#endif
