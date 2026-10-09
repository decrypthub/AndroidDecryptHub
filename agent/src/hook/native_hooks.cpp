// Unified native hook manager: GOT or arm64 inline hook, with a fixed register-capture
// stub per slot. The recorder only formats a bounded JSON event and pushes it into the
// existing capture ring; no allocation or blocking happens on the target thread.
#include "native_hooks.h"
#include "got.h"
#include "native_inline.h"
#include "site_hooks.h"
#include "slot_hooks.h"
#include "../capture/capture.h"

#include <android/log.h>
#include <atomic>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <string>
#include <time.h>

#define TAG "rt.hook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#define ADH_NATIVE_MAX_HOOKS 16
// Caller frames captured at the hit (x30 + the x29 chain). 8 covers ordinary call depth without
// growing the event; the host symbolizes them and reports the count it actually got.
#define ADH_NATIVE_BT_MAX 8
// ADH_NATIVE_THROTTLE_MAX_MS (the window ceiling) lives in native_hooks.h so the install clamp, the
// command parser in agent_main.c and this file cannot drift apart.

struct NativeHookContext {
    int id;
    int active;              // 0 free, 1 active, 2 reserved
    int used;                // slots are never reused after unhook (race safety)
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

static NativeHookContext g_native_hooks[ADH_NATIVE_MAX_HOOKS];
static pthread_mutex_t g_native_hooks_lock = PTHREAD_MUTEX_INITIALIZER;

// Addresses whose prologue we restored by hand. Dobby still believes they are hooked, so a
// second DobbyHook on the same address may silently not patch: refuse it loudly instead.
#define ADH_RESTORED_MAX 8
static void *g_restored_targets[ADH_RESTORED_MAX];
static int g_restored_count = 0;

static bool target_was_hard_restored(void *target) {
    for (int i = 0; i < g_restored_count; i++) if (g_restored_targets[i] == target) return true;
    return false;
}
static void remember_hard_restored(void *target) {
    if (target_was_hard_restored(target)) return;
    if (g_restored_count < ADH_RESTORED_MAX) g_restored_targets[g_restored_count++] = target;
}
static int g_next_native_hook_id = 1;
static std::atomic<unsigned long long> g_native_hook_hits[ADH_NATIVE_MAX_HOOKS];
static std::atomic<int> g_native_hook_slot_ids[ADH_NATIVE_MAX_HOOKS];

// Per-hook event throttle state (v4.48). The recorder sits on the target thread, so this is
// lock-free and allocation-free: one relaxed timestamp load in the common case, one relaxed store
// when an event is actually emitted.
//   last_ns  - when this hook last EMITTED an event (0 = nothing emitted yet)
//   total    - hits suppressed since the hook was installed
//   reported - value of total at the previous emitted event, so the event can carry the delta
static std::atomic<uint64_t> g_native_hook_throttle_last_ns[ADH_NATIVE_MAX_HOOKS];
static std::atomic<unsigned long long> g_native_hook_throttled_total[ADH_NATIVE_MAX_HOOKS];
static std::atomic<unsigned long long> g_native_hook_throttled_reported[ADH_NATIVE_MAX_HOOKS];
// Wall-clock ms of the FIRST hit, 0 until then. The stub pays one relaxed load per hit and one
// store on the very first one, which is what turns a bare `hits:0` into an answerable question:
// "installed and never fired" is a different finding from "no traffic to observe".
static std::atomic<uint64_t> g_native_hook_first_hit_ms[ADH_NATIVE_MAX_HOOKS];

// Wall-clock milliseconds, epoch-based so the host can render the lifecycle fields directly.
static uint64_t wall_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000);
}

static int clamp_throttle_ms(int requested) {
    if (requested <= 0) return 0;
    return requested > ADH_NATIVE_THROTTLE_MAX_MS ? ADH_NATIVE_THROTTLE_MAX_MS : requested;
}

// Slot reuse / reactivation must start from a clean window: inheriting the previous hook's
// timestamp would suppress the first events of a brand new hook for no reason.
static void reset_throttle_counters(int slot) {
    if (slot < 0 || slot >= ADH_NATIVE_MAX_HOOKS) return;
    g_native_hook_throttle_last_ns[slot].store(0, std::memory_order_relaxed);
    g_native_hook_throttled_total[slot].store(0, std::memory_order_relaxed);
    g_native_hook_throttled_reported[slot].store(0, std::memory_order_relaxed);
}

// Window clock. On Android CLOCK_MONOTONIC is served from the vDSO, i.e. this is a user-space read
// and not a syscall (the same call the capture ring already makes per event). A ROM without a vDSO
// would turn each suppressed hit into one real syscall, which is the one case where throttling a
// hot site costs more than it saves - worth re-measuring on such a device, not worth a fallback
// clock here.
static uint64_t adh_mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// Referenced directly by the fixed arm64 stubs below.
extern "C" void *g_native_hook_originals[ADH_NATIVE_MAX_HOOKS] = {};

static const char *kind_name(int hook_id) {
    if (hook_id < 0 || hook_id >= ADH_NATIVE_MAX_HOOKS) return "?";
    const int mode = g_native_hooks[hook_id].mode;
    return mode == 0 ? "got" : (mode == 1 ? "inline" : (mode == 2 ? "sites" : "vtable"));
}

static void set_error(char *error, size_t error_size, const char *format, ...) {
    if (!error || !error_size) return;
    va_list ap;
    va_start(ap, format);
    vsnprintf(error, error_size, format, ap);
    va_end(ap);
    error[error_size - 1] = 0;
}

// Bounded JSON append. snprintf returns the WOULD-BE length, so adding it to the offset blindly
// walks the offset past the buffer and the next "cap - off" underflows into a huge size_t. This
// clamps at the end instead, and the caller reports the truncation rather than emitting a
// half-written event.
static size_t adh_json_append(char *out, size_t cap, size_t off, const char *format, ...) {
    if (off >= cap) return cap;
    va_list ap;
    va_start(ap, format);
    int n = vsnprintf(out + off, cap - off, format, ap);
    va_end(ap);
    if (n < 0) return cap;
    size_t next = off + (size_t)n;
    return next < cap ? next : cap;
}

// At-hit caller chain. The x29 chain must be read WHILE the hit is live: reading it later from the
// host reads a stack that the process has already reused (the first version did that and found zeros
// where the frame records had been). The current thread's stack bounds come from
// pthread_attr_getstack - cached per thread, so a bogus frame pointer can never make this read
// outside the stack.
static __thread uintptr_t t_stack_lo;
static __thread uintptr_t t_stack_hi;
static __thread int t_stack_known;

static void adh_stack_bounds_once(void) {
    if (t_stack_known) return;
    // Only latch SUCCESS: pthread_getattr_np can fail transiently, and latching that would disable
    // backtrace on this thread for the rest of the process.
    pthread_attr_t attr;
    if (pthread_getattr_np(pthread_self(), &attr) != 0) return;
    void *base = NULL;
    size_t size = 0;
    if (pthread_attr_getstack(&attr, &base, &size) == 0 && base && size) {
        t_stack_lo = (uintptr_t)base;
        t_stack_hi = (uintptr_t)base + size;
    }
    pthread_attr_destroy(&attr);
    if (t_stack_hi) t_stack_known = 1;
}

// out[0] is the immediate caller (the value x30 held at the hit); the rest come from the frame
// records. Returns the number of frames written (0 when the chain is unusable, which the host reports
// as "only the immediate caller is known" instead of inventing frames).
static int adh_walk_x29(uint64_t fp, uint64_t *out, int max) {
    adh_stack_bounds_once();
    if (!t_stack_hi) return 0;
    int n = 0;
    while (n < max && fp >= t_stack_lo && fp + 16 <= t_stack_hi) {
        uint64_t next = *(volatile uint64_t *)(uintptr_t)fp;
        uint64_t ret = *(volatile uint64_t *)(uintptr_t)(fp + 8);
        if (!ret) break;
        out[n++] = ret;
        if (next <= fp) break;
        fp = next;
    }
    return n;
}

// Called by the site thunks: same recording as the entry stubs, but the return value tells the
// thunk whether it may still call the real function (skipOriginal and returnSet both answer from
// the saved frame instead).
extern "C" uint64_t adh_native_hook_record_site(uint64_t *regs, int hook_id) {
    adh_native_hook_record(regs, hook_id);
    if (hook_id < 0 || hook_id >= ADH_NATIVE_MAX_HOOKS) return 1;
    NativeHookContext &ctx = g_native_hooks[hook_id];
    if (__atomic_load_n(&ctx.skip_original, __ATOMIC_RELAXED)) return 1;
    if (__atomic_load_n(&ctx.return_set, __ATOMIC_RELAXED)) return 1;
    return 0;
}

extern "C" unsigned long long adh_native_hook_hits(int hook_id) {
    if (hook_id < 0 || hook_id >= ADH_NATIVE_MAX_HOOKS) return 0;
    return g_native_hook_hits[hook_id].load(std::memory_order_relaxed);
}

extern "C" uint64_t adh_native_hook_record(uint64_t *regs, int hook_id) {
    if (!regs || hook_id < 0 || hook_id >= ADH_NATIVE_MAX_HOOKS) return 0;
    NativeHookContext &ctx = g_native_hooks[hook_id];
    if (__atomic_load_n(&ctx.active, __ATOMIC_ACQUIRE) != 1) return 0;

    uint64_t in0 = regs[0], in1 = regs[1], in2 = regs[2], in3 = regs[3];
    uint64_t in4 = regs[4], in5 = regs[5], in6 = regs[6], in7 = regs[7];
    uint64_t in8 = regs[8], in18 = regs[12];
    // x29/x30 were already saved by the stub ([sp,#80]) but never published. They are the frame
    // pointer and the return address AT THE HIT, i.e. exactly what a caller backtrace needs (the
    // host walks the x29 chain by reading the stack; see daemon/src/backtrace.ts).
    uint64_t in29 = regs[10], in30 = regs[11];
    int arg_index = __atomic_load_n(&ctx.arg_index, __ATOMIC_RELAXED);
    uint64_t arg_value = __atomic_load_n(&ctx.arg_value, __ATOMIC_RELAXED);
    int return_set = __atomic_load_n(&ctx.return_set, __ATOMIC_RELAXED);
    uint64_t return_value = __atomic_load_n(&ctx.return_value, __ATOMIC_RELAXED);
    int skip_original = __atomic_load_n(&ctx.skip_original, __ATOMIC_RELAXED);

    if (arg_index >= 0 && arg_index < 8) regs[arg_index] = arg_value;
    if (return_set) regs[0] = return_value;
    else if (skip_original) regs[0] = 0;

    int hook_uid = g_native_hook_slot_ids[hook_id].load(std::memory_order_relaxed);
    // No id means this slot was never published to the Host. Inventing one would hand the operator a
    // hookId that no install ever returned, so stay silent (the argument/return rewrite above has
    // already been applied either way).
    if (hook_uid <= 0) return (skip_original || return_set) ? 1 : 0;
    g_native_hook_hits[hook_id].fetch_add(1, std::memory_order_relaxed);
    if (g_native_hook_first_hit_ms[hook_id].load(std::memory_order_relaxed) == 0)
        g_native_hook_first_hit_ms[hook_id].store(wall_ms(), std::memory_order_relaxed);
    // Per-hook event throttle. The rewrite above has already been applied, so dropping the EVENT
    // never changes what the target does - it only stops a hot site (read/write/futex) from
    // overflowing the capture ring and making the digest look quiet. Suppressed hits are counted and
    // reported, so a thinned log is never mistaken for a quiet target. Best effort by design: two
    // threads can pass the window check together (one extra event), and nothing ever blocks.
    const int throttle_ms = __atomic_load_n(&ctx.throttle_ms, __ATOMIC_RELAXED);
    unsigned long long throttled = 0;
    if (throttle_ms > 0) {
        const uint64_t now = adh_mono_ns();
        const uint64_t last = g_native_hook_throttle_last_ns[hook_id].load(std::memory_order_relaxed);
        if (last != 0 && now - last < (uint64_t)throttle_ms * 1000000ull) {
            g_native_hook_throttled_total[hook_id].fetch_add(1, std::memory_order_relaxed);
            return (skip_original || return_set) ? 1 : 0;
        }
        g_native_hook_throttle_last_ns[hook_id].store(now, std::memory_order_relaxed);
        const unsigned long long total = g_native_hook_throttled_total[hook_id].load(std::memory_order_relaxed);
        // exchange, not load+store: two emitters racing here must not both claim the same delta.
        const unsigned long long seen = g_native_hook_throttled_reported[hook_id].exchange(total, std::memory_order_relaxed);
        throttled = total > seen ? total - seen : 0;
    }
    // v4.31: the stub saved q0-q7 at regs[16..31] (low/high lane per 128-bit register), so float,
    // double and vector arguments are visible too. Every lane is rendered twice - as the double
    // (d0-d7) and as the float (s0-s7) it would be - because a float argument only fills the low
    // 32 bits of its register: whichever reading is a sane finite number is the one the caller
    // actually used. High lanes stay raw hex (vector/struct arguments).
    char json[3072];
    size_t joff = 0;
    joff = adh_json_append(json, sizeof(json), joff,
                           "{\"hookId\":%d,\"kind\":\"%s\",\"throttleMs\":%d,\"throttled\":%llu,"
                           "\"x0\":\"0x%llx\",\"x1\":\"0x%llx\",\"x2\":\"0x%llx\","
                           "\"x3\":\"0x%llx\",\"x4\":\"0x%llx\",\"x5\":\"0x%llx\",\"x6\":\"0x%llx\","
                           "\"x7\":\"0x%llx\",\"x8\":\"0x%llx\",\"x18\":\"0x%llx\","
                           "\"x29\":\"0x%llx\",\"x30\":\"0x%llx\",",
                           hook_uid, kind_name(hook_id), throttle_ms, throttled,
                           (unsigned long long)in0, (unsigned long long)in1,
                           (unsigned long long)in2, (unsigned long long)in3,
                           (unsigned long long)in4, (unsigned long long)in5,
                           (unsigned long long)in6, (unsigned long long)in7,
                           (unsigned long long)in8, (unsigned long long)in18,
                           (unsigned long long)in29, (unsigned long long)in30);
    if (__atomic_load_n(&ctx.want_backtrace, __ATOMIC_RELAXED)) {
        // bt[0] is the immediate caller (what x30 held at the hit); the rest come from the x29
        // chain STARTING AT THE FRAME POINTER - walking from x30 (a code address) finds nothing,
        // which is exactly the bug the first deployment of this had.
        uint64_t bt[ADH_NATIVE_BT_MAX];
        int n = 0;
        bt[n++] = in30;
        int walked = adh_walk_x29(in29, bt + n, ADH_NATIVE_BT_MAX - n);
        n += walked;
        // Say so when WE stopped at the cap: without this the host cannot tell a complete chain from
        // a truncated one (both arrive as a full bt[] array).
        int bt_truncated = (n >= ADH_NATIVE_BT_MAX) ? 1 : 0;
        joff = adh_json_append(json, sizeof(json), joff, "\"bt\":[");
        for (int i = 0; i < n; i++) {
            joff = adh_json_append(json, sizeof(json), joff, "%s\"0x%llx\"", i ? "," : "",
                                   (unsigned long long)bt[i]);
        }
        joff = adh_json_append(json, sizeof(json), joff, "],\"btCount\":%d,\"btTruncated\":%s,",
                               n, bt_truncated ? "true" : "false");
    }
    joff = adh_json_append(json, sizeof(json), joff, "\"fp\":{");
    for (int i = 0; i < 8; i++) {
        uint64_t bits = regs[16 + i * 2];
        uint32_t low = (uint32_t)(bits & 0xffffffffu);
        double d = 0;
        float f = 0;
        memcpy(&d, &bits, sizeof(d));
        memcpy(&f, &low, sizeof(f));
        char dv[24], sv[24];
        if (std::isfinite(d) && d > -1e12 && d < 1e12) snprintf(dv, sizeof(dv), "%.6g", d);
        else snprintf(dv, sizeof(dv), "0x%016llx", (unsigned long long)bits);
        if (std::isfinite(f) && f > -1e12f && f < 1e12f) snprintf(sv, sizeof(sv), "%.6g", (double)f);
        else snprintf(sv, sizeof(sv), "0x%08x", (unsigned)low);
        joff = adh_json_append(json, sizeof(json), joff,
                               "%s\"d%d\":\"%s\",\"s%d\":\"%s\",\"q%dhi\":\"0x%llx\"",
                               i ? "," : "", i, dv, i, sv, i,
                               (unsigned long long)regs[17 + i * 2]);
    }
    joff = adh_json_append(json, sizeof(json), joff,
                           "},\"argIndex\":%d,\"argValue\":\"0x%llx\",\"skipOriginal\":%s,"
                           "\"returnSet\":%s,\"returnValue\":\"0x%llx\"}",
                           arg_index, (unsigned long long)arg_value, skip_original ? "true" : "false",
                           return_set ? "true" : "false", (unsigned long long)return_value);
    if (joff >= sizeof(json)) {
        // A half-written object is not JSON and the daemon cannot parse it, so replace it with a
        // valid event that says the record was truncated instead of pushing a broken line.
        LOGE("native hook event truncated: %zu-byte buffer exhausted", sizeof(json));
        snprintf(json, sizeof(json), "{\"hookId\":%d,\"truncated\":true,\"buffer\":%zu}",
                 hook_uid, sizeof(json));
    }
    adh_capture_push_text("NATIVE_HOOK", json);
    return (skip_original || return_set) ? 1 : 0;
}

#define ADH_NATIVE_STUB(N, OFF) \
extern "C" void adh_native_stub_##N(void) __attribute__((naked)); \
extern "C" void adh_native_stub_##N(void) { \
    __asm__ volatile( \
        "sub sp, sp, #256\n" \
        "stp x0, x1, [sp, #0]\n" \
        "stp x2, x3, [sp, #16]\n" \
        "stp x4, x5, [sp, #32]\n" \
        "stp x6, x7, [sp, #48]\n" \
        "stp x8, x9, [sp, #64]\n" \
        "stp x29, x30, [sp, #80]\n" \
        "str x18, [sp, #96]\n" \
        "stp q0, q1, [sp, #128]\n" \
        "stp q2, q3, [sp, #160]\n" \
        "stp q4, q5, [sp, #192]\n" \
        "stp q6, q7, [sp, #224]\n" \
        "mov x0, sp\n" \
        "mov x1, #" #N "\n" \
        "bl adh_native_hook_record\n" \
        "mov x16, x0\n" \
        "ldp x0, x1, [sp, #0]\n" \
        "ldp x2, x3, [sp, #16]\n" \
        "ldp x4, x5, [sp, #32]\n" \
        "ldp x6, x7, [sp, #48]\n" \
        "ldp x8, x9, [sp, #64]\n" \
        "ldp x29, x30, [sp, #80]\n" \
        "ldr x18, [sp, #96]\n" \
        "ldp q0, q1, [sp, #128]\n" \
        "ldp q2, q3, [sp, #160]\n" \
        "ldp q4, q5, [sp, #192]\n" \
        "ldp q6, q7, [sp, #224]\n" \
        "add sp, sp, #256\n" \
        "cbnz x16, 1f\n" \
        "adrp x17, g_native_hook_originals+" #OFF "\n" \
        "add x17, x17, :lo12:g_native_hook_originals+" #OFF "\n" \
        "ldr x17, [x17]\n" \
        "br x17\n" \
        "1:\n" \
        "ret\n" \
    ); \
}

ADH_NATIVE_STUB(0, 0)
ADH_NATIVE_STUB(1, 8)
ADH_NATIVE_STUB(2, 16)
ADH_NATIVE_STUB(3, 24)
ADH_NATIVE_STUB(4, 32)
ADH_NATIVE_STUB(5, 40)
ADH_NATIVE_STUB(6, 48)
ADH_NATIVE_STUB(7, 56)
ADH_NATIVE_STUB(8, 64)
ADH_NATIVE_STUB(9, 72)
ADH_NATIVE_STUB(10, 80)
ADH_NATIVE_STUB(11, 88)
ADH_NATIVE_STUB(12, 96)
ADH_NATIVE_STUB(13, 104)
ADH_NATIVE_STUB(14, 112)
ADH_NATIVE_STUB(15, 120)

static void *stub_for_id(int id) {
    switch (id) {
        case 0: return (void *)adh_native_stub_0;
        case 1: return (void *)adh_native_stub_1;
        case 2: return (void *)adh_native_stub_2;
        case 3: return (void *)adh_native_stub_3;
        case 4: return (void *)adh_native_stub_4;
        case 5: return (void *)adh_native_stub_5;
        case 6: return (void *)adh_native_stub_6;
        case 7: return (void *)adh_native_stub_7;
        case 8: return (void *)adh_native_stub_8;
        case 9: return (void *)adh_native_stub_9;
        case 10: return (void *)adh_native_stub_10;
        case 11: return (void *)adh_native_stub_11;
        case 12: return (void *)adh_native_stub_12;
        case 13: return (void *)adh_native_stub_13;
        case 14: return (void *)adh_native_stub_14;
        case 15: return (void *)adh_native_stub_15;
        default: return nullptr;
    }
}

static int find_free_slot_locked() {
    for (int i = 0; i < ADH_NATIVE_MAX_HOOKS; i++) {
        if (g_native_hooks[i].active == 0 && !g_native_hooks[i].used) return i;
    }
    return -1;
}

static NativeHookContext *find_hook_locked(int id) {
    for (int i = 0; i < ADH_NATIVE_MAX_HOOKS; i++) {
        if (g_native_hooks[i].active == 1 && g_native_hooks[i].id == id) return &g_native_hooks[i];
    }
    return nullptr;
}

static void reset_context(NativeHookContext &ctx) {
    ctx.prologue_len = 0;
    ctx.id = 0;
    ctx.active = 0;
    ctx.mode = 0;
    ctx.target = nullptr;
    ctx.original = nullptr;
    ctx.replacement = nullptr;
    ctx.module[0] = 0;
    ctx.symbol[0] = 0;
    ctx.address = 0;
    ctx.skip_original = 0;
    ctx.return_set = 0;
    ctx.return_value = 0;
    ctx.arg_index = -1;
    ctx.want_backtrace = 0;   // slot reuse must not inherit the previous hook's capture choice
    ctx.throttle_ms = 0;      // ...nor the previous hook's throttle window
    ctx.arg_value = 0;
    ctx.patched = 0;
}

static void copy_cstr(char *dst, size_t size, const char *src) {
    if (!dst || !size) return;
    if (!src) { dst[0] = 0; return; }
    strncpy(dst, src, size - 1);
    dst[size - 1] = 0;
}

extern "C" int adh_native_hook_install(const char *mode, const char *module, const char *symbol,
                                        const char *addr, int skip_original, int return_set,
                                        uint64_t return_value, int arg_index, uint64_t arg_value,
                                        int max_sites, const char *sites_scope, int allow_writable_slots,
                                        int want_backtrace, int throttle_ms, int *hook_id_out, char *error, size_t error_size) {
    if (hook_id_out) *hook_id_out = 0;
    // Effective (clamped) window: installed state and status must report what was really applied.
    const int effective_throttle_ms = clamp_throttle_ms(throttle_ms);
    if (!mode) return (set_error(error, error_size, "need mode got|inline"), 0);
    pthread_mutex_lock(&g_native_hooks_lock);
    int slot = find_free_slot_locked();
    int id = g_next_native_hook_id++;
    if (id <= 0) { g_next_native_hook_id = 1; id = g_next_native_hook_id++; }
    if (slot >= 0) {
        g_native_hooks[slot].active = 2;
        g_native_hooks[slot].used = 1;
        g_native_hooks[slot].id = id;
        g_native_hook_slot_ids[slot].store(id, std::memory_order_relaxed);
    }
    pthread_mutex_unlock(&g_native_hooks_lock);
    if (slot < 0) return (set_error(error, error_size, "too many native hooks (max %d)", ADH_NATIVE_MAX_HOOKS), 0);

    auto fail = [&](const char *message) -> int {
        pthread_mutex_lock(&g_native_hooks_lock);
        if (g_native_hooks[slot].active == 2) {
            // The slot was only RESERVED here (active==2 means it was never published, so no hit can
            // be in flight - the recorder bails out unless active==1). Hand it back instead of
            // burning it: before this, sixteen failed installs (a typo, a missing symbol, an
            // unusable address) consumed the entire budget for the lifetime of the process, and with
            // the v4.52 slot accounting those burned slots showed up as "used" as well.
            reset_context(g_native_hooks[slot]);
            g_native_hooks[slot].used = 0;
            g_native_hook_slot_ids[slot].store(0, std::memory_order_relaxed);
            g_native_hook_hits[slot].store(0ULL, std::memory_order_relaxed);
            g_native_hook_first_hit_ms[slot].store(0ULL, std::memory_order_relaxed);
        }
        pthread_mutex_unlock(&g_native_hooks_lock);
        set_error(error, error_size, "%s", message);
        return 0;
    };

    void *stub = stub_for_id(slot);
    void *target = nullptr;
    void *original = nullptr;
    int hook_mode = -1;
    // Mechanism facts only the got branch can produce; published with the rest of the context so the
    // status reply can prove what was actually rewritten.
    uintptr_t got_slot_addr = 0;
    char got_perms_before[8] = "";

    if (strcmp(mode, "got") == 0) {
        if (!module || !module[0] || !symbol || !symbol[0]) return fail("got hook needs module and symbol");
        // Prefer the relocation slot's current resolved value: imported calls (open/access/
        // ptrace/...) are not defined by the caller module, so adh_resolve_sym alone cannot
        // recover the original function pointer. Fall back to the module-defined symbol.
        void *slot_addr = nullptr;
        void *slot_value = nullptr;
        char perms_before[8] = "";
        int replaced = adh_got_replace_by_name_ex(module, symbol, stub, &slot_addr, &slot_value,
                                                  perms_before, sizeof(perms_before));
        if (replaced != 1 || !slot_addr || !slot_value) {
            g_native_hook_originals[slot] = nullptr;
            return fail(replaced == 0 ? "GOT target symbol/slot not found"
                                      : "GOT target matched multiple slots; use an exact module path");
        }
        target = slot_value;
        g_native_hook_originals[slot] = target;
        original = target;
        hook_mode = 0;
        got_slot_addr = (uintptr_t)slot_addr;
        copy_cstr(got_perms_before, sizeof(got_perms_before), perms_before);
    } else if (strcmp(mode, "inline") == 0) {
        if (addr && addr[0]) {
            target = (void *)(uintptr_t)strtoull(addr, nullptr, 0);
        } else if (module && module[0] && symbol && symbol[0]) {
            target = adh_resolve_sym(module, symbol);
        }
        if (!target) return fail("inline hook needs address or module+symbol");
        if (!adh_addr_is_executable(target)) return fail("inline target is not in an executable mapping");
        // Reuse an already-installed stub before touching Dobby. Re-hooking a patched
        // function is not reliable across Dobby versions.
        pthread_mutex_lock(&g_native_hooks_lock);
        for (int i = 0; i < ADH_NATIVE_MAX_HOOKS; i++) {
            NativeHookContext &old = g_native_hooks[i];
            if (i == slot || old.active != 0 || old.target != target || (old.mode != 1 && old.mode != 2 && old.mode != 3) || !old.replacement) continue;
            old.id = id;
            old.skip_original = skip_original ? 1 : 0;
            old.return_set = return_set ? 1 : 0;
            old.return_value = return_value;
            old.arg_index = arg_index;
            old.want_backtrace = want_backtrace ? 1 : 0;
            old.throttle_ms = effective_throttle_ms;
            old.arg_value = arg_value;
            // Reactivating a soft-unhooked target is a new hook for the operator: start its window
            // and its suppressed-hit counters from zero instead of inheriting the old run.
            reset_throttle_counters(i);
            copy_cstr(old.module, sizeof(old.module), module);
            copy_cstr(old.symbol, sizeof(old.symbol), symbol);
            old.address = (uintptr_t)target;
            g_native_hook_hits[i].store(0ULL, std::memory_order_relaxed);
            g_native_hook_first_hit_ms[i].store(0ULL, std::memory_order_relaxed);
            // This new id is about to be returned to the Host, so the events this hook emits must
            // carry it too; leaving the old value here makes status and events disagree.
            g_native_hook_slot_ids[i].store(id, std::memory_order_relaxed);
            __atomic_store_n(&old.active, 1, __ATOMIC_RELEASE);
            reset_context(g_native_hooks[slot]);
            g_native_hooks[slot].used = 0;
            pthread_mutex_unlock(&g_native_hooks_lock);
            if (hook_id_out) *hook_id_out = id;
            LOGI("native_hook reactivated id=%d target=%p", id, target);
            return 1;
        }
        pthread_mutex_unlock(&g_native_hooks_lock);
        if (target_was_hard_restored(target)) {
            return fail("target was hard-unhooked earlier in this process: its backend state is stale, restart the target before hooking it again");
        }
        // Snapshot the original prologue so a hard unhook can write it back without asking Dobby
        // to free its trampoline pool (DobbyDestroy breaks later DobbyHook calls on this build).
        unsigned char prologue[24];
        memcpy(prologue, target, sizeof(prologue));
        if (!adh_inline_hook(target, stub, &original)) return fail("inline hook installation failed");
        if (memcmp(prologue, target, 4) == 0) {
            // Dobby reported success but the entry is unchanged: never claim a hook that is not there.
            (void)adh_inline_unhook(target);
            return fail("inline patch did not change the target entry (stale backend state?)");
        }
        pthread_mutex_lock(&g_native_hooks_lock);
        memcpy(g_native_hooks[slot].prologue, prologue, sizeof(prologue));
        g_native_hooks[slot].prologue_len = (int)sizeof(prologue);
        pthread_mutex_unlock(&g_native_hooks_lock);
        g_native_hook_originals[slot] = original;
        hook_mode = 1;
    } else if (strcmp(mode, "sites") == 0) {
        if (addr && addr[0]) {
            target = (void *)(uintptr_t)strtoull(addr, nullptr, 0);
        } else if (module && module[0] && symbol && symbol[0]) {
            target = adh_resolve_sym(module, symbol);
        }
        if (!target) return fail("sites hook needs address or module+symbol");
        if (!adh_addr_is_executable(target)) return fail("sites target is not in an executable mapping");
        if (skip_original || return_set) {
            return fail("sites mode cannot replace the return value: which register carries it depends on "
                        "the target (x0/x1 or d0/d1), so skipping the call would hand the caller an "
                        "undefined value - use mode=inline (or mode=got) for skipOriginal/returnValue");
        }
        // The function itself is never written; only the BL instructions that call it are.
        original = target;
        g_native_hook_originals[slot] = target;
        hook_mode = 2;
    } else if (strcmp(mode, "vtable") == 0) {
        if (addr && addr[0]) {
            target = (void *)(uintptr_t)strtoull(addr, nullptr, 0);
        } else if (module && module[0] && symbol && symbol[0]) {
            target = adh_resolve_sym(module, symbol);
        }
        if (!target) return fail("vtable hook needs address or module+symbol");
        if (!adh_addr_is_executable(target)) return fail("vtable target is not in an executable mapping");
        if (skip_original || return_set) {
            return fail("vtable mode cannot replace the return value: which register carries it depends on "
                        "the target (x0/x1 or d0/d1) - use mode=inline for skipOriginal/returnValue");
        }
        // The function itself is never written; only data slots that point at it are.
        original = target;
        g_native_hook_originals[slot] = target;
        hook_mode = 3;
    } else {
        return fail("mode must be got, inline, sites or vtable");
    }

    // Reject a second hook on the same resolved target. Duplicate Dobby patches and
    // GOT-original bookkeeping both become ambiguous otherwise.
    int duplicate_id = 0;
    pthread_mutex_lock(&g_native_hooks_lock);
    for (int i = 0; i < ADH_NATIVE_MAX_HOOKS; i++) {
        if (i == slot || g_native_hooks[i].active != 1 || !g_native_hooks[i].target) continue;
        if (g_native_hooks[i].target == target) { duplicate_id = g_native_hooks[i].id; break; }
    }
    pthread_mutex_unlock(&g_native_hooks_lock);
    if (duplicate_id) {
        char duplicate_error[96];
        snprintf(duplicate_error, sizeof(duplicate_error), "target already hooked by id %d", duplicate_id);
        return fail(duplicate_error);
    }

    if (hook_mode == 3) {
        if (!adh_slot_hook_apply(slot, target, max_sites, sites_scope, allow_writable_slots, error, error_size)) {
            char slot_error[224];
            snprintf(slot_error, sizeof(slot_error), "%s", (error && error[0]) ? error : "vtable hook installation failed");
            return fail(slot_error);
        }
    }
    if (hook_mode == 2) {
        if (!adh_site_hook_apply(slot, target, max_sites, sites_scope, error, error_size)) {
            char site_error[192];
            snprintf(site_error, sizeof(site_error), "%s", (error && error[0]) ? error : "site hook installation failed");
            return fail(site_error);
        }
    }

    pthread_mutex_lock(&g_native_hooks_lock);
    NativeHookContext &ctx = g_native_hooks[slot];
    ctx.id = id;
    ctx.skip_original = skip_original ? 1 : 0;
    ctx.return_set = return_set ? 1 : 0;
    ctx.return_value = return_value;
    ctx.arg_index = arg_index;
    ctx.arg_value = arg_value;
    ctx.want_backtrace = want_backtrace ? 1 : 0;
    ctx.throttle_ms = effective_throttle_ms;
    ctx.mode = hook_mode;
    ctx.target = target;
    ctx.original = original;
    if (hook_mode == 2) ctx.replacement = adh_site_hook_page(slot) ? adh_site_hook_page(slot) : stub;
    else if (hook_mode == 3) ctx.replacement = adh_slot_hook_page(slot) ? adh_slot_hook_page(slot) : stub;
    else ctx.replacement = stub;
    copy_cstr(ctx.module, sizeof(ctx.module), module);
    copy_cstr(ctx.symbol, sizeof(ctx.symbol), symbol);
    ctx.address = (uintptr_t)target;
    ctx.site_count = (hook_mode == 2) ? adh_site_hook_count(slot)
                    : (hook_mode == 3 ? adh_slot_hook_count(slot) : 0);
    ctx.slot_addr = got_slot_addr;
    copy_cstr(ctx.slot_perms_before, sizeof(ctx.slot_perms_before), got_perms_before);
    ctx.installed_at_ms = wall_ms();
    copy_cstr(ctx.sites_scope, sizeof(ctx.sites_scope), (hook_mode == 2 && sites_scope) ? sites_scope : "");
    ctx.patched = (hook_mode == 1 || hook_mode == 2 || hook_mode == 3) ? 1 : 0;
    // Hard unhook frees the slot for reuse but leaves the throttle atomics behind, so clear them
    // BEFORE publishing active: otherwise the first hits of a new hook on a recycled slot could be
    // suppressed by the previous hook's timestamp (and their count wiped by this reset).
    reset_throttle_counters(slot);
    __atomic_store_n(&ctx.active, 1, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&g_native_hooks_lock);
    g_native_hook_hits[slot].store(0ULL, std::memory_order_relaxed);
    g_native_hook_first_hit_ms[slot].store(0ULL, std::memory_order_relaxed);
    if (hook_id_out) *hook_id_out = id;
    LOGI("native_hook installed id=%d mode=%s target=%p original=%p", id, mode, target, original);
    return 1;
}

// hard=1 performs a REAL inline unhook: deactivate, quiesce (wait until the hit counter stops
// moving, so nothing entered the stub/trampoline during a settle window), then DobbyDestroy the
// patch and free the slot for reuse. DobbyDestroy restores the original prologue and releases
// the trampoline - that is what removes the RWX/anon-exec footprint a soft unhook leaves behind.
// Residual race (documented, not hidden): a thread that already read the patched branch can be a
// few instructions inside the trampoline; the settle window bounds it but does not suspend
// threads, so hard unhook stays opt-in while soft unhook remains the default.
extern "C" int adh_native_hook_unhook(int hook_id, int hard, char *error, size_t error_size) {
    pthread_mutex_lock(&g_native_hooks_lock);
    NativeHookContext *ctx = find_hook_locked(hook_id);
    if (!ctx) {
        pthread_mutex_unlock(&g_native_hooks_lock);
        return (set_error(error, error_size, "no native hook with id %d", hook_id), 0);
    }
    int slot = (int)(ctx - g_native_hooks);
    if (ctx->mode == 0) {
        int restored = adh_got_replace(ctx->module, ctx->replacement, ctx->original);
        if (restored <= 0) {
            pthread_mutex_unlock(&g_native_hooks_lock);
            return (set_error(error, error_size, "native unhook failed id=%d", hook_id), 0);
        }
        g_native_hook_hits[slot].store(0ULL, std::memory_order_relaxed);
        g_native_hook_first_hit_ms[slot].store(0ULL, std::memory_order_relaxed);
        __atomic_store_n(&ctx->active, 0, __ATOMIC_RELEASE);
        reset_context(*ctx);
        ctx->used = 0;   // GOT restore is a real, safe unhook: free the slot
        pthread_mutex_unlock(&g_native_hooks_lock);
        LOGI("native_hook removed id=%d (got)", hook_id);
        return 1;
    }
    if (ctx->mode == 3) {
        // A vtable hook writes data pointers only; hard unhook = put the original pointers back.
        pthread_mutex_unlock(&g_native_hooks_lock);
        char slot_error[192] = "";
        if (!adh_slot_hook_revert(slot, slot_error, sizeof(slot_error))) {
            set_error(error, error_size, "%s", slot_error[0] ? slot_error : "vtable hook revert failed");
            return 0;
        }
        pthread_mutex_lock(&g_native_hooks_lock);
        reset_context(*ctx);
        ctx->used = 0;
        pthread_mutex_unlock(&g_native_hooks_lock);
        LOGI("native_hook hard-unhooked id=%d (vtable slots restored)", hook_id);
        return 1;
    }
    if (ctx->mode == 2) {
        // A sites hook has no Dobby state: hard unhook = write the original BLs back, verify, and
        // free the thunk page after a quiet window. Fully repeatable (re-hooking works again).
        pthread_mutex_unlock(&g_native_hooks_lock);
        char site_error[192] = "";
        if (!adh_site_hook_revert(slot, site_error, sizeof(site_error))) {
            set_error(error, error_size, "%s", site_error[0] ? site_error : "site hook revert failed");
            return 0;
        }
        pthread_mutex_lock(&g_native_hooks_lock);
        reset_context(*ctx);
        ctx->used = 0;
        pthread_mutex_unlock(&g_native_hooks_lock);
        LOGI("native_hook hard-unhooked id=%d (sites restored)", hook_id);
        return 1;
    }
    if (!ctx->patched || !ctx->target || !ctx->replacement) {
        pthread_mutex_unlock(&g_native_hooks_lock);
        return (set_error(error, error_size, "inline patch state unavailable for id=%d", hook_id), 0);
    }
    void *target = ctx->target;
    g_native_hook_hits[slot].store(0ULL, std::memory_order_relaxed);
    g_native_hook_first_hit_ms[slot].store(0ULL, std::memory_order_relaxed);
    __atomic_store_n(&ctx->active, 0, __ATOMIC_RELEASE);
    ctx->skip_original = 0;
    ctx->return_set = 0;
    ctx->arg_index = -1;
    if (!hard) {
        // Soft unhook: leave the installed stub in place, deactivated, and keep the slot
        // patched for safe reactivation (never frees a trampoline a thread may still use).
        pthread_mutex_unlock(&g_native_hooks_lock);
        LOGI("native_hook soft-unhooked id=%d target=%p", hook_id, target);
        return 1;
    }
    pthread_mutex_unlock(&g_native_hooks_lock);
    // Quiesce: the trampoline is only reachable through our stub, so a hit counter that stays
    // still for a few milliseconds means nothing entered it during that window.
    bool quiet = false;
    for (int round = 0; round < 80 && !quiet; round++) {
        unsigned long long before = g_native_hook_hits[slot].load(std::memory_order_relaxed);
        struct timespec ts = { 0, 5 * 1000 * 1000 };
        nanosleep(&ts, nullptr);
        unsigned long long after = g_native_hook_hits[slot].load(std::memory_order_relaxed);
        if (after == before && round >= 4) quiet = true;   // ~25 ms of silence before touching code
        else if (after != before) round = 0;
    }
    pthread_mutex_lock(&g_native_hooks_lock);
    unsigned char prologue[24];
    int prologue_len = ctx->prologue_len;
    memcpy(prologue, ctx->prologue, sizeof(prologue));
    pthread_mutex_unlock(&g_native_hooks_lock);
    if (prologue_len <= 0) {
        set_error(error, error_size, "no captured prologue for id=%d (cannot restore safely)", hook_id);
        return 0;
    }
    // Restore the ORIGINAL BYTES ourselves. DobbyDestroy is deliberately not used: on this Dobby
    // build it frees the trampoline pool in a way that makes the next DobbyHook crash inside
    // Dobby's own memcpy (observed on device). Leaving the pool alone keeps later hooks working;
    // the price is that this exact address cannot be re-hooked in this process (refused loudly).
    if (!adh_patch_code_bytes(target, prologue, (size_t)prologue_len)) {
        set_error(error, error_size, "failed to restore the original prologue for id=%d target=%p (hook stays patched)", hook_id, target);
        return 0;
    }
    remember_hard_restored(target);
    pthread_mutex_lock(&g_native_hooks_lock);
    void *stale_stub = ctx->replacement;
    unsigned long long stale_id = (unsigned long long)ctx->id;
    reset_context(*ctx);
    ctx->used = 0;
    pthread_mutex_unlock(&g_native_hooks_lock);
    LOGI("native_hook hard-unhooked id=%llu target=%p (quiet=%d, original bytes restored, stub=%p parked)", stale_id, target, quiet ? 1 : 0, stale_stub);
    return 1;
}

extern "C" int adh_native_hook_status_json(char *out, size_t out_size) {
    if (!out || !out_size) return 0;
    std::string hooks = "[";
    int count = 0;
    int patched_count = 0;
    // Per-mode usage: the host needs to know how much of the budget is left BEFORE it asks for a
    // batch of hooks, otherwise the 17th install just fails one symbol at a time.
    // `used` counts CONSUMED slots, not active hooks: a soft-unhooked inline hook keeps its stub
    // installed (race safety) and the slot stays burned until a hard unhook frees it, so
    // free = max - used is the number that actually matters. `active` is reported next to it.
    int by_mode[4] = {0, 0, 0, 0};
    int used_slots = 0;
    pthread_mutex_lock(&g_native_hooks_lock);
    for (int i = 0; i < ADH_NATIVE_MAX_HOOKS; i++) {
        NativeHookContext &ctx = g_native_hooks[i];
        if (ctx.used) used_slots++;
        if (ctx.active != 1) { if (ctx.patched) patched_count++; continue; }
        if (count) hooks += ",";
        if (ctx.mode >= 0 && ctx.mode < 4) by_mode[ctx.mode]++;
        unsigned long long hits = g_native_hook_hits[i].load(std::memory_order_relaxed);
        char sitebuf[1400] = "";
        if (ctx.mode == 3) {
            size_t used = snprintf(sitebuf, sizeof(sitebuf), ",\"sitesScope\":\"%s\"", ctx.sites_scope);
            if (used >= sizeof(sitebuf)) used = 0;
            adh_slot_hook_slots_json(i, sitebuf, sizeof(sitebuf), &used);
        } else if (ctx.mode == 2) {
            size_t used = snprintf(sitebuf, sizeof(sitebuf), ",\"sitesScope\":\"%s\"", ctx.sites_scope);
            if (used >= sizeof(sitebuf)) used = 0;
            adh_site_hook_sites_json(i, sitebuf, sizeof(sitebuf), &used);
        }
        // hits counts EVERY hit; throttled counts the hits whose event was suppressed inside the
        // window, so emitted events = hits - throttled and a quiet log stays explainable.
        unsigned long long throttled = g_native_hook_throttled_total[i].load(std::memory_order_relaxed);
        // mode 0 mechanism facts. address/target/original are all the slot's pre-patch VALUE for a
        // got hook, so they say nothing about which slot was touched; these do. A hook that installs
        // and never fires otherwise looks exactly like a target with no traffic to observe.
        char gotbuf[288] = "";
        if (ctx.mode == 0 && ctx.slot_addr) {
            char perms_now[8] = "?";
            adh_perms_of_addr((void *)ctx.slot_addr, perms_now, sizeof(perms_now));
            void *cur = *(void **)ctx.slot_addr;
            // got_write_slot puts the page protection back; comparing the live value with the one we
            // recorded before the write is what proves it. Leaving a RELRO page writable is a
            // footprint a target can see.
            const int prot_restored = ctx.slot_perms_before[0] != 0 &&
                                      strncmp(perms_now, ctx.slot_perms_before, 3) == 0;
            snprintf(gotbuf, sizeof(gotbuf),
                     ",\"slot\":\"0x%llx\",\"slotCurrent\":\"0x%llx\",\"pageProtRestored\":%s,"
                     "\"pagePermsBefore\":\"%s\",\"pagePermsNow\":\"%s\"",
                     (unsigned long long)ctx.slot_addr, (unsigned long long)(uintptr_t)cur,
                     prot_restored ? "true" : "false", ctx.slot_perms_before, perms_now);
        }
        // got rewrites exactly one relocation slot (its install refuses anything else); sites/vtable
        // report how many they rewrote. Inline patches a function entry rather than a slot.
        const int slots_patched = (ctx.mode == 0) ? (ctx.slot_addr ? 1 : 0) : ctx.site_count;
        const uint64_t first_hit = g_native_hook_first_hit_ms[i].load(std::memory_order_relaxed);
        const char *verdict = hits > 0 ? "fired" : "installed-never-fired";
        char item[4096];   // sitebuf is 1400 and gotbuf 288; 2048 truncated the JSON for a sites hook
        snprintf(item, sizeof(item),
                 "{\"id\":%d,\"mode\":\"%s\",\"module\":\"%s\",\"symbol\":\"%s\","
                 "\"address\":\"0x%llx\",\"target\":\"0x%llx\",\"original\":\"0x%llx\","
                 "\"replacement\":\"0x%llx\",\"hits\":%llu,\"argIndex\":%d,\"argValue\":\"0x%llx\",\"skipOriginal\":%s,\"returnSet\":%s,\"returnValue\":\"0x%llx\",\"backtrace\":%s,\"throttleMs\":%d,\"throttled\":%llu"
                 ",\"slotsPatched\":%d,\"installedAtMs\":%llu,\"firstHitMs\":%llu,\"verdict\":\"%s\""
                 "%s%s}",
                 ctx.id, ctx.mode == 0 ? "got" : (ctx.mode == 1 ? "inline" : (ctx.mode == 2 ? "sites" : "vtable")), ctx.module, ctx.symbol,
                 (unsigned long long)ctx.address, (unsigned long long)(uintptr_t)ctx.target,
                 (unsigned long long)(uintptr_t)ctx.original,
                 (unsigned long long)(uintptr_t)ctx.replacement, hits, ctx.arg_index,
                 (unsigned long long)ctx.arg_value, ctx.skip_original ? "true" : "false",
                 ctx.return_set ? "true" : "false", (unsigned long long)ctx.return_value,
                 ctx.want_backtrace ? "true" : "false", ctx.throttle_ms, throttled,
                 slots_patched, (unsigned long long)ctx.installed_at_ms, (unsigned long long)first_hit,
                 verdict, gotbuf, sitebuf);
        hooks += item;
        count++;
    }
    pthread_mutex_unlock(&g_native_hooks_lock);
    hooks += "]";
    char kept[96] = "";
    adh_site_hook_last_revert_json(kept, sizeof(kept));
    char slots[256];
    snprintf(slots, sizeof(slots),
             "\"slots\":{\"max\":%d,\"used\":%d,\"active\":%d,\"free\":%d,"
             "\"byMode\":{\"got\":%d,\"inline\":%d,\"sites\":%d,\"vtable\":%d}},",
             ADH_NATIVE_MAX_HOOKS, used_slots, count, ADH_NATIVE_MAX_HOOKS - used_slots,
             by_mode[0], by_mode[1], by_mode[2], by_mode[3]);
    std::string json = "{" + std::string(slots) +
                       "\"count\":" + std::to_string(count) + ",\"patched\":" + std::to_string(patched_count) + "," +
                       kept + "\"hooks\":" + hooks + "}";
    snprintf(out, out_size, "%s", json.c_str());
    out[out_size - 1] = 0;
    return 1;
}
