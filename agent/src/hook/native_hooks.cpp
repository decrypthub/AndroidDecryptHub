// Native hooks: shared state, helpers, install/unhook/status and slot mgmt.
// Spec parsing, event recording and trampolines live in native_hooks_{spec,record,stubs}.cpp.

#include "native_hooks_internal.h"

 NativeHookContext g_native_hooks[ADH_NATIVE_MAX_HOOKS];
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
 std::atomic<unsigned long long> g_native_hook_hits[ADH_NATIVE_MAX_HOOKS];
 std::atomic<int> g_native_hook_slot_ids[ADH_NATIVE_MAX_HOOKS];
 AdhNativeEventBudget g_native_hook_budget[ADH_NATIVE_MAX_HOOKS];
// A site/vtable thunk CALLS the original, so it can still be a live return address after the
// recorder itself finished. Its shared epilogue releases this lease only after the original returns.
 std::atomic<unsigned long long> g_native_hook_inflight[ADH_NATIVE_MAX_HOOKS];

// Per-hook event throttle state (v4.48). The recorder sits on the target thread, so this is
// lock-free and allocation-free: one relaxed timestamp load in the common case, one relaxed store
// when an event is actually emitted.
//   last_ns  - when this hook last EMITTED an event (0 = nothing emitted yet)
//   total    - hits suppressed since the hook was installed
//   reported - value of total at the previous emitted event, so the event can carry the delta
 std::atomic<uint64_t> g_native_hook_throttle_last_ns[ADH_NATIVE_MAX_HOOKS];
 std::atomic<unsigned long long> g_native_hook_throttled_total[ADH_NATIVE_MAX_HOOKS];
 std::atomic<unsigned long long> g_native_hook_throttled_reported[ADH_NATIVE_MAX_HOOKS];
// Wall-clock ms of the FIRST hit, 0 until then. The stub pays one relaxed load per hit and one
// store on the very first one, which is what turns a bare `hits:0` into an answerable question:
// "installed and never fired" is a different finding from "no traffic to observe".
 std::atomic<uint64_t> g_native_hook_first_hit_ms[ADH_NATIVE_MAX_HOOKS];
// Pairs a NATIVE_HOOK event with its NATIVE_HOOK_MEM companion. Incremented only when an
// event is actually emitted and the hook has windows, so a throttled hit does not advance it.
 std::atomic<unsigned long long> g_native_hook_mem_seq[ADH_NATIVE_MAX_HOOKS];

// Wall-clock milliseconds, epoch-based so the host can render the lifecycle fields directly.
 uint64_t wall_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000);
}

static int clamp_throttle_ms(int requested) {
    if (requested <= 0) return 0;
    return requested > ADH_NATIVE_THROTTLE_MAX_MS ? ADH_NATIVE_THROTTLE_MAX_MS : requested;
}

// A virgin slot or same-target soft-inline reactivation starts from a clean window: inheriting the previous hook's
// timestamp would suppress the first events of a brand new hook for no reason.
static void reset_throttle_counters(int slot) {
    if (slot < 0 || slot >= ADH_NATIVE_MAX_HOOKS) return;
    g_native_hook_throttle_last_ns[slot].store(0, std::memory_order_relaxed);
    g_native_hook_throttled_total[slot].store(0, std::memory_order_relaxed);
    g_native_hook_throttled_reported[slot].store(0, std::memory_order_relaxed);
    g_native_hook_mem_seq[slot].store(0, std::memory_order_relaxed);
    g_native_hook_budget[slot].reset();
}

// Window clock. On Android CLOCK_MONOTONIC is served from the vDSO, i.e. this is a user-space read
// and not a syscall (the same call the capture ring already makes per event). A ROM without a vDSO
// would turn each suppressed hit into one real syscall, which is the one case where throttling a
// hot site costs more than it saves - worth re-measuring on such a device, not worth a fallback
// clock here.
 uint64_t adh_mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// Referenced directly by the fixed arm64 stubs below.
extern "C" void *g_native_hook_originals[ADH_NATIVE_MAX_HOOKS] = {};

 const char *kind_name(int hook_id) {
    if (hook_id < 0 || hook_id >= ADH_NATIVE_MAX_HOOKS) return "?";
    const int mode = g_native_hooks[hook_id].mode;
    return mode == 0 ? "got" : (mode == 1 ? "inline" : (mode == 2 ? "sites" : "vtable"));
}

 void set_error(char *error, size_t error_size, const char *format, ...) {
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
 size_t adh_json_append(char *out, size_t cap, size_t off, const char *format, ...) {
    if (off >= cap) return cap;
    va_list ap;
    va_start(ap, format);
    int n = vsnprintf(out + off, cap - off, format, ap);
    va_end(ap);
    if (n < 0) return cap;
    size_t next = off + (size_t)n;
    return next < cap ? next : cap;
}

// Event JSON budget for the optional trace sub-object: 32 first instructions at up to 48 characters,
// 16 mnemonic counters and the header come to ~3 KB worst case. The register object is ~1 KB, so the
// event buffer below is sized as 3072 + this.

// `traceFrom` ("x0".."x9", "x29", "x30") -> the index of that register in the stub's saved bank.
// The stub saves x0-x9 at regs[0..9], x29 at regs[10], x30 at regs[11] and x18 at regs[12]; the real
// sp at regs[32] and x19-x28 at regs[33..42]. traceFrom names only the argument bank, so a request for
// another register is refused instead of reading a stale slot.
// Returns -1 for "not given", -2 for a bad name.
static int find_free_slot_locked() {
    for (int i = 0; i < ADH_NATIVE_MAX_HOOKS; i++) {
        if (g_native_hooks[i].active == 0 && !g_native_hooks[i].used) return i;
    }
    return -1;
}

static NativeHookContext *find_hook_locked(int id) {
    for (int i = 0; i < ADH_NATIVE_MAX_HOOKS; i++) {
        // Keyed on `used`, not on `active`. A soft-unhooked hook is inactive but still occupies a slot
        // and still carries our patch, so keying on active made it un-hookable by id: status could not
        // even list it before, and after it could be listed it still answered "no native hook with id
        // N". Retired slots remain addressable by id for idempotent restore/status; they are not reclaimed.
        if (g_native_hooks[i].used && g_native_hooks[i].id == id) return &g_native_hooks[i];
    }
    return nullptr;
}

static void reset_context(NativeHookContext &ctx) {
    ctx.prologue_len = 0;
    ctx.id = 0;
    ctx.active = 0;
    ctx.unhook_pending = 0;
    ctx.retired = 0;
    ctx.exposed = 0;
    ctx.patches_restored = 0;
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
    ctx.write_arg = -1;
    ctx.write_off = 0;
    ctx.write_len = 0;
    ctx.write_ok = 0;
    memset(ctx.write_bytes, 0, sizeof(ctx.write_bytes));
    ctx.errno_set = 0;
    ctx.want_backtrace = 0;   // an unexposed reservation must not inherit stale configuration
    ctx.throttle_ms = 0;      // ...nor the previous hook's throttle window
    ctx.max_events = 0;
    ctx.sample_every = 1;
    ctx.tid_filter = 0;
    ctx.return_address = 0;
    ctx.mem_nwin = 0;         // ...nor the previous hook's memory windows
    ctx.mem_spec[0] = 0;
    memset(ctx.mem_win, 0, sizeof(ctx.mem_win));
    ctx.after_arg = -1;       // ...nor its post-call window
    ctx.after_off = 0;
    ctx.after_len = 0;
    ctx.after_spec[0] = 0;
    ctx.filter_reg = -1;      // ...nor its hit-time register filter
    ctx.filter_val = 0;
    ctx.filter_spec[0] = 0;
    ctx.trace_insns = 0;      // ...nor its in-hook trace: a recycled slot must not trace unasked
    ctx.trace_from_reg = -1;
    ctx.trace_from[0] = 0;
    ctx.watch_reg = -1;       // ...nor its write watch
    ctx.watch_off = 0;
    ctx.watch_len = 0;
    ctx.watch_deref = 0;
    ctx.watch_abs = 0;
    ctx.watch_abs_addr = 0;
    ctx.watch_spec[0] = 0;
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
                                        int want_backtrace, int throttle_ms, const char *mem_spec,
                                        int write_reg, int write_off, const char *write_hex,
                                        int set_errno, const char *after_spec,
                                        const char *filter_spec,
                                        int trace_insns, const char *trace_from, const char *trace_watch,
                                        int max_events, int sample_every, int tid_filter, const char *return_address,
                                        int *hook_id_out, char *error, size_t error_size) {
    if (hook_id_out) *hook_id_out = 0;
    // Effective (clamped) window: installed state and status must report what was really applied.
    const int effective_throttle_ms = clamp_throttle_ms(throttle_ms);
    if (after_spec && after_spec[0] && mode &&
        (strcmp(mode, "sites") == 0 || strcmp(mode, "vtable") == 0)) {
        set_error(error, error_size, "memAfter requires mode=inline or got; sites/vtable do not use the after stub");
        return 0;
    }
    if (max_events < 0 || max_events > ADH_NATIVE_EVENT_LIMIT_MAX ||
        sample_every < 1 || sample_every > ADH_NATIVE_EVENT_LIMIT_MAX || tid_filter < 0) {
        set_error(error, error_size, "maxEvents must be 0..%d, sampleEvery 1..%d, tid >= 0",
                  ADH_NATIVE_EVENT_LIMIT_MAX, ADH_NATIVE_EVENT_LIMIT_MAX);
        return 0;
    }
    uint64_t caller_filter = 0;
    if (return_address && return_address[0]) {
        char *end = nullptr;
        errno = 0;
        caller_filter = strtoull(return_address, &end, 16);
        if (errno || end == return_address || *end || !caller_filter || return_address[0] == '-') {
            set_error(error, error_size, "returnAddress must be a nonzero hexadecimal entry x30 address");
            return 0;
        }
    }
    if (set_errno < 0 || set_errno > 4095) {
        set_error(error, error_size, "errno must be 0 (off) or 1..4095");
        return 0;
    }
    // In-hook trace, validated BEFORE a slot is reserved like every other option (a typo must not
    // burn one of the sixteen slots). 0 means off and is the default: no key, no cost.
    if (trace_insns < 0 || trace_insns > ADH_QTRACE_INHOOK_MAX) {
        set_error(error, error_size, "traceInsns must be 0 (off) or 1..%d", ADH_QTRACE_INHOOK_MAX);
        return 0;
    }
    int trace_from_reg = -1;
    char trace_from_canon[ADH_TRACE_FROM_MAX] = "";
    if (trace_from && trace_from[0]) {
        if (trace_insns <= 0) {
            set_error(error, error_size, "traceFrom needs traceInsns (nothing would read that register)");
            return 0;
        }
        trace_from_reg = trace_from_stub_index(trace_from, trace_from_canon, sizeof(trace_from_canon));
        if (trace_from_reg == -2) {
            set_error(error, error_size, "traceFrom must be a register holding a code address: x0..x9, x29 or x30");
            return 0;
        }
    }
    if (trace_insns > 0 && (skip_original || return_set)) {
        // The tracer EXECUTES the traced function (that is what a trace is). These two options exist
        // to prevent exactly that, so combining them would silently undo what the caller asked for.
        set_error(error, error_size,
                  "traceInsns cannot be combined with skipOriginal/returnSet: the trace runs the "
                  "original function, which those options are there to prevent");
        return 0;
    }
    // Write watch for the run: the same window grammar as `mem` (a register, an optional signed offset
    // and an optional one-level dereference), because the caller knows a register, not an address.
    int watch_reg = -1, watch_off = 0, watch_len = 0, watch_deref = 0;
    int watch_abs = 0;
    unsigned long long watch_abs_addr = 0;
    char watch_canon[48] = "";
    if (trace_watch && trace_watch[0]) {
        if (trace_insns <= 0) {
            set_error(error, error_size, "traceWatch needs traceInsns (the watch lives for the run only)");
            return 0;
        }
        WinSpec w;
        const char *wp = trace_watch;
        while (*wp == ' ') wp++;
        if (!parse_window(&wp, ADH_WATCH_LEN_MAX, "traceWatch", &w, error, error_size)) return 0;
        while (*wp == ' ') wp++;
        if (*wp) {
            set_error(error, error_size, "traceWatch must be exactly one window, e.g. x0:32");
            return 0;
        }
        watch_reg = w.absolute ? -1 : w.reg;
        watch_off = w.off;
        watch_len = w.len;
        watch_deref = w.deref ? 1 : 0;
        watch_abs = w.absolute;
        watch_abs_addr = w.abs_addr;
        format_window(watch_canon, sizeof(watch_canon), &w);
    }
    // Hit-time register filter: "x2=0x7320abc0" or "x2=4660". Validated BEFORE a slot is reserved, so
    // a typo cannot burn one of the sixteen slots. A non-matching hit is not counted and not
    // recorded, which is what keeps a shared dispatch site's event stream to the interesting calls.
    int filter_reg = -1;
    unsigned long long filter_val = 0;
    char filter_canon[48] = "";
    if (filter_spec && filter_spec[0]) {
        const char *fp = filter_spec;
        while (*fp == ' ') fp++;
        if (fp[0] != 'x' || fp[1] < '0' || fp[1] > '8' || fp[2] != '=') {
            set_error(error, error_size, "filter must look like x2=0x7320abc0 or x2=4660");
            return 0;
        }
        filter_reg = fp[1] - '0';
        fp += 3;
        char *fend = nullptr;
        filter_val = strtoull(fp, &fend, 0);
        if (fend == fp) {
            set_error(error, error_size, "filter value must be a number");
            return 0;
        }
        while (*fend == ' ') fend++;
        if (*fend) {
            set_error(error, error_size, "filter must be exactly one reg=value pair");
            return 0;
        }
        snprintf(filter_canon, sizeof(filter_canon), "x%d=0x%llx", filter_reg, filter_val);
    }
    // Hit-time pointer write. Validated BEFORE a slot is reserved, so a typo cannot burn one of the
    // sixteen slots (and cannot install a hook that silently does not do what was asked).
    unsigned char write_bytes[ADH_HOOK_WRITE_MAX];
    int write_len = 0;
    const char *write_canon = "";
    if (write_hex && write_hex[0]) {
        if (write_reg < 0 || write_reg > 8) {
            set_error(error, error_size, "writeReg must be x0..x8 when writeHex is set");
            return 0;
        }
        if (write_off < 0 || write_off > ADH_MEM_WIN_OFF_MAX) {
            set_error(error, error_size, "writeOff must be 0..%d", ADH_MEM_WIN_OFF_MAX);
            return 0;
        }
        write_len = hex2bytes(write_hex, write_bytes, (int)sizeof(write_bytes));
        if (write_len <= 0) {
            set_error(error, error_size, "writeHex must be 1..%d bytes of even-length hex", ADH_HOOK_WRITE_MAX);
            return 0;
        }
        write_canon = write_hex;
    } else if (write_reg >= 0) {
        set_error(error, error_size, "writeReg is set but writeHex is empty (nothing to write)");
        return 0;
    }
    // Refuse a bad window list before a slot is reserved. An install that drops the windows
    // and still returns ok would look like the bytes were simply never touched.
    int mem_regs[ADH_MEM_WIN_MAX];
    int mem_offs[ADH_MEM_WIN_MAX];
    int mem_lens[ADH_MEM_WIN_MAX];
    int mem_derefs[ADH_MEM_WIN_MAX];
    int mem_froms[ADH_MEM_WIN_MAX];
    int mem_is_abs[ADH_MEM_WIN_MAX];
    unsigned long long mem_abs[ADH_MEM_WIN_MAX];
    int mem_nwin = 0;
    char mem_canon[96];
    if (!parse_mem_spec(mem_spec, mem_regs, mem_offs, mem_lens, mem_derefs, mem_froms, mem_abs, mem_is_abs,
                        &mem_nwin, mem_canon, sizeof(mem_canon), error, error_size))
        return 0;
    // Post-call window: exactly one, same syntax, no "auto" (after the call the "pointer-like"
    // guess is meaningless - the caller names the buffer the function wrote into).
    int after_reg = -1, after_off = 0, after_len = 0;
    char after_canon[64] = "";
    if (after_spec && after_spec[0]) {
        // Same grammar as `mem`, with two differences that are the caller's to choose: there is
        // exactly ONE window (the buffer the function wrote into), and its ceiling is
        // ADH_MEM_AFTER_MAX rather than ADH_MEM_WIN_LEN - an output buffer can be a whole payload,
        // while a per-hit `mem` window is copied on every call. `auto` is refused here: after the
        // call the "pointer-like" guess is meaningless.
        const char *p = after_spec;
        while (*p == ' ') p++;
        if (!strncmp(p, "auto", 4)) {
            set_error(error, error_size, "memAfter must be exactly one window, e.g. x0:256");
            return 0;
        }
        WinSpec w;
        if (!parse_window(&p, ADH_MEM_AFTER_MAX, "memAfter", &w, error, error_size)) return 0;
        if (w.absolute) {
            set_error(error, error_size, "memAfter starts at a register (x0:256); an absolute address is only accepted by traceWatch");
            return 0;
        }
        while (*p == ' ') p++;
        if (*p != 0) {
            set_error(error, error_size, "memAfter must be exactly one window, e.g. x0:256");
            return 0;
        }
        after_reg = w.reg;
        after_off = w.off;
        after_len = w.len;
        format_window(after_canon, sizeof(after_canon), &w);
    }
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
    if (slot < 0) return (set_error(error, error_size, "native hook slot budget exhausted (max %d); retired slots cannot be reused until a new target process", ADH_NATIVE_MAX_HOOKS), 0);

    auto fail = [&](const char *message) -> int {
        pthread_mutex_lock(&g_native_hooks_lock);
        if (g_native_hooks[slot].active == 2) {
            const int is_site = strcmp(mode, "sites") == 0, is_slot = strcmp(mode, "vtable") == 0;
            const int retained = is_site ? adh_site_hook_retained_pages(slot) : is_slot ? adh_slot_hook_retained_pages(slot) : 0;
            if (retained) {
                NativeHookContext &failed = g_native_hooks[slot];
                failed.mode=is_site?2:3; failed.target=g_native_hook_originals[slot]; failed.original=failed.target;
                failed.replacement=is_site?adh_site_hook_page(slot):adh_slot_hook_page(slot);
                failed.site_count=is_site?adh_site_hook_count(slot):adh_slot_hook_count(slot);
                failed.retired=1; failed.patched=0;
                failed.unhook_pending=!(is_site?adh_site_hook_patches_restored(slot):adh_slot_hook_patches_restored(slot));
                copy_cstr(failed.module,sizeof(failed.module),module); copy_cstr(failed.symbol,sizeof(failed.symbol),symbol);
                failed.address=(uintptr_t)failed.target;
                __atomic_store_n(&failed.active,0,__ATOMIC_RELEASE);
                if (hook_id_out) *hook_id_out=id;
            } else if (g_native_hooks[slot].exposed) {
                NativeHookContext &failed=g_native_hooks[slot];
                failed.retired=1; failed.unhook_pending=!failed.patches_restored;
                __atomic_store_n(&failed.active,0,__ATOMIC_RELEASE);
                if(hook_id_out)*hook_id_out=id;
            } else {
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
        }
        pthread_mutex_unlock(&g_native_hooks_lock);
        set_error(error, error_size, "%s", message);
        return 0;
    };

    void *stub = after_len > 0 ? after_stub_for_id(slot) : stub_for_id(slot);
    // One line that makes the post-call window observable: it says whether the after spec actually
    // reached install (a silent drop on the way from the daemon showed up as "install ok but no
    // after record"), which stub was chosen, and the parsed register/offset/length it will copy.
    LOGI("native_hook install id=%d slot=%d mode=%s stub=%s afterSpec=\"%s\" arg=%d off=%d len=%d filter=\"%s\"",
         id, slot, mode ? mode : "", after_len > 0 ? "after" : "pre", after_canon,
         after_reg, after_off, after_len, filter_canon);
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
        int replaced = adh_got_unique_slot(module, symbol, &slot_addr, &slot_value);
        if (replaced != 1 || !slot_addr || !slot_value) {
            return fail(replaced == 0 ? "GOT target symbol/slot not found"
                                      : "GOT target matched multiple slots; use an exact module path");
        }
        pthread_mutex_lock(&g_native_hooks_lock);
        int conflict=0;
        for(int i=0;i<ADH_NATIVE_MAX_HOOKS;i++) if(i!=slot&&g_native_hooks[i].active==1&&
            (g_native_hooks[i].target==slot_value||g_native_hooks[i].slot_addr==(uintptr_t)slot_addr)){conflict=g_native_hooks[i].id;break;}
        pthread_mutex_unlock(&g_native_hooks_lock);
        if(conflict)return fail("GOT slot or target is already hooked");
        adh_perms_of_addr(slot_addr,perms_before,sizeof(perms_before));
        target = slot_value;
        g_native_hook_originals[slot] = target;
        original = target;
        hook_mode = 0;
        got_slot_addr = (uintptr_t)slot_addr;
        copy_cstr(got_perms_before, sizeof(got_perms_before), perms_before);
        NativeHookContext &pending=g_native_hooks[slot];
        pending.mode=0;pending.target=target;pending.original=original;pending.replacement=stub;
        pending.address=(uintptr_t)target;pending.slot_addr=got_slot_addr;pending.exposed=1;
        copy_cstr(pending.module,sizeof(pending.module),module);copy_cstr(pending.symbol,sizeof(pending.symbol),symbol);
        if(!adh_swap_pointer_in_ro_page((void **)slot_addr,stub)){
            pending.patches_restored=adh_swap_pointer_in_ro_page((void **)slot_addr,target)&&*(void **)slot_addr==target;
            return fail("GOT publication failed; exposed slot retained for process lifetime");
        }
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
            if (old.retired) continue;
            // Post-call and plain hooks use DIFFERENT stubs, and the installed one cannot be swapped
            // without touching Dobby again. Only reuse the slot when the shape matches; otherwise let
            // the normal install path report that this target is already patched.
            if ((after_len > 0) != (old.after_len > 0)) continue;
            if (old.unhook_pending) {
                pthread_mutex_unlock(&g_native_hooks_lock);
                return fail("previous unhook is pending; retry unhook before installing again");
            }
            if (adh_native_hook_inflight(i) != 0) {
                pthread_mutex_unlock(&g_native_hooks_lock);
                return fail("previous hook callback is still in flight; retry reactivation after it finishes");
            }
            old.id = id;
            old.skip_original = skip_original ? 1 : 0;
            old.return_set = return_set ? 1 : 0;
            old.return_value = return_value;
            old.arg_index = arg_index;
            old.write_arg = write_len > 0 ? write_reg : -1;
            old.write_off = write_off;
            old.write_len = write_len;
            if (write_len > 0) memcpy(old.write_bytes, write_bytes, (size_t)write_len);
            else memset(old.write_bytes, 0, sizeof(old.write_bytes));
            old.write_ok = 0;
            old.errno_set = set_errno;
            old.want_backtrace = want_backtrace ? 1 : 0;
            old.throttle_ms = effective_throttle_ms;
            old.max_events = max_events;
            old.sample_every = sample_every;
            old.tid_filter = tid_filter;
            old.return_address = caller_filter;
            old.mem_nwin = mem_nwin;
            memset(old.mem_win, 0, sizeof(old.mem_win));
            for (int w = 0; w < mem_nwin; w++) {
                old.mem_win[w].reg = mem_regs[w];
                old.mem_win[w].offset = mem_offs[w];
                old.mem_win[w].len = mem_lens[w];
                old.mem_win[w].deref = mem_derefs[w];
                old.mem_win[w].from_win = mem_froms[w];
                old.mem_win[w].absolute = mem_is_abs[w];
                old.mem_win[w].abs_addr = mem_abs[w];
            }
            copy_cstr(old.mem_spec, sizeof(old.mem_spec), mem_canon);
            // The post-call window and the hit-time filter must be re-applied too. They used to be
            // left at the previous run's values, so "soft unhook then hook again with a different
            // memAfter/filter" silently kept observing the old thing.
            old.after_arg = after_reg;
            old.after_off = after_off;
            old.after_len = after_len;
            copy_cstr(old.after_spec, sizeof(old.after_spec), after_canon);
            old.filter_reg = filter_reg;
            old.filter_val = filter_val;
            copy_cstr(old.filter_spec, sizeof(old.filter_spec), filter_canon);
            // The trace request belongs to this install too: reactivating an old target with a new
            // traceInsns must not keep tracing (or stop tracing) because of the previous run.
            old.trace_insns = trace_insns;
            old.trace_from_reg = trace_from_reg;
            copy_cstr(old.trace_from, sizeof(old.trace_from), trace_from_canon);
            old.watch_reg = watch_reg;
            old.watch_off = watch_off;
            old.watch_len = watch_len;
            old.watch_deref = watch_deref;
            old.watch_abs = watch_abs;
            old.watch_abs_addr = watch_abs_addr;
            copy_cstr(old.watch_spec, sizeof(old.watch_spec), watch_canon);
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
        pthread_mutex_lock(&g_native_hooks_lock);
        int existing_active=0, existing_retired=0;
        for(int i=0;i<ADH_NATIVE_MAX_HOOKS;i++) if(i!=slot&&g_native_hooks[i].target==target){
            if(g_native_hooks[i].active==1)existing_active=1;
            if(g_native_hooks[i].retired&&g_native_hooks[i].mode==1)existing_retired=1;
        }
        pthread_mutex_unlock(&g_native_hooks_lock);
        if(existing_active)return fail("target already hooked; no second inline patch was attempted");
        if(existing_retired)return fail("target was hard-unhooked earlier in this process; its retired backend cannot be reinstalled");
        if (target_was_hard_restored(target)) {
            return fail("target was hard-unhooked earlier in this process: its backend state is stale, restart the target before hooking it again");
        }
        // Snapshot the original prologue so a hard unhook can write it back without asking Dobby
        // to free its trampoline pool (DobbyDestroy breaks later DobbyHook calls on this build).
        unsigned char prologue[24];
        memcpy(prologue, target, sizeof(prologue));
        NativeHookContext &pending=g_native_hooks[slot];
        pending.mode=1;pending.target=target;pending.replacement=stub;pending.exposed=1;
        pending.address=(uintptr_t)target;pending.prologue_len=(int)sizeof(prologue);
        memcpy(pending.prologue,prologue,sizeof(prologue));
        copy_cstr(pending.module,sizeof(pending.module),module);copy_cstr(pending.symbol,sizeof(pending.symbol),symbol);
        int installed=adh_inline_hook(target,stub,&g_native_hook_originals[slot]);
        original=g_native_hook_originals[slot];pending.original=original;
        if(!installed){pending.patches_restored=memcmp(prologue,target,sizeof(prologue))==0;return fail("inline hook installation failed; attempted slot retained");}
        if (memcmp(prologue, target, 4) == 0) {
            // Dobby reported success but the entry is unchanged: never claim a hook that is not there.
            pending.patches_restored=1;
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
    ctx.write_arg = write_len > 0 ? write_reg : -1;
    ctx.write_off = write_off;
    ctx.write_len = write_len;
    if (write_len > 0) memcpy(ctx.write_bytes, write_bytes, (size_t)write_len);
    else memset(ctx.write_bytes, 0, sizeof(ctx.write_bytes));
    ctx.write_ok = 0;
    ctx.errno_set = set_errno;
    ctx.want_backtrace = want_backtrace ? 1 : 0;
    ctx.throttle_ms = effective_throttle_ms;
    ctx.max_events = max_events;
    ctx.sample_every = sample_every;
    ctx.tid_filter = tid_filter;
    ctx.return_address = caller_filter;
    ctx.mem_nwin = mem_nwin;
    ctx.filter_reg = filter_reg;
    ctx.filter_val = filter_val;
    copy_cstr(ctx.filter_spec, sizeof(ctx.filter_spec), filter_canon);
    ctx.trace_insns = trace_insns;
    ctx.trace_from_reg = trace_from_reg;
    copy_cstr(ctx.trace_from, sizeof(ctx.trace_from), trace_from_canon);
    ctx.watch_reg = watch_reg;
    ctx.watch_off = watch_off;
    ctx.watch_len = watch_len;
    ctx.watch_deref = watch_deref;
    ctx.watch_abs = watch_abs;
    ctx.watch_abs_addr = watch_abs_addr;
    copy_cstr(ctx.watch_spec, sizeof(ctx.watch_spec), watch_canon);
    memset(ctx.mem_win, 0, sizeof(ctx.mem_win));
    for (int w = 0; w < mem_nwin; w++) {
        ctx.mem_win[w].reg = mem_regs[w];
        ctx.mem_win[w].offset = mem_offs[w];
        ctx.mem_win[w].len = mem_lens[w];
        ctx.mem_win[w].deref = mem_derefs[w];
        ctx.mem_win[w].from_win = mem_froms[w];
        ctx.mem_win[w].absolute = mem_is_abs[w];
        ctx.mem_win[w].abs_addr = mem_abs[w];
    }
    copy_cstr(ctx.mem_spec, sizeof(ctx.mem_spec), mem_canon);
    ctx.after_arg = after_reg;
    ctx.after_off = after_off;
    ctx.after_len = after_len;
    copy_cstr(ctx.after_spec, sizeof(ctx.after_spec), after_canon);
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
    ctx.exposed = 1;
    ctx.patches_restored = 0;
    // Initialize the virgin physical slot BEFORE publishing active. Exposed retired slots never
    // reach this path; only same-target soft-inline reactivation uses its existing backend above.
    reset_throttle_counters(slot);
    g_native_hook_hits[slot].store(0ULL, std::memory_order_relaxed);
    g_native_hook_first_hit_ms[slot].store(0ULL, std::memory_order_relaxed);
    // The post-call path resolves the external id through this map (adh_native_hook_after looks up
    // g_native_hook_slot_ids[slot] and bails when it is <= 0). A FIRST-time install used to leave it
    // at 0 - only the reset and the reactivate paths wrote it - so `memAfter` silently produced no
    // record while the pre-call record (which takes the id straight from the stub) looked fine.
    g_native_hook_slot_ids[slot].store(id, std::memory_order_relaxed);
    __atomic_store_n(&ctx.active, 1, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&g_native_hooks_lock);
    if (hook_id_out) *hook_id_out = id;
    LOGI("native_hook installed id=%d mode=%s target=%p original=%p", id, mode, target, original);
    return 1;
}

// Hard-inline, GOT, sites and vtable unhook restore the published entry/slot/call-site bytes and
// retire the physical context until process exit. Quiet counters never prove reclamation safe:
// a thread can pause before entry accounting. We retain stubs, original pointers and backend pages.
// Only soft-inline may reactivate the SAME target/backend, without an absolute observation-generation
// boundary for a paused thread. The fixed 16-slot budget includes both active and retired contexts.
extern "C" int adh_native_hook_at(uint64_t addr, int *hook_id_out, int *active_out) {
    if (hook_id_out) *hook_id_out = 0;
    if (active_out) *active_out = 0;
    if (addr == 0) return 0;
    pthread_mutex_lock(&g_native_hooks_lock);
    for (int i = 0; i < ADH_NATIVE_MAX_HOOKS; i++) {
        NativeHookContext &c = g_native_hooks[i];
        // NOT keyed on `active`: the soft-unhooked state we care about has active == 0 while the
        // Dobby branch is still sitting in the target's prologue. `used && patched && target` is
        // the state that means "there are bytes of ours at this address".
        if (!c.used || !c.patched || !c.target) continue;
        if ((uintptr_t)c.target != (uintptr_t)addr) continue;
        if (hook_id_out) *hook_id_out = c.id;
        if (active_out) *active_out = __atomic_load_n(&c.active, __ATOMIC_ACQUIRE) == 1 ? 1 : 0;
        pthread_mutex_unlock(&g_native_hooks_lock);
        return 1;
    }
    pthread_mutex_unlock(&g_native_hooks_lock);
    return 0;
}

extern "C" int adh_native_hook_unhook(int hook_id, int hard, char *error, size_t error_size) {
    pthread_mutex_lock(&g_native_hooks_lock);
    NativeHookContext *ctx = find_hook_locked(hook_id);
    if (!ctx) {
        pthread_mutex_unlock(&g_native_hooks_lock);
        return (set_error(error, error_size, "no native hook with id %d", hook_id), 0);
    }
    int slot = (int)(ctx - g_native_hooks);
    if (ctx->retired && !ctx->unhook_pending) {
        pthread_mutex_unlock(&g_native_hooks_lock);
        return 1; // idempotent restore+retire, never a promise of resource reclamation
    }
    if (ctx->mode == 0) {
        const int restored = adh_restore_pointer_if_owned((void **)ctx->slot_addr,
                                                          ctx->replacement, ctx->original);
        if (restored != 1) {
            pthread_mutex_unlock(&g_native_hooks_lock);
            return (set_error(error, error_size, restored < 0
                ? "not-unhooked: GOT ownership lost id=%d; current slot left untouched, stub retained"
                : "not-unhooked: GOT restore/protection unconfirmed id=%d; stub retained", hook_id), 0);
        }
        __atomic_store_n(&ctx->active, 0, __ATOMIC_RELEASE);
        ctx->unhook_pending = 1;
        ctx->retired = 1;
        pthread_mutex_unlock(&g_native_hooks_lock);
        if (!adh_native_hook_wait_quiet(slot, 1500))
            return (set_error(error, error_size, "not-unhooked: GOT restored but a callback is still in flight; slot retained, retry later"), 0);
        pthread_mutex_lock(&g_native_hooks_lock);
        ctx->retired=1;ctx->patches_restored=1;ctx->unhook_pending=0;ctx->patched=0;
        pthread_mutex_unlock(&g_native_hooks_lock);
        LOGI("native_hook removed id=%d (got)", hook_id);
        return 1;
    }
    if (ctx->mode == 3) {
        // A vtable hook writes data pointers only; hard unhook = put the original pointers back.
        __atomic_store_n(&ctx->active, 0, __ATOMIC_RELEASE);
        ctx->unhook_pending = 1;
        ctx->retired = 1;
        pthread_mutex_unlock(&g_native_hooks_lock);
        char slot_error[192] = "";
        if (!adh_slot_hook_revert(slot, slot_error, sizeof(slot_error))) {
            set_error(error, error_size, "%s", slot_error[0] ? slot_error : "vtable hook revert failed");
            return 0;
        }
        pthread_mutex_lock(&g_native_hooks_lock);
        ctx->unhook_pending = 0;
        ctx->patched = 0;
        pthread_mutex_unlock(&g_native_hooks_lock);
        LOGI("native_hook hard-unhooked id=%d (vtable slots restored)", hook_id);
        return 1;
    }
    if (ctx->mode == 2) {
        // Restore original B/BL instructions, then permanently retire the RX pages and context.
        // Another installation may consume a different virgin physical slot; this one is never reused.
        __atomic_store_n(&ctx->active, 0, __ATOMIC_RELEASE);
        ctx->unhook_pending = 1;
        ctx->retired = 1;
        pthread_mutex_unlock(&g_native_hooks_lock);
        char site_error[192] = "";
        if (!adh_site_hook_revert(slot, site_error, sizeof(site_error))) {
            set_error(error, error_size, "%s", site_error[0] ? site_error : "site hook revert failed");
            return 0;
        }
        pthread_mutex_lock(&g_native_hooks_lock);
        ctx->unhook_pending = 0;
        ctx->patched = 0;
        pthread_mutex_unlock(&g_native_hooks_lock);
        LOGI("native_hook hard-unhooked id=%d (sites restored)", hook_id);
        return 1;
    }
    if (!ctx->patched || !ctx->target || !ctx->replacement) {
        pthread_mutex_unlock(&g_native_hooks_lock);
        return (set_error(error, error_size, "inline patch state unavailable for id=%d", hook_id), 0);
    }
    void *target = ctx->target;
    __atomic_store_n(&ctx->active, 0, __ATOMIC_RELEASE);
    if (hard) { ctx->unhook_pending = 1; ctx->retired=1; }
    if (!hard) {
        // Soft unhook: leave the installed stub in place, deactivated, and keep the slot
        // patched for safe reactivation (never frees a trampoline a thread may still use).
        pthread_mutex_unlock(&g_native_hooks_lock);
        LOGI("native_hook soft-unhooked id=%d target=%p", hook_id, target);
        return 1;
    }
    pthread_mutex_unlock(&g_native_hooks_lock);
    // The bounded wait reports callbacks already in flight. It is not a reclamation proof and
    // does not authorize freeing or reassigning a context after a quiet interval.
    //
    // BOUNDED ON PURPOSE. The first version reset its counter every time a hit arrived, so on a HOT
    // hook the loop never terminated - and because this runs on the agent's command thread, the whole
    // session stopped answering: `agent_ping` timed out and only restarting the target recovered it
    // (measured twice, on the hex-encoder and malloc hooks). A hard unhook is an explicit request, so
    // after a bounded wait we return not-unhooked and retain the inactive patch/slot instead of
    // hanging the control channel or pretending that live callbacks finished. The residual race is
    // the one already documented for hard unhook:
    // a thread that already read the patched branch can be inside the trampoline, which lives in a
    // separate pool this code never frees - so restoring the prologue does not pull it out from under
    // that thread.
    const bool quiet = adh_native_hook_wait_quiet(slot, 1500) != 0;
    if (!quiet) {
        set_error(error, error_size, "not-unhooked: callback still in flight after 1500 ms; inactive patch and slot retained, retry later");
        return 0;
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
    ctx->retired=1;ctx->patches_restored=1;ctx->unhook_pending=0;ctx->patched=0;
    pthread_mutex_unlock(&g_native_hooks_lock);
    LOGI("native_hook hard-unhooked id=%llu target=%p (quiet=%d, original bytes restored, stub=%p parked)", stale_id, target, quiet ? 1 : 0, stale_stub);
    return 1;
}

extern "C" int adh_native_hook_status_json(char *out, size_t out_size) {
    if (!out || !out_size) return 0;
    std::string hooks = "[";
    std::string dormant = "[";
    int count = 0;
    int patched_count = 0;
    int dormant_count = 0;
    // Per-mode usage: the host needs to know how much of the budget is left BEFORE it asks for a
    // batch of hooks, otherwise the 17th install just fails one symbol at a time.
    // `used` counts CONSUMED slots, not active hooks: a soft-unhooked inline hook keeps its stub
    // installed, and a hard unhook permanently retires that slot. free=max-used is the remaining
    // physical budget for this process; unhook does not replenish exposed slots.
    int by_mode[4] = {0, 0, 0, 0};
    int used_slots = 0;
    int retired_slots = 0, retired_pages = 0;
    pthread_mutex_lock(&g_native_hooks_lock);
    for (int i = 0; i < ADH_NATIVE_MAX_HOOKS; i++) {
        NativeHookContext &ctx = g_native_hooks[i];
        if (ctx.used) used_slots++;
        const int pages = ctx.mode==2?adh_site_hook_retained_pages(i):ctx.mode==3?adh_slot_hook_retained_pages(i):0;
        const int patches_restored = ctx.mode==2?adh_site_hook_patches_restored(i):ctx.mode==3?adh_slot_hook_patches_restored(i):ctx.patches_restored;
        if (ctx.retired) { retired_slots++; retired_pages+=pages; }
        if (ctx.active != 1) {
            if (ctx.patched) patched_count++;
            // A soft-unhooked hook keeps its slot, its stub and its patch, but used to be OMITTED from
            // status entirely - so a caller enumerating `hooks` could neither see it nor unhook it, and
            // the session quietly lost slots with no way to reclaim them (measured: `used:5` with an
            // empty `hooks` list). `inactive` also reports permanently retired physical contexts,
            // including restored bytes, retained resources and an idempotent unhook handle.
            if (ctx.used) {
                char item[1536];
                snprintf(item, sizeof(item),
                         "%s{\"id\":%d,\"mode\":\"%s\",\"module\":\"%s\",\"symbol\":\"%s\","
                         "\"address\":\"0x%llx\",\"target\":\"0x%llx\",\"patched\":%s,"
                         "\"mem\":\"%s\",\"memAfter\":\"%s\",\"filter\":\"%s\","
                         "\"traceInsns\":%d,\"traceFrom\":\"%s\",\"traceWatch\":\"%s\",\"state\":\"%s\",\"inFlight\":%llu,"
                         "\"patchesRestored\":%s,\"resourcesReclaimed\":false,\"retiredPages\":%d,\"retiredBytes\":%d}",
                         dormant_count ? "," : "",
                         ctx.id,
                         ctx.mode == 0 ? "got" : (ctx.mode == 1 ? "inline" : (ctx.mode == 2 ? "sites" : "vtable")),
                         ctx.module, ctx.symbol,
                         (unsigned long long)ctx.address,
                         (unsigned long long)(uintptr_t)ctx.target,
                         ctx.patched ? "true" : "false",
                         ctx.mem_spec, ctx.after_spec, ctx.filter_spec,
                         ctx.trace_insns, ctx.trace_from, ctx.watch_spec,
                         ctx.unhook_pending ? "unhook-pending" : ctx.retired ? "retired" : ctx.patched ? "soft-unhooked" : "reserved",
                         adh_native_hook_inflight(i), patches_restored?"true":"false", ctx.retired?pages:0, ctx.retired?pages*4096:0);
                dormant += item;
                dormant_count++;
            }
            continue;
        }
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
        // At quiescence: hits = filtered + selected, selected = sampledOut + throttled +
        // limited + emitted. A live concurrent snapshot may have callbacks still in flight.
        unsigned long long throttled = g_native_hook_throttled_total[i].load(std::memory_order_relaxed);
        const auto &budget = g_native_hook_budget[i];
        const auto selected = budget.selected.load(std::memory_order_relaxed);
        const auto filtered = budget.filtered.load(std::memory_order_relaxed);
        const auto sampled_out = budget.sampled_out.load(std::memory_order_relaxed);
        const auto limited = budget.limited.load(std::memory_order_relaxed);
        const auto emitted = budget.emitted.load(std::memory_order_relaxed);
        char budgetbuf[560];
        snprintf(budgetbuf, sizeof(budgetbuf),
                 ",\"maxEvents\":%d,\"sampleEvery\":%d,\"tid\":%d,\"returnAddress\":\"0x%llx\","
                 "\"selected\":%llu,\"filtered\":%llu,\"sampledOut\":%llu,\"limited\":%llu,\"emitted\":%llu,"
                 "\"budgetReached\":%s,\"observationSuppressed\":%s,\"emittedMeaning\":\"submitted-to-capture-ring\",\"inFlight\":%llu",
                 ctx.max_events, ctx.sample_every, ctx.tid_filter, (unsigned long long)ctx.return_address,
                 selected, filtered, sampled_out, limited, emitted,
                 ctx.max_events > 0 && emitted >= (unsigned)ctx.max_events ? "true" : "false",
                 filtered || sampled_out || limited || throttled ? "true" : "false", adh_native_hook_inflight(i));
        // mode 0 mechanism facts. address/target/original are all the slot's pre-patch VALUE for a
        // got hook, so they say nothing about which slot was touched; these do. A hook that installs
        // and never fires otherwise looks exactly like a target with no traffic to observe.
        char gotbuf[384] = "";
        int got_owned = 1;
        if (ctx.mode == 0 && ctx.slot_addr) {
            char perms_now[8] = "?";
            adh_perms_of_addr((void *)ctx.slot_addr, perms_now, sizeof(perms_now));
            const int readable = perms_now[0] == 'r';
            void *cur = readable ? __atomic_load_n((void **)ctx.slot_addr, __ATOMIC_ACQUIRE) : NULL;
            got_owned = readable ? (cur == ctx.replacement ? 1 : 0) : -1;
            // got_write_slot puts the page protection back; comparing the live value with the one we
            // recorded before the write is what proves it. Leaving a RELRO page writable is a
            // footprint a target can see.
            const int prot_restored = ctx.slot_perms_before[0] != 0 &&
                                      strncmp(perms_now, ctx.slot_perms_before, 3) == 0;
            snprintf(gotbuf, sizeof(gotbuf),
                     ",\"slot\":\"0x%llx\",\"slotCurrent\":\"0x%llx\",\"pageProtRestored\":%s,"
                     "\"pagePermsBefore\":\"%s\",\"pagePermsNow\":\"%s\",\"slotOwned\":%s",
                     (unsigned long long)ctx.slot_addr, (unsigned long long)(uintptr_t)cur,
                     prot_restored ? "true" : "false", ctx.slot_perms_before, perms_now,
                     got_owned < 0 ? "null" : got_owned ? "true" : "false");
        }
        // got rewrites exactly one relocation slot (its install refuses anything else); sites/vtable
        // report how many they rewrote. Inline patches a function entry rather than a slot.
        const int slots_patched = (ctx.mode == 0) ? (ctx.slot_addr ? 1 : 0) : ctx.site_count;
        const uint64_t first_hit = g_native_hook_first_hit_ms[i].load(std::memory_order_relaxed);
        const char *verdict = got_owned < 0 ? "slot-unreadable" : !got_owned ? "ownership-lost" :
                              hits > 0 ? "fired" : "installed-never-fired";
        // "x1+0:8" = the hit writes 8 bytes at *(x1). Empty when the hook does not write.
        char writebuf[24] = "";
        if (ctx.write_len > 0) {
            snprintf(writebuf, sizeof(writebuf), "x%d+%d:%d", ctx.write_arg, ctx.write_off, ctx.write_len);
        }
        char item[4096];   // sitebuf is 1400 and gotbuf 384; 2048 truncated the JSON for a sites hook
        snprintf(item, sizeof(item),
                 "{\"id\":%d,\"mode\":\"%s\",\"module\":\"%s\",\"symbol\":\"%s\","
                 "\"address\":\"0x%llx\",\"target\":\"0x%llx\",\"original\":\"0x%llx\","
                 "\"replacement\":\"0x%llx\",\"hits\":%llu,\"argIndex\":%d,\"argValue\":\"0x%llx\",\"skipOriginal\":%s,\"returnSet\":%s,\"returnValue\":\"0x%llx\",\"backtrace\":%s,\"throttleMs\":%d,\"throttled\":%llu,\"mem\":\"%s\",\"memAfter\":\"%s\",\"afterActive\":%s,\"filter\":\"%s\",\"write\":\"%s\",\"errno\":%d,\"traceInsns\":%d,\"traceFrom\":\"%s\",\"traceWatch\":\"%s\""
                 ",\"slotsPatched\":%d,\"installedAtMs\":%llu,\"firstHitMs\":%llu,\"verdict\":\"%s\""
                 "%s%s%s}",
                 ctx.id, ctx.mode == 0 ? "got" : (ctx.mode == 1 ? "inline" : (ctx.mode == 2 ? "sites" : "vtable")), ctx.module, ctx.symbol,
                 (unsigned long long)ctx.address, (unsigned long long)(uintptr_t)ctx.target,
                 (unsigned long long)(uintptr_t)ctx.original,
                 (unsigned long long)(uintptr_t)ctx.replacement, hits, ctx.arg_index,
                 (unsigned long long)ctx.arg_value, ctx.skip_original ? "true" : "false",
                 ctx.return_set ? "true" : "false", (unsigned long long)ctx.return_value,
                 ctx.want_backtrace ? "true" : "false", ctx.throttle_ms, throttled, ctx.mem_spec,
                 ctx.after_spec, ctx.after_len > 0 ? "true" : "false", ctx.filter_spec, writebuf, ctx.errno_set,
                 ctx.trace_insns, ctx.trace_from, ctx.watch_spec,
                 slots_patched, (unsigned long long)ctx.installed_at_ms, (unsigned long long)first_hit,
                 verdict, gotbuf, sitebuf, budgetbuf);
        hooks += item;
        count++;
    }
    pthread_mutex_unlock(&g_native_hooks_lock);
    hooks += "]";
    dormant += "]";
    char kept[96] = "";
    adh_site_hook_last_revert_json(kept, sizeof(kept));
    char slots[512];
    snprintf(slots, sizeof(slots),
             "\"slots\":{\"max\":%d,\"used\":%d,\"active\":%d,\"free\":%d,\"retired\":%d,"
             "\"byMode\":{\"got\":%d,\"inline\":%d,\"sites\":%d,\"vtable\":%d}},"
             "\"retiredPages\":%d,\"retiredBytes\":%d,\"retirementPolicy\":\"process-lifetime-no-slot-reuse\",",
             ADH_NATIVE_MAX_HOOKS, used_slots, count, ADH_NATIVE_MAX_HOOKS - used_slots, retired_slots,
             by_mode[0], by_mode[1], by_mode[2], by_mode[3], retired_pages, retired_pages*4096);
    std::string json = "{\"observationControlsVersion\":1," + std::string(slots) +
                       "\"count\":" + std::to_string(count) + ",\"patched\":" + std::to_string(patched_count) + "," +
                       "\"inactiveCount\":" + std::to_string(dormant_count) + "," + kept +
                       "\"hooks\":" + hooks + ",\"inactive\":" + dormant + "}";
    snprintf(out, out_size, "%s", json.c_str());
    out[out_size - 1] = 0;
    return 1;
}
