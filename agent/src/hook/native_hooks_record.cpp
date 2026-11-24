// ---- native hooks (split from native_hooks.cpp) -------------------------
#include "native_hooks_internal.h"

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
    if (hook_id < 0 || hook_id >= ADH_NATIVE_MAX_HOOKS) return 0;
    g_native_hook_inflight[hook_id].fetch_add(1, std::memory_order_acquire);
    return adh_native_hook_record(regs, hook_id, nullptr);
}
extern "C" void adh_native_hook_leave_site(int slot) {
    if (slot >= 0 && slot < ADH_NATIVE_MAX_HOOKS)
        g_native_hook_inflight[slot].fetch_sub(1, std::memory_order_release);
}
// A thunk must LEAVE its disposable page before dropping the lease. Returning from a C release
// callback into that page leaves a UAF window between counter==0 and the final ret instructions.
// This epilogue lives in the resident agent image; the thunk BRs here while its lease is held.
extern "C" void adh_native_site_epilogue(void) __attribute__((naked));
extern "C" void adh_native_site_epilogue(void) {
    __asm__ volatile(
        "stp x0, x1, [sp, #0]\n"
        "stp q0, q1, [sp, #128]\n"
        "stp q2, q3, [sp, #160]\n"
        "mov x0, x16\n"
        "bl adh_native_hook_leave_site\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp q0, q1, [sp, #128]\n"
        "ldp q2, q3, [sp, #160]\n"
        "ldp x29, x30, [sp, #80]\n"
        "ldr x18, [sp, #96]\n"
        "add sp, sp, #256\n"
        "ret\n");
}
extern "C" unsigned long long adh_native_hook_inflight(int slot) {
    if (slot < 0 || slot >= ADH_NATIVE_MAX_HOOKS) return 0;
    return g_native_hook_inflight[slot].load(std::memory_order_acquire);
}
extern "C" int adh_native_hook_wait_quiet(int slot, int timeout_ms) {
    if (slot < 0 || slot >= ADH_NATIVE_MAX_HOOKS || timeout_ms < 1) return 0;
    const uint64_t deadline = adh_mono_ns() + (uint64_t)timeout_ms * 1000000ull;
    int quiet_rounds = 0;
    while (adh_mono_ns() < deadline) {
        const auto before = adh_native_hook_hits(slot);
        struct timespec ts = {0, 5 * 1000 * 1000};
        nanosleep(&ts, nullptr);
        if (before == adh_native_hook_hits(slot) && adh_native_hook_inflight(slot) == 0) {
            if (++quiet_rounds >= 5) return 1;
        } else quiet_rounds = 0;
    }
    return 0;
}

extern "C" unsigned long long adh_native_hook_hits(int hook_id) {
    if (hook_id < 0 || hook_id >= ADH_NATIVE_MAX_HOOKS) return 0;
    return g_native_hook_hits[hook_id].load(std::memory_order_relaxed);
}

// `seq_out` (may be NULL) receives the seq of the mem record this hit pushed, so the after-stub can
// stamp its own record with the SAME seq. Without that the after record carries no seq at all, and a
// reader joining on (hookId, seq) - the documented way to pair a register event with its memory
// record - silently drops every post-call copy. Measured cost of that bug: three separate analysis
// rounds on this target concluded "memAfter produced nothing" when the records were there, unjoinable.
extern "C" uint64_t adh_native_hook_record(uint64_t *regs, int hook_id, uint64_t *seq_out) {
    if (seq_out) { seq_out[0] = 0; seq_out[1] = 0; }
    if (!regs || hook_id < 0 || hook_id >= ADH_NATIVE_MAX_HOOKS) return 0;
    NativeErrnoGuard errno_guard;
    NativeRecorderLease lease(hook_id);
    if (seq_out) seq_out[1] = (uint64_t)g_native_hook_slot_ids[hook_id].load(std::memory_order_relaxed);
    NativeHookContext &ctx = g_native_hooks[hook_id];
    if (__atomic_load_n(&ctx.active, __ATOMIC_ACQUIRE) != 1) return 0;
    g_native_hook_hits[hook_id].fetch_add(1, std::memory_order_relaxed);
    if (g_native_hook_first_hit_ms[hook_id].load(std::memory_order_relaxed) == 0)
        g_native_hook_first_hit_ms[hook_id].store(wall_ms(), std::memory_order_relaxed);
    // Filters select calls BEFORE rewrites, preserving the existing reg=value semantics: an
    // unmatched call runs untouched. Count it, so a quiet observation is not mistaken for no calls.
    const int filter_reg = __atomic_load_n(&ctx.filter_reg, __ATOMIC_RELAXED);
    const int hit_tid = (int)gettid();
    const int tid_filter = __atomic_load_n(&ctx.tid_filter, __ATOMIC_RELAXED);
    const uint64_t caller_filter = __atomic_load_n(&ctx.return_address, __ATOMIC_RELAXED);
    if ((filter_reg >= 0 && (filter_reg > 8 || regs[filter_reg] != ctx.filter_val)) ||
        (tid_filter > 0 && tid_filter != hit_tid) || (caller_filter && caller_filter != regs[11])) {
        g_native_hook_budget[hook_id].filtered.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }

    uint64_t in0 = regs[0], in1 = regs[1], in2 = regs[2], in3 = regs[3];
    uint64_t in4 = regs[4], in5 = regs[5], in6 = regs[6], in7 = regs[7];
    uint64_t in8 = regs[8], in18 = regs[12];
    // x29/x30 were already saved by the stub ([sp,#80]) but never published. They are the frame
    // pointer and the return address AT THE HIT, i.e. exactly what a caller backtrace needs (the
    // host walks the x29 chain by reading the stack; see daemon/src/backtrace.ts).
    uint64_t in29 = regs[10], in30 = regs[11];
    // The stub's saved bank, indexed the way `traceFrom` names registers: 0-9 = x0-x9, 10 = x29,
    // 11 = x30. Kept here (not inside the window block) because the in-hook trace needs it too.
    uint64_t in9 = regs[9];
    // Callee-saved bank and the real stack pointer, saved by the stub at fixed offsets past the
    // x0..x18 block. An in-hook instruction trace starts INSIDE the traced function, after its own
    // prologue saved these, so it must see the real values - zeros make any function that keeps its
    // state pointer here fault on first dereference.
    const uint64_t in_sp = regs[32];
    const uint64_t in19 = regs[33], in20 = regs[34], in21 = regs[35], in22 = regs[36];
    const uint64_t in23 = regs[37], in24 = regs[38], in25 = regs[39], in26 = regs[40];
    const uint64_t in27 = regs[41], in28 = regs[42];
    const uint64_t saved_regs[12] = { in0, in1, in2, in3, in4, in5, in6, in7, in8, in9, in29, in30 };
    int arg_index = __atomic_load_n(&ctx.arg_index, __ATOMIC_RELAXED);
    uint64_t arg_value = __atomic_load_n(&ctx.arg_value, __ATOMIC_RELAXED);
    int return_set = __atomic_load_n(&ctx.return_set, __ATOMIC_RELAXED);
    uint64_t return_value = __atomic_load_n(&ctx.return_value, __ATOMIC_RELAXED);
    int skip_original = __atomic_load_n(&ctx.skip_original, __ATOMIC_RELAXED);
    // Neutralize the errno half of a check on EVERY hit (throttled ones included): the return value
    // says "failed", errno says why, and a detector branches on the pair. `errno` is bionic's
    // thread-local macro, so this writes the HIT thread's slot (an explicit __errno_location does
    // not exist at the API levels this agent supports).
    const int errno_want = __atomic_load_n(&ctx.errno_set, __ATOMIC_RELAXED);
    if (errno_want > 0) { errno_guard.saved = errno_want; errno = errno_want; }

    // Hit-time pointer write. Runs BEFORE the original and BEFORE any register rewrite, so the
    // address comes from what the target actually passed in. Only a range that already sits in a
    // writable mapping is touched (adh_mem_write_checked): the recorder runs on an arbitrary target
    // thread and must never fault it. A refused write is reported in the event, never assumed.
    const int wr_arg = __atomic_load_n(&ctx.write_arg, __ATOMIC_RELAXED);
    const int wr_len = __atomic_load_n(&ctx.write_len, __ATOMIC_RELAXED);
    int wr_ok = 0;
    if (wr_arg >= 0 && wr_arg <= 8 && wr_len > 0) {
        const uintptr_t wr_dst = (uintptr_t)regs[wr_arg] + (uintptr_t)ctx.write_off;
        wr_ok = adh_mem_write_checked((unsigned long long)wr_dst, ctx.write_bytes, (size_t)wr_len) ? 1 : 0;
        ctx.write_ok = wr_ok;
    }

    if (arg_index >= 0 && arg_index < 8) regs[arg_index] = arg_value;
    if (return_set) regs[0] = return_value;
    else if (skip_original) regs[0] = 0;

    int hook_uid = g_native_hook_slot_ids[hook_id].load(std::memory_order_relaxed);
    // No id means this slot was never published to the Host. Inventing one would hand the operator a
    // hookId that no install ever returned, so stay silent (the argument/return rewrite above has
    // already been applied either way).
    if (hook_uid <= 0) return (skip_original || return_set) ? 1 : 0;
    // Sampling and quotas affect observations ONLY. The rewrites above have already happened.
    if (!g_native_hook_budget[hook_id].sample((unsigned)ctx.sample_every))
        return (skip_original || return_set) ? 1 : 0;
    // Per-hook event throttle. The rewrite above has already been applied, so dropping the EVENT
    // never changes what the target does - it only stops a hot site (read/write/futex) from
    // overflowing the capture ring and making the digest look quiet. Suppressed hits are counted and
    // reported, so a thinned log is never mistaken for a quiet target. A single CAS closes the
    // concurrent-emitter race without waiting on another target thread.
    const int throttle_ms = __atomic_load_n(&ctx.throttle_ms, __ATOMIC_RELAXED);
    unsigned long long throttled = 0;
    if (throttle_ms > 0) {
        const uint64_t now = adh_mono_ns();
        uint64_t last = g_native_hook_throttle_last_ns[hook_id].load(std::memory_order_relaxed);
        if ((last != 0 && now - last < (uint64_t)throttle_ms * 1000000ull) ||
            !g_native_hook_throttle_last_ns[hook_id].compare_exchange_strong(last, now, std::memory_order_relaxed)) {
            g_native_hook_throttled_total[hook_id].fetch_add(1, std::memory_order_relaxed);
            return (skip_original || return_set) ? 1 : 0;
        }
        const unsigned long long total = g_native_hook_throttled_total[hook_id].load(std::memory_order_relaxed);
        // exchange, not load+store: two emitters racing here must not both claim the same delta.
        const unsigned long long seen = g_native_hook_throttled_reported[hook_id].exchange(total, std::memory_order_relaxed);
        throttled = total > seen ? total - seen : 0;
    }
    if (!g_native_hook_budget[hook_id].reserve((unsigned)ctx.max_events))
        return (skip_original || return_set) ? 1 : 0;
    // Windows are the bytes the target passed in, taken from the entry registers (before any
    // argIndex rewrite) and before the original function runs. Throttled hits skip this: the
    // companion record is paired with an emitted event, and a hot site must not pay a copy it
    // will not report. A bad pointer on an explicit window is "unreadable", not a crash.
    // mem_nwin == -1 ("auto") keeps only registers that are readable pointers, 64 bytes each.
    int mem_mode = ctx.mem_nwin;
    if (mem_mode < -1 || mem_mode > ADH_MEM_WIN_MAX) mem_mode = 0;
    const int mem_auto = mem_mode == -1;
    const int mem_asked = mem_auto || mem_mode > 0;
    int mem_reg[ADH_MEM_WIN_MAX];
    int mem_off[ADH_MEM_WIN_MAX];
    int mem_len[ADH_MEM_WIN_MAX];
    int mem_got[ADH_MEM_WIN_MAX];
    int mem_deref[ADH_MEM_WIN_MAX];
    int mem_from[ADH_MEM_WIN_MAX];
    int mem_abs[ADH_MEM_WIN_MAX];
    unsigned long long mem_abs_addr[ADH_MEM_WIN_MAX];
    unsigned long long mem_ptr[ADH_MEM_WIN_MAX];
    const char *mem_err[ADH_MEM_WIN_MAX];
    unsigned char mem_bytes[ADH_MEM_WIN_MAX][ADH_MEM_WIN_LEN];
    int mem_nwin = 0;
    unsigned long long mem_seq = 0;
    if (mem_asked) {
        const uint64_t inreg[9] = { in0, in1, in2, in3, in4, in5, in6, in7, in8 };
        if (mem_auto) {
            for (int r = 0; r <= 8 && mem_nwin < ADH_MEM_WIN_MAX; r++) {
                int got = hook_mem_copy(inreg[r], mem_bytes[mem_nwin], 64);
                if (got <= 0) continue;
                mem_reg[mem_nwin] = r;
                mem_off[mem_nwin] = 0;
                mem_len[mem_nwin] = 64;
                mem_got[mem_nwin] = got;
                mem_deref[mem_nwin] = 0;
                mem_abs[mem_nwin] = 0;
                mem_abs_addr[mem_nwin] = 0;
                mem_ptr[mem_nwin] = inreg[r];
                mem_err[mem_nwin] = "";
                mem_nwin++;
            }
        } else {
            mem_nwin = mem_mode;
            for (int w = 0; w < mem_nwin; w++) {
                mem_reg[w] = ctx.mem_win[w].reg;
                mem_off[w] = ctx.mem_win[w].offset;
                mem_len[w] = ctx.mem_win[w].len;
                mem_deref[w] = ctx.mem_win[w].deref;
                mem_from[w] = ctx.mem_win[w].from_win;
                mem_abs[w] = ctx.mem_win[w].absolute;
                mem_abs_addr[w] = ctx.mem_win[w].abs_addr;
                mem_got[w] = 0;
                mem_ptr[w] = 0;
                mem_err[w] = "";
                uint64_t src = 0;
                if (mem_deref[w] == 2) {
                    // Follow a pointer that an EARLIER window already copied. Windows are processed in
                    // order, so that copy exists here; the bounds were checked at install time and are
                    // re-checked against what was actually read, because a short read shrinks it.
                    const int fw = mem_from[w] - 1;
                    if (fw < 0 || fw >= w || fw >= ADH_MEM_WIN_MAX) {
                        mem_err[w] = "window-ref";
                        continue;
                    }
                    if (mem_got[fw] < mem_off[w] + 8) {
                        mem_err[w] = "window-short";
                        continue;
                    }
                    uint64_t target = 0;
                    memcpy(&target, mem_bytes[fw] + mem_off[w], 8);
                    mem_ptr[w] = (unsigned long long)target;
                    if (target == 0) {
                        mem_err[w] = "null";
                        continue;
                    }
                    src = target;
                } else {
                    if (mem_abs[w]) {
                        // "What does this address hold NOW": the address came from an earlier hit, so no
                        // register is involved and nothing here can be stale.
                        src = mem_abs_addr[w];
                    } else {
                    if (mem_reg[w] < 0 || mem_reg[w] > 8 || mem_len[w] < 1 || mem_len[w] > ADH_MEM_WIN_LEN) {
                        mem_err[w] = "unreadable";
                        continue;
                    }
                    uint64_t base = inreg[mem_reg[w]];
                    // Signed offset: negative reads BEFORE the register's address (the instruction record
                    // before the current one). A negative that would wrap below 0 is refused as
                    // "underflow" instead of becoming a huge address that reads unmapped memory.
                    if (mem_off[w] < 0) {
                        const uint64_t back = (uint64_t)(-(int64_t)mem_off[w]);
                        if (back > base) {
                            mem_err[w] = "underflow";
                            continue;
                        }
                        src = base - back;
                    } else {
                        if ((uint64_t)mem_off[w] > ~0ull - base) {
                            mem_err[w] = "overflow";
                            continue;
                        }
                        src = base + (uint64_t)mem_off[w];
                    }
                    if (mem_deref[w]) {
                        // Follow one pointer. A frame's link field is not the bytes the caller wants,
                        // and reading it as if it were produces a plausible-looking window that answers
                        // a different question - so the resolved pointer is reported with the record.
                        unsigned char slot[8];
                        if (hook_mem_copy(src, slot, 8) != 8) {
                            mem_err[w] = "unreadable";
                            continue;
                        }
                        uint64_t target = 0;
                        memcpy(&target, slot, 8);
                        mem_ptr[w] = (unsigned long long)target;
                        if (target == 0) {
                            mem_err[w] = "null";
                            continue;
                        }
                        src = target;
                    }
                    }   // end of the register/offset form
                }
                if (mem_len[w] < 1 || mem_len[w] > ADH_MEM_WIN_LEN) { mem_err[w] = "unreadable"; continue; }
                int got = hook_mem_copy(src, mem_bytes[w], mem_len[w]);
                if (got <= 0) mem_err[w] = "unreadable";
                else mem_got[w] = got;
            }
        }
    }
    // Every admitted event has an identity, even without pre-call windows. seq=0 means this hit
    // was suppressed, so the after-stub must not copy or emit a stray memAfter record for it.
    mem_seq = g_native_hook_mem_seq[hook_id].fetch_add(1, std::memory_order_relaxed) + 1;
    if (seq_out) *seq_out = mem_seq;
    // v4.31: the stub saved q0-q7 at regs[16..31] (low/high lane per 128-bit register), so float,
    // double and vector arguments are visible too. Every lane is rendered twice - as the double
    // (d0-d7) and as the float (s0-s7) it would be - because a float argument only fills the low
    // 32 bits of its register: whichever reading is a sane finite number is the one the caller
    // actually used. High lanes stay raw hex (vector/struct arguments).
    //
    // The object is all-or-nothing: when every q0-q7 lane is zero the key is omitted entirely.
    // Integer-only calls (the overwhelming majority - an 8-register object costs ~600 bytes, which
    // is why a 128-event capture used to fill the reply) then pay nothing, while a call that DOES
    // use the vector bank still reports all eight, so a 0.0 argument stays distinguishable from an
    // unused register. 600 bytes x 128 events is 75 KB of pure noise per capture.
    int fp_any = 0;
    for (int i = 0; i < 8 && !fp_any; i++) {
        if (regs[16 + i * 2] || regs[17 + i * 2]) fp_any = 1;
    }
    // The register object is bounded (~1 KB), the optional trace sub-object is the largest thing that
    // can follow it, and the two must fit in ONE record (see the trace block below).
    char json[3072 + ADH_TRACE_JSON_MAX];
    size_t joff = 0;
    joff = adh_json_append(json, sizeof(json), joff,
                           "{\"hookId\":%d,\"kind\":\"%s\",\"tid\":%d,\"throttleMs\":%d,\"throttled\":%llu,"
                           "\"x0\":\"0x%llx\",\"x1\":\"0x%llx\",\"x2\":\"0x%llx\","
                           "\"x3\":\"0x%llx\",\"x4\":\"0x%llx\",\"x5\":\"0x%llx\",\"x6\":\"0x%llx\","
                           "\"x7\":\"0x%llx\",\"x8\":\"0x%llx\",\"x18\":\"0x%llx\","
                           "\"x29\":\"0x%llx\",\"x30\":\"0x%llx\",",
                           hook_uid, kind_name(hook_id), hit_tid, throttle_ms, throttled,
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
    if (fp_any) {
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
        joff = adh_json_append(json, sizeof(json), joff, "},");
    }
    joff = adh_json_append(json, sizeof(json), joff,
                           "\"argIndex\":%d,\"argValue\":\"0x%llx\",\"skipOriginal\":%s,"
                           "\"returnSet\":%s,\"returnValue\":\"0x%llx\"",
                           arg_index, (unsigned long long)arg_value, skip_original ? "true" : "false",
                           return_set ? "true" : "false", (unsigned long long)return_value);
    if (wr_arg >= 0 && wr_len > 0) {
        // "did the write land" is a separate fact from "the hook fired": an unmapped or read-only
        // destination is reported instead of leaving the caller to guess why the target behaved
        // exactly as before.
        joff = adh_json_append(json, sizeof(json), joff,
                               ",\"write\":{\"reg\":\"x%d\",\"offset\":%d,\"len\":%d,\"ok\":%s}",
                               wr_arg, (int)ctx.write_off, wr_len, wr_ok ? "true" : "false");
    }
    if (errno_want > 0) {
        joff = adh_json_append(json, sizeof(json), joff, ",\"errnoSet\":%d", errno_want);
    }
    joff = adh_json_append(json, sizeof(json), joff, ",\"seq\":%llu,\"memWindows\":%d",
                           mem_seq, mem_nwin);
    // In-hook instruction trace. It runs HERE - after the hit-time copies above (so the bytes and the
    // registers describe the moment the hook fired) and before the record is pushed - and its summary
    // goes into THIS record, not a companion one: a companion would need a seq to be joinable, and
    // (hookId, seq) pairing is where the memAfter work already went wrong once.
    //
    // The run happens on the target thread and executes the traced function, so the three guards in
    // qbdi_trace.c (instruction budget / wall clock / exec range) are what keep a pathological
    // function from taking the target down. traceInsns == 0 is the default and adds nothing at all -
    // not even an empty key, so "not traced" is distinguishable from "traced, nothing seen".
    const int trace_insns = __atomic_load_n(&ctx.trace_insns, __ATOMIC_RELAXED);
    if (trace_insns > 0) {
        char trace_json[ADH_TRACE_JSON_MAX];
        uint64_t hint = (uint64_t)(uintptr_t)ctx.target;
        uint64_t tpc = hint;
        const int from_reg = __atomic_load_n(&ctx.trace_from_reg, __ATOMIC_RELAXED);
        if (from_reg >= 0 && from_reg < (int)(sizeof(saved_regs) / sizeof(saved_regs[0]))) {
            tpc = saved_regs[from_reg];
        } else if (ctx.mode == 1 && __atomic_load_n(&ctx.patched, __ATOMIC_RELAXED) && ctx.original) {
            // An inline hook's entry carries OUR branch. QBDI follows it into Dobby's trampoline and
            // never comes back to the emulator (measured on libjdg: the run ended at pc=0x2a and the
            // target died with SIGBUS). The trampoline holds the relocated ORIGINAL prologue and
            // branches back into the function, so starting there traces the function's real body -
            // it is also exactly what the stub calls for the real invocation.
            tpc = (uint64_t)(uintptr_t)ctx.original;
        }
        qbdi_summary_t sum;
        // gpr layout expected by adh_qbdi_run_from: [0..8]=x0-x8, [9]=x29, [10]=x30, [11]=x18,
        // [12..21]=x19-x28, [22]=x9, [23]=sp.
        //
        // x19..x28 must carry the values the function actually has: this run starts INSIDE it, after
        // its prologue saved them, so it is entitled to read them as its own. Passing zeros made any
        // function that keeps a state pointer in that bank fault on first dereference - measured on a
        // VM interpreter holding its context in x19/x21, where the trace died instantly.
        // sp is the real stack pointer for the same reason: the function's own frame is live.
        const uint64_t tgpr[ADH_QTRACE_GPR_LEN] = {
            in0, in1, in2, in3, in4, in5, in6, in7, in8,
            in29, in30, in18,
            in19, in20, in21, in22, in23, in24, in25, in26, in27, in28,
            in9,
            in_sp,
        };
        // Write watch: resolve the range NOW (on the hit thread, from the hit's registers) and arm it for
        // this run only. A pointer that cannot be resolved is reported, never silently dropped - "the
        // watch saw nothing" and "the watch was never armed" must not look alike.
        const int wreg = __atomic_load_n(&ctx.watch_reg, __ATOMIC_RELAXED);
        const int woff = __atomic_load_n(&ctx.watch_off, __ATOMIC_RELAXED);
        const int wlen = __atomic_load_n(&ctx.watch_len, __ATOMIC_RELAXED);
        const int wderef = __atomic_load_n(&ctx.watch_deref, __ATOMIC_RELAXED);
        const int wabs = __atomic_load_n(&ctx.watch_abs, __ATOMIC_RELAXED);
        const uint64_t wabs_addr = ctx.watch_abs_addr;
        const int watch_cfg = ((wabs || wreg >= 0) && wlen > 0) ? 1 : 0;
        qbdi_watch_t watch;
        adh_qbdi_watch_reset(&watch);
        uint64_t wlo = 0, whi = 0;
        if (watch_cfg && wabs) {
            // An address learned from an earlier hit: no register involved, so nothing can be stale.
            if ((uint64_t)wlen <= ~0ull - wabs_addr) {
                wlo = wabs_addr;
                whi = wabs_addr + (uint64_t)wlen;
            } else {
                snprintf(watch.error, sizeof(watch.error), "traceWatch range overflow");
            }
        } else if (watch_cfg) {
            watch.lo = 0;
            watch.hi = 0;
            uint64_t wbase = (wreg < (int)(sizeof(saved_regs) / sizeof(saved_regs[0]))) ? saved_regs[wreg] : 0;
            const uint64_t back = woff < 0 ? (uint64_t)(-(int64_t)woff) : 0;
            if (woff < 0 && back > wbase) {
                snprintf(watch.error, sizeof(watch.error), "traceWatch address underflow");
            } else if (woff >= 0 && (uint64_t)woff > ~0ull - wbase) {
                snprintf(watch.error, sizeof(watch.error), "traceWatch address overflow");
            } else {
                wbase = (uint64_t)((int64_t)wbase + (int64_t)woff);
                if (wderef) {
                    uint64_t target = 0;
                    unsigned char slot[8];
                    if (hook_mem_copy(wbase, slot, 8) != 8) {
                        snprintf(watch.error, sizeof(watch.error), "traceWatch pointer unreadable");
                        wbase = 0;
                    } else {
                        memcpy(&target, slot, sizeof(target));
                        if (target == 0) {
                            snprintf(watch.error, sizeof(watch.error), "traceWatch pointer is null");
                            wbase = 0;
                        } else {
                            wbase = target;
                        }
                    }
                }
                if (wbase && (uint64_t)wlen <= ~0ull - wbase) {
                    wlo = wbase;
                    whi = wbase + (uint64_t)wlen;
                } else if (!watch.error[0]) {
                    snprintf(watch.error, sizeof(watch.error), "traceWatch range overflow");
                }
            }
        }
        int patched_id = 0, patched_active = 0;
        if (tpc == 0) {
            adh_qbdi_summary_reset(&sum);
            sum.insns = trace_insns;
            sum.stop_reason = "did-not-run";
            snprintf(sum.error, sizeof(sum.error), "traceFrom register is null");
        } else if (from_reg >= 0 && adh_native_hook_at(tpc, &patched_id, &patched_active)) {
            // Same rule as the standalone tracer: a start address that carries one of our patches
            // sends QBDI into a trampoline it never returns from. Only checked for an explicit
            // traceFrom (the default path never points at a patched address: an inline hook starts
            // in the trampoline by construction), because this lookup takes the hook registry lock.
            adh_qbdi_summary_reset(&sum);
            sum.insns = trace_insns;
            sum.start_pc = tpc;
            sum.stop_reason = "did-not-run";
            snprintf(sum.error, sizeof(sum.error),
                     "traceFrom 0x%llx carries our inline patch (hook %d, %s)",
                     (unsigned long long)tpc, patched_id, patched_active ? "active" : "soft-unhooked");
        } else {
            (void)adh_qbdi_run_from_watch(tpc, tgpr, trace_insns, ADH_QTRACE_INHOOK_TIME_MS, hint,
                                          wlo, whi, &sum, watch_cfg ? &watch : NULL);
        }
        int tl = adh_qbdi_summary_json(&sum, trace_json, sizeof(trace_json));
        if (tl > 0) joff = adh_json_append(json, sizeof(json), joff, ",\"trace\":%s", trace_json);
        else joff = adh_json_append(json, sizeof(json), joff,
                                    ",\"trace\":{\"insns\":%d,\"seen\":0,\"stopReason\":\"did-not-run\",\"clipped\":true}",
                                    trace_insns);
        if (watch_cfg) {
            char wjson[640];
            int wl = adh_qbdi_watch_json(&watch, wjson, sizeof(wjson));
            if (wl > 0) joff = adh_json_append(json, sizeof(json), joff, ",\"traceWatch\":%s", wjson);
            else joff = adh_json_append(json, sizeof(json), joff,
                                        ",\"traceWatch\":{\"count\":0,\"truncated\":true,\"error\":\"watch json did not fit\"}");
        }
    }
    joff = adh_json_append(json, sizeof(json), joff, "}");
    if (joff >= sizeof(json)) {
        // A half-written object is not JSON and the daemon cannot parse it, so replace it with a
        // valid event that says the record was truncated instead of pushing a broken line.
        LOGE("native hook event truncated: %zu-byte buffer exhausted", sizeof(json));
        snprintf(json, sizeof(json), "{\"hookId\":%d,\"truncated\":true,\"buffer\":%zu}",
                 hook_uid, sizeof(json));
    }
    adh_capture_push_text("NATIVE_HOOK", json);
    g_native_hook_budget[hook_id].emitted.fetch_add(1, std::memory_order_relaxed);
    if (mem_asked) {
        // Separate record: the copied windows do not fit beside the register object, and a later
        // memory_read would see whatever the original function wrote over the buffer. Sized from
        // the caps so raising a cap cannot silently truncate the record.
        char memjson[ADH_MEM_WIN_TOTAL * 2 + 512];
        size_t moff = 0;
        moff = adh_json_append(memjson, sizeof(memjson), moff,
                               "{\"hookId\":%d,\"seq\":%llu%s,\"mem\":[",
                               hook_uid, mem_seq, mem_auto ? ",\"auto\":true" : "");
        char hex[ADH_MEM_WIN_LEN * 2 + 1];
        for (int w = 0; w < mem_nwin; w++) {
            int short_read = (mem_got[w] > 0 && mem_got[w] < mem_len[w]) ? 1 : 0;
            if (mem_abs[w]) {
                // An absolute window has no register: report the address it read, otherwise "reg":"x-1"
                // would look like a broken register window instead of what was asked for.
                moff = adh_json_append(memjson, sizeof(memjson), moff,
                                       "%s{\"reg\":\"abs\",\"addr\":\"0x%llx\",\"requested\":%d,\"got\":%d,\"short\":%s",
                                       w ? "," : "", mem_abs_addr[w], mem_len[w], mem_got[w],
                                       short_read ? "true" : "false");
            } else {
                moff = adh_json_append(memjson, sizeof(memjson), moff,
                                       "%s{\"reg\":\"x%d\",\"offset\":%d,\"requested\":%d,\"got\":%d,\"short\":%s",
                                       w ? "," : "", mem_reg[w], mem_off[w], mem_len[w], mem_got[w],
                                       short_read ? "true" : "false");
            }
            // A deref window must SAY so: the same bytes read with and without the indirection answer
            // different questions, and a reader that cannot tell them apart will believe the pointer
            // value is the payload.
            if (mem_deref[w]) {
                moff = adh_json_append(memjson, sizeof(memjson), moff, ",\"deref\":true,\"ptr\":\"0x%llx\"",
                                       mem_ptr[w]);
                if (mem_deref[w] == 2) {
                    moff = adh_json_append(memjson, sizeof(memjson), moff, ",\"from\":%d", mem_from[w]);
                }
            }
            if (mem_err[w][0]) {
                moff = adh_json_append(memjson, sizeof(memjson), moff, ",\"error\":\"%s\"}", mem_err[w]);
            } else {
                hex_encode(mem_bytes[w], mem_got[w], hex);
                moff = adh_json_append(memjson, sizeof(memjson), moff, ",\"hex\":\"%s\"}", hex);
            }
        }
        moff = adh_json_append(memjson, sizeof(memjson), moff, "]}");
        if (moff >= sizeof(memjson)) {
            snprintf(memjson, sizeof(memjson),
                     "{\"hookId\":%d,\"seq\":%llu,\"truncated\":true}", hook_uid, mem_seq);
        }
        adh_capture_push_text("NATIVE_HOOK_MEM", memjson);
    }
    return (skip_original || return_set) ? 1 : 0;
}

// Runs on the target thread AFTER the original returned. Copies the one configured window and pushes
// a NATIVE_HOOK_MEM record tagged phase:"after", so a reader can tell what the function was GIVEN
// (untagged record, copied before the call) from what it PRODUCED. The return value is handed back
// unchanged: this observes, it does not rewrite. An unreadable buffer is reported, never guessed.
extern "C" uint64_t adh_native_hook_after(uint64_t retval, uint64_t *regs, int hook_id, uint64_t seq, uint64_t expected_id) {
    if (!seq) return retval;
    if (!regs || hook_id < 0 || hook_id >= ADH_NATIVE_MAX_HOOKS) return retval;
    NativeErrnoGuard errno_guard;
    NativeRecorderLease lease(hook_id);
    NativeHookContext &ctx = g_native_hooks[hook_id];
    if (__atomic_load_n(&ctx.active, __ATOMIC_ACQUIRE) != 1) return retval;
    const int arg = __atomic_load_n(&ctx.after_arg, __ATOMIC_RELAXED);
    const int len = __atomic_load_n(&ctx.after_len, __ATOMIC_RELAXED);
    const int off = __atomic_load_n(&ctx.after_off, __ATOMIC_RELAXED);
    if (arg < 0 || arg > 8 || len <= 0 || len > ADH_MEM_AFTER_MAX) return retval;
    int hook_uid = g_native_hook_slot_ids[hook_id].load(std::memory_order_relaxed);
    if (hook_uid <= 0 || (uint64_t)hook_uid != expected_id) return retval;

    const uint64_t base = regs[arg];
    const uint64_t addr = base + (uint64_t)off;
    unsigned char buf[ADH_MEM_AFTER_MAX];
    int got = hook_mem_copy(addr, buf, len);
    if (got < 0) got = 0;
    // Same SHAPE as the pre-call record: mem:[{reg,offset,requested,got,short[,hex|error]}], plus
    // phase/ret at the top. The old flat shape ({reg,offset,got,hex} at the top level) had two costs
    // that looked like something else: the host preview reads obj.mem, so a post-call copy showed as
    // an EMPTY preview, and a reader written against the pre-call shape had to special-case it.
    char hex[ADH_MEM_AFTER_MAX * 2 + 1];
    char json[ADH_MEM_AFTER_MAX * 2 + 640];
    size_t joff = 0;
    const int short_read = (got > 0 && got < len) ? 1 : 0;
    joff = adh_json_append(json, sizeof(json), joff,
                           "{\"hookId\":%d,\"seq\":%llu,\"phase\":\"after\",\"ret\":\"0x%llx\",\"mem\":["
                           "{\"reg\":\"x%d\",\"offset\":%d,\"requested\":%d,\"got\":%d,\"short\":%s",
                           hook_uid, (unsigned long long)seq, (unsigned long long)retval, arg, off, len, got,
                           short_read ? "true" : "false");
    if (got > 0) {
        hex_encode(buf, got, hex);
        joff = adh_json_append(json, sizeof(json), joff, ",\"hex\":\"%s\"}]}", hex);
    } else {
        joff = adh_json_append(json, sizeof(json), joff, ",\"error\":\"unreadable\"}]}");
    }
    (void)joff;
    adh_capture_push_text("NATIVE_HOOK_MEM", json);
    // A buffer the function just produced usually does not exist before the call, so the only
    // moment its address is both known and live is right here: arm a watchpoint on it now (the
    // first access after this point is what reveals who transforms the buffer).
    adh_hw_watch_arm_for_hook(hook_uid, regs);
    return retval;
}

