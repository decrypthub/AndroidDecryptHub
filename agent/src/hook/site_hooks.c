// Call-site hooking: rewrite the BL instructions that call a target instead of touching the target
// itself. See site_hooks.h for why (entry prologue stays byte-identical) and the honest limits.
//
// The emitted thunk is hand-encoded AArch64. Every encoding in this file was checked against
// llvm-mc output (clang --target=aarch64 -c) before it was used, because a wrong word here is a
// crash inside the target's own call path, not a wrong return value.
#include "site_hooks.h"

#include "got.h"
#include "native_hooks.h"

#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define STAG "ADH_SITE"
#define SLOGI(...) __android_log_print(ANDROID_LOG_INFO, STAG, __VA_ARGS__)
#define SLOGE(...) __android_log_print(ANDROID_LOG_ERROR, STAG, __VA_ARGS__)

#define ADH_SITE_MAX_SLOTS 16
#define ADH_SITE_MAX_SITES 8
#define ADH_SITE_THUNK_STRIDE 256
#define ADH_SITE_PAGE_LEN 4096
#define ADH_SITE_SCAN_BUDGET (32u * 1024u * 1024u)   // never scan more than this many .text bytes
#define ADH_BL_RANGE (128u * 1024u * 1024u)

// Frame layout must match the entry stubs in native_hooks.cpp (x0-x7, x8, x9, x29/x30, x18, q0-q7).
#define FR_X0 0
#define FR_X8 64
#define FR_X9 72
#define FR_X29 80
#define FR_X18 96
#define FR_Q0 128
#define FR_FRAME 256

struct site_entry {
    unsigned int *at;        // BL instruction address
    unsigned int orig;       // original instruction word
    void *thunk;
};

struct site_ctx {
    int used;
    int count;
    void *target;
    void *page;              // near page holding the thunks (memfd-backed, r-x)
    int page_kept;           // set when unmapping was refused after revert (thread was inside a thunk)
    long long scanned;
    struct site_entry sites[ADH_SITE_MAX_SITES];
};

static struct site_ctx g_site_ctx[ADH_SITE_MAX_SLOTS];
static pthread_mutex_t g_site_lock = PTHREAD_MUTEX_INITIALIZER;
// Last revert that could not unmap its page (a thread was still inside a thunk). Kept for status so
// a revert never looks like "nothing left behind" while a page is still mapped.
static void *g_last_kept_page;
static int g_last_kept_slot = -1;

// ---- AArch64 encoders (verified against llvm-mc) ----------------------------------------
static unsigned int enc_sub_sp(int imm) { return 0xD1000000u | ((unsigned)imm << 10) | (31u << 5) | 31u; }
static unsigned int enc_add_sp(int imm) { return 0x91000000u | ((unsigned)imm << 10) | (31u << 5) | 31u; }
static unsigned int enc_mov_sp_to_x0(void) { return 0x91000000u | (31u << 5) | 0u; }
static unsigned int enc_stp_x(int rt, int rt2, int rn, int off) {
    return 0xA9000000u | (((unsigned)(off / 8) & 0x7Fu) << 15) | ((unsigned)rt2 << 10) | ((unsigned)rn << 5) | (unsigned)rt;
}
static unsigned int enc_ldp_x(int rt, int rt2, int rn, int off) {
    return 0xA9400000u | (((unsigned)(off / 8) & 0x7Fu) << 15) | ((unsigned)rt2 << 10) | ((unsigned)rn << 5) | (unsigned)rt;
}
static unsigned int enc_stp_q(int rt, int rt2, int rn, int off) {
    return 0xAD000000u | (((unsigned)(off / 16) & 0x7Fu) << 15) | ((unsigned)rt2 << 10) | ((unsigned)rn << 5) | (unsigned)rt;
}
static unsigned int enc_ldp_q(int rt, int rt2, int rn, int off) {
    return 0xAD400000u | (((unsigned)(off / 16) & 0x7Fu) << 15) | ((unsigned)rt2 << 10) | ((unsigned)rn << 5) | (unsigned)rt;
}
static unsigned int enc_str_x(int rt, int rn, int off) {
    return 0xF9000000u | (((unsigned)(off / 8) & 0xFFFu) << 10) | ((unsigned)rn << 5) | (unsigned)rt;
}
static unsigned int enc_ldr_x(int rt, int rn, int off) {
    return 0xF9400000u | (((unsigned)(off / 8) & 0xFFFu) << 10) | ((unsigned)rn << 5) | (unsigned)rt;
}
static unsigned int enc_movz_x(int rd, unsigned imm16) { return 0xD2800000u | ((imm16 & 0xFFFFu) << 5) | (unsigned)rd; }
static unsigned int enc_ldr_lit(int rt, int at_idx, int lit_idx) {
    int imm19 = lit_idx - at_idx;
    return 0x58000000u | (((unsigned)imm19 & 0x7FFFFu) << 5) | (unsigned)rt;
}
static unsigned int enc_ldr_x_lit(int rt, int at_idx, int lit_idx) {
    // LDR (literal) is the same encoding family for X registers: opc=01 -> 0x58000000.
    return enc_ldr_lit(rt, at_idx, lit_idx);
}
static const unsigned int kBlrX16 = 0xD63F0200u;
static const unsigned int kRet = 0xD65F03C0u;
static unsigned int enc_cbnz_x(int rt, int at_idx, int target_idx) {
    int imm19 = target_idx - at_idx;
    return 0xB5000000u | (((unsigned)imm19 & 0x7FFFFu) << 5) | (unsigned)rt;
}
static unsigned int enc_b(int at_idx, int target_idx) {
    int imm26 = target_idx - at_idx;
    return 0x14000000u | ((unsigned)imm26 & 0x03FFFFFFu);
}
static unsigned int enc_bl(int64_t site, int64_t target) {
    int64_t delta = target - site;
    return 0x94000000u | (unsigned)((delta >> 2) & 0x03FFFFFF);
}
// Same immediate but a plain B, used when the original site was itself a B (a tail call). A B does
// not touch x30, so the thunk keeps the caller's return address in its frame and rets straight to
// it. Patching a tail call with a BL instead would make the thunk return to the instruction after
// the site - with this fixture that is the callee body, and the CPU looped there forever (observed
// on device: PC pinned to the function entry at 100%).
static unsigned int enc_b_site(int64_t site, int64_t target) {
    int64_t delta = target - site;
    return 0x14000000u | (unsigned)((delta >> 2) & 0x03FFFFFF);
}

// Emit one thunk. Returns the word count, or 0 when the layout check fails.
static int emit_thunk(unsigned int *c, int cap, void *recorder, void *original, int hook_slot) {
    int n = 0;
    if (cap < 48) return 0;
    c[n++] = enc_sub_sp(FR_FRAME);
    c[n++] = enc_stp_x(0, 1, 31, 0);
    c[n++] = enc_stp_x(2, 3, 31, 16);
    c[n++] = enc_stp_x(4, 5, 31, 32);
    c[n++] = enc_stp_x(6, 7, 31, 48);
    c[n++] = enc_str_x(8, 31, FR_X8);
    c[n++] = enc_str_x(9, 31, FR_X9);
    c[n++] = enc_stp_x(29, 30, 31, FR_X29);
    c[n++] = enc_str_x(18, 31, FR_X18);
    c[n++] = enc_stp_q(0, 1, 31, FR_Q0);
    c[n++] = enc_stp_q(2, 3, 31, FR_Q0 + 32);
    c[n++] = enc_stp_q(4, 5, 31, FR_Q0 + 64);
    c[n++] = enc_stp_q(6, 7, 31, FR_Q0 + 96);
    c[n++] = enc_mov_sp_to_x0();
    c[n++] = enc_movz_x(1, (unsigned)hook_slot);
    const int lit1 = n; c[n++] = 0;              // ldr x16, =recorder
    c[n++] = kBlrX16;                            // blr x16 -> record (also applies rewrites)
    const int skip_branch = n; c[n++] = 0;       // cbnz x0, -> skip block
    // Reload everything the target may take as an argument (the recorder may have rewritten x0-x7).
    c[n++] = enc_ldp_x(0, 1, 31, 0);
    c[n++] = enc_ldp_x(2, 3, 31, 16);
    c[n++] = enc_ldp_x(4, 5, 31, 32);
    c[n++] = enc_ldp_x(6, 7, 31, 48);
    c[n++] = enc_ldr_x(8, 31, FR_X8);
    c[n++] = enc_ldr_x(9, 31, FR_X9);
    c[n++] = enc_ldp_q(0, 1, 31, FR_Q0);
    c[n++] = enc_ldp_q(2, 3, 31, FR_Q0 + 32);
    c[n++] = enc_ldp_q(4, 5, 31, FR_Q0 + 64);
    c[n++] = enc_ldp_q(6, 7, 31, FR_Q0 + 96);
    const int lit2 = n; c[n++] = 0;              // ldr x16, =original
    c[n++] = kBlrX16;                            // blr x16 -> the real function (result stays in x0/x1/d0/d1)
    const int branch_over_skip = n; c[n++] = 0;  // placeholder: branch to the shared epilogue
    const int skip_block = n;
    c[n++] = enc_ldr_x(0, 31, FR_X0);            // skip/returnSet: result was written into the frame
    const int epilogue = n;
    c[n++] = enc_ldr_x(30, 31, FR_X29 + 8);      // restore our caller's link register
    c[n++] = enc_add_sp(FR_FRAME);
    c[n++] = kRet;
    // 64-bit literals, 8-byte aligned. Check the room instead of trusting the current count.
    if (n + 6 > cap) return 0;
    while (n & 1) c[n++] = 0xD503201Fu;          // nop padding so the pool stays 8-byte aligned
    if (n + 4 > cap) return 0;
    const int pool = n;
    uint64_t rec = (uint64_t)(uintptr_t)recorder;
    uint64_t org = (uint64_t)(uintptr_t)original;
    c[n++] = (unsigned)(rec & 0xFFFFFFFFu);
    c[n++] = (unsigned)(rec >> 32);
    c[n++] = (unsigned)(org & 0xFFFFFFFFu);
    c[n++] = (unsigned)(org >> 32);
    // Fill in the four pc-relative slots.
    c[lit1] = enc_ldr_x_lit(16, lit1, pool);
    c[lit2] = enc_ldr_x_lit(16, lit2, pool + 2);
    c[skip_branch] = enc_cbnz_x(0, skip_branch, skip_block);
    c[branch_over_skip] = enc_b(branch_over_skip, epilogue);
    return n;
}

// ---- /proc/self/maps helpers -------------------------------------------------------------
// Copy the path of the mapping containing addr and report its exec bit.
static int mapping_of(unsigned long long addr, char *path, size_t path_size, int *is_exec) {
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), m)) {
        unsigned long long s = 0, e = 0;
        char perms[8] = "";
        if (sscanf(line, "%llx-%llx %7s", &s, &e, perms) != 3) continue;
        if (addr < s || addr >= e) continue;
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        char *q = line;
        for (int f = 0; f < 5 && q; f++) { q = strchr(q, ' '); if (q) while (*q == ' ') q++; }
        snprintf(path, path_size, "%s", (q && *q) ? q : "");
        if (is_exec) *is_exec = perms[2] == 'x';
        found = 1;
        break;
    }
    fclose(m);
    return found;
}

struct mod_range { unsigned long long start, end; int exec, read; };

// Collect the module's mappings (bounded): executable ones are the scan targets, readable ones
// gate the PLT/GOT dereference below.
static int module_ranges(const char *path, struct mod_range *out, int max) {
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return 0;
    char line[512];
    int n = 0;
    while (fgets(line, sizeof(line), m) && n < max) {
        unsigned long long s = 0, e = 0;
        char perms[8] = "";
        if (sscanf(line, "%llx-%llx %7s", &s, &e, perms) != 3) continue;
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        char *q = line;
        for (int f = 0; f < 5 && q; f++) { q = strchr(q, ' '); if (q) while (*q == ' ') q++; }
        if (!q || strcmp(q, path) != 0) continue;
        out[n].start = s;
        out[n].end = e;
        out[n].exec = perms[2] == 'x';
        out[n].read = perms[0] == 'r';
        n++;
    }
    fclose(m);
    return n;
}

static int range_contains(const struct mod_range *rs, int n, unsigned long long addr, int want_exec, int want_read) {
    for (int i = 0; i < n; i++) {
        if (addr < rs[i].start || addr >= rs[i].end) continue;
        if (want_exec && !rs[i].exec) continue;
        if (want_read && !rs[i].read) continue;
        return 1;
    }
    return 0;
}

// One level of PLT indirection. A stub is 'adrp x16, page ; ldr x17, [x16, #off] ; ... ; br x17',
// so the address it jumps to sits in the GOT slot read by the second instruction. A call to an
// interposable symbol inside the same module goes through such a stub, which is why matching only
// the function entry misses it (the sandbox fixture is a tail call through one).
static void *stub_jump_target(void *stub, const struct mod_range *rs, int n) {
    if (!range_contains(rs, n, (unsigned long long)(uintptr_t)stub, 1, 0)) return NULL;
    unsigned int i0 = *(unsigned int *)stub;
    if (((i0 >> 24) & 0x1Fu) != 0x10u) return NULL;              // ADRP
    if ((int)(i0 & 31u) != 16) return NULL;
    unsigned long long immlo = (i0 >> 29) & 3u;
    unsigned long long immhi = (i0 >> 5) & 0x7FFFFu;
    long long imm = (long long)((immhi << 2) | immlo);
    if (imm & (1LL << 20)) imm -= (1LL << 21);
    unsigned long long page = ((unsigned long long)(uintptr_t)stub & ~0xFFFull) + ((unsigned long long)imm << 12);
    unsigned int i1 = *((unsigned int *)stub + 1);
    if ((i1 & 0xFFC00000u) != 0xF9400000u) return NULL;          // LDR (unsigned offset, 64-bit)
    if ((int)((i1 >> 5) & 31u) != 16) return NULL;
    unsigned long long slot = page + (unsigned long long)((i1 >> 10) & 0xFFFu) * 8ull;
    if (!range_contains(rs, n, slot, 0, 1)) return NULL;
    return *(void **)(uintptr_t)slot;
}

// Executable scan targets, taken from the collected mappings (bounded total).
static int module_exec_ranges(const struct mod_range *all, int all_n, struct mod_range *out, int max, long long *total) {
    int n = 0;
    unsigned long long seen_total = 0;
    for (int i = 0; i < all_n && n < max; i++) {
        if (!all[i].exec) continue;
        out[n++] = all[i];
        seen_total += all[i].end - all[i].start;
        if (seen_total > ADH_SITE_SCAN_BUDGET) break;
    }
    if (total) *total = (long long)seen_total;
    return n;
}

static int in_existing_thunk_page(void *addr) {
    int hit = 0;
    pthread_mutex_lock(&g_site_lock);
    for (int i = 0; i < ADH_SITE_MAX_SLOTS; i++) {
        struct site_ctx *c = &g_site_ctx[i];
        if (!c->used || !c->page) continue;
        if ((uintptr_t)addr >= (uintptr_t)c->page && (uintptr_t)addr < (uintptr_t)c->page + ADH_SITE_PAGE_LEN) { hit = 1; break; }
    }
    pthread_mutex_unlock(&g_site_lock);
    return hit;
}

// ---- near page ---------------------------------------------------------------------------
// BL can only reach +-128 MB, so the thunks must live next to the module. The page is a memfd
// mapping (same family as the ART JIT cache), so a sites hook does not add an anonymous
// executable page either. MAP_FIXED_NOREPLACE is verified by the result address itself: kernels
// that predate the flag ignore it and would otherwise place the page anywhere.
// Take one exact address if the range is free. MAP_FIXED_NOREPLACE is verified by the returned
// address: kernels that predate the flag ignore it and would place the page anywhere, silently
// breaking the BL range assumption.
static void *take_exact(int mfd, void *want, size_t len, int *err_out) {
    errno = 0;
    void *got = mmap(want, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED_NOREPLACE, mfd, 0);
    if (got == MAP_FAILED) { if (err_out) *err_out = errno; return NULL; }
    if (got != want) {   // kernel ignored NOREPLACE (pre-4.17) and placed it elsewhere
        munmap(got, len);
        if (err_out) *err_out = EEXIST;
        return NULL;
    }
    return got;
}

// A page free within +-128 MB of near_addr (BL reach).
//
// Cost matters here: the calling command runs on the agent's single command thread, and every
// failing MAP_FIXED_NOREPLACE costs a VMA walk - a naive 64 KB sweep over +-128 MB took ~15 s in a
// 2600-mapping process and wedged every other command. So: one kernel-picked hint, then the ends of
// the module's own mappings, then a coarse 2 MB sweep, and only a small 64 KB refinement.
static void *alloc_near_page(unsigned long long near_addr, size_t len, const struct mod_range *rs, int n, int *attempts_out) {
    int mfd = (int)syscall(__NR_memfd_create, "jit-cache", 0);
    if (mfd < 0) return NULL;
    if (ftruncate(mfd, (off_t)len) != 0) { close(mfd); return NULL; }
    int attempts = 0;
    int last_errno = 0;
    void *page = NULL;
    const unsigned long long lo = near_addr > ADH_BL_RANGE ? near_addr - ADH_BL_RANGE : 0;
    const unsigned long long hi = near_addr + ADH_BL_RANGE;
    #define IN_RANGE(a) ((unsigned long long)(uintptr_t)(a) >= lo && (unsigned long long)(uintptr_t)(a) + len <= hi)

    // 1) let the kernel place it, using the module as a hint (usually one syscall)
    {
        attempts++;
        void *hint = (void *)(uintptr_t)((near_addr & ~0xFFFFull) + 0x10000ull);
        void *got = mmap(hint, len, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
        if (got != MAP_FAILED) {
            if (IN_RANGE(got)) page = got;
            else munmap(got, len);
        }
    }
    // 2) right after each of the module's own mappings
    for (int i = 0; i < n && !page; i++) {
        if (rs[i].end > (unsigned long long)-1 - 0x10000ull) continue;   // cannot round up safely
        unsigned long long cand = (rs[i].end + 0xFFFFull) & ~0xFFFFull;
        if (cand + len > hi || rs[i].end < lo) continue;
        attempts++;
        page = take_exact(mfd, (void *)(uintptr_t)cand, len, &last_errno);
    }
    // 3) coarse outward sweep, 2 MB steps
    for (unsigned long long off = 0x200000ull; off <= ADH_BL_RANGE && !page; off += 0x200000ull) {
        for (int dir = 0; dir < 2 && !page; dir++) {
            unsigned long long cand = (dir ? (near_addr + off) : (near_addr - off)) & ~0xFFFFull;
            if (cand + len > hi || cand < lo) continue;
            attempts++;
            page = take_exact(mfd, (void *)(uintptr_t)cand, len, &last_errno);
        }
    }
    // 4) bounded 64 KB refinement around the target
    for (unsigned long long off = 0x10000ull; off <= 0x800000ull && !page; off += 0x10000ull) {
        for (int dir = 0; dir < 2 && !page; dir++) {
            unsigned long long cand = (dir ? (near_addr + off) : (near_addr - off)) & ~0xFFFFull;
            if (cand + len > hi || cand < lo) continue;
            attempts++;
            page = take_exact(mfd, (void *)(uintptr_t)cand, len, &last_errno);
        }
    }
    #undef IN_RANGE
    close(mfd);
    if (attempts_out) *attempts_out = attempts;
    errno = last_errno;
    return page;
}

// ---- scan + install ----------------------------------------------------------------------
static int scan_bl_sites(void *target, int max_sites, const struct mod_range *ranges, int range_count,
                         const struct mod_range *mod_ranges, int mod_count,
                         struct site_entry *out, long long *scanned, int *mismatch) {
    int found = 0;
    if (mismatch) *mismatch = 0;
    for (int r = 0; r < range_count && found < max_sites; r++) {
        unsigned int *p = (unsigned int *)(uintptr_t)ranges[r].start;
        unsigned int *end = (unsigned int *)(uintptr_t)ranges[r].end;
        for (; p < end && found < max_sites; p++) {
            unsigned int insn = *p;
            // B (tail call) and BL both reach the function, and a tail call still returns to the
            // original caller, so the same thunk shape serves either form.
            if ((insn & 0x7C000000u) != 0x14000000u) continue;
            int imm26 = (int)(insn & 0x03FFFFFFu);
            if (imm26 & 0x02000000) imm26 -= 0x04000000;
            void *dst = (void *)((uintptr_t)p + (intptr_t)imm26 * 4);
            if (dst != target && stub_jump_target(dst, mod_ranges, mod_count) != target) continue;
            if (in_existing_thunk_page(p)) continue;
            out[found].at = p;
            out[found].orig = insn;
            out[found].thunk = NULL;
            found++;
        }
        *scanned += (long long)(ranges[r].end - ranges[r].start);
    }
    return found;
}

int adh_site_hook_apply(int slot, void *target, int max_sites, char *error, size_t error_size) {
    if (slot < 0 || slot >= ADH_SITE_MAX_SLOTS) {
        snprintf(error, error_size, "site slot %d out of range", slot);
        return 0;
    }
    if (!target || !adh_addr_is_executable(target)) {
        snprintf(error, error_size, "site hook target is not in an executable mapping");
        return 0;
    }
    if (max_sites <= 0) max_sites = ADH_SITE_MAX_SITES;
    if (max_sites > ADH_SITE_MAX_SITES) max_sites = ADH_SITE_MAX_SITES;

    char path[256] = "";
    int is_exec = 0;
    if (!mapping_of((unsigned long long)(uintptr_t)target, path, sizeof(path), &is_exec) || !is_exec || !path[0]) {
        snprintf(error, error_size, "could not resolve the module of target %p from /proc/self/maps", target);
        return 0;
    }
    struct mod_range mod_ranges[64];
    int mod_count = module_ranges(path, mod_ranges, 64);
    struct mod_range ranges[32];
    long long total = 0;
    int range_count = module_exec_ranges(mod_ranges, mod_count, ranges, 32, &total);
    if (range_count <= 0) {
        snprintf(error, error_size, "no executable ranges for %s", path);
        return 0;
    }

    struct site_ctx *ctx = &g_site_ctx[slot];
    pthread_mutex_lock(&g_site_lock);
    if (ctx->used) {
        pthread_mutex_unlock(&g_site_lock);
        snprintf(error, error_size, "site slot %d is still in use", slot);
        return 0;
    }
    ctx->used = 1;                 // claim the slot while we work
    pthread_mutex_unlock(&g_site_lock);

    long long scanned = 0;
    int count = scan_bl_sites(target, max_sites, ranges, range_count, mod_ranges, mod_count, ctx->sites, &scanned, NULL);
    ctx->scanned = scanned;
    if (count <= 0) {
        pthread_mutex_lock(&g_site_lock);
        memset(ctx, 0, sizeof(*ctx));
        pthread_mutex_unlock(&g_site_lock);
        snprintf(error, error_size,
                 "no BL call site for %p found in %s (scanned %lld bytes, %d ranges) - use mode=inline or mode=got",
                 target, path, scanned, range_count);
        return 0;
    }

    int alloc_attempts = 0;
    void *page = alloc_near_page((unsigned long long)(uintptr_t)target, ADH_SITE_PAGE_LEN, mod_ranges, mod_count, &alloc_attempts);
    if (!page) {
        pthread_mutex_lock(&g_site_lock);
        memset(ctx, 0, sizeof(*ctx));
        pthread_mutex_unlock(&g_site_lock);
        snprintf(error, error_size, "could not allocate a thunk page within +-%u MB of %s after %d probes (errno=%d)",
                 ADH_BL_RANGE / (1024u * 1024u), path, alloc_attempts, errno);
        return 0;
    }

    // Emit the thunks first: a half-written thunk must never be reachable.
    for (int i = 0; i < count; i++) {
        unsigned char *at = (unsigned char *)page + (size_t)i * ADH_SITE_THUNK_STRIDE;
        unsigned int words[64];
        int n = emit_thunk(words, 64, (void *)&adh_native_hook_record_site, target, slot);
        if (n <= 0 || n * 4 > ADH_SITE_THUNK_STRIDE) {
            munmap(page, ADH_SITE_PAGE_LEN);
            pthread_mutex_lock(&g_site_lock);
            memset(ctx, 0, sizeof(*ctx));
            pthread_mutex_unlock(&g_site_lock);
            snprintf(error, error_size, "thunk layout overflow for site %d", i);
            return 0;
        }
        memcpy(at, words, (size_t)n * 4);
        __builtin___clear_cache((char *)at, (char *)at + ADH_SITE_THUNK_STRIDE);
        ctx->sites[i].thunk = at;
    }
    if (mprotect(page, ADH_SITE_PAGE_LEN, PROT_READ | PROT_EXEC) != 0) {
        munmap(page, ADH_SITE_PAGE_LEN);
        pthread_mutex_lock(&g_site_lock);
        memset(ctx, 0, sizeof(*ctx));
        pthread_mutex_unlock(&g_site_lock);
        snprintf(error, error_size, "could not make the thunk page executable (errno=%d)", errno);
        return 0;
    }

    // Patch the call sites. On the first failure, put back everything already patched.
    int patched = 0;
    for (int i = 0; i < count; i++) {
        int64_t site = (int64_t)(uintptr_t)ctx->sites[i].at;
        int64_t thunk = (int64_t)(uintptr_t)ctx->sites[i].thunk;
        int64_t delta = thunk - site;
        if (delta > (int64_t)ADH_BL_RANGE || delta < -(int64_t)ADH_BL_RANGE) {
            for (int j = 0; j < patched; j++) adh_patch_code_bytes(ctx->sites[j].at, &ctx->sites[j].orig, 4);
            munmap(page, ADH_SITE_PAGE_LEN);
            pthread_mutex_lock(&g_site_lock);
            memset(ctx, 0, sizeof(*ctx));
            pthread_mutex_unlock(&g_site_lock);
            snprintf(error, error_size, "thunk for site %d is out of BL range (%lld bytes)", i, (long long)delta);
            return 0;
        }
        const int was_bl = (ctx->sites[i].orig & 0xFC000000u) == 0x94000000u;
        unsigned int patched_insn = was_bl ? enc_bl(site, thunk) : enc_b_site(site, thunk);
        if (!adh_patch_code_bytes(ctx->sites[i].at, &patched_insn, 4)) {
            for (int j = 0; j < patched; j++) adh_patch_code_bytes(ctx->sites[j].at, &ctx->sites[j].orig, 4);
            munmap(page, ADH_SITE_PAGE_LEN);
            pthread_mutex_lock(&g_site_lock);
            memset(ctx, 0, sizeof(*ctx));
            pthread_mutex_unlock(&g_site_lock);
            snprintf(error, error_size, "could not patch call site %p (errno=%d)", ctx->sites[i].at, errno);
            return 0;
        }
        patched++;
    }

    pthread_mutex_lock(&g_site_lock);
    ctx->target = target;
    ctx->page = page;
    ctx->count = count;
    ctx->page_kept = 0;
    pthread_mutex_unlock(&g_site_lock);
    SLOGI("site hook installed slot=%d target=%p sites=%d scanned=%lld page=%p", slot, target, count, scanned, page);
    return 1;
}

int adh_site_hook_revert(int slot, char *error, size_t error_size) {
    if (slot < 0 || slot >= ADH_SITE_MAX_SLOTS) return 0;
    struct site_ctx *ctx = &g_site_ctx[slot];
    pthread_mutex_lock(&g_site_lock);
    if (!ctx->used || !ctx->page || ctx->count <= 0) {
        pthread_mutex_unlock(&g_site_lock);
        snprintf(error, error_size, "site slot %d has no installed sites", slot);
        return 0;
    }
    void *page = ctx->page;
    int count = ctx->count;
    unsigned long long hits_before = adh_native_hook_hits(slot);
    int restored = 0;
    for (int i = 0; i < count; i++) {
        // Write the original BL back and prove it landed: a failed restore must not be reported
        // as a clean unhook.
        if (!adh_patch_code_bytes(ctx->sites[i].at, &ctx->sites[i].orig, 4) || *ctx->sites[i].at != ctx->sites[i].orig) {
            pthread_mutex_unlock(&g_site_lock);
            snprintf(error, error_size, "could not restore call site %p (%d/%d restored)", ctx->sites[i].at, restored, count);
            return 0;
        }
        restored++;
    }
    memset(ctx, 0, sizeof(*ctx));
    pthread_mutex_unlock(&g_site_lock);

    // A thread that already entered a thunk may still be inside it; the page must stay mapped until
    // a quiet window proves otherwise (same policy as the hard unhook quiesce).
    int quiet = 0;
    for (int round = 0; round < 80 && !quiet; round++) {
        unsigned long long before = adh_native_hook_hits(slot);
        struct timespec ts = { 0, 5 * 1000 * 1000 };
        nanosleep(&ts, NULL);
        unsigned long long after = adh_native_hook_hits(slot);
        if (after == before && round >= 4) quiet = 1;
        else if (after != before) round = 0;
    }
    if (quiet || hits_before == 0) {
        if (munmap(page, ADH_SITE_PAGE_LEN) != 0) {
            snprintf(error, error_size, "sites restored but the thunk page could not be unmapped (errno=%d)", errno);
            return 0;
        }
    } else {
        pthread_mutex_lock(&g_site_lock);
        g_last_kept_page = page;
        g_last_kept_slot = slot;
        pthread_mutex_unlock(&g_site_lock);
        SLOGE("thunk page %p kept mapped: hits kept moving during the quiesce window", page);
    }
    SLOGI("site hook reverted slot=%d sites=%d quiet=%d kept=%d", slot, restored, quiet, quiet ? 0 : 1);
    return 1;
}

int adh_site_hook_count(int slot) {
    if (slot < 0 || slot >= ADH_SITE_MAX_SLOTS) return 0;
    return g_site_ctx[slot].count;
}

void *adh_site_hook_page(int slot) {
    if (slot < 0 || slot >= ADH_SITE_MAX_SLOTS) return NULL;
    return g_site_ctx[slot].page;
}

void adh_site_hook_sites_json(int slot, char *out, size_t out_size, size_t *used) {
    if (!out || !out_size || !used || slot < 0 || slot >= ADH_SITE_MAX_SLOTS) return;
    struct site_ctx *ctx = &g_site_ctx[slot];
    size_t off = *used;
    void *kept = (g_last_kept_slot == slot) ? g_last_kept_page : NULL;
    int n = snprintf(out + off, out_size - off,
                     ",\"siteCount\":%d,\"scanned\":%lld,\"thunkPage\":\"0x%llx\",\"pageKept\":\"%s\",\"sites\":[",
                     ctx->count, ctx->scanned, (unsigned long long)(uintptr_t)ctx->page,
                     kept ? "true" : "false");
    if (n < 0 || (size_t)n >= out_size - off) return;
    off += (size_t)n;
    for (int i = 0; i < ctx->count; i++) {
        unsigned int now = ctx->sites[i].at ? *ctx->sites[i].at : 0;
        n = snprintf(out + off, out_size - off,
                     "%s{\"at\":\"0x%llx\",\"form\":\"%s\",\"orig\":\"0x%08x\",\"now\":\"0x%08x\",\"thunk\":\"0x%llx\"}",
                     i ? "," : "", (unsigned long long)(uintptr_t)ctx->sites[i].at,
                     ((ctx->sites[i].orig & 0xFC000000u) == 0x94000000u) ? "bl" : "b",
                     ctx->sites[i].orig, now,
                     (unsigned long long)(uintptr_t)ctx->sites[i].thunk);
        if (n < 0 || (size_t)n >= out_size - off) return;
        off += (size_t)n;
    }
    n = snprintf(out + off, out_size - off, "]");
    if (n < 0 || (size_t)n >= out_size - off) return;
    *used = off + (size_t)n;
}
