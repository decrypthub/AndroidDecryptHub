// Call-site hooking: rewrite the B/BL instructions that call a target instead of touching the
// target itself. See site_hooks.h for why (the entry stays byte-identical) and the honest limits.
//
// Every emitted thunk is hand-encoded AArch64. Each encoding was checked against llvm-mc output
// (clang --target=aarch64 -c) before it was used: a wrong word here is a crash inside the target's
// own call path, not a wrong return value.
#include "site_hooks.h"

#include "got.h"
#include "native_hooks.h"

#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define STAG "rt.site"
#define SLOGI(...) __android_log_print(ANDROID_LOG_INFO, STAG, __VA_ARGS__)
#define SLOGE(...) __android_log_print(ANDROID_LOG_ERROR, STAG, __VA_ARGS__)

#define ADH_SITE_MAX_SLOTS 16
#define ADH_SITE_MAX_SITES 8
#define ADH_SITE_THUNK_STRIDE 256
#define ADH_SITE_PAGE_LEN 4096
#define ADH_SITE_SCAN_BUDGET (128u * 1024u * 1024u)  // never scan more .text than this per apply
#define ADH_MAX_RANGES 4096   // dynamic: the sandbox process has ~2600 mappings; a truncated table used to hide the caller module
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
    unsigned int *at;        // B/BL instruction address
    unsigned int orig;       // original instruction word
    void *thunk;             // this site's thunk
    void *page;              // this site's thunk page (memfd, r-x)
    char mod[96];            // basename of the module that owns the call site
};

struct site_ctx {
    int used;
    int count;
    void *target;
    int page_kept;           // a site page had to stay mapped (thread was inside a thunk)
    long long scanned;       // bytes actually scanned
    int truncated;           // the byte budget stopped the scan early
    struct site_entry sites[ADH_SITE_MAX_SITES];
};

static struct site_ctx g_site_ctx[ADH_SITE_MAX_SLOTS];
static pthread_mutex_t g_site_lock = PTHREAD_MUTEX_INITIALIZER;
// Last revert that could not unmap a page, kept so status never claims "nothing left behind".
static void *g_last_kept_page;
static int g_last_kept_slot = -1;

struct mod_range { unsigned long long start, end; int exec, read; int is_file; char path[160]; };

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
static const unsigned int kBlrX16 = 0xD63F0200u;
static const unsigned int kRet = 0xD65F03C0u;
static unsigned int enc_cbnz_x(int rt, int at_idx, int target_idx) {
    int imm19 = target_idx - at_idx;
    return 0xB5000000u | (((unsigned)imm19 & 0x7FFFFu) << 5) | (unsigned)rt;
}
static unsigned int enc_branch(int64_t site, int64_t target, int link) {
    int64_t delta = target - site;
    return (link ? 0x94000000u : 0x14000000u) | (unsigned)((delta >> 2) & 0x03FFFFFF);
}

static int off_ok(int off, int unit, int max) { return off >= 0 && off % unit == 0 && off <= max; }

// Emit one thunk. Returns the word count, or 0 when the layout check fails.
static int emit_thunk(unsigned int *c, int cap, void *recorder, void *original, int hook_slot) {
    int n = 0;
    if (cap < 48) return 0;
    // The encoders mask their immediates, so an out-of-range offset would silently emit a different
    // instruction. Check every offset this thunk actually uses before encoding anything.
    if (hook_slot < 0 || hook_slot > 0xFFFF) return 0;
    if (!off_ok(0, 8, 32760) || !off_ok(16, 8, 32760) || !off_ok(32, 8, 32760) || !off_ok(48, 8, 32760)) return 0;
    if (!off_ok(FR_X8, 8, 32760) || !off_ok(FR_X9, 8, 32760) || !off_ok(FR_X29, 8, 32760) || !off_ok(FR_X18, 8, 32760)) return 0;
    if (!off_ok(FR_Q0, 16, 504) || !off_ok(FR_Q0 + 32, 16, 504) || !off_ok(FR_Q0 + 64, 16, 504) || !off_ok(FR_Q0 + 96, 16, 504)) return 0;
    if (!off_ok(FR_FRAME, 16, 4095)) return 0;
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
    c[n++] = kBlrX16;                            // blr x16 -> record (also applies arg rewrites)
    const int skip_branch = n; c[n++] = 0;       // cbnz x0, -> skip block
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
    const int branch_over_skip = n; c[n++] = 0;  // b -> shared epilogue
    const int skip_block = n;
    c[n++] = enc_ldr_x(0, 31, FR_X0);            // skip path: the recorder wrote the answer into the frame
    const int epilogue = n;
    c[n++] = enc_ldr_x(30, 31, FR_X29 + 8);      // restore the return address this thunk must use
    c[n++] = enc_add_sp(FR_FRAME);
    c[n++] = kRet;
    // 64-bit literals, 8-byte aligned. Check the room instead of trusting the current count.
    if (n + 6 > cap) return 0;
    while (n & 1) c[n++] = 0xD503201Fu;          // nop padding keeps the pool 8-byte aligned
    if (n + 4 > cap) return 0;
    const int pool = n;
    uint64_t rec = (uint64_t)(uintptr_t)recorder;
    uint64_t org = (uint64_t)(uintptr_t)original;
    c[n++] = (unsigned)(rec & 0xFFFFFFFFu);
    c[n++] = (unsigned)(rec >> 32);
    c[n++] = (unsigned)(org & 0xFFFFFFFFu);
    c[n++] = (unsigned)(org >> 32);
    c[lit1] = enc_ldr_lit(16, lit1, pool);
    c[lit2] = enc_ldr_lit(16, lit2, pool + 2);
    c[skip_branch] = enc_cbnz_x(0, skip_branch, skip_block);
    // NOTE: index math on purpose here. enc_branch() takes BYTE addresses (it patches call sites);
    // passing instruction indices to it emitted a branch to itself and the target spun forever.
    c[branch_over_skip] = 0x14000000u | ((unsigned)(epilogue - branch_over_skip) & 0x03FFFFFFu);
    // Self-check before this thunk can ever be reached: a wrong word here is a hang inside the
    // target's own call path, so verify both pc-relative fields and both literals.
    if ((c[lit1] & 0xFF000000u) != 0x58000000u) return 0;
    if ((int)((c[lit1] >> 5) & 0x7FFFFu) != pool - lit1) return 0;
    if ((c[lit2] & 0xFF000000u) != 0x58000000u) return 0;
    if ((int)((c[lit2] >> 5) & 0x7FFFFu) != (pool + 2) - lit2) return 0;
    if ((c[skip_branch] & 0xFF000000u) != 0xB5000000u) return 0;
    if ((int)((c[skip_branch] >> 5) & 0x7FFFFu) != skip_block - skip_branch) return 0;
    const unsigned int b_word = c[branch_over_skip];
    if ((b_word & 0xFC000000u) != 0x14000000u) return 0;
    if ((int)(b_word & 0x03FFFFFFu) != epilogue - branch_over_skip) return 0;
    const uint64_t lit_rec = (uint64_t)c[pool] | ((uint64_t)c[pool + 1] << 32);
    const uint64_t lit_org = (uint64_t)c[pool + 2] | ((uint64_t)c[pool + 3] << 32);
    if (lit_rec != (uint64_t)(uintptr_t)recorder || lit_org != (uint64_t)(uintptr_t)original) return 0;
    return n;
}

// ---- process mappings --------------------------------------------------------------------
static int basename_of(const char *path, char *out, size_t out_size) {
    if (!path || !*path) return 0;
    const char *slash = strrchr(path, '/');
    snprintf(out, out_size, "%s", slash ? slash + 1 : path);
    return 1;
}

// Collect file-backed executable ranges (scan targets) and every readable range (so a PLT stub's
// GOT slot can be dereferenced safely). Anonymous and memfd mappings are skipped: they are JIT
// caches and our own thunk pages, never call sites of interest, and scanning them is pure cost.
// Store the mappings that matter: file-backed executable ranges (scan targets) and file-backed
// readable ranges (where a module keeps the GOT slot a PLT stub reads). Anonymous/memfd mappings are
// JIT caches and thunk pages - never a call site of interest and expensive to walk - so they are
// skipped, but the WHOLE file is parsed: the app's own libraries sit far beyond the first few
// hundred lines of a 2600-mapping process, and stopping early silently lost the target module.
static int collect_ranges(struct mod_range *out, int max, int *exec_n, int *table_full) {
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return 0;
    char line[512];
    int n = 0;
    int e_count = 0;
    while (fgets(line, sizeof(line), m)) {
        unsigned long long s = 0, e = 0;
        char perms[8] = "";
        if (sscanf(line, "%llx-%llx %7s", &s, &e, perms) != 3) continue;
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        char *q = line;
        for (int f = 0; f < 5 && q; f++) { q = strchr(q, ' '); if (q) while (*q == ' ') q++; }
        const char *path = (q && *q) ? q : "";
        // Anonymous mappings have no path; memfd mappings (ART JIT caches) DO start with "/", so
        // they need their own check - missing it let the scanner treat JIT code as a call site and
        // burn the byte budget on it.
        if (path[0] != '/') continue;
        if (strncmp(path, "/memfd:", 7) == 0) continue;
        const int exec = perms[2] == 'x';
        const int read = perms[0] == 'r';
        if (!exec && !read) continue;
        if (n >= max) { if (exec) e_count++; continue; }    // still count for honest reporting
        struct mod_range *r = &out[n++];
        r->start = s;
        r->end = e;
        r->exec = exec;
        r->read = read;
        r->is_file = 1;
        snprintf(r->path, sizeof(r->path), "%s", path);
        if (exec) e_count++;
    }
    fclose(m);
    if (exec_n) *exec_n = e_count;
    if (table_full) *table_full = (n >= max) ? 1 : 0;
    return n;
}

static int range_readable(const struct mod_range *rs, int n, unsigned long long addr) {
    for (int i = 0; i < n; i++) {
        if (addr >= rs[i].start && addr < rs[i].end && rs[i].read) return 1;
    }
    return 0;
}

static int range_contains_addr(const struct mod_range *rs, int n, unsigned long long addr, int want_exec) {
    for (int i = 0; i < n; i++) {
        if (addr >= rs[i].start && addr < rs[i].end && (!want_exec || rs[i].exec)) return 1;
    }
    return 0;
}

// The module a code address belongs to (basename), or "" for anonymous/memfd mappings.
static void module_of_addr(const struct mod_range *rs, int n, unsigned long long addr, char *out, size_t out_size) {
    out[0] = 0;
    for (int i = 0; i < n; i++) {
        if (addr < rs[i].start || addr >= rs[i].end) continue;
        if (rs[i].is_file) basename_of(rs[i].path, out, out_size);
        return;
    }
}

// One level of PLT indirection: a stub is 'adrp x16, page ; ldr x17, [x16, #off] ; ... ; br x17', so
// the address it jumps to lives in the GOT slot the second instruction reads. A call to an
// interposable symbol (which is how the compiler calls a function exported by another module, and
// even a same-module default-visibility symbol) goes through such a stub.
static void *stub_jump_target(const struct mod_range *all, int all_n, void *stub) {
    if (!range_contains_addr(all, all_n, (unsigned long long)(uintptr_t)stub, 1)) return NULL;
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
    if (!range_readable(all, all_n, slot)) return NULL;
    // The slot must belong to the same module as the stub: the GOT a PLT entry reads is in its own
    // module, and without this check a random data word elsewhere could resolve to the target and
    // turn a non-call instruction into a "site".
    char stub_mod[96] = "", slot_mod[96] = "";
    module_of_addr(all, all_n, (unsigned long long)(uintptr_t)stub, stub_mod, sizeof(stub_mod));
    module_of_addr(all, all_n, slot, slot_mod, sizeof(slot_mod));
    if (!stub_mod[0] || strcmp(stub_mod, slot_mod) != 0) return NULL;
    return *(void **)(uintptr_t)slot;
}

// ---- near page ---------------------------------------------------------------------------
// Take one exact address if the range is free. MAP_FIXED_NOREPLACE is verified by the returned
// address: kernels that predate the flag ignore it and would place the page anywhere, silently
// breaking the BL range assumption.
static void *take_exact(int mfd, void *want, size_t len, int *err_out) {
    errno = 0;
    void *got = mmap(want, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED_NOREPLACE, mfd, 0);
    if (got == MAP_FAILED) { if (err_out) *err_out = errno; return NULL; }
    if (got != want) {
        munmap(got, len);
        if (err_out) *err_out = EEXIST;
        return NULL;
    }
    return got;
}

// A page free within +-128 MB of near_addr (BL reach).
//
// Cost matters: this runs on the agent's single command thread and every failing
// MAP_FIXED_NOREPLACE costs a VMA walk - a naive 64 KB sweep over +-128 MB took ~15 s in a
// 2600-mapping process and wedged every other command. So: one kernel-picked hint, then the ends of
// the caller module's mappings, then a coarse 2 MB sweep, and a bounded 64 KB refinement.
static void *alloc_near_page(unsigned long long near_addr, size_t len, const struct mod_range *rs,
                             int rs_n, int *attempts_out) {
    int mfd = (int)syscall(__NR_memfd_create, "jit-cache", 0);
    if (mfd < 0) return NULL;
    if (ftruncate(mfd, (off_t)len) != 0) { close(mfd); return NULL; }
    int attempts = 0;
    int last_errno = 0;
    void *page = NULL;
    const unsigned long long lo = near_addr > ADH_BL_RANGE ? near_addr - ADH_BL_RANGE : 0;
    const unsigned long long hi = near_addr + ADH_BL_RANGE;
    #define IN_RANGE(a) ((unsigned long long)(uintptr_t)(a) >= lo && (unsigned long long)(uintptr_t)(a) + len <= hi)

    // 1) let the kernel place it, using the site as a hint (usually one syscall)
    attempts++;
    void *hint = (void *)(uintptr_t)((near_addr & ~0xFFFFull) + 0x10000ull);
    void *got = mmap(hint, len, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
    if (got != MAP_FAILED) {
        if (IN_RANGE(got)) page = got;
        else munmap(got, len);
    }
    // 2) right after each mapping of the module that owns the site
    for (int i = 0; i < rs_n && !page; i++) {
        if (!rs[i].is_file) continue;
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
    // 4) bounded 64 KB refinement around the site
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

// ---- scan --------------------------------------------------------------------------------
// Ranges to scan for a given scope: the target module only, one named module, or every file-backed
// executable mapping except our own agent (never hook ourselves).
static int wanted_range(const struct mod_range *r, const char *scope, const char *target_module,
                        const char *self_module) {
    if (!r->exec || !r->is_file) return 0;
    char bn[96];
    if (!basename_of(r->path, bn, sizeof(bn))) return 0;
    if (self_module[0] && strcmp(bn, self_module) == 0) return 0;
    // An EMPTY scope means "default" as well: the MCP/HTTP layers pass an empty string when the
    // caller omits it, and treating that as a module name matched nothing (caught by v70).
    if (!scope || !scope[0] || strcmp(scope, "module") == 0) {
        return target_module[0] && strcmp(bn, target_module) == 0;
    }
    if (strcmp(scope, "all") == 0) return 1;
    return strcmp(bn, scope) == 0 || strcmp(r->path, scope) == 0;
}

// 0 = the target's own module, 1 = a module under /data (the app's own code), 2 = everything else.
// Order matters: with a flat budget the scan used to spend all of it on system libraries and never
// reached the app's own callers ("scan budget hit", 0 sites).
static int range_class(const struct mod_range *r, const char *target_module, const char *target_dir) {
    char bn[96];
    if (basename_of(r->path, bn, sizeof(bn)) && target_module[0] && strcmp(bn, target_module) == 0) return 0;
    // Everything in the target module's own directory first too: for an app that is every sibling
    // library, which is where cross-module callers realistically live.
    if (target_dir[0] && strncmp(r->path, target_dir, strlen(target_dir)) == 0) return 0;
    if (strncmp(r->path, "/data/", 6) == 0) return 1;
    return 2;
}

static int scan_sites(void *target, int max_sites, const struct mod_range *all, int all_n,
                      const char *scope, const char *target_module, const char *target_dir,
                      const char *self_module,
                      struct site_entry *out, long long *scanned, int *truncated) {
    int found = 0;
    long long budget = 0;
    *truncated = 0;
    for (int pass = 0; pass < 3; pass++) {
    for (int r = 0; r < all_n && found < max_sites; r++) {
        if (!wanted_range(&all[r], scope, target_module, self_module)) continue;
        if (range_class(&all[r], target_module, target_dir) != pass) continue;
        unsigned long long len = all[r].end - all[r].start;
        if (budget + (long long)len > (long long)ADH_SITE_SCAN_BUDGET) { *truncated = 1; goto scan_done; }
        budget += (long long)len;
        unsigned int *p = (unsigned int *)(uintptr_t)all[r].start;
        unsigned int *end = (unsigned int *)(uintptr_t)all[r].end;
        for (; p < end && found < max_sites; p++) {
            unsigned int insn = *p;
            // B (tail call) and BL both reach the function; the patch keeps the same form.
            if ((insn & 0x7C000000u) != 0x14000000u) continue;
            int imm26 = (int)(insn & 0x03FFFFFFu);
            if (imm26 & 0x02000000) imm26 -= 0x04000000;
            void *dst = (void *)((uintptr_t)p + (intptr_t)imm26 * 4);
            if (dst != target && stub_jump_target(all, all_n, dst) != target) continue;
            out[found].at = p;
            out[found].orig = insn;
            out[found].thunk = NULL;
            out[found].page = NULL;
            module_of_addr(all, all_n, (unsigned long long)(uintptr_t)p, out[found].mod, sizeof(out[found].mod));
            found++;
        }
    }
    }
scan_done:
    *scanned = budget;
    return found;
}

// ---- apply / revert ----------------------------------------------------------------------
int adh_site_hook_apply(int slot, void *target, int max_sites, const char *scope,
                        char *error, size_t error_size) {
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

    // Dynamically sized on purpose: this used to be a stack array capped at 512 entries, which in a
    // 2600-mapping process cut the table off before the app's own libraries and made the target
    // module unresolvable ("scanned 0 bytes"). The table is freed on every exit path.
    struct mod_range *ranges = (struct mod_range *)calloc(ADH_MAX_RANGES, sizeof(struct mod_range));
    if (!ranges) {
        snprintf(error, error_size, "out of memory for the mapping table");
        return 0;
    }
    int table_full = 0;
    int all_n = collect_ranges(ranges, ADH_MAX_RANGES, NULL, &table_full);
    if (all_n <= 0) {
        free(ranges);
        snprintf(error, error_size, "could not read /proc/self/maps");
        return 0;
    }
    char target_module[96] = "";
    module_of_addr(ranges, all_n, (unsigned long long)(uintptr_t)target, target_module, sizeof(target_module));
    if (!target_module[0]) {
        free(ranges);
        snprintf(error, error_size, "could not resolve the module of target %p from /proc/self/maps", target);
        return 0;
    }
    char self_module[96] = "";
    module_of_addr(ranges, all_n, (unsigned long long)(uintptr_t)&adh_site_hook_apply, self_module, sizeof(self_module));
    if ((!scope || !scope[0] || strcmp(scope, "all") == 0) && !self_module[0]) {
        // Without our own module name the scanner cannot exclude the agent, and "all" would then be
        // free to rewrite the agent's own calls. Fail loud instead of hooking ourselves.
        free(ranges);
        snprintf(error, error_size, "cannot resolve the agent module name; scope=all would be unsafe");
        return 0;
    }
    char target_dir[160] = "";
    {
        char target_path[160] = "";
        for (int i = 0; i < all_n; i++) {
            if ((unsigned long long)(uintptr_t)target < ranges[i].start || (unsigned long long)(uintptr_t)target >= ranges[i].end) continue;
            snprintf(target_path, sizeof(target_path), "%s", ranges[i].path);
            break;
        }
        const char *slash = target_path[0] ? strrchr(target_path, '/') : NULL;
        if (slash) {
            size_t len = (size_t)(slash - target_path);
            if (len >= sizeof(target_dir)) len = sizeof(target_dir) - 1;
            memcpy(target_dir, target_path, len);
            target_dir[len] = 0;
        }
    }

    struct site_ctx *ctx = &g_site_ctx[slot];
    pthread_mutex_lock(&g_site_lock);
    if (ctx->used) {
        pthread_mutex_unlock(&g_site_lock);
        free(ranges);
        snprintf(error, error_size, "site slot %d is still in use", slot);
        return 0;
    }
    ctx->used = 1;                 // claim the slot while we work
    pthread_mutex_unlock(&g_site_lock);

    int matched_ranges = 0, matched_masked = 0;
    for (int i = 0; i < all_n; i++) {
        if (wanted_range(&ranges[i], scope, target_module, self_module)) matched_ranges++;
        else if (ranges[i].exec && ranges[i].is_file) matched_masked++;
    }
    long long scanned = 0;
    int truncated = 0;
    int count = scan_sites(target, max_sites, ranges, all_n, scope, target_module, target_dir, self_module,
                           ctx->sites, &scanned, &truncated);
    ctx->scanned = scanned;
    ctx->truncated = truncated || table_full;
    if (count <= 0) {
        pthread_mutex_lock(&g_site_lock);
        memset(ctx, 0, sizeof(*ctx));
        pthread_mutex_unlock(&g_site_lock);
        free(ranges);
        snprintf(error, error_size,
                 "no B/BL call site for %p found (scope=%s target module=%s self=%s, %d ranges%s (%d matched, %d other exec file), scanned %lld bytes%s) - use mode=inline or mode=got",
                 target, scope && scope[0] ? scope : "module", target_module, self_module, all_n,
                 table_full ? " (table full - some modules were not indexed)" : "",
                 matched_ranges, matched_masked, scanned,
                 truncated ? ", scan budget hit" : "");
        return 0;
    }

    // Emit + patch one site at a time. Each site gets its own near page, because two callers in
    // different modules can easily be more than one BL apart from each other.
    int done = 0;
    for (int i = 0; i < count; i++) {
        int64_t site = (int64_t)(uintptr_t)ctx->sites[i].at;
        int alloc_attempts = 0;
        void *page = alloc_near_page((unsigned long long)(uintptr_t)site, ADH_SITE_PAGE_LEN,
                                     ranges, all_n, &alloc_attempts);
        if (!page) {
            snprintf(error, error_size,
                     "could not allocate a thunk page within +-%u MB of site %p after %d probes (errno=%d)",
                     ADH_BL_RANGE / (1024u * 1024u), ctx->sites[i].at, alloc_attempts, errno);
            break;
        }
        unsigned char *thunk = (unsigned char *)page;
        unsigned int words[64];
        int n = emit_thunk(words, 64, (void *)&adh_native_hook_record_site, target, slot);
        if (n <= 0 || n * 4 > ADH_SITE_THUNK_STRIDE) {
            munmap(page, ADH_SITE_PAGE_LEN);
            snprintf(error, error_size, "thunk layout overflow for site %d", i);
            break;
        }
        memcpy(thunk, words, (size_t)n * 4);
        __builtin___clear_cache((char *)thunk, (char *)thunk + ADH_SITE_THUNK_STRIDE);
        if (mprotect(page, ADH_SITE_PAGE_LEN, PROT_READ | PROT_EXEC) != 0) {
            munmap(page, ADH_SITE_PAGE_LEN);
            snprintf(error, error_size, "could not make the thunk page executable (errno=%d)", errno);
            break;
        }
        ctx->sites[i].page = page;
        ctx->sites[i].thunk = thunk;

        int64_t delta = (int64_t)(uintptr_t)thunk - site;
        if (delta > (int64_t)ADH_BL_RANGE || delta < -(int64_t)ADH_BL_RANGE) {
            // This site's page was already recorded: unmap it here or the rollback below (which only
            // walks the finished sites) leaks it.
            munmap(page, ADH_SITE_PAGE_LEN);
            ctx->sites[i].page = NULL;
            ctx->sites[i].thunk = NULL;
            snprintf(error, error_size, "thunk for site %d is out of BL range (%lld bytes)", i, (long long)delta);
            break;
        }
        const int was_bl = (ctx->sites[i].orig & 0xFC000000u) == 0x94000000u;
        unsigned int patched = enc_branch(site, (int64_t)(uintptr_t)thunk, was_bl);
        if (!adh_patch_code_bytes(ctx->sites[i].at, &patched, 4)) {
            snprintf(error, error_size, "could not patch call site %p (errno=%d)", ctx->sites[i].at, errno);
            break;
        }
        done++;
    }

    if (done != count) {
        // Roll back everything already installed: a half-applied hook is worse than none.
        // Rollback: restore what we patched. If a restore FAILS the site still branches into that
        // thunk, so the page must stay mapped (never unmap the landing pad of live code) and the
        // kept page is recorded for status.
        for (int i = 0; i < done; i++) {
            int restored = 1;
            if (ctx->sites[i].at) {
                restored = adh_patch_code_bytes(ctx->sites[i].at, &ctx->sites[i].orig, 4) &&
                           *ctx->sites[i].at == ctx->sites[i].orig;
            }
            if (ctx->sites[i].page && restored) {
                munmap(ctx->sites[i].page, ADH_SITE_PAGE_LEN);
            } else if (ctx->sites[i].page) {
                g_last_kept_page = ctx->sites[i].page;
                g_last_kept_slot = slot;
            }
        }
        pthread_mutex_lock(&g_site_lock);
        memset(ctx, 0, sizeof(*ctx));
        pthread_mutex_unlock(&g_site_lock);
        free(ranges);
        if (!error[0]) snprintf(error, error_size, "site hook installation aborted after %d/%d sites", done, count);
        return 0;
    }

    pthread_mutex_lock(&g_site_lock);
    ctx->target = target;
    ctx->count = count;
    ctx->page_kept = 0;
    pthread_mutex_unlock(&g_site_lock);
    free(ranges);
    SLOGI("site hook installed slot=%d target=%p sites=%d scope=%s scanned=%lld truncated=%d",
          slot, target, count, scope && scope[0] ? scope : "module", scanned, truncated);
    return 1;
}

int adh_site_hook_revert(int slot, char *error, size_t error_size) {
    if (slot < 0 || slot >= ADH_SITE_MAX_SLOTS) return 0;
    struct site_ctx *ctx = &g_site_ctx[slot];
    pthread_mutex_lock(&g_site_lock);
    if (!ctx->used || ctx->count <= 0) {
        pthread_mutex_unlock(&g_site_lock);
        snprintf(error, error_size, "site slot %d has no installed sites", slot);
        return 0;
    }
    int count = ctx->count;
    unsigned long long hits_before = adh_native_hook_hits(slot);
    int restored = 0;
    for (int i = 0; i < count; i++) {
        // Write the original instruction back and prove it landed: a failed restore must never be
        // reported as a clean unhook.
        if (!adh_patch_code_bytes(ctx->sites[i].at, &ctx->sites[i].orig, 4) || *ctx->sites[i].at != ctx->sites[i].orig) {
            pthread_mutex_unlock(&g_site_lock);
            snprintf(error, error_size, "could not restore call site %p (%d/%d restored)", ctx->sites[i].at, restored, count);
            return 0;
        }
        restored++;
    }
    void *pages[ADH_SITE_MAX_SITES];
    int page_count = 0;
    for (int i = 0; i < count; i++) {
        if (ctx->sites[i].page) pages[page_count++] = ctx->sites[i].page;
    }
    memset(ctx, 0, sizeof(*ctx));
    pthread_mutex_unlock(&g_site_lock);

    // A thread that already entered a thunk may still be inside it; pages stay mapped until a quiet
    // window proves otherwise (same policy as the hard unhook quiesce).
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
        for (int i = 0; i < page_count; i++) {
            if (munmap(pages[i], ADH_SITE_PAGE_LEN) != 0) {
                snprintf(error, error_size, "sites restored but a thunk page could not be unmapped (errno=%d)", errno);
                return 0;
            }
        }
    } else {
        pthread_mutex_lock(&g_site_lock);
        g_last_kept_page = page_count ? pages[0] : NULL;
        g_last_kept_slot = slot;
        pthread_mutex_unlock(&g_site_lock);
        SLOGE("thunk pages kept mapped: hits kept moving during the quiesce window");
    }
    SLOGI("site hook reverted slot=%d sites=%d quiet=%d", slot, restored, quiet);
    return 1;
}

int adh_site_thunk_write(void *page, void *recorder, void *original, int hook_slot) {
    if (!page) return 0;
    unsigned int words[64];
    int n = emit_thunk(words, 64, recorder, original, hook_slot);
    if (n <= 0 || n * 4 > ADH_SITE_THUNK_STRIDE) return 0;
    memcpy(page, words, (size_t)n * 4);
    __builtin___clear_cache((char *)page, (char *)page + ADH_SITE_THUNK_STRIDE);
    return n * 4;
}

int adh_site_hook_count(int slot) {
    if (slot < 0 || slot >= ADH_SITE_MAX_SLOTS) return 0;
    return g_site_ctx[slot].count;
}

void *adh_site_hook_page(int slot) {
    if (slot < 0 || slot >= ADH_SITE_MAX_SLOTS) return NULL;
    if (g_site_ctx[slot].count > 0) return g_site_ctx[slot].sites[0].page;
    return NULL;
}

// Last revert that had to keep a thunk page mapped, as a JSON fragment for the hook status. Without
// this the information existed only in the agent log: the hook entry is already gone by then.
void adh_site_hook_last_revert_json(char *out, size_t out_size) {
    if (!out || !out_size) return;
    pthread_mutex_lock(&g_site_lock);
    void *kept = g_last_kept_page;
    int slot = g_last_kept_slot;
    pthread_mutex_unlock(&g_site_lock);
    snprintf(out, out_size, "\"sitesPageKept\":\"0x%llx\",\"sitesPageKeptSlot\":%d,",
             (unsigned long long)(uintptr_t)kept, slot);
}

void adh_site_hook_sites_json(int slot, char *out, size_t out_size, size_t *used) {
    if (!out || !out_size || !used || slot < 0 || slot >= ADH_SITE_MAX_SLOTS) return;
    struct site_ctx *ctx = &g_site_ctx[slot];
    size_t off = *used;
    void *kept = (g_last_kept_slot == slot) ? g_last_kept_page : NULL;
    int n = snprintf(out + off, out_size - off,
                     ",\"siteCount\":%d,\"scanned\":%lld,\"truncated\":\"%s\",\"pageKept\":\"%s\","
                     "\"thunkPage\":\"0x%llx\",\"sites\":[",
                     ctx->count, ctx->scanned, ctx->truncated ? "true" : "false", kept ? "true" : "false",
                     (unsigned long long)(uintptr_t)(ctx->count > 0 ? ctx->sites[0].page : NULL));
    if (n < 0 || (size_t)n >= out_size - off) return;
    off += (size_t)n;
    for (int i = 0; i < ctx->count; i++) {
        unsigned int now = ctx->sites[i].at ? *ctx->sites[i].at : 0;
        n = snprintf(out + off, out_size - off,
                     "%s{\"at\":\"0x%llx\",\"form\":\"%s\",\"module\":\"%s\",\"orig\":\"0x%08x\","
                     "\"now\":\"0x%08x\",\"thunk\":\"0x%llx\",\"page\":\"0x%llx\"}",
                     i ? "," : "", (unsigned long long)(uintptr_t)ctx->sites[i].at,
                     ((ctx->sites[i].orig & 0xFC000000u) == 0x94000000u) ? "bl" : "b",
                     ctx->sites[i].mod, ctx->sites[i].orig, now,
                     (unsigned long long)(uintptr_t)ctx->sites[i].thunk,
                     (unsigned long long)(uintptr_t)ctx->sites[i].page);
        if (n < 0 || (size_t)n >= out_size - off) return;
        off += (size_t)n;
    }
    n = snprintf(out + off, out_size - off, "]");
    if (n < 0 || (size_t)n >= out_size - off) return;
    *used = off + (size_t)n;
}
