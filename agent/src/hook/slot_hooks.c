// Pointer-slot ("vtable") hooking: see slot_hooks.h for what it covers and what it does not.
#include "slot_hooks.h"

#include "got.h"
#include "native_hooks.h"
#include "site_hooks.h"

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

#define TSTAG "rt.slot"
#define TLOGI(...) __android_log_print(ANDROID_LOG_INFO, TSTAG, __VA_ARGS__)
#define TLOGE(...) __android_log_print(ANDROID_LOG_ERROR, TSTAG, __VA_ARGS__)

#define ADH_SLOT_MAX_SLOTS_CTX 16
#define ADH_SLOT_MAX_ENTRIES 8
#define ADH_SLOT_PAGE_LEN 4096
#define ADH_SLOT_THUNK_STRIDE 256
#define ADH_SLOT_SCAN_BUDGET (96u * 1024u * 1024u)
#define ADH_SLOT_MAX_RANGES 4096

struct slot_entry {
    void **at;
    void *orig;
    void *thunk;
    char mod[96];
    char perms[8];
    int kind_got;        // 1 = a relocation (GOT) slot, 0 = plain data (vtable / callback table)
};

struct slot_ctx {
    int used;
    int count;
    void *target;
    void *page;
    long long scanned;
    int truncated;
    int skipped_writable;      // slots skipped because they live in writable data
    struct slot_entry entries[ADH_SLOT_MAX_ENTRIES];
};

static struct slot_ctx g_slot_ctx[ADH_SLOT_MAX_SLOTS_CTX];
static pthread_mutex_t g_slot_lock = PTHREAD_MUTEX_INITIALIZER;
// Last revert that had to keep a thunk page mapped, so the client can see it (the hook entry is gone
// by then, exactly like in the sites backend).
static void *g_slot_last_kept_page;
static int g_slot_last_kept_slot = -1;
// Slots the target rewrote itself while we held the hook (common for a writable callback). Those must
// NOT be clobbered with our stale original on revert, so the count is kept for status.
static int g_slot_last_changed_by_target;
static int g_slot_last_changed_slot = -1;

struct slot_range { unsigned long long start, end; int exec, read, write; char path[160]; };

static int slot_basename(const char *path, char *out, size_t out_size) {
    if (!path || !*path) return 0;
    const char *slash = strrchr(path, '/');
    snprintf(out, out_size, "%s", slash ? slash + 1 : path);
    return 1;
}

static int slot_collect(struct slot_range *out, int max, int *table_full) {
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return 0;
    char line[512];
    int n = 0;
    while (fgets(line, sizeof(line), m)) {
        unsigned long long s = 0, e = 0;
        char perms[8] = "";
        if (sscanf(line, "%llx-%llx %7s", &s, &e, perms) != 3) continue;
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        char *q = line;
        for (int f = 0; f < 5 && q; f++) { q = strchr(q, ' '); if (q) while (*q == ' ') q++; }
        const char *path = (q && *q) ? q : "";
        if (path[0] != '/') continue;
        if (strncmp(path, "/memfd:", 7) == 0) continue;      // JIT caches and our thunk pages
        if (n >= max) { if (table_full) *table_full = 1; continue; }
        struct slot_range *r = &out[n++];
        r->start = s;
        r->end = e;
        r->exec = perms[2] == 'x';
        r->read = perms[0] == 'r';
        r->write = perms[1] == 'w';
        snprintf(r->path, sizeof(r->path), "%s", path);
    }
    fclose(m);
    return n;
}

static void slot_module_of(const struct slot_range *rs, int n, unsigned long long addr, char *out, size_t out_size) {
    out[0] = 0;
    for (int i = 0; i < n; i++) {
        if (addr < rs[i].start || addr >= rs[i].end) continue;
        slot_basename(rs[i].path, out, out_size);
        return;
    }
}

static void slot_perms_of(const struct slot_range *rs, int n, unsigned long long addr, char *out, size_t out_size) {
    snprintf(out, out_size, "?");
    for (int i = 0; i < n; i++) {
        if (addr < rs[i].start || addr >= rs[i].end) continue;
        snprintf(out, out_size, "%c%c%c", rs[i].read ? 'r' : '-', rs[i].write ? 'w' : '-', rs[i].exec ? 'x' : '-');
        return;
    }
}

static int slot_wanted_range(const struct slot_range *r, const char *scope, const char *target_module,
                             const char *target_dir, const char *self_module) {
    if (!r->read || r->exec) return 0;                  // data only: a pointer slot lives in data
    char bn[96];
    if (!slot_basename(r->path, bn, sizeof(bn))) return 0;
    if (self_module[0] && strcmp(bn, self_module) == 0) return 0;
    if (!scope || !scope[0] || strcmp(scope, "module") == 0) {
        if (target_module[0] && strcmp(bn, target_module) == 0) return 1;
        return target_dir[0] && strncmp(r->path, target_dir, strlen(target_dir)) == 0;
    }
    if (strcmp(scope, "all") == 0) return 1;
    return strcmp(bn, scope) == 0 || strcmp(r->path, scope) == 0;
}

static int slot_class(const struct slot_range *r, const char *target_module, const char *target_dir) {
    char bn[96];
    if (slot_basename(r->path, bn, sizeof(bn)) && target_module[0] && strcmp(bn, target_module) == 0) return 0;
    if (target_dir[0] && strncmp(r->path, target_dir, strlen(target_dir)) == 0) return 0;
    if (strncmp(r->path, "/data/", 6) == 0) return 1;
    return 2;
}

static int slot_scan(void *target, int max_slots, const struct slot_range *rs, int n,
                     const char *scope, const char *target_module, const char *target_dir,
                     const char *self_module, int allow_writable, int *skipped_writable,
                     struct slot_entry *out, long long *scanned, int *truncated) {
    int found = 0;
    long long budget = 0;
    *truncated = 0;
    *skipped_writable = 0;
    for (int pass = 0; pass < 3; pass++) {
        for (int r = 0; r < n && found < max_slots; r++) {
            if (!slot_wanted_range(&rs[r], scope, target_module, target_dir, self_module)) continue;
            if (slot_class(&rs[r], target_module, target_dir) != pass) continue;
            unsigned long long len = rs[r].end - rs[r].start;
            if (budget + (long long)len > (long long)ADH_SLOT_SCAN_BUDGET) { *truncated = 1; goto done; }
            budget += (long long)len;
            for (unsigned long long a = rs[r].start; a + 8 <= rs[r].end && found < max_slots; a += 8) {
                void *value = *(void **)(uintptr_t)a;
                if (value != target) continue;
                // A writable data word that happens to equal the target is as likely to be a
                // constant/RTTI entry as a call target, so writable slots are opt-in.
                if (!allow_writable) {
                    int writable = 0;
                    for (int q = 0; q < n; q++) {
                        if (a < rs[q].start || a >= rs[q].end) continue;
                        writable = rs[q].write;
                        break;
                    }
                    if (writable) { (*skipped_writable)++; continue; }
                }
                out[found].at = (void **)(uintptr_t)a;
                out[found].orig = value;
                out[found].thunk = NULL;
                slot_module_of(rs, n, a, out[found].mod, sizeof(out[found].mod));
                slot_perms_of(rs, n, a, out[found].perms, sizeof(out[found].perms));
                out[found].kind_got = adh_got_is_slot(out[found].mod, (void *)(uintptr_t)a);
                found++;
            }
        }
    }
done:
    *scanned = budget;
    return found;
}

int adh_slot_hook_apply(int slot, void *target, int max_slots, const char *scope,
                        int allow_writable, char *error, size_t error_size) {
    if (slot < 0 || slot >= ADH_SLOT_MAX_SLOTS_CTX) {
        snprintf(error, error_size, "slot index %d out of range", slot);
        return 0;
    }
    if (!target || !adh_addr_is_executable(target)) {
        snprintf(error, error_size, "vtable hook target is not in an executable mapping");
        return 0;
    }
    if (max_slots <= 0) max_slots = ADH_SLOT_MAX_ENTRIES;
    if (max_slots > ADH_SLOT_MAX_ENTRIES) max_slots = ADH_SLOT_MAX_ENTRIES;

    struct slot_range *rs = (struct slot_range *)calloc(ADH_SLOT_MAX_RANGES, sizeof(struct slot_range));
    if (!rs) { snprintf(error, error_size, "out of memory for the mapping table"); return 0; }
    int table_full = 0;
    int n = slot_collect(rs, ADH_SLOT_MAX_RANGES, &table_full);
    if (n <= 0) { free(rs); snprintf(error, error_size, "could not read /proc/self/maps"); return 0; }

    char target_module[96] = "", target_dir[160] = "", self_module[96] = "";
    slot_module_of(rs, n, (unsigned long long)(uintptr_t)target, target_module, sizeof(target_module));
    slot_module_of(rs, n, (unsigned long long)(uintptr_t)&adh_slot_hook_apply, self_module, sizeof(self_module));
    if (!target_module[0]) {
        free(rs);
        snprintf(error, error_size, "could not resolve the module of target %p", target);
        return 0;
    }
    if ((!scope || !scope[0] || strcmp(scope, "all") == 0) && !self_module[0]) {
        free(rs);
        snprintf(error, error_size, "cannot resolve the agent module name; scope=all would be unsafe");
        return 0;
    }
    {
        char target_path[160] = "";
        for (int i = 0; i < n; i++) {
            if ((unsigned long long)(uintptr_t)target < rs[i].start || (unsigned long long)(uintptr_t)target >= rs[i].end) continue;
            snprintf(target_path, sizeof(target_path), "%s", rs[i].path);
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

    struct slot_ctx *ctx = &g_slot_ctx[slot];
    pthread_mutex_lock(&g_slot_lock);
    if (ctx->used) {
        pthread_mutex_unlock(&g_slot_lock);
        free(rs);
        snprintf(error, error_size, "slot %d is still in use", slot);
        return 0;
    }
    ctx->used = 1;
    pthread_mutex_unlock(&g_slot_lock);

    long long scanned = 0;
    int truncated = 0;
    int skipped_writable = 0;
    int count = slot_scan(target, max_slots, rs, n, scope, target_module, target_dir, self_module,
                          allow_writable, &skipped_writable, ctx->entries, &scanned, &truncated);
    ctx->scanned = scanned;
    ctx->truncated = truncated || table_full;
    ctx->skipped_writable = skipped_writable;
    if (count <= 0) {
        pthread_mutex_lock(&g_slot_lock);
        memset(ctx, 0, sizeof(*ctx));
        pthread_mutex_unlock(&g_slot_lock);
        free(rs);
        snprintf(error, error_size,
                 "no data slot holding %p found (scope=%s target module=%s, %d ranges%s, scanned %lld bytes%s%s)",
                 target, scope && scope[0] ? scope : "module", target_module, n,
                 table_full ? " (table full)" : "", scanned, truncated ? ", scan budget hit" : "",
                 skipped_writable ? " - writable slots were skipped; pass slotsWritable:true to include them" : "");
        return 0;
    }

    int mfd = (int)syscall(__NR_memfd_create, "jit-cache", 0);
    void *page = NULL;
    if (mfd >= 0) {
        if (ftruncate(mfd, ADH_SLOT_PAGE_LEN) == 0) {
            page = mmap(NULL, ADH_SLOT_PAGE_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
            if (page == MAP_FAILED) page = NULL;
        }
        close(mfd);
    }
    if (!page) {
        pthread_mutex_lock(&g_slot_lock);
        memset(ctx, 0, sizeof(*ctx));
        pthread_mutex_unlock(&g_slot_lock);
        free(rs);
        snprintf(error, error_size, "could not create the thunk page (errno=%d)", errno);
        return 0;
    }

    int done = 0;
    for (int i = 0; i < count; i++) {
        void *thunk = (char *)page + (size_t)i * ADH_SLOT_THUNK_STRIDE;
        if (!adh_site_thunk_write(thunk, (void *)&adh_native_hook_record_site, target, slot)) {
            snprintf(error, error_size, "thunk layout self-check failed for slot %d", i);
            break;
        }
        ctx->entries[i].thunk = thunk;
        // A slot lives in data (often in a RELRO page), so the swap goes through the RO-page helper.
        if (!adh_swap_pointer_in_ro_page(ctx->entries[i].at, thunk)) {
            snprintf(error, error_size, "could not patch data slot %p (errno=%d)", ctx->entries[i].at, errno);
            break;
        }
        done++;
    }
    if (done != count) {
        // Roll back what we wrote. A slot we could NOT restore still points at the thunk page, so the
        // page must stay mapped (never unmap the landing pad of live code) and be reported.
        int kept = 0;
        for (int i = 0; i < done; i++) {
            if (adh_swap_pointer_in_ro_page(ctx->entries[i].at, ctx->entries[i].orig) &&
                *ctx->entries[i].at == ctx->entries[i].orig) {
                ctx->entries[i].at = NULL;
            } else {
                g_slot_last_kept_page = page;
                g_slot_last_kept_slot = slot;
                kept = 1;
            }
        }
        if (!kept) munmap(page, ADH_SLOT_PAGE_LEN);
        pthread_mutex_lock(&g_slot_lock);
        memset(ctx, 0, sizeof(*ctx));
        pthread_mutex_unlock(&g_slot_lock);
        free(rs);
        if (!error[0]) snprintf(error, error_size, "vtable hook aborted after %d/%d slots", done, count);
        return 0;
    }
    if (mprotect(page, ADH_SLOT_PAGE_LEN, PROT_READ | PROT_EXEC) != 0) {
        for (int i = 0; i < done; i++) adh_swap_pointer_in_ro_page(ctx->entries[i].at, ctx->entries[i].orig);
        munmap(page, ADH_SLOT_PAGE_LEN);
        pthread_mutex_lock(&g_slot_lock);
        memset(ctx, 0, sizeof(*ctx));
        pthread_mutex_unlock(&g_slot_lock);
        free(rs);
        snprintf(error, error_size, "could not make the thunk page executable (errno=%d)", errno);
        return 0;
    }

    pthread_mutex_lock(&g_slot_lock);
    ctx->target = target;
    ctx->count = count;
    ctx->page = page;
    pthread_mutex_unlock(&g_slot_lock);
    free(rs);
    TLOGI("vtable hook installed slot=%d target=%p slots=%d scope=%s scanned=%lld truncated=%d",
          slot, target, count, scope && scope[0] ? scope : "module", scanned, ctx->truncated);
    return 1;
}

int adh_slot_hook_revert(int slot, char *error, size_t error_size) {
    if (slot < 0 || slot >= ADH_SLOT_MAX_SLOTS_CTX) return 0;
    struct slot_ctx *ctx = &g_slot_ctx[slot];
    pthread_mutex_lock(&g_slot_lock);
    if (!ctx->used || ctx->count <= 0) {
        pthread_mutex_unlock(&g_slot_lock);
        snprintf(error, error_size, "slot %d has no installed vtable hook", slot);
        return 0;
    }
    int count = ctx->count;
    void *page = ctx->page;
    int restored = 0;
    int changed_by_target = 0;
    for (int i = 0; i < count; i++) {
        void *now = *ctx->entries[i].at;
        if (now != ctx->entries[i].thunk) {
            // The target rewrote this slot itself (typical for a writable callback): leave ITS value
            // alone and report it instead of clobbering it with our stale original.
            changed_by_target++;
            continue;
        }
        if (!adh_swap_pointer_in_ro_page(ctx->entries[i].at, ctx->entries[i].orig) ||
            *ctx->entries[i].at != ctx->entries[i].orig) {
            pthread_mutex_unlock(&g_slot_lock);
            snprintf(error, error_size, "could not restore slot %p (%d/%d restored)", ctx->entries[i].at, restored, count);
            return 0;
        }
        restored++;
    }
    if (changed_by_target) { g_slot_last_changed_by_target = changed_by_target; g_slot_last_changed_slot = slot; }
    memset(ctx, 0, sizeof(*ctx));
    pthread_mutex_unlock(&g_slot_lock);

    int quiet = 0;
    for (int round = 0; round < 80 && !quiet; round++) {
        unsigned long long before = adh_native_hook_hits(slot);
        struct timespec ts = { 0, 5 * 1000 * 1000 };
        nanosleep(&ts, NULL);
        unsigned long long after = adh_native_hook_hits(slot);
        if (after == before && round >= 4) quiet = 1;
        else if (after != before) round = 0;
    }
    if (quiet) {
        if (munmap(page, ADH_SLOT_PAGE_LEN) != 0) {
            snprintf(error, error_size, "slots restored but the thunk page could not be unmapped (errno=%d)", errno);
            return 0;
        }
    } else {
        pthread_mutex_lock(&g_slot_lock);
        g_slot_last_kept_page = page;
        g_slot_last_kept_slot = slot;
        pthread_mutex_unlock(&g_slot_lock);
        TLOGE("vtable thunk page %p kept mapped: hits kept moving during the quiesce window", page);
    }
    TLOGI("vtable hook reverted slot=%d slots=%d quiet=%d", slot, restored, quiet);
    return 1;
}

int adh_slot_hook_count(int slot) {
    if (slot < 0 || slot >= ADH_SLOT_MAX_SLOTS_CTX) return 0;
    return g_slot_ctx[slot].count;
}

void *adh_slot_hook_page(int slot) {
    if (slot < 0 || slot >= ADH_SLOT_MAX_SLOTS_CTX) return NULL;
    return g_slot_ctx[slot].page;
}

void adh_slot_hook_slots_json(int slot, char *out, size_t out_size, size_t *used) {
    if (!out || !out_size || !used || slot < 0 || slot >= ADH_SLOT_MAX_SLOTS_CTX) return;
    struct slot_ctx *ctx = &g_slot_ctx[slot];
    size_t off = *used;
    int kept = (g_slot_last_kept_slot == slot && g_slot_last_kept_page) ? 1 : 0;
    int changed = (g_slot_last_changed_slot == slot && g_slot_last_changed_by_target > 0) ? 1 : 0;
    int n = snprintf(out + off, out_size - off,
                     ",\"slotCount\":%d,\"skippedWritable\":%d,\"scanned\":%lld,\"truncated\":\"%s\","
                     "\"pageKept\":\"%s\",\"slotChangedByTarget\":\"%s\",\"thunkPage\":\"0x%llx\",\"slots\":[",
                     ctx->count, ctx->skipped_writable, ctx->scanned, ctx->truncated ? "true" : "false",
                     kept ? "true" : "false", changed ? "true" : "false",
                     (unsigned long long)(uintptr_t)ctx->page);
    if (n < 0 || (size_t)n >= out_size - off) return;
    off += (size_t)n;
    for (int i = 0; i < ctx->count; i++) {
        void *now = ctx->entries[i].at ? *ctx->entries[i].at : NULL;
        n = snprintf(out + off, out_size - off,
                     "%s{\"at\":\"0x%llx\",\"module\":\"%s\",\"perms\":\"%s\",\"kind\":\"%s\",\"orig\":\"0x%llx\","
                     "\"now\":\"0x%llx\",\"thunk\":\"0x%llx\"}",
                     i ? "," : "", (unsigned long long)(uintptr_t)ctx->entries[i].at,
                     ctx->entries[i].mod, ctx->entries[i].perms,
                     ctx->entries[i].kind_got ? "got" : "data",
                     (unsigned long long)(uintptr_t)ctx->entries[i].orig,
                     (unsigned long long)(uintptr_t)now,
                     (unsigned long long)(uintptr_t)ctx->entries[i].thunk);
        if (n < 0 || (size_t)n >= out_size - off) return;
        off += (size_t)n;
    }
    n = snprintf(out + off, out_size - off, "]");
    if (n < 0 || (size_t)n >= out_size - off) return;
    *used = off + (size_t)n;
}
