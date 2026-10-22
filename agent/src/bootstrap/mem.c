// mem.c — target-memory commands: read a range, scan for container magics, search for a byte
// pattern, and dump /proc/self/maps. Collect-only, bounded, fail-loud. Uses util/io helpers.
#include "agent_internal.h"
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <stdint.h>

// Build a JSON array of maps regions. limit<=0 = all. *total set to line count.
// *truncated set to 1 iff the buffer could not grow (OOM data-loss) — distinct from the
// intentional `limit` cap. Returns malloc'd string (caller frees) or NULL.
char *build_maps_json(int limit, int *total, int *truncated) {
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) { *total = 0; if (truncated) *truncated = 0; return NULL; }
    size_t cap = 1 << 16, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) { fclose(m); *total = 0; if (truncated) *truncated = 1; return NULL; }
    buf[0] = 0;
    int count = 0, emitted = 0, trunc = 0;
    char line[1024];
    while (fgets(line, sizeof(line), m)) {
        count++;
        if (limit > 0 && emitted >= limit) continue;
        char sa[64], ea[64], perms[8], off[32], dev[16], path[600] = "";
        unsigned long long inode = 0;
        int nf = sscanf(line, "%63[0-9a-f]-%63[0-9a-f] %7s %31s %15s %llu %599[^\n]",
                        sa, ea, perms, off, dev, &inode, path);
        if (nf < 6) continue;
        char *p = path; while (*p == ' ') p++;
        char epath[640]; json_escape(p, epath, sizeof(epath));
        char rec[900];
        int w = snprintf(rec, sizeof(rec),
            "%s{\"start\":\"%s\",\"end\":\"%s\",\"perms\":\"%s\",\"offset\":\"%s\",\"dev\":\"%s\",\"inode\":%llu,\"path\":\"%s\"}",
            emitted ? "," : "", sa, ea, perms, off, dev, inode, epath);
        if (w < 0) continue;
        if (len + (size_t)w + 1 >= cap) {
            while (len + (size_t)w + 1 >= cap) cap *= 2;
            char *nb = (char *)realloc(buf, cap);
            if (!nb) { trunc = 1; break; }   // OOM: stop, but report it — don't silently under-report
            buf = nb;
        }
        memcpy(buf + len, rec, (size_t)w);
        len += (size_t)w; buf[len] = 0;
        emitted++;
    }
    fclose(m);
    *total = count;
    if (truncated) *truncated = trunc;
    return buf;
}

// ---- address -> region metadata -----------------------------------------------------------
// Strict hex validation. hex2bytes stops at the first bad pair and returns what it got, which is
// fine for a capture name and wrong for a write: a typo must refuse the whole operation, not patch
// a prefix of the bytes the caller asked for.
int adh_hex_strict(const char *hex, size_t *len_out) {
    if (!hex) return 0;
    size_t n = strlen(hex);
    if (!n || (n & 1) || n > 4096 * 2) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return 0;
    }
    if (len_out) *len_out = n / 2;
    return 1;
}

// Address parsing shared by read/write. The host sends bare lowercase hex (no 0x) while a human or
// an MCP client often writes 0x...; both must mean the same address, and a partial parse must be
// refused (strtoull stops at the first bad character, so "0x1234zz" used to read as 0x1234).
static int parse_mem_addr(const char *text, unsigned long long *out) {
    if (!text || !text[0]) return 0;
    const char *p = text;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    if (!*p) return 0;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(p, &end, 16);
    if (end == p || (end && *end) || errno == ERANGE) return 0;
    *out = v;
    return 1;
}

// The ONE place that answers "what is at this address". /proc/self/maps is readable even for a
// non-dumpable target (the maps command already relies on that), so a write never has to probe
// with a signal handler first.
int adh_mem_region_of(unsigned long long addr, char perms[5], unsigned long long *lo_out,
                      unsigned long long *hi_out) {
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return 0;
    addr = adh_untag(addr);          // maps only lists canonical ranges
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), m)) {
        unsigned long long lo = 0, hi = 0;
        char p[8] = "";
        if (sscanf(line, "%llx-%llx %7s", &lo, &hi, p) != 3) continue;
        if (addr < lo || addr >= hi) continue;
        if (perms) snprintf(perms, 5, "%s", p);
        if (lo_out) *lo_out = lo;
        if (hi_out) *hi_out = hi;
        found = 1;
        break;
    }
    fclose(m);
    return found;
}

// Copy bytes into the target ONLY inside one already-writable mapping. Called from the native-hook
// recorder on an arbitrary target thread, so it must not mprotect and must not fault: a bad pointer
// answers "no", and the event reports that the write did not land.
int adh_mem_write_checked(unsigned long long addr, const void *src, size_t len) {
    if (!src || !len) return 0;
    if (addr + len < addr) return 0;              // wrap-around
    addr = adh_untag(addr);
    char perms[5] = "";
    unsigned long long lo = 0, hi = 0;
    if (!adh_mem_region_of(addr, perms, &lo, &hi)) return 0;
    if (perms[1] != 'w') return 0;
    if (addr + len > hi) return 0;                // leaves the mapping
    memcpy((void *)(uintptr_t)addr, src, len);
    return 1;
}

static int prot_from_perms(const char *perms) {
    int p = 0;
    if (perms[0] == 'r') p |= PROT_READ;
    if (perms[1] == 'w') p |= PROT_WRITE;
    if (perms[2] == 'x') p |= PROT_EXEC;
    return p;
}

// Write bytes at an address: the deliberate, host-driven counterpart of adh_mem_write_checked.
// It MAY patch a read-only page, but only when the caller says force:true; it restores the original
// protection immediately, flushes the instruction cache for code pages, and returns the bytes it
// replaced so the host can build an undo record. This is the primitive VMP handler tables, OLLVM
// state variables and inline checks need: read-only observation cannot change a branch.
void cmd_write(int fd, const char *id, const char *addr_hex, const char *hex, int force) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    char err[512];
    unsigned long long addr = 0;
    if (!parse_mem_addr(addr_hex, &addr) || addr == 0) {
        snprintf(err, sizeof(err),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"write\",\"ok\":false,"
                 "\"error\":\"bad addr: expected a hex address like 0x7f12345678 or 7f12345678\"}\n", idj);
        send_line(fd, err); return;
    }
    // A tagged pointer (Scudo top byte) is the same address; maps wants it canonical.
    addr = adh_untag(addr);
    size_t want = 0;
    if (!adh_hex_strict(hex, &want) || want == 0) {
        snprintf(err, sizeof(err),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"write\",\"ok\":false,"
                 "\"error\":\"bad hex: 1..4096 bytes, even-length, hex only\"}\n", idj);
        send_line(fd, err); return;
    }
    unsigned char bytes[4096];
    int len = hex2bytes(hex, bytes, (int)sizeof(bytes));
    if (len <= 0 || (size_t)len != want) {
        snprintf(err, sizeof(err),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"write\",\"ok\":false,\"error\":\"hex decode failed\"}\n", idj);
        send_line(fd, err); return;
    }
    char perms[5] = "";
    unsigned long long lo = 0, hi = 0;
    if (!adh_mem_region_of(addr, perms, &lo, &hi)) {
        snprintf(err, sizeof(err),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"write\",\"ok\":false,"
                 "\"error\":\"addr 0x%llx is not in any mapping of this process\"}\n", idj, addr);
        send_line(fd, err); return;
    }
    if (addr + (unsigned long long)len > hi) {
        snprintf(err, sizeof(err),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"write\",\"ok\":false,"
                 "\"error\":\"write of %d bytes crosses the end of its mapping (region 0x%llx-0x%llx)\"}\n",
                 idj, len, lo, hi);
        send_line(fd, err); return;
    }
    const int writable = (perms[1] == 'w');
    if (!writable && !force) {
        snprintf(err, sizeof(err),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"write\",\"ok\":false,"
                 "\"error\":\"mapping is %s (not writable); pass force:true to patch it - the original protection is restored immediately\"}\n",
                 idj, perms);
        send_line(fd, err); return;
    }
    // Bytes being replaced, only when the page is readable (a --w mapping cannot be read from).
    unsigned char before[4096];
    int have_before = 0;
    if (perms[0] == 'r') {
        memcpy(before, (void *)(uintptr_t)addr, (size_t)len);
        have_before = 1;
    }
    int mp_used = 0;
    if (!writable) {
        const long page = sysconf(_SC_PAGESIZE);
        if (page <= 0) {
            snprintf(err, sizeof(err),
                     "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"write\",\"ok\":false,\"error\":\"cannot read page size\"}\n", idj);
            send_line(fd, err); return;
        }
        const uintptr_t pstart = (uintptr_t)addr & ~((uintptr_t)page - 1);
        const uintptr_t plast = ((uintptr_t)addr + (uintptr_t)len - 1) & ~((uintptr_t)page - 1);
        const size_t span = (size_t)(plast - pstart) + (size_t)page;
        const int prot = prot_from_perms(perms);
        if (mprotect((void *)pstart, span, prot | PROT_WRITE) != 0) {
            snprintf(err, sizeof(err),
                     "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"write\",\"ok\":false,"
                     "\"error\":\"mprotect(%s|w) failed: errno %d\"}\n", idj, perms, errno);
            send_line(fd, err); return;
        }
        memcpy((void *)(uintptr_t)addr, bytes, (size_t)len);
        mp_used = 1;
        // Code pages: the target may fetch the old instructions from its I-cache.
        if (perms[2] == 'x') __builtin___clear_cache((char *)(uintptr_t)addr, (char *)(uintptr_t)(addr + (unsigned long long)len));
        if (mprotect((void *)pstart, span, prot) != 0) {
            // The bytes are already written; report the weakened protection instead of claiming
            // a clean patch. The host can retry/restore.
            LOGE("cmd_write: restoring protection on %p failed (errno %d)", (void *)pstart, errno);
        }
    } else {
        memcpy((void *)(uintptr_t)addr, bytes, (size_t)len);
    }
    char before_hex[8193];
    before_hex[0] = 0;
    if (have_before) {
        static const char *hx = "0123456789abcdef";
        for (int i = 0; i < len; i++) {
            before_hex[i * 2] = hx[before[i] >> 4];
            before_hex[i * 2 + 1] = hx[before[i] & 15];
        }
        before_hex[len * 2] = 0;
    }
    const size_t cap = 512 + (size_t)len * 2 + strlen(before_hex);
    char *out = (char *)malloc(cap);
    if (!out) { send_oom(fd, idj, "write"); return; }
    snprintf(out, cap,
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"write\",\"ok\":true,\"addr\":\"0x%llx\","
             "\"wrote\":%d,\"permBefore\":\"%s\",\"mprotectUsed\":%s,\"beforeReadable\":%s,"
             "\"before\":\"%s\"}\n",
             idj, addr, len, perms, mp_used ? "true" : "false",
             have_before ? "true" : "false", before_hex);
    send_line(fd, out);
    free(out);
}

// Read `size` bytes at hex `addr` and reply as base64 cmdResult. Uses the shared backend
// (mem_read.c), so a target that refuses /proc/self/mem still reads through a direct copy.
// `via` = "direct" forces the direct route for this one read, so the two routes can be
// cross-checked against a target that answers /proc/self/mem with plausible garbage.
void cmd_read(int fd, const char *id, const char *addr_hex, long long size, const char *via) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    if (size <= 0 || size > (1 << 20)) {  // cap 1MB per read in v0.2
        char err[160];
        snprintf(err, sizeof(err), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"read\",\"ok\":false,\"error\":\"bad size\"}\n", idj);
        send_line(fd, err); return;
    }
    unsigned long long addr = 0;
    if (!parse_mem_addr(addr_hex, &addr)) {
        char err[200];
        snprintf(err, sizeof(err),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"read\",\"ok\":false,"
                 "\"error\":\"bad addr: expected a hex address like 0x7f12345678 or 7f12345678\"}\n", idj);
        send_line(fd, err); return;
    }
    int direct = (via && strcmp(via, "direct") == 0);
    const char *route = direct ? "direct" : adh_mem_backend_name();
    // Canonical echo: the caller may have sent 0x-prefixed or a tagged pointer, and both errors and
    // the success reply must state the address that was actually used.
    char addr_text[24];
    snprintf(addr_text, sizeof(addr_text), "%llx", addr);
    unsigned char *raw = (unsigned char *)malloc((size_t)size);
    if (!raw) { send_oom(fd, idj, "read"); return; }
    ssize_t got = direct ? adh_mem_read_direct(raw, (size_t)size, addr)
                         : adh_mem_pread(raw, (size_t)size, addr);
    adh_mem_fd_release();          // no standing /proc/self/mem fd between commands
    if (got <= 0) {
        free(raw);
        char err[220];
        // errno only means something on the fd route; the direct route refused the range itself.
        if (direct || strcmp(route, "direct") == 0)
            snprintf(err, sizeof(err), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"read\",\"ok\":false,"
                     "\"error\":\"unreadable at 0x%s (via direct)\"}\n", idj, addr_text);
        else
            snprintf(err, sizeof(err), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"read\",\"ok\":false,"
                     "\"error\":\"unreadable at 0x%s (via %s, errno %d)\"}\n", idj, addr_text, route, errno);
        send_line(fd, err); return;
    }
    char *b64 = (char *)malloc((size_t)got * 4 / 3 + 8);
    if (!b64) { free(raw); send_oom(fd, idj, "read"); return; }
    b64_encode(raw, (size_t)got, b64);
    free(raw);
    size_t hlen = strlen(b64) + 200;
    char *out = (char *)malloc(hlen);
    if (out) {
        snprintf(out, hlen,
            "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"read\",\"ok\":true,\"addr\":\"%s\",\"size\":%zd,"
            "\"requested\":%lld,\"short\":%s,\"via\":\"%s\",\"b64\":\"%s\"}\n",
            idj, addr_text, got, size, (got < size) ? "true" : "false", route, b64);
        send_line(fd, out);
        free(out);
    }
    free(b64);
}

// Scan readable regions of /proc/self/maps for known container magics.
// Bounded: <=64MB scanned per region, <=512MB total, <=256 hits. Collect-only.
void cmd_scan_magic(int fd, const char *id, unsigned long long win_lo, unsigned long long win_hi) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    struct { const char *name; const char *pat; int len; } P[] = {
        { "dex",  "dex\n03", 6 },   // dex\n035..041 (match "dex\n03" prefix)
        { "cdex", "cdex",    4 },
        { "elf",  "\x7f""ELF", 4 },
        { "zip",  "PK\x03\x04", 4 },
        { "oat",  "oat\n",   4 },
        { "vdex", "vdex",    4 },
    };
    const int NP = (int)(sizeof(P) / sizeof(P[0]));
    // Budgets. The old 256-hit / 512 MB / 64 MB-per-region caps were exhausted by the framework's
    // own OAT dex magics before the scan ever reached the app's heap, so a packed target looked
    // like it had no dex in memory at all. Raise all three and report a clipped region as
    // truncated instead of silently stopping short of it.
    const size_t CHUNK = 1u << 20, PERREGION = 256u << 20, TOTALCAP = 2048u << 20;
    const int MAXHITS = 2048;

    int mem = adh_mem_fd();          // -1 on a non-dumpable target: fall back to a direct read
    const char *route = adh_mem_backend_name();   // captured before the fd is released
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) {
        char err[160];
        snprintf(err, sizeof(err), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"scan_magic\",\"ok\":false,\"error\":\"read maps\"}\n", idj);
        send_line(fd, err); return;
    }

    size_t cap = 1 << 16, len = 0;
    char *hits = (char *)malloc(cap); if (hits) hits[0] = 0;
    int nhits = 0, truncated = 0, clipped = 0;
    size_t total_scanned = 0;
    unsigned char *cbuf = (unsigned char *)malloc(CHUNK + 8);
    char line[1024];

    while (hits && cbuf && fgets(line, sizeof(line), m)) {
        char sa[64], ea[64], perms[8], off[32], dev[16], path[600] = "";
        unsigned long long inode = 0;
        int nf = sscanf(line, "%63[0-9a-f]-%63[0-9a-f] %7s %31s %15s %llu %599[^\n]",
                        sa, ea, perms, off, dev, &inode, path);
        if (nf < 5 || perms[0] != 'r') continue;
        char *pp = path; while (*pp == ' ') pp++;
        if (strncmp(pp, "/dev/", 5) == 0) continue;          // avoid device mmaps (fault/block)
        unsigned long long start = strtoull(sa, NULL, 16);
        unsigned long long end = strtoull(ea, NULL, 16);
        if (end <= start) continue;
        // Optional window. A 3700-region app burns the whole budget on framework OAT before the scan
        // reaches its heap, and there was no way to aim it. Regions outside the window are SKIPPED
        // (not clipped), so the caps apply to the part the caller actually asked about.
        if (win_hi && start >= win_hi) continue;
        if (win_lo && end <= win_lo) continue;
        unsigned long long rsize = end - start;
        if (rsize > PERREGION) { rsize = PERREGION; clipped = 1; }   // say so, don't clip silently
        if (total_scanned >= TOTALCAP) { truncated = 1; break; }

        unsigned long long o = 0;
        int carry = 0;                                       // bytes kept from previous chunk tail
        while (o < rsize && nhits < MAXHITS) {
            size_t want = (size_t)((rsize - o) < CHUNK ? (rsize - o) : CHUNK);
            ssize_t got = (mem >= 0)
                ? pread(mem, cbuf + carry, want, (off_t)(start + o))
                : adh_mem_read_in_region(cbuf + carry, want, start + o, end);
            if (got <= 0) break;                             // unreadable/uncommitted -> skip region
            size_t avail = (size_t)got + (size_t)carry;
            total_scanned += (size_t)got;
            for (int pi = 0; pi < NP && nhits < MAXHITS; pi++) {
                unsigned char *base = cbuf, *found;
                size_t remain = avail;
                while ((found = (unsigned char *)memmem(base, remain, P[pi].pat, (size_t)P[pi].len)) != NULL) {
                    size_t pos = (size_t)(found - cbuf);
                    unsigned long long hitaddr = start + o - (unsigned long long)carry + pos;
                    char rec[900], epath[640]; json_escape(pp, epath, sizeof(epath));
                    int w = snprintf(rec, sizeof(rec),
                        "%s{\"addr\":\"%llx\",\"magic\":\"%s\",\"region\":\"%s-%s\",\"perms\":\"%s\",\"path\":\"%s\"}",
                        nhits ? "," : "", hitaddr, P[pi].name, sa, ea, perms, epath);
                    if (w > 0) {
                        if (len + (size_t)w + 1 >= cap) { while (len + (size_t)w + 1 >= cap) cap *= 2; char *nb = realloc(hits, cap); if (!nb) { truncated = 1; break; } hits = nb; }
                        memcpy(hits + len, rec, (size_t)w); len += (size_t)w; hits[len] = 0; nhits++;
                    }
                    base = found + 1; remain = avail - (size_t)(base - cbuf);
                    if (nhits >= MAXHITS) { truncated = 1; break; }
                }
            }
            // keep last 8 bytes as carry so patterns spanning chunk edges are caught
            carry = (avail >= 8) ? 8 : (int)avail;
            memmove(cbuf, cbuf + avail - carry, (size_t)carry);
            o += (unsigned long long)got;
        }
    }
    fclose(m); free(cbuf); adh_mem_fd_release();

    // Window label: "all" when unbounded, else "lo-hi" in hex. A reply must never read like a full
    // scan when it only covered the part of the address space the caller asked about.
    char window[48];
    if (win_lo || win_hi) snprintf(window, sizeof(window), "0x%llx-0x%llx", win_lo, win_hi);
    else snprintf(window, sizeof(window), "all");
    size_t hlen = (hits ? strlen(hits) : 0) + 260;
    char *out = (char *)malloc(hlen);
    if (out) {
        snprintf(out, hlen,
            "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"scan_magic\",\"ok\":true,\"count\":%d,\"truncated\":%s,\"regionClipped\":%s,\"scanned\":%zu,\"backend\":\"%s\",\"window\":\"%s\",\"hits\":[%s]}\n",
            idj, nhits, truncated ? "true" : "false", clipped ? "true" : "false", total_scanned, route, window, hits ? hits : "");
        send_line(fd, out);
        free(out);
    }
    free(hits);
}

// Search readable memory for a byte pattern (hex-encoded). Returns hit addresses.
// Same bounds as scan_magic. Collect-only.
void cmd_search(int fd, const char *id, const char *pat_hex, int limit,
                unsigned long long win_lo, unsigned long long win_hi) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    unsigned char pat[256];
    int patlen = hex2bytes(pat_hex, pat, sizeof(pat));
    if (patlen <= 0) {
        char err[160];
        snprintf(err, sizeof(err), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"search\",\"ok\":false,\"error\":\"empty pattern\"}\n", idj);
        send_line(fd, err); return;
    }
    if (limit <= 0 || limit > 4096) limit = 256;
    // Same budget reasoning as scan_magic: the old 128 MB per-region cap never reached the app's
    // own heap on a large target, and clipping a region was not reported.
    const size_t CHUNK = 1u << 20, PERREGION = 256u << 20, TOTALCAP = 2048u << 20;

    int mem = adh_mem_fd();          // -1 on a non-dumpable target: fall back to a direct read
    const char *route = adh_mem_backend_name();   // captured before the fd is released
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) {
        char e[160]; snprintf(e, sizeof(e), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"search\",\"ok\":false,\"error\":\"read maps\"}\n", idj);
        send_line(fd, e); return; }

    size_t cap = 1 << 14, len = 0; char *hits = (char *)malloc(cap); if (hits) hits[0] = 0;
    int nhits = 0, clipped = 0; size_t total = 0;
    unsigned char *cbuf = (unsigned char *)malloc(CHUNK + (size_t)patlen);
    char line[1024];
    while (hits && cbuf && fgets(line, sizeof(line), m) && nhits < limit) {
        char sa[64], ea[64], perms[8], off[32], dev[16], path[600] = "";
        unsigned long long inode = 0;
        int nf = sscanf(line, "%63[0-9a-f]-%63[0-9a-f] %7s %31s %15s %llu %599[^\n]", sa, ea, perms, off, dev, &inode, path);
        if (nf < 5 || perms[0] != 'r') continue;
        char *pp = path; while (*pp == ' ') pp++;
        if (strncmp(pp, "/dev/", 5) == 0) continue;
        unsigned long long start = strtoull(sa, NULL, 16), end = strtoull(ea, NULL, 16);
        if (end <= start) continue;
        // Same optional window as scan_magic: aim the bounded scan instead of spending its budget on
        // whatever happens to come first in address order.
        if (win_hi && start >= win_hi) continue;
        if (win_lo && end <= win_lo) continue;
        // NEVER scan this thread's own stack. The pattern was just decoded into a buffer in this
        // very function, so its bytes live in the frame we are standing in: every search would
        // then "find" its own input at a fixed stack address, and such a hit is indistinguishable
        // from a real one. Measured: a random 16-byte pattern that had never been sent anywhere
        // returned exactly one hit, always at the same address, across processes and restarts.
        {
            static unsigned long long self_lo = 0, self_hi = 0;
            if (!self_hi) {
                pthread_attr_t ta;
                if (pthread_getattr_np(pthread_self(), &ta) == 0) {
                    void *saddr = NULL;
                    size_t ssize = 0;
                    if (pthread_attr_getstack(&ta, &saddr, &ssize) == 0 && ssize > 0) {
                        self_lo = (unsigned long long)(uintptr_t)saddr;
                        self_hi = self_lo + ssize;
                    }
                    pthread_attr_destroy(&ta);
                }
            }
            if (self_hi && start < self_hi && end > self_lo) continue;
        }
        unsigned long long rsize = end - start; if (rsize > PERREGION) { rsize = PERREGION; clipped = 1; }
        if (total >= TOTALCAP) break;
        unsigned long long o = 0; int carry = 0;
        while (o < rsize && nhits < limit) {
            size_t want = (size_t)((rsize - o) < CHUNK ? (rsize - o) : CHUNK);
            ssize_t got = (mem >= 0) ? pread(mem, cbuf + carry, want, (off_t)(start + o))
                                     : adh_mem_read_in_region(cbuf + carry, want, start + o, end);
            if (got <= 0) break;
            size_t avail = (size_t)got + (size_t)carry; total += (size_t)got;
            unsigned char *base = cbuf; size_t remain = avail; unsigned char *found;
            while ((found = (unsigned char *)memmem(base, remain, pat, (size_t)patlen)) != NULL && nhits < limit) {
                unsigned long long hitaddr = start + o - (unsigned long long)carry + (size_t)(found - cbuf);
                char rec[800], epath[640]; json_escape(pp, epath, sizeof(epath));
                int w = snprintf(rec, sizeof(rec), "%s{\"addr\":\"%llx\",\"region\":\"%s-%s\",\"perms\":\"%s\",\"path\":\"%s\"}",
                                 nhits ? "," : "", hitaddr, sa, ea, perms, epath);
                if (w > 0) { if (len + (size_t)w + 1 >= cap) { while (len + (size_t)w + 1 >= cap) cap *= 2; char *nb = realloc(hits, cap); if (!nb) break; hits = nb; }
                    memcpy(hits + len, rec, (size_t)w); len += (size_t)w; hits[len] = 0; nhits++; }
                base = found + 1; remain = avail - (size_t)(base - cbuf);
            }
            carry = (avail >= (size_t)patlen) ? patlen - 1 : (int)avail;
            memmove(cbuf, cbuf + avail - carry, (size_t)carry);
            o += (unsigned long long)got;
        }
    }
    fclose(m); free(cbuf); adh_mem_fd_release();
    char window[48];
    if (win_lo || win_hi) snprintf(window, sizeof(window), "0x%llx-0x%llx", win_lo, win_hi);
    else snprintf(window, sizeof(window), "all");
    size_t hlen = (hits ? strlen(hits) : 0) + 260; char *out = (char *)malloc(hlen);
    if (out) { snprintf(out, hlen, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"search\",\"ok\":true,\"count\":%d,\"truncated\":%s,\"regionClipped\":%s,\"backend\":\"%s\",\"window\":\"%s\",\"hits\":[%s]}\n", idj, nhits, nhits >= limit ? "true" : "false", clipped ? "true" : "false", route, window, hits ? hits : ""); send_line(fd, out); free(out); }
    free(hits);
}

// Force the memory-read route. Only "direct" is meaningful as a FORCE (auto and proc both mean "let
// the backend decide"); an unknown value is rejected instead of silently ignored. This exists so the
// direct fallback can be exercised across every read command — a target that refuses /proc/self/mem
// cannot be produced on demand, so without it search / magic-scan / dump / art_dexfiles never run on
// the direct route at all.
void cmd_mem_backend(int fd, const char *id, const char *backend) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    char want[32] = "";
    snprintf(want, sizeof(want), "%s", backend ? backend : "");
    if (want[0] && strcmp(want, "auto") != 0 && strcmp(want, "proc") != 0 && strcmp(want, "direct") != 0) {
        char err[220];
        snprintf(err, sizeof(err), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"mem_backend\",\"ok\":false,"
                 "\"error\":\"unknown backend '%s' (expected auto|direct|proc)\"}\n", idj, want);
        send_line(fd, err); return;
    }
    adh_mem_set_backend(want);
    char out[340];
    snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"mem_backend\",\"ok\":true,\"requested\":\"%s\","
        "\"backend\":\"%s\",\"forced\":%s,\"memOpenErrno\":%d}\n",
        idj, want[0] ? want : "auto", adh_mem_backend_name(),
        adh_mem_forced_direct() ? "true" : "false", adh_mem_open_errno());
    send_line(fd, out);
    LOGI("mem_backend: requested=%s effective=%s forced=%d", want[0] ? want : "auto",
         adh_mem_backend_name(), adh_mem_forced_direct());
}

void cmd_maps(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    int total = 0, trunc = 0;
    char *regions = build_maps_json(0, &total, &trunc);
    if (!regions) {
        char err[160];
        snprintf(err, sizeof(err), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"maps\",\"ok\":false,\"error\":\"read maps\"}\n", idj);
        send_line(fd, err); return;
    }
    size_t hlen = strlen(regions) + 200;
    char *out = (char *)malloc(hlen);
    if (out) {
        snprintf(out, hlen,
            "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"maps\",\"ok\":true,\"count\":%d,\"truncated\":%s,\"regions\":[%s]}\n",
            idj, total, trunc ? "true" : "false", regions);
        send_line(fd, out);
        free(out);
    }
    free(regions);
}
