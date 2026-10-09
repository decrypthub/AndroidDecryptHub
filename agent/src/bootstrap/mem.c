// mem.c — target-memory commands: read a range, scan for container magics, search for a byte
// pattern, and dump /proc/self/maps. Collect-only, bounded, fail-loud. Uses util/io helpers.
#include "agent_internal.h"
#include <fcntl.h>
#include <errno.h>

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
    unsigned long long addr = strtoull(addr_hex, NULL, 16);
    const char *shown = addr_hex;                       // accept "0x.." without echoing "0x0x.."
    if (shown[0] == '0' && (shown[1] == 'x' || shown[1] == 'X')) shown += 2;
    int direct = (via && strcmp(via, "direct") == 0);
    const char *route = direct ? "direct" : adh_mem_backend_name();
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
                     "\"error\":\"unreadable at 0x%s (via direct)\"}\n", idj, shown);
        else
            snprintf(err, sizeof(err), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"read\",\"ok\":false,"
                     "\"error\":\"unreadable at 0x%s (via %s, errno %d)\"}\n", idj, shown, route, errno);
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
            idj, addr_hex, got, size, (got < size) ? "true" : "false", route, b64);
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
