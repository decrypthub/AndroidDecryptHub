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

// Read `size` bytes at hex `addr` from /proc/self/mem; reply as base64 cmdResult.
void cmd_read(int fd, const char *id, const char *addr_hex, long long size) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    if (size <= 0 || size > (1 << 20)) {  // cap 1MB per read in v0.2
        char err[160];
        snprintf(err, sizeof(err), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"read\",\"ok\":false,\"error\":\"bad size\"}\n", idj);
        send_line(fd, err); return;
    }
    unsigned long long addr = strtoull(addr_hex, NULL, 16);
    int mem = open("/proc/self/mem", O_RDONLY);
    unsigned char *raw = (unsigned char *)malloc((size_t)size);
    if (mem < 0 || !raw) {
        if (mem >= 0) close(mem);
        free(raw);
        char err[160];
        snprintf(err, sizeof(err), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"read\",\"ok\":false,\"error\":\"open mem\"}\n", idj);
        send_line(fd, err); return;
    }
    ssize_t got = pread(mem, raw, (size_t)size, (off_t)addr);
    close(mem);
    if (got <= 0) {
        free(raw);
        char err[200];
        snprintf(err, sizeof(err), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"read\",\"ok\":false,\"error\":\"pread errno %d (unreadable)\"}\n", idj, errno);
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
            "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"read\",\"ok\":true,\"addr\":\"%s\",\"size\":%zd,\"b64\":\"%s\"}\n",
            idj, addr_hex, got, b64);
        send_line(fd, out);
        free(out);
    }
    free(b64);
}

// Scan readable regions of /proc/self/maps for known container magics.
// Bounded: <=64MB scanned per region, <=512MB total, <=256 hits. Collect-only.
void cmd_scan_magic(int fd, const char *id) {
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
    const size_t CHUNK = 1u << 20, PERREGION = 64u << 20, TOTALCAP = 512u << 20;
    const int MAXHITS = 256;

    int mem = open("/proc/self/mem", O_RDONLY);
    FILE *m = fopen("/proc/self/maps", "r");
    if (mem < 0 || !m) {
        if (mem >= 0) close(mem);
        if (m) fclose(m);
        char err[160];
        snprintf(err, sizeof(err), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"scan_magic\",\"ok\":false,\"error\":\"open\"}\n", idj);
        send_line(fd, err); return;
    }

    size_t cap = 1 << 16, len = 0;
    char *hits = (char *)malloc(cap); if (hits) hits[0] = 0;
    int nhits = 0, truncated = 0;
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
        unsigned long long rsize = end - start;
        if (rsize > PERREGION) rsize = PERREGION;
        if (total_scanned >= TOTALCAP) { truncated = 1; break; }

        unsigned long long o = 0;
        int carry = 0;                                       // bytes kept from previous chunk tail
        while (o < rsize && nhits < MAXHITS) {
            size_t want = (size_t)((rsize - o) < CHUNK ? (rsize - o) : CHUNK);
            ssize_t got = pread(mem, cbuf + carry, want, (off_t)(start + o));
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
    fclose(m); close(mem); free(cbuf);

    size_t hlen = (hits ? strlen(hits) : 0) + 200;
    char *out = (char *)malloc(hlen);
    if (out) {
        snprintf(out, hlen,
            "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"scan_magic\",\"ok\":true,\"count\":%d,\"truncated\":%s,\"scanned\":%zu,\"hits\":[%s]}\n",
            idj, nhits, truncated ? "true" : "false", total_scanned, hits ? hits : "");
        send_line(fd, out);
        free(out);
    }
    free(hits);
}

// Search readable memory for a byte pattern (hex-encoded). Returns hit addresses.
// Same bounds as scan_magic. Collect-only.
void cmd_search(int fd, const char *id, const char *pat_hex, int limit) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    unsigned char pat[256];
    int patlen = hex2bytes(pat_hex, pat, sizeof(pat));
    if (patlen <= 0) {
        char err[160];
        snprintf(err, sizeof(err), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"search\",\"ok\":false,\"error\":\"empty pattern\"}\n", idj);
        send_line(fd, err); return;
    }
    if (limit <= 0 || limit > 4096) limit = 256;
    const size_t CHUNK = 1u << 20, PERREGION = 128u << 20, TOTALCAP = 1024u << 20;

    int mem = open("/proc/self/mem", O_RDONLY);
    FILE *m = fopen("/proc/self/maps", "r");
    if (mem < 0 || !m) { if (mem >= 0) close(mem); if (m) fclose(m);
        char e[160]; snprintf(e, sizeof(e), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"search\",\"ok\":false,\"error\":\"open\"}\n", idj);
        send_line(fd, e); return; }

    size_t cap = 1 << 14, len = 0; char *hits = (char *)malloc(cap); if (hits) hits[0] = 0;
    int nhits = 0; size_t total = 0;
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
        unsigned long long rsize = end - start; if (rsize > PERREGION) rsize = PERREGION;
        if (total >= TOTALCAP) break;
        unsigned long long o = 0; int carry = 0;
        while (o < rsize && nhits < limit) {
            size_t want = (size_t)((rsize - o) < CHUNK ? (rsize - o) : CHUNK);
            ssize_t got = pread(mem, cbuf + carry, want, (off_t)(start + o));
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
    fclose(m); close(mem); free(cbuf);
    size_t hlen = (hits ? strlen(hits) : 0) + 160; char *out = (char *)malloc(hlen);
    if (out) { snprintf(out, hlen, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"search\",\"ok\":true,\"count\":%d,\"truncated\":%s,\"hits\":[%s]}\n", idj, nhits, nhits >= limit ? "true" : "false", hits ? hits : ""); send_line(fd, out); free(out); }
    free(hits);
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
