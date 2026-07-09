// libidh_agent.so — bootstrap + command loop (v0.2)
// Dual entry:
//   - JNI_OnLoad()      : fires when a host loads us via System.loadLibrary (模拟注入 / gadget)
//   - idh_agent_start() : exported C symbol for injector-driven load
// Both connect to idhd over TCP (127.0.0.1:8761, via `adb reverse`), report identity +
// an initial maps sample, then serve commands: maps / read (memory). Collect-only.

#include <jni.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/system_properties.h>
#include <android/log.h>

#define AGENT_VER   "0.2.0"
#define IDH_HOST    "127.0.0.1"
#define IDH_PORT    8761
#define TAG         "IDH_AGENT"
#define LOGI(...)   __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...)   __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static char g_entry[16] = "start";
static JavaVM *g_vm = NULL;   // cached in JNI_OnLoad (also recoverable via JNI_GetCreatedJavaVMs)

// Attach the calling (native) thread to the VM and return a JNIEnv.
// *did_attach set to 1 if we attached (caller must Detach when done).
static JNIEnv *attach_env(int *did_attach) {
    *did_attach = 0;
    if (!g_vm) {
        // Fallback for injector-loaded (non JNI_OnLoad) case.
        typedef jint (*GetVMs)(JavaVM **, jsize, jsize *);
        void *lib = dlopen("libart.so", RTLD_NOW);
        GetVMs f = lib ? (GetVMs)dlsym(lib, "JNI_GetCreatedJavaVMs") : NULL;
        if (f) { JavaVM *vm = NULL; jsize n = 0; if (f(&vm, 1, &n) == 0 && n > 0) g_vm = vm; }
        if (!g_vm) return NULL;
    }
    JNIEnv *env = NULL;
    jint st = (*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6);
    if (st == JNI_EDETACHED) {
        if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != 0) return NULL;
        *did_attach = 1;
    } else if (st != JNI_OK) return NULL;
    return env;
}
static void detach_env(int did_attach) { if (did_attach && g_vm) (*g_vm)->DetachCurrentThread(g_vm); }

// ---- small utils ----------------------------------------------------------

static void prop(const char *key, char *out, size_t n) {
    out[0] = 0;
    char buf[PROP_VALUE_MAX] = {0};
    if (__system_property_get(key, buf) > 0) { strncpy(out, buf, n - 1); out[n - 1] = 0; }
}

static void read_cmdline(char *out, size_t n) {
    out[0] = 0;
    FILE *f = fopen("/proc/self/cmdline", "rb");
    if (!f) { strncpy(out, "unknown", n - 1); return; }
    size_t r = fread(out, 1, n - 1, f);
    fclose(f);
    out[r > 0 ? r : 0] = 0;
}

static void json_escape(const char *in, char *out, size_t n) {
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 2 < n; i++) {
        char c = in[i];
        if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = c; }
        else if ((unsigned char)c < 0x20) { out[o++] = ' '; }
        else out[o++] = c;
    }
    out[o] = 0;
}

// Minimal JSON field extractors for our own controlled protocol.
static int json_get_str(const char *json, const char *key, char *out, size_t n) {
    char pat[64]; snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char *p = strstr(json, pat);
    if (!p) { out[0] = 0; return 0; }
    p += strlen(pat);
    size_t o = 0;
    while (*p && *p != '"' && o + 1 < n) out[o++] = *p++;
    out[o] = 0;
    return 1;
}
static long long json_get_num(const char *json, const char *key) {
    char pat[64]; snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    return strtoll(p, NULL, 10);
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static size_t b64_encode(const unsigned char *in, size_t len, char *out) {
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        unsigned v = in[i] << 16;
        if (i + 1 < len) v |= in[i + 1] << 8;
        if (i + 2 < len) v |= in[i + 2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = (i + 1 < len) ? B64[(v >> 6) & 63] : '=';
        out[o++] = (i + 2 < len) ? B64[v & 63] : '=';
    }
    out[o] = 0;
    return o;
}

// ---- socket io ------------------------------------------------------------

static int connect_idhd(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(IDH_PORT);
    inet_pton(AF_INET, IDH_HOST, &a.sin_addr);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(fd); return -1; }
    int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return fd;
}

static int send_all(int fd, const char *s, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, s + off, len - off);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}
static int send_line(int fd, const char *s) { return send_all(fd, s, strlen(s)); }

// ---- maps -----------------------------------------------------------------

// Build a JSON array of maps regions. limit<=0 = all. *total set to line count.
// Returns malloc'd string (caller frees) or NULL.
static char *build_maps_json(int limit, int *total) {
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) { *total = 0; return NULL; }
    size_t cap = 1 << 16, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) { fclose(m); *total = 0; return NULL; }
    buf[0] = 0;
    int count = 0, emitted = 0;
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
            if (!nb) break;
            buf = nb;
        }
        memcpy(buf + len, rec, (size_t)w);
        len += (size_t)w; buf[len] = 0;
        emitted++;
    }
    fclose(m);
    *total = count;
    return buf;
}

// ---- memory read ----------------------------------------------------------

// Read `size` bytes at hex `addr` from /proc/self/mem; reply as base64 cmdResult.
static void cmd_read(int fd, const char *id, const char *addr_hex, long long size) {
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
    if (!b64) { free(raw); return; }
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
static void cmd_scan_magic(int fd, const char *id) {
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

static int hex2bytes(const char *hex, unsigned char *out, int maxlen) {
    int n = 0;
    while (hex[0] && hex[1] && n < maxlen) {
        char b[3] = { hex[0], hex[1], 0 };
        out[n++] = (unsigned char)strtol(b, NULL, 16);
        hex += 2;
    }
    return n;
}

// Search readable memory for a byte pattern (hex-encoded). Returns hit addresses.
// Same bounds as scan_magic. Collect-only.
static void cmd_search(int fd, const char *id, const char *pat_hex, int limit) {
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
    if (out) { snprintf(out, hlen, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"search\",\"ok\":true,\"count\":%d,\"hits\":[%s]}\n", idj, nhits, hits ? hits : ""); send_line(fd, out); free(out); }
    free(hits);
}

// ---- GOT/PLT hook engine (E.8.1) -----------------------------------------
// Replace the GOT slot that holds `orig` with `wrapper` in modules matching name.
// Linear scan over non-exec segments (incl. RELRO). Hooks EXACTLY the first match
// (lowest address = the real .got.plt/RELRO slot); replacing duplicate copies in
// other data segments corrupts the original's own call path, so we stop at one.
#include <sys/mman.h>

static int got_replace(const char *module_substr, void *orig, void *wrapper) {
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return -1;
    char line[512];
    int replaced = 0;
    long pagesz = sysconf(_SC_PAGESIZE);
    while (replaced == 0 && fgets(line, sizeof(line), m)) {
        char sa[32], ea[32], perms[8], off[32], dev[16], path[400] = "";
        unsigned long long inode = 0;
        int nf = sscanf(line, "%31[0-9a-f]-%31[0-9a-f] %7s %31s %15s %llu %399[^\n]", sa, ea, perms, off, dev, &inode, path);
        if (nf < 6 || perms[0] != 'r') continue;
        char *pp = path; while (*pp == ' ') pp++;
        if (!strstr(pp, module_substr)) continue;
        if (strstr(perms, "x")) continue;                 // GOT lives in data/RELRO, not exec
        unsigned long long start = strtoull(sa, NULL, 16), end = strtoull(ea, NULL, 16);
        if (end <= start) continue;
        for (unsigned long long a = start; a + sizeof(void *) <= end; a += sizeof(void *)) {
            void **slot = (void **)a;
            if (*slot == orig) {
                void *page = (void *)(a & ~((unsigned long long)pagesz - 1));
                if (mprotect(page, pagesz, PROT_READ | PROT_WRITE) == 0) {
                    *slot = wrapper;
                    replaced++;
                    break;   // exactly one slot
                }
            }
        }
    }
    fclose(m);
    return replaced;
}

// --- self-test target: hook the agent's own close() (plain syscall wrapper) ---
static void *g_orig_close = NULL;
static volatile int g_close_hits = 0;
static int my_close(int fd) {
    __atomic_add_fetch(&g_close_hits, 1, __ATOMIC_RELAXED);
    typedef int (*close_t)(int);
    return ((close_t)g_orig_close)(fd);
}

static void cmd_gothook_selftest(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    void *libc = dlopen("libc.so", RTLD_NOW);
    void *orig = libc ? dlsym(libc, "close") : NULL;
    g_orig_close = orig;
    int replaced = orig ? got_replace("libidh_agent.so", orig, (void *)my_close) : -1;
    int before = g_close_hits;
    // trigger a controlled close() from agent code -> routes through the hooked GOT slot
    int tfd = open("/proc/self/stat", O_RDONLY);
    if (tfd >= 0) close(tfd);
    int after = g_close_hits;
    if (replaced > 0 && orig) got_replace("libidh_agent.so", (void *)my_close, orig);  // restore
    char out[256];
    snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"gothook_selftest\",\"ok\":true,\"replaced\":%d,\"hitsBefore\":%d,\"hitsAfter\":%d,\"fired\":%s}\n",
        idj, replaced, before, after, (after > before) ? "true" : "false");
    send_line(fd, out);
    LOGI("gothook_selftest: replaced=%d hits=%d fired=%d", replaced, after - before, after > before);
}

// Resolve an exported symbol in an already-loaded module by parsing its in-memory
// dynamic symbol table (namespace-independent; works when dlopen is blocked).
static void *resolve_sym(const char *mod_substr, const char *symbol) {
    unsigned long long base = 0;
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return NULL;
    char line[512];
    while (fgets(line, sizeof(line), m)) {
        char sa[32], ea[32], perms[8], off[32], dev[16], path[400] = "";
        unsigned long long inode = 0;
        if (sscanf(line, "%31[0-9a-f]-%31[0-9a-f] %7s %31s %15s %llu %399[^\n]", sa, ea, perms, off, dev, &inode, path) < 6) continue;
        char *pp = path; while (*pp == ' ') pp++;
        const char *bn = strrchr(pp, '/'); bn = bn ? bn + 1 : pp;
        if (strcmp(bn, mod_substr) != 0) continue;                   // exact basename match
        if (strcmp(off, "0") && strcmp(off, "00000000")) continue;   // want the mapping at file offset 0 (ELF header)
        unsigned long long s = strtoull(sa, NULL, 16);
        if (base == 0 || s < base) base = s;
    }
    fclose(m);
    if (!base) return NULL;
    unsigned char *p = (unsigned char *)base;
    if (memcmp(p, "\x7f""ELF", 4) != 0) return NULL;
    unsigned long long phoff = *(unsigned long long *)(p + 32);
    unsigned short phentsize = *(unsigned short *)(p + 54);
    unsigned short phnum = *(unsigned short *)(p + 56);
    unsigned long long dyn_vaddr = 0;
    for (int i = 0; i < phnum; i++) {
        unsigned char *ph = p + phoff + (unsigned long long)i * phentsize;
        if (*(unsigned int *)ph == 2) { dyn_vaddr = *(unsigned long long *)(ph + 16); break; }  // PT_DYNAMIC
    }
    if (!dyn_vaddr) return NULL;
    unsigned long long symtab = 0, strtab = 0;
    unsigned long long *d = (unsigned long long *)(base + dyn_vaddr);
    for (; d[0] != 0; d += 2) {           // Elf64_Dyn: {d_tag, d_val}
        if (d[0] == 6) symtab = d[1];     // DT_SYMTAB
        else if (d[0] == 5) strtab = d[1];// DT_STRTAB
    }
    if (!symtab || !strtab) return NULL;
    if (symtab < base) symtab += base;    // link-time vaddr -> runtime
    if (strtab < base) strtab += base;
    if (strtab <= symtab) return NULL;
    long count = (long)((strtab - symtab) / 24);  // .dynstr follows .dynsym (common layout)
    if (count <= 0 || count > 300000) return NULL;
    for (long i = 0; i < count; i++) {
        unsigned char *sym = (unsigned char *)(symtab + (unsigned long long)i * 24);
        unsigned int st_name = *(unsigned int *)sym;
        unsigned long long st_value = *(unsigned long long *)(sym + 8);
        const char *name = (const char *)(strtab + st_name);
        if (st_value && strcmp(name, symbol) == 0) return (void *)(base + st_value);
    }
    return NULL;
}

// ---- crypto plaintext capture (thread-safe; wrapper runs on the app's crypto thread) ----
#define CAP_MAX 64
#define CAP_BYTES 256
struct CapRec { char func[24]; int inl; int n; unsigned char data[CAP_BYTES]; };
static struct CapRec g_caps[CAP_MAX];
static int g_ncaps = 0;
static pthread_mutex_t g_cap_lock = PTHREAD_MUTEX_INITIALIZER;
static void capture(const char *func, const unsigned char *in, int inl) {
    if (inl <= 0 || !in) return;
    pthread_mutex_lock(&g_cap_lock);
    if (g_ncaps < CAP_MAX) {
        struct CapRec *r = &g_caps[g_ncaps++];
        strncpy(r->func, func, sizeof(r->func) - 1); r->func[sizeof(r->func)-1]=0;
        r->inl = inl; r->n = inl < CAP_BYTES ? inl : CAP_BYTES;
        memcpy(r->data, in, r->n);
    }
    pthread_mutex_unlock(&g_cap_lock);
}

typedef int (*EVP_CipherUpdate_t)(void *, unsigned char *, int *, const unsigned char *, int);
static EVP_CipherUpdate_t g_evp_cipher_orig = NULL;
static int my_EVP_CipherUpdate(void *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl) {
    capture("EVP_CipherUpdate", in, inl);
    return g_evp_cipher_orig(ctx, out, outl, in, inl);
}

// Recon: for each EVP/HMAC function, report which loaded modules' GOT holds its
// pointer (candidate hook sites) and how many slots. Guides where to install hooks.
static void cmd_crypto_probe(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    const char *names[] = { "EVP_CipherUpdate", "EVP_EncryptUpdate", "EVP_DecryptUpdate", "EVP_DigestUpdate", "HMAC_Update" };
    const int NF = 5;
    void *addrs[5];
    for (int i = 0; i < NF; i++) addrs[i] = resolve_sym("libcrypto.so", names[i]);

    // aggregate per-module match counts
    struct Mod { char name[128]; int cnt[5]; };
    struct Mod mods[96]; int nmods = 0;
    FILE *m = fopen("/proc/self/maps", "r");
    char line[512];
    while (m && fgets(line, sizeof(line), m)) {
        char sa[32], ea[32], perms[8], off[32], dev[16], path[400] = "";
        unsigned long long inode = 0;
        int nf = sscanf(line, "%31[0-9a-f]-%31[0-9a-f] %7s %31s %15s %llu %399[^\n]", sa, ea, perms, off, dev, &inode, path);
        if (nf < 6 || perms[0] != 'r' || strstr(perms, "x")) continue;
        char *pp = path; while (*pp == ' ') pp++;
        if (!strstr(pp, ".so")) continue;
        const char *base = strrchr(pp, '/'); base = base ? base + 1 : pp;
        unsigned long long s = strtoull(sa, NULL, 16), e = strtoull(ea, NULL, 16);
        if (e <= s || e - s > (64u << 20)) continue;
        int hit[5] = {0,0,0,0,0}, any = 0;
        for (unsigned long long a = s; a + 8 <= e; a += 8) {
            void *v = *(void **)a;
            for (int i = 0; i < NF; i++) if (addrs[i] && v == addrs[i]) { hit[i]++; any = 1; }
        }
        if (!any) continue;
        // find/create module entry
        int mi = -1;
        for (int k = 0; k < nmods; k++) if (strcmp(mods[k].name, base) == 0) { mi = k; break; }
        if (mi < 0 && nmods < 96) { mi = nmods++; strncpy(mods[mi].name, base, sizeof(mods[mi].name) - 1); mods[mi].name[sizeof(mods[mi].name)-1]=0; for (int i=0;i<NF;i++) mods[mi].cnt[i]=0; }
        if (mi >= 0) for (int i = 0; i < NF; i++) mods[mi].cnt[i] += hit[i];
    }
    if (m) fclose(m);

    // build JSON
    size_t cap = 1 << 14, len = 0; char *out = malloc(cap); if (!out) { detach_env(0); return; }
    len += snprintf(out + len, cap - len, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"crypto_probe\",\"ok\":true,\"fns\":{", idj);
    for (int i = 0; i < NF; i++) len += snprintf(out + len, cap - len, "%s\"%s\":\"%llx\"", i?",":"", names[i], (unsigned long long)addrs[i]);
    len += snprintf(out + len, cap - len, "},\"modules\":[");
    for (int k = 0; k < nmods; k++) {
        len += snprintf(out + len, cap - len, "%s{\"name\":\"%s\"", k?",":"", mods[k].name);
        for (int i = 0; i < NF; i++) if (mods[k].cnt[i]) len += snprintf(out + len, cap - len, ",\"%s\":%d", names[i], mods[k].cnt[i]);
        len += snprintf(out + len, cap - len, "}");
    }
    snprintf(out + len, cap - len, "]}\n");
    send_line(fd, out);
    free(out);
    LOGI("crypto_probe: %d modules with EVP/HMAC GOT refs", nmods);
}

// Install EVP_CipherUpdate GOT hook in libjavacrypto (Conscrypt), trigger the
// sandbox's AES via JNI reflection, and return what plaintext the wrapper captured.
static void cmd_crypto_hook_test(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    void *orig = resolve_sym("libcrypto.so", "EVP_CipherUpdate");
    g_evp_cipher_orig = (EVP_CipherUpdate_t)orig;
    int replaced = orig ? got_replace("libjavacrypto.so", orig, (void *)my_EVP_CipherUpdate) : -1;
    pthread_mutex_lock(&g_cap_lock); g_ncaps = 0; pthread_mutex_unlock(&g_cap_lock);

    // trigger com.idh.sandbox.JavaCrypto.run() via JNI reflection (app classloader)
    int did = 0, triggered = 0;
    JNIEnv *env = attach_env(&did);
    if (env) {
        (*env)->PushLocalFrame(env, 64);
        jclass at = (*env)->FindClass(env, "android/app/ActivityThread");
        jmethodID cur = at ? (*env)->GetStaticMethodID(env, at, "currentApplication", "()Landroid/app/Application;") : NULL;
        jobject app = cur ? (*env)->CallStaticObjectMethod(env, at, cur) : NULL;
        if (app) {
            jclass ctx = (*env)->FindClass(env, "android/content/Context");
            jmethodID gcl = (*env)->GetMethodID(env, ctx, "getClassLoader", "()Ljava/lang/ClassLoader;");
            jobject loader = (*env)->CallObjectMethod(env, app, gcl);
            jclass clc = (*env)->FindClass(env, "java/lang/ClassLoader");
            jmethodID load = (*env)->GetMethodID(env, clc, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
            jstring cn = (*env)->NewStringUTF(env, "com.idh.sandbox.JavaCrypto");
            jclass jc = loader ? (jclass)(*env)->CallObjectMethod(env, loader, load, cn) : NULL;
            if (jc) {
                jmethodID run = (*env)->GetStaticMethodID(env, jc, "run", "()V");
                if (run) { (*env)->CallStaticVoidMethod(env, jc, run); triggered = 1; }
            }
        }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->PopLocalFrame(env, NULL);
        detach_env(did);
    }

    // unhook (restore) before building reply
    if (replaced > 0 && orig) got_replace("libjavacrypto.so", (void *)my_EVP_CipherUpdate, orig);

    // build reply with captured records (hex)
    size_t cap = 1 << 15, len = 0; char *out = malloc(cap); if (!out) return;
    len += snprintf(out + len, cap - len, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"crypto_hook_test\",\"ok\":true,\"replaced\":%d,\"triggered\":%s,\"captures\":[", idj, replaced, triggered ? "true" : "false");
    pthread_mutex_lock(&g_cap_lock);
    for (int k = 0; k < g_ncaps; k++) {
        struct CapRec *r = &g_caps[k];
        len += snprintf(out + len, cap - len, "%s{\"func\":\"%s\",\"inl\":%d,\"hex\":\"", k ? "," : "", r->func, r->inl);
        for (int b = 0; b < r->n && len + 3 < cap; b++) len += snprintf(out + len, cap - len, "%02x", r->data[b]);
        len += snprintf(out + len, cap - len, "\"}");
    }
    int ncaps = g_ncaps;
    pthread_mutex_unlock(&g_cap_lock);
    snprintf(out + len, cap - len, "],\"count\":%d}\n", ncaps);
    send_line(fd, out);
    free(out);
    LOGI("crypto_hook_test: replaced=%d triggered=%d captures=%d", replaced, triggered, ncaps);
}

// ---- anti-analysis behavior observation (module V) ----
// GOT-hook the target's own detection calls to see WHAT it checks for.
struct DetRec { char cat[16]; char detail[160]; };
static struct DetRec g_dets[64];
static int g_ndets = 0;
static pthread_mutex_t g_det_lock = PTHREAD_MUTEX_INITIALIZER;
static void det_record(const char *cat, const char *detail) {
    pthread_mutex_lock(&g_det_lock);
    if (g_ndets < 64) { struct DetRec *r = &g_dets[g_ndets++];
        strncpy(r->cat, cat, sizeof(r->cat) - 1); r->cat[sizeof(r->cat)-1]=0;
        strncpy(r->detail, detail, sizeof(r->detail) - 1); r->detail[sizeof(r->detail)-1]=0; }
    pthread_mutex_unlock(&g_det_lock);
}

typedef long (*ptrace_t)(int, void *, void *, void *);
static ptrace_t g_orig_ptrace = NULL;
static long my_ptrace(int req, void *a, void *b, void *c) {
    char d[64]; snprintf(d, sizeof(d), "ptrace(request=%d%s)", req, req == 0 ? " PTRACE_TRACEME" : "");
    det_record("debug", d);
    if (req == 0) return 0;                 // neutralize TRACEME: observe (V) + defeat (S)
    return g_orig_ptrace(req, a, b, c);
}
typedef int (*access_t)(const char *, int);
static access_t g_orig_access = NULL;
static int my_access(const char *p, int m) {
    if (p) det_record(strstr(p, "su") ? "root" : "file", p);
    return g_orig_access(p, m);
}
typedef int (*prop_t)(const char *, char *);
static prop_t g_orig_prop = NULL;
static int my_prop(const char *name, char *value) {
    det_record("prop", name ? name : "?");
    return g_orig_prop(name, value);
}

// Load an app class from the native thread via ActivityThread.currentApplication()'s loader.
static jclass load_app_class(JNIEnv *env, const char *dotname) {
    jclass at = (*env)->FindClass(env, "android/app/ActivityThread");
    jmethodID cur = at ? (*env)->GetStaticMethodID(env, at, "currentApplication", "()Landroid/app/Application;") : NULL;
    jobject app = cur ? (*env)->CallStaticObjectMethod(env, at, cur) : NULL;
    if (!app) return NULL;
    jclass ctx = (*env)->FindClass(env, "android/content/Context");
    jmethodID gcl = (*env)->GetMethodID(env, ctx, "getClassLoader", "()Ljava/lang/ClassLoader;");
    jobject loader = (*env)->CallObjectMethod(env, app, gcl);
    jclass clc = (*env)->FindClass(env, "java/lang/ClassLoader");
    jmethodID load = (*env)->GetMethodID(env, clc, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    jstring cn = (*env)->NewStringUTF(env, dotname);
    return loader ? (jclass)(*env)->CallObjectMethod(env, loader, load, cn) : NULL;
}

// Install GOT hooks on libidhdetect's detection calls, trigger Detection.run(),
// report what the target checked.
static void cmd_detect_watch(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    void *op = resolve_sym("libc.so", "ptrace");
    void *oa = resolve_sym("libc.so", "access");
    void *og = resolve_sym("libc.so", "__system_property_get");
    g_orig_ptrace = (ptrace_t)op; g_orig_access = (access_t)oa; g_orig_prop = (prop_t)og;
    int r1 = op ? got_replace("libidhdetect.so", op, (void *)my_ptrace) : -1;
    int r2 = oa ? got_replace("libidhdetect.so", oa, (void *)my_access) : -1;
    int r3 = og ? got_replace("libidhdetect.so", og, (void *)my_prop) : -1;
    pthread_mutex_lock(&g_det_lock); g_ndets = 0; pthread_mutex_unlock(&g_det_lock);

    int did = 0, triggered = 0, rc = -999;
    JNIEnv *env = attach_env(&did);
    if (env) {
        (*env)->PushLocalFrame(env, 32);
        jclass jc = load_app_class(env, "com.idh.sandbox.Detection");
        if (jc) {
            jmethodID run = (*env)->GetStaticMethodID(env, jc, "run", "()I");
            if (run) { rc = (*env)->CallStaticIntMethod(env, jc, run); triggered = 1; }
        }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->PopLocalFrame(env, NULL);
        detach_env(did);
    }
    // restore
    if (r1 > 0) got_replace("libidhdetect.so", (void *)my_ptrace, op);
    if (r2 > 0) got_replace("libidhdetect.so", (void *)my_access, oa);
    if (r3 > 0) got_replace("libidhdetect.so", (void *)my_prop, og);

    size_t cap = 1 << 13, len = 0; char *out = malloc(cap); if (!out) return;
    len += snprintf(out + len, cap - len, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"detect_watch\",\"ok\":true,\"hooked\":{\"ptrace\":%d,\"access\":%d,\"prop\":%d},\"triggered\":%s,\"detectRc\":%d,\"detections\":[", idj, r1, r2, r3, triggered ? "true" : "false", rc);
    pthread_mutex_lock(&g_det_lock);
    for (int k = 0; k < g_ndets; k++) { char dj[200]; json_escape(g_dets[k].detail, dj, sizeof(dj));
        len += snprintf(out + len, cap - len, "%s{\"category\":\"%s\",\"detail\":\"%s\"}", k ? "," : "", g_dets[k].cat, dj); }
    int n = g_ndets;
    pthread_mutex_unlock(&g_det_lock);
    snprintf(out + len, cap - len, "],\"count\":%d}\n", n);
    send_line(fd, out);
    free(out);
    LOGI("detect_watch: hooked p=%d a=%d g=%d triggered=%d detections=%d", r1, r2, r3, triggered, n);
}

// Module T: Runtime Object Inspector — read a live object's fields via reflection.
// Reaches the object through a static field of `className`, then enumerates the
// object's declared fields (name + String.valueOf(value)). Foundation for full
// heap-instance enumeration. All-reflection => no field-signature strings needed.
static void cmd_object_inspect(int fd, const char *id, const char *className, const char *fieldName) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    int did = 0;
    JNIEnv *env = attach_env(&did);
    if (!env) { char e[160]; snprintf(e, sizeof(e), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_inspect\",\"ok\":false,\"error\":\"no JavaVM\"}\n", idj); send_line(fd, e); return; }
    (*env)->PushLocalFrame(env, 256);

    size_t cap = 1 << 14, len = 0; char *out = malloc(cap);
    int ok = 0; char err[128] = ""; char objClass[160] = ""; int nfields = 0;
    char *recs = malloc(1 << 13); if (recs) recs[0] = 0; size_t rlen = 0, rcap = 1 << 13;

    jclass clsClass = (*env)->FindClass(env, "java/lang/Class");
    jclass fieldClass = (*env)->FindClass(env, "java/lang/reflect/Field");
    jclass strClass = (*env)->FindClass(env, "java/lang/String");
    jmethodID mGetField = (*env)->GetMethodID(env, clsClass, "getDeclaredField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
    jmethodID mGetFields = (*env)->GetMethodID(env, clsClass, "getDeclaredFields", "()[Ljava/lang/reflect/Field;");
    jmethodID mGetName = (*env)->GetMethodID(env, clsClass, "getName", "()Ljava/lang/String;");
    jmethodID mSetAcc = (*env)->GetMethodID(env, fieldClass, "setAccessible", "(Z)V");
    jmethodID mFieldGet = (*env)->GetMethodID(env, fieldClass, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
    jmethodID mFieldName = (*env)->GetMethodID(env, fieldClass, "getName", "()Ljava/lang/String;");
    jmethodID mValueOf = (*env)->GetStaticMethodID(env, strClass, "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;");

    jclass target = load_app_class(env, className);
    if (!target) { strncpy(err, "class not found", sizeof(err)-1); goto done; }

    jstring fn = (*env)->NewStringUTF(env, fieldName);
    jobject fieldObj = (*env)->CallObjectMethod(env, target, mGetField, fn);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); strncpy(err, "field not found", sizeof(err)-1); goto done; }
    (*env)->CallVoidMethod(env, fieldObj, mSetAcc, JNI_TRUE);
    jobject obj = (*env)->CallObjectMethod(env, fieldObj, mFieldGet, NULL);   // static field -> null
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); strncpy(err, "field.get failed (not static?)", sizeof(err)-1); goto done; }
    if (!obj) { strncpy(err, "field value is null", sizeof(err)-1); goto done; }

    jclass ocls = (*env)->GetObjectClass(env, obj);
    jstring ocn = (jstring)(*env)->CallObjectMethod(env, ocls, mGetName);
    if (ocn) { const char *s = (*env)->GetStringUTFChars(env, ocn, NULL); if (s) { strncpy(objClass, s, sizeof(objClass)-1); (*env)->ReleaseStringUTFChars(env, ocn, s); } }

    jobjectArray fields = (jobjectArray)(*env)->CallObjectMethod(env, ocls, mGetFields);
    jsize nf = fields ? (*env)->GetArrayLength(env, fields) : 0;
    for (jsize i = 0; i < nf && recs; i++) {
        jobject f = (*env)->GetObjectArrayElement(env, fields, i);
        (*env)->CallVoidMethod(env, f, mSetAcc, JNI_TRUE);
        jstring nm = (jstring)(*env)->CallObjectMethod(env, f, mFieldName);
        jobject val = (*env)->CallObjectMethod(env, f, mFieldGet, obj);
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        jstring vs = (jstring)(*env)->CallStaticObjectMethod(env, strClass, mValueOf, val);
        char nbuf[96] = "", vbuf[300] = "";
        if (nm) { const char *s = (*env)->GetStringUTFChars(env, nm, NULL); if (s) { strncpy(nbuf, s, sizeof(nbuf)-1); (*env)->ReleaseStringUTFChars(env, nm, s); } }
        if (vs) { const char *s = (*env)->GetStringUTFChars(env, vs, NULL); if (s) { strncpy(vbuf, s, sizeof(vbuf)-1); (*env)->ReleaseStringUTFChars(env, vs, s); } }
        char nj[120], vj[600]; json_escape(nbuf, nj, sizeof(nj)); json_escape(vbuf, vj, sizeof(vj));
        char rec[760]; int w = snprintf(rec, sizeof(rec), "%s{\"name\":\"%s\",\"value\":\"%s\"}", nfields ? "," : "", nj, vj);
        if (w > 0 && rlen + (size_t)w + 1 < rcap) { memcpy(recs + rlen, rec, w); rlen += w; recs[rlen] = 0; nfields++; }
        (*env)->DeleteLocalRef(env, f);
    }
    ok = 1;

done:
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    (*env)->PopLocalFrame(env, NULL);
    detach_env(did);
    if (out) {
        char cj[160], ecj[160]; json_escape(objClass, cj, sizeof(cj)); json_escape(err, ecj, sizeof(ecj));
        if (ok) snprintf(out, cap, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_inspect\",\"ok\":true,\"objectClass\":\"%s\",\"fieldCount\":%d,\"fields\":[%s]}\n", idj, cj, nfields, recs ? recs : "");
        else snprintf(out, cap, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_inspect\",\"ok\":false,\"error\":\"%s\"}\n", idj, ecj);
        send_line(fd, out);
        free(out);
    }
    free(recs);
    LOGI("object_inspect: %s.%s -> %s fields=%d ok=%d", className, fieldName, objClass, nfields, ok);
}

// Module T: invoke a no-arg (low-risk) method on the object reached via a static
// field, returning String.valueOf(result). For getters/toString/size/length.
static void cmd_object_invoke(int fd, const char *id, const char *className, const char *fieldName, const char *methodName) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    int did = 0;
    JNIEnv *env = attach_env(&did);
    if (!env) { char e[160]; snprintf(e, sizeof(e), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_invoke\",\"ok\":false,\"error\":\"no JavaVM\"}\n", idj); send_line(fd, e); return; }
    (*env)->PushLocalFrame(env, 128);
    int ok = 0; char err[128] = "", result[400] = "";

    jclass clsClass = (*env)->FindClass(env, "java/lang/Class");
    jclass fieldClass = (*env)->FindClass(env, "java/lang/reflect/Field");
    jclass methodClass = (*env)->FindClass(env, "java/lang/reflect/Method");
    jclass strClass = (*env)->FindClass(env, "java/lang/String");
    jmethodID mGetField = (*env)->GetMethodID(env, clsClass, "getDeclaredField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
    jmethodID mGetMethod = (*env)->GetMethodID(env, clsClass, "getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");
    jmethodID mSetAccF = (*env)->GetMethodID(env, fieldClass, "setAccessible", "(Z)V");
    jmethodID mFieldGet = (*env)->GetMethodID(env, fieldClass, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
    jmethodID mInvoke = (*env)->GetMethodID(env, methodClass, "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
    jmethodID mValueOf = (*env)->GetStaticMethodID(env, strClass, "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;");

    jclass target = load_app_class(env, className);
    if (!target) { strncpy(err, "class not found", sizeof(err)-1); goto done; }
    jobject fieldObj = (*env)->CallObjectMethod(env, target, mGetField, (*env)->NewStringUTF(env, fieldName));
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); strncpy(err, "field not found", sizeof(err)-1); goto done; }
    (*env)->CallVoidMethod(env, fieldObj, mSetAccF, JNI_TRUE);
    jobject obj = (*env)->CallObjectMethod(env, fieldObj, mFieldGet, NULL);
    if (!obj || (*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); strncpy(err, "field value null", sizeof(err)-1); goto done; }

    jclass ocls = (*env)->GetObjectClass(env, obj);
    jobject method = (*env)->CallObjectMethod(env, ocls, mGetMethod, (*env)->NewStringUTF(env, methodName), NULL);  // no-arg
    if (!method || (*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); strncpy(err, "method not found (no-arg only)", sizeof(err)-1); goto done; }
    jobject ret = (*env)->CallObjectMethod(env, method, mInvoke, obj, NULL);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); strncpy(err, "invoke threw", sizeof(err)-1); goto done; }
    jstring vs = (jstring)(*env)->CallStaticObjectMethod(env, strClass, mValueOf, ret);
    if (vs) { const char *s = (*env)->GetStringUTFChars(env, vs, NULL); if (s) { strncpy(result, s, sizeof(result)-1); (*env)->ReleaseStringUTFChars(env, vs, s); } }
    ok = 1;

done:
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    (*env)->PopLocalFrame(env, NULL);
    detach_env(did);
    char rj[500], ej[160]; json_escape(result, rj, sizeof(rj)); json_escape(err, ej, sizeof(ej));
    char out[800];
    if (ok) snprintf(out, sizeof(out), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_invoke\",\"ok\":true,\"result\":\"%s\"}\n", idj, rj);
    else snprintf(out, sizeof(out), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_invoke\",\"ok\":false,\"error\":\"%s\"}\n", idj, ej);
    send_line(fd, out);
    LOGI("object_invoke: %s.%s.%s() -> %s ok=%d", className, fieldName, methodName, result, ok);
}

// Module S: self-assess the runtime environment / hook-backend availability so the
// operator knows what's usable and whether the target is interfering (授权抗干扰诊断).
static void cmd_compat_probe(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    int tracer = -1, seccomp = -1;
    FILE *st = fopen("/proc/self/status", "r");
    if (st) { char line[256];
        while (fgets(line, sizeof(line), st)) {
            if (strncmp(line, "TracerPid:", 10) == 0) tracer = atoi(line + 10);
            else if (strncmp(line, "Seccomp:", 8) == 0) seccomp = atoi(line + 8);
        }
        fclose(st);
    }
    // hook-backend availability: symbol resolution is the prerequisite for GOT hooks
    int got_ok = (resolve_sym("libc.so", "access") != NULL);
    int jni_ok = (g_vm != NULL);
    int module_count = 0, maps_count = 0;
    FILE *m = fopen("/proc/self/maps", "r"); char l[512]; char lastmod[400] = "";
    while (m && fgets(l, sizeof(l), m)) { maps_count++;
        char *p = strstr(l, "/"); if (p) { char *nl = strchr(p, '\n'); if (nl) *nl = 0; if (strcmp(p, lastmod)) { strncpy(lastmod, p, sizeof(lastmod)-1); module_count++; } } }
    if (m) fclose(m);

    char out[640];
    snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"compat_probe\",\"ok\":true,"
        "\"tracerPid\":%d,\"seccomp\":%d,\"backends\":{\"gotHook\":%s,\"jniReflect\":%s,\"artDexCapture\":%s,\"memRead\":true},"
        "\"mapsCount\":%d,\"moduleMappings\":%d,\"dlopenSystemLibsBlocked\":%s,"
        "\"minimalModeAvailable\":true}\n",
        idj, tracer, seccomp, got_ok ? "true" : "false", jni_ok ? "true" : "false",
        (g_vm != NULL) ? "true" : "false", maps_count, module_count,
        "true" /* observed: system libcrypto not dlopen-able -> use resolve_sym */);
    send_line(fd, out);
    LOGI("compat_probe: tracer=%d seccomp=%d got=%d jni=%d", tracer, seccomp, got_ok, jni_ok);
}

// Prove JNI reflection works from the agent's native thread: read Build.VERSION.
static void cmd_jni_probe(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    int did = 0;
    JNIEnv *env = attach_env(&did);
    if (!env) {
        char e[160]; snprintf(e, sizeof(e), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"jni_probe\",\"ok\":false,\"error\":\"no JavaVM\"}\n", idj);
        send_line(fd, e); return;
    }
    jint sdk = -1; char rel[64] = "";
    jclass ver = (*env)->FindClass(env, "android/os/Build$VERSION");
    if (ver) {
        jfieldID fi = (*env)->GetStaticFieldID(env, ver, "SDK_INT", "I");
        if (fi) sdk = (*env)->GetStaticIntField(env, ver, fi);
        jfieldID rf = (*env)->GetStaticFieldID(env, ver, "RELEASE", "Ljava/lang/String;");
        if (rf) {
            jstring js = (jstring)(*env)->GetStaticObjectField(env, ver, rf);
            if (js) {
                const char *s = (*env)->GetStringUTFChars(env, js, NULL);
                if (s) { strncpy(rel, s, sizeof(rel) - 1); (*env)->ReleaseStringUTFChars(env, js, s); }
                (*env)->DeleteLocalRef(env, js);
            }
        }
        (*env)->DeleteLocalRef(env, ver);
    }
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    detach_env(did);

    char out[256], relj[128]; json_escape(rel, relj, sizeof(relj));
    snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"jni_probe\",\"ok\":true,\"sdk_int\":%d,\"release\":\"%s\",\"attached\":%d}\n",
        idj, sdk, relj, did);
    send_line(fd, out);
    LOGI("jni_probe: sdk=%d release=%s", sdk, rel);
}

// Android tags heap pointers in the top byte (TBI). The CPU ignores it on deref,
// but pread(/proc/self/mem) treats the address literally — strip the tag first.
#define UNTAG(x) ((unsigned long long)(x) & 0x00FFFFFFFFFFFFFFULL)

// Read n bytes at addr from /proc/self/mem into buf; returns bytes read (0 on fault).
static ssize_t safe_read_at(int memfd, unsigned long long addr, void *buf, size_t n) {
    addr = UNTAG(addr);
    if (addr < 0x1000) return 0;
    ssize_t r = pread(memfd, buf, n, (off_t)addr);
    return r > 0 ? r : 0;
}

// Given an art::DexFile* candidate, scavenge its first words for the member that
// points to dex/cdex magic (begin_), then read file_size from the dex header.
// Version-robust: no hardcoded struct offsets. Returns 1 on success.
static int resolve_dexfile(int memfd, unsigned long long dexfile_ptr,
                           unsigned long long *begin_out, unsigned int *size_out, const char **magic_out) {
    unsigned long long words[24];
    ssize_t got = safe_read_at(memfd, dexfile_ptr, words, sizeof(words));
    int nwords = (int)(got / 8);
    for (int i = 0; i < nwords; i++) {
        unsigned long long b = words[i];
        unsigned char hdr[40];
        if (safe_read_at(memfd, b, hdr, sizeof(hdr)) < 40) continue;
        const char *magic = NULL;
        if (hdr[0] == 'd' && hdr[1] == 'e' && hdr[2] == 'x' && hdr[3] == '\n') magic = "dex";
        else if (hdr[0] == 'c' && hdr[1] == 'd' && hdr[2] == 'e' && hdr[3] == 'x') magic = "cdex";
        if (!magic) continue;
        unsigned int fsz = (unsigned int)hdr[32] | ((unsigned int)hdr[33] << 8) | ((unsigned int)hdr[34] << 16) | ((unsigned int)hdr[35] << 24);
        if (fsz < 0x70 || fsz > (200u << 20)) continue;   // sane dex size
        *begin_out = UNTAG(b); *size_out = fsz; *magic_out = magic;   // untagged so idhd can read it
        return 1;
    }
    return 0;
}

// Enumerate ART DexFiles structurally via ClassLoader cookies (no magic scan of RAM,
// no hardcoded ART offsets). Walks live threads' context loaders + parents.
static void cmd_art_dexfiles(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    int did = 0;
    JNIEnv *env = attach_env(&did);
    if (!env) { char e[160]; snprintf(e, sizeof(e), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"art_dexfiles\",\"ok\":false,\"error\":\"no JavaVM\"}\n", idj); send_line(fd, e); return; }
    (*env)->PushLocalFrame(env, 512);

    // classes + fields
    jclass cThread = (*env)->FindClass(env, "java/lang/Thread");
    jclass cMap = (*env)->FindClass(env, "java/util/Map");
    jclass cSet = (*env)->FindClass(env, "java/util/Set");
    jclass cIter = (*env)->FindClass(env, "java/util/Iterator");
    jclass cCL = (*env)->FindClass(env, "java/lang/ClassLoader");
    jclass cBDCL = (*env)->FindClass(env, "dalvik/system/BaseDexClassLoader");
    jclass cDPL = (*env)->FindClass(env, "dalvik/system/DexPathList");
    jclass cElem = (*env)->FindClass(env, "dalvik/system/DexPathList$Element");
    jclass cDexFile = (*env)->FindClass(env, "dalvik/system/DexFile");
    jclass cClass = (*env)->FindClass(env, "java/lang/Class");
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    jmethodID mGetAll = cThread ? (*env)->GetStaticMethodID(env, cThread, "getAllStackTraces", "()Ljava/util/Map;") : NULL;
    jmethodID mKeySet = cMap ? (*env)->GetMethodID(env, cMap, "keySet", "()Ljava/util/Set;") : NULL;
    jmethodID mIterator = cSet ? (*env)->GetMethodID(env, cSet, "iterator", "()Ljava/util/Iterator;") : NULL;
    jmethodID mHasNext = cIter ? (*env)->GetMethodID(env, cIter, "hasNext", "()Z") : NULL;
    jmethodID mNext = cIter ? (*env)->GetMethodID(env, cIter, "next", "()Ljava/lang/Object;") : NULL;
    jmethodID mGetCtx = cThread ? (*env)->GetMethodID(env, cThread, "getContextClassLoader", "()Ljava/lang/ClassLoader;") : NULL;
    jmethodID mGetParent = cCL ? (*env)->GetMethodID(env, cCL, "getParent", "()Ljava/lang/ClassLoader;") : NULL;
    jmethodID mGetName = cClass ? (*env)->GetMethodID(env, cClass, "getName", "()Ljava/lang/String;") : NULL;
    jfieldID fPathList = cBDCL ? (*env)->GetFieldID(env, cBDCL, "pathList", "Ldalvik/system/DexPathList;") : NULL;
    jfieldID fDexElements = cDPL ? (*env)->GetFieldID(env, cDPL, "dexElements", "[Ldalvik/system/DexPathList$Element;") : NULL;
    jfieldID fDexFileFld = cElem ? (*env)->GetFieldID(env, cElem, "dexFile", "Ldalvik/system/DexFile;") : NULL;
    jfieldID fCookie = cDexFile ? (*env)->GetFieldID(env, cDexFile, "mCookie", "Ljava/lang/Object;") : NULL;
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    int memfd = open("/proc/self/mem", O_RDONLY);
    size_t cap = 1 << 14, len = 0; char *recs = (char *)malloc(cap); if (recs) recs[0] = 0;
    int nrec = 0, nloaders = 0;
    unsigned long long seen[512]; int nseen = 0;

    if (mGetAll && mKeySet && mIterator && fPathList && fDexElements && fDexFileFld && fCookie && memfd >= 0 && recs) {
        jobject map = (*env)->CallStaticObjectMethod(env, cThread, mGetAll);
        jobject set = map ? (*env)->CallObjectMethod(env, map, mKeySet) : NULL;
        jobject it = set ? (*env)->CallObjectMethod(env, set, mIterator) : NULL;
        while (it && (*env)->CallBooleanMethod(env, it, mHasNext)) {
            jobject th = (*env)->CallObjectMethod(env, it, mNext);
            jobject loader = th ? (*env)->CallObjectMethod(env, th, mGetCtx) : NULL;
            // walk loader + parent chain
            int depth = 0;
            while (loader && depth++ < 16) {
                if ((*env)->IsInstanceOf(env, loader, cBDCL)) {
                    nloaders++;
                    // loader class name
                    char lname[128] = "";
                    jobject lcls = (*env)->GetObjectClass(env, loader);
                    if (lcls && mGetName) { jstring nm = (jstring)(*env)->CallObjectMethod(env, lcls, mGetName);
                        if (nm) { const char *s = (*env)->GetStringUTFChars(env, nm, NULL); if (s) { strncpy(lname, s, sizeof(lname) - 1); (*env)->ReleaseStringUTFChars(env, nm, s); } } }
                    jobject pathList = (*env)->GetObjectField(env, loader, fPathList);
                    jobjectArray elems = pathList ? (jobjectArray)(*env)->GetObjectField(env, pathList, fDexElements) : NULL;
                    jsize ne = elems ? (*env)->GetArrayLength(env, elems) : 0;
                    jclass cLongArr = (*env)->FindClass(env, "[J");
                    for (jsize e = 0; e < ne; e++) {
                        jobject elem = (*env)->GetObjectArrayElement(env, elems, e);
                        jobject dexFile = elem ? (*env)->GetObjectField(env, elem, fDexFileFld) : NULL;
                        jobject cookie = dexFile ? (*env)->GetObjectField(env, dexFile, fCookie) : NULL;
                        if (cookie && (*env)->IsInstanceOf(env, cookie, cLongArr)) {
                            jlongArray arr = (jlongArray)cookie;
                            jsize cl = (*env)->GetArrayLength(env, arr);
                            jlong *vals = (*env)->GetLongArrayElements(env, arr, NULL);
                            for (jsize c = 0; c < cl && nrec < 256; c++) {
                                unsigned long long p = (unsigned long long)vals[c];
                                if (p < 0x10000) continue;
                                unsigned long long begin = 0; unsigned int sz = 0; const char *mg = NULL;
                                if (resolve_dexfile(memfd, p, &begin, &sz, &mg)) {
                                    int dup = 0; for (int k = 0; k < nseen; k++) if (seen[k] == begin) { dup = 1; break; }
                                    if (dup) continue;
                                    if (nseen < 512) seen[nseen++] = begin;
                                    char lj[160]; json_escape(lname, lj, sizeof(lj));
                                    char rec[420];
                                    int w = snprintf(rec, sizeof(rec), "%s{\"dexFilePtr\":\"%llx\",\"begin\":\"%llx\",\"size\":%u,\"magic\":\"%s\",\"loader\":\"%s\"}",
                                                     nrec ? "," : "", p, begin, sz, mg, lj);
                                    if (w > 0) { if (len + (size_t)w + 1 >= cap) { while (len + (size_t)w + 1 >= cap) cap *= 2; char *nb = realloc(recs, cap); if (nb) recs = nb; }
                                        memcpy(recs + len, rec, (size_t)w); len += (size_t)w; recs[len] = 0; nrec++; }
                                }
                            }
                            (*env)->ReleaseLongArrayElements(env, arr, vals, JNI_ABORT);
                        }
                        if (elem) (*env)->DeleteLocalRef(env, elem);
                        if (dexFile) (*env)->DeleteLocalRef(env, dexFile);
                        if (cookie) (*env)->DeleteLocalRef(env, cookie);
                    }
                }
                jobject parent = (*env)->CallObjectMethod(env, loader, mGetParent);
                (*env)->DeleteLocalRef(env, loader);
                loader = parent;
            }
            if (th) (*env)->DeleteLocalRef(env, th);
        }
    }
    if (memfd >= 0) close(memfd);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    (*env)->PopLocalFrame(env, NULL);
    detach_env(did);

    size_t hlen = (recs ? strlen(recs) : 0) + 200;
    char *out = (char *)malloc(hlen);
    if (out) { snprintf(out, hlen, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"art_dexfiles\",\"ok\":true,\"loaders\":%d,\"count\":%d,\"dexfiles\":[%s]}\n", idj, nloaders, nrec, recs ? recs : ""); send_line(fd, out); free(out); }
    free(recs);
    LOGI("art_dexfiles: loaders=%d dexfiles=%d", nloaders, nrec);
}

static void cmd_maps(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    int total = 0;
    char *regions = build_maps_json(0, &total);
    if (!regions) {
        char err[160];
        snprintf(err, sizeof(err), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"maps\",\"ok\":false,\"error\":\"read maps\"}\n", idj);
        send_line(fd, err); return;
    }
    size_t hlen = strlen(regions) + 200;
    char *out = (char *)malloc(hlen);
    if (out) {
        snprintf(out, hlen,
            "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"maps\",\"ok\":true,\"count\":%d,\"regions\":[%s]}\n",
            idj, total, regions);
        send_line(fd, out);
        free(out);
    }
    free(regions);
}

// ---- report + command loop ------------------------------------------------

static void report(int fd) {
    char cmd[256]; read_cmdline(cmd, sizeof(cmd));
    char pkg[512]; json_escape(cmd, pkg, sizeof(pkg));
    char rel[PROP_VALUE_MAX]; prop("ro.build.version.release", rel, sizeof(rel));
    char sdk[PROP_VALUE_MAX]; prop("ro.build.version.sdk", sdk, sizeof(sdk));
    char abi[PROP_VALUE_MAX]; prop("ro.product.cpu.abi", abi, sizeof(abi));

    char hello[1200];
    snprintf(hello, sizeof(hello),
        "{\"t\":\"hello\",\"agentVer\":\"%s\",\"pid\":%d,\"uid\":%d,"
        "\"package\":\"%s\",\"process\":\"%s\",\"abi\":\"%s\",\"android\":\"%s\",\"sdk\":%s,\"entry\":\"%s\"}\n",
        AGENT_VER, getpid(), getuid(), pkg, pkg,
        abi[0] ? abi : "arm64-v8a", rel[0] ? rel : "?", sdk[0] ? sdk : "0", g_entry);
    if (send_line(fd, hello) != 0) { LOGE("send hello failed"); return; }

    int total = 0;
    char *sample = build_maps_json(40, &total);
    if (sample) {
        size_t hlen = strlen(sample) + 128;
        char *msg = (char *)malloc(hlen);
        if (msg) {
            snprintf(msg, hlen, "{\"t\":\"maps\",\"count\":%d,\"regions\":[%s]}\n", total, sample);
            send_line(fd, msg);
            free(msg);
        }
        free(sample);
    }
    LOGI("reported: pkg=%s pid=%d maps=%d entry=%s", cmd, getpid(), total, g_entry);
}

// Read newline-delimited commands from idhd and dispatch.
static void command_loop(int fd) {
    char buf[8192];
    size_t len = 0;
    for (;;) {
        ssize_t r = read(fd, buf + len, sizeof(buf) - len - 1);
        if (r <= 0) break;
        len += (size_t)r;
        buf[len] = 0;
        char *nl;
        while ((nl = memchr(buf, '\n', len)) != NULL) {
            *nl = 0;
            char *line = buf;
            size_t linelen = (size_t)(nl - buf);
            if (strstr(line, "\"t\":\"cmd\"")) {
                char id[64] = "", op[32] = "";
                json_get_str(line, "id", id, sizeof(id));
                json_get_str(line, "op", op, sizeof(op));
                if (strcmp(op, "maps") == 0) {
                    cmd_maps(fd, id);
                } else if (strcmp(op, "read") == 0) {
                    char addr[40] = ""; json_get_str(line, "addr", addr, sizeof(addr));
                    long long size = json_get_num(line, "size");
                    cmd_read(fd, id, addr, size);
                } else if (strcmp(op, "jni_probe") == 0) {
                    cmd_jni_probe(fd, id);
                } else if (strcmp(op, "gothook_selftest") == 0) {
                    cmd_gothook_selftest(fd, id);
                } else if (strcmp(op, "crypto_probe") == 0) {
                    cmd_crypto_probe(fd, id);
                } else if (strcmp(op, "crypto_hook_test") == 0) {
                    cmd_crypto_hook_test(fd, id);
                } else if (strcmp(op, "detect_watch") == 0) {
                    cmd_detect_watch(fd, id);
                } else if (strcmp(op, "compat_probe") == 0) {
                    cmd_compat_probe(fd, id);
                } else if (strcmp(op, "object_inspect") == 0) {
                    char cls[160] = "", fld[64] = "";
                    json_get_str(line, "className", cls, sizeof(cls));
                    json_get_str(line, "field", fld, sizeof(fld));
                    cmd_object_inspect(fd, id, cls, fld);
                } else if (strcmp(op, "object_invoke") == 0) {
                    char cls[160] = "", fld[64] = "", mth[64] = "";
                    json_get_str(line, "className", cls, sizeof(cls));
                    json_get_str(line, "field", fld, sizeof(fld));
                    json_get_str(line, "method", mth, sizeof(mth));
                    cmd_object_invoke(fd, id, cls, fld, mth);
                } else if (strcmp(op, "art_dexfiles") == 0) {
                    cmd_art_dexfiles(fd, id);
                } else if (strcmp(op, "scan_magic") == 0) {
                    cmd_scan_magic(fd, id);
                } else if (strcmp(op, "search") == 0) {
                    char pat[520] = ""; json_get_str(line, "pat", pat, sizeof(pat));
                    long long lim = json_get_num(line, "limit");
                    cmd_search(fd, id, pat, (int)lim);
                } else if (strcmp(op, "ping") == 0) {
                    char idj[64]; json_escape(id, idj, sizeof(idj));
                    char pong[128];
                    snprintf(pong, sizeof(pong), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"ping\",\"ok\":true}\n", idj);
                    send_line(fd, pong);
                }
            }
            size_t consumed = linelen + 1;
            memmove(buf, buf + consumed, len - consumed);
            len -= consumed;
            buf[len] = 0;
        }
        if (len >= sizeof(buf) - 1) len = 0;  // overflow guard: drop partial giant line
    }
}

static void *agent_thread(void *arg) {
    (void)arg;
    for (int attempt = 0; attempt < 30; attempt++) {
        int fd = connect_idhd();
        if (fd >= 0) {
            LOGI("connected to idhd %s:%d", IDH_HOST, IDH_PORT);
            report(fd);
            command_loop(fd);
            close(fd);
            LOGI("idhd connection closed");
            return NULL;
        }
        usleep(500 * 1000);
    }
    LOGE("could not reach idhd after retries (need: adb reverse tcp:%d tcp:%d)", IDH_PORT, IDH_PORT);
    return NULL;
}

static void do_start(void) {
    pthread_t t;
    if (pthread_create(&t, NULL, agent_thread, NULL) == 0) pthread_detach(t);
    else LOGE("pthread_create failed");
}

__attribute__((visibility("default")))
void idh_agent_start(void) {
    strncpy(g_entry, "start", sizeof(g_entry) - 1);
    pthread_once(&g_once, do_start);
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    g_vm = vm;
    strncpy(g_entry, "jni_onload", sizeof(g_entry) - 1);
    LOGI("JNI_OnLoad — agent " AGENT_VER " starting");
    pthread_once(&g_once, do_start);
    return JNI_VERSION_1_6;
}
