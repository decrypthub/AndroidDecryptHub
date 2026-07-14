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
#include <stdarg.h>
#include <time.h>
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

// forward decl: defined later, used by several commands
static jclass load_app_class(JNIEnv *env, const char *dotname);
// QBDI instruction trace (src/trace/qbdi_trace.c) — loads libQBDI.so at runtime.
extern int idh_qbdi_trace(void *func, char *out, int outsz);

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

// ---- wire framing (v2.0, WS-D) --------------------------------------------
// Every message is [u32 len BE][u8 type][payload of len bytes]. Replaces the old
// NDJSON + 8192-byte single-line reader. Control/events/cmd/cmdResult all ride as
// FRAME_JSON (payload = one JSON object). Binary/bulk types are reserved for later
// (WS-C capture batch, chunked dump). One send lock so a future drain thread and the
// command-response path never interleave bytes on the same fd.
#define FRAME_JSON     0x01
#define FRAME_CAPTURE  0x02          // reserved (WS-C)
#define FRAME_MAX_IN   (16u << 20)   // inbound (command) payload cap — fail-loud beyond
static pthread_mutex_t g_send_lock = PTHREAD_MUTEX_INITIALIZER;

static int send_frame(int fd, unsigned char type, const char *payload, size_t len) {
    unsigned char hdr[5];
    hdr[0] = (unsigned char)(len >> 24); hdr[1] = (unsigned char)(len >> 16);
    hdr[2] = (unsigned char)(len >> 8);  hdr[3] = (unsigned char)(len & 0xff);
    hdr[4] = type;
    pthread_mutex_lock(&g_send_lock);
    int rc = send_all(fd, (const char *)hdr, 5);
    if (rc == 0 && len) rc = send_all(fd, payload, len);
    pthread_mutex_unlock(&g_send_lock);
    return rc;
}
// Unchanged call sites: callers still pass a NUL-terminated JSON string (some end in
// '\n' — harmless inside a framed payload, the daemon's JSON.parse ignores it).
static int send_line(int fd, const char *s) { return send_frame(fd, FRAME_JSON, s, strlen(s)); }

// Read exactly n bytes into buf; 0 = ok, -1 = EOF/error.
static int read_full(int fd, unsigned char *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, buf + off, n - off);
        if (r <= 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

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

// Parse a maps perms string ("r--p"/"rw-p") into an mprotect flag set.
static int perms_to_prot(const char *perms) {
    int prot = 0;
    if (perms[0] == 'r') prot |= PROT_READ;
    if (perms[1] == 'w') prot |= PROT_WRITE;
    if (perms[2] == 'x') prot |= PROT_EXEC;
    return prot;
}

// Swap one slot: temporarily make its page writable, publish the new pointer with a
// full barrier, then RESTORE the page's original protection. RELRO (r--) is put back
// read-only so we neither weaken the linker's RELRO hardening nor leave a rw-flipped
// page that an integrity self-check could flag. Returns 1 on success, 0 if not writable.
static int got_write_slot(void **slot, void *newval, int orig_prot, long pagesz) {
    void *page = (void *)((unsigned long long)slot & ~((unsigned long long)pagesz - 1));
    if (mprotect(page, pagesz, PROT_READ | PROT_WRITE) != 0) return 0;
    *slot = newval;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);   // publish before restoring protection
    mprotect(page, pagesz, orig_prot);         // RELRO r-- goes back to r--
    return 1;
}

// Debug/verification: last successfully-hooked slot + its original maps perms, so a
// self-test can confirm the page protection was restored (RELRO r-- stays r--).
static unsigned long long g_dbg_slot = 0;
static char g_dbg_orig_perms[8] = "";

// Read the maps perms string ("r--p") of the mapping containing `addr`. "?" if unmapped.
static void perms_of_addr(unsigned long long addr, char *out, int outsz) {
    snprintf(out, outsz, "?");
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return;
    char line[512];
    while (fgets(line, sizeof(line), m)) {
        char sa[32], ea[32], perms[8];
        if (sscanf(line, "%31[0-9a-f]-%31[0-9a-f] %7s", sa, ea, perms) < 3) continue;
        unsigned long long s = strtoull(sa, NULL, 16), e = strtoull(ea, NULL, 16);
        if (addr >= s && addr < e) { snprintf(out, outsz, "%s", perms); break; }
    }
    fclose(m);
}

// ---- relocation-slot cross-verification (v2.x audit P1) --------------------
// got_replace used to patch ANY readable non-exec word equal to `orig`. On a large obfuscated
// .so a coincidental data word == the function address would be clobbered into a wrapper ->
// memory corruption / crash. These helpers enumerate the module's REAL GOT/PLT relocation
// slots (.rela.plt + .rela.dyn) so we only ever patch genuine relocation entries.
#define RSET_MAX 262144   // per-module reloc-slot cap (~2 MiB transient); truncation -> fallback

static unsigned long long module_base_of(const char *basename) {
    unsigned long long base = 0;
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return 0;
    char line[512];
    while (fgets(line, sizeof(line), m)) {
        char sa[32], ea[32], perms[8], off[32], dev[16], path[400] = "";
        unsigned long long inode = 0;
        if (sscanf(line, "%31[0-9a-f]-%31[0-9a-f] %7s %31s %15s %llu %399[^\n]", sa, ea, perms, off, dev, &inode, path) < 6) continue;
        char *pp = path; while (*pp == ' ') pp++;
        const char *bn = strrchr(pp, '/'); bn = bn ? bn + 1 : pp;
        if (strcmp(bn, basename) != 0) continue;
        if (strcmp(off, "0") && strcmp(off, "00000000")) continue;   // mapping at file offset 0
        unsigned long long s = strtoull(sa, NULL, 16);
        if (base == 0 || s < base) base = s;
    }
    fclose(m);
    return base;
}

// Fill out[] with absolute reloc-slot addresses of the module based at `base`. Returns count,
// -1 if ELF/dynamic unparsable, or RSET_MAX on truncation (caller treats as untrusted).
// Elf64_Rela = { r_offset(8), r_info(8), r_addend(8) } = 24 bytes.
static int reloc_slots(unsigned long long base, unsigned long long *out, int max) {
    if (!base) return -1;
    unsigned char *p = (unsigned char *)base;
    if (memcmp(p, "\x7f""ELF", 4) != 0) return -1;
    unsigned long long phoff = *(unsigned long long *)(p + 32);
    unsigned short phentsize = *(unsigned short *)(p + 54);
    unsigned short phnum = *(unsigned short *)(p + 56);
    unsigned long long dyn_vaddr = 0;
    for (int i = 0; i < phnum; i++) {
        unsigned char *ph = p + phoff + (unsigned long long)i * phentsize;
        if (*(unsigned int *)ph == 2) { dyn_vaddr = *(unsigned long long *)(ph + 16); break; }  // PT_DYNAMIC
    }
    if (!dyn_vaddr) return -1;
    unsigned long long jmprel = 0, pltrelsz = 0, rela = 0, relasz = 0, relaent = 24;
    unsigned long long *d = (unsigned long long *)(base + dyn_vaddr);
    for (; d[0] != 0; d += 2) {                 // Elf64_Dyn: {d_tag, d_val}
        if (d[0] == 23) jmprel = d[1];          // DT_JMPREL   (.rela.plt)
        else if (d[0] == 2)  pltrelsz = d[1];   // DT_PLTRELSZ
        else if (d[0] == 7)  rela = d[1];       // DT_RELA     (.rela.dyn)
        else if (d[0] == 8)  relasz = d[1];     // DT_RELASZ
        else if (d[0] == 9)  relaent = d[1];    // DT_RELAENT
    }
    if (relaent == 0) relaent = 24;
    int n = 0;
    unsigned long long regions[2][2] = { { jmprel, pltrelsz }, { rela, relasz } };
    for (int r = 0; r < 2; r++) {
        unsigned long long off = regions[r][0], sz = regions[r][1];
        if (!off || !sz) continue;
        if (off < base) off += base;                 // link-time vaddr -> runtime
        for (unsigned long long e = off; e + relaent <= off + sz; e += relaent) {
            if (n >= max) return RSET_MAX;           // truncated -> untrusted
            unsigned long long r_offset = *(unsigned long long *)e;
            out[n++] = r_offset < base ? base + r_offset : r_offset;
        }
    }
    return n;
}

static int slot_in_set(unsigned long long a, const unsigned long long *set, int n) {
    for (int i = 0; i < n; i++) if (set[i] == a) return 1;
    return 0;
}

// Hook the real slot in EVERY matching caller module (not just the first). Exactly one
// slot PER module (lowest-address RELRO/.got.plt slot) — hooking duplicate copies in a
// module's other data segments would corrupt that module's own call path and deadlock
// the trampoline. Returns total slots replaced. Generalizes over multiple callers; for
// a filter that matches a single module it reduces to hooking that one slot.
static int got_replace(const char *module_substr, void *orig, void *wrapper) {
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return -1;
    char line[512];
    int replaced = 0;
    long pagesz = sysconf(_SC_PAGESIZE);
    char cur_mod[400] = "";
    int hooked_this_mod = 0;
    unsigned long long *rset = NULL; int nrset = -1;   // cur_mod reloc slots (-1 = unavailable)
    while (fgets(line, sizeof(line), m)) {
        char sa[32], ea[32], perms[8], off[32], dev[16], path[400] = "";
        unsigned long long inode = 0;
        int nf = sscanf(line, "%31[0-9a-f]-%31[0-9a-f] %7s %31s %15s %llu %399[^\n]", sa, ea, perms, off, dev, &inode, path);
        if (nf < 6 || perms[0] != 'r') continue;
        char *pp = path; while (*pp == ' ') pp++;
        if (!strstr(pp, module_substr)) continue;
        if (strcmp(pp, cur_mod) != 0) {
            snprintf(cur_mod, sizeof(cur_mod), "%s", pp); hooked_this_mod = 0;
            // (re)compute this module's real relocation slots, so we never clobber a
            // coincidental data word == orig. If unparsable/truncated, fall back (logged).
            free(rset); rset = NULL; nrset = -1;
            const char *bn = strrchr(cur_mod, '/'); bn = bn ? bn + 1 : cur_mod;
            unsigned long long mb = module_base_of(bn);
            if (mb) {
                rset = (unsigned long long *)malloc(sizeof(unsigned long long) * RSET_MAX);
                if (rset) {
                    nrset = reloc_slots(mb, rset, RSET_MAX);
                    if (nrset < 0 || nrset >= RSET_MAX) { free(rset); rset = NULL; nrset = -1; }
                }
            }
            if (nrset < 0) LOGI("got_replace: reloc validation unavailable for %s — value-match fallback", bn);
        }
        if (hooked_this_mod) continue;                    // one slot per module already done
        if (strstr(perms, "x")) continue;
        int orig_prot = perms_to_prot(perms);
        unsigned long long start = strtoull(sa, NULL, 16), end = strtoull(ea, NULL, 16);
        if (end <= start) continue;
        for (unsigned long long a = start; a + sizeof(void *) <= end && !hooked_this_mod; a += sizeof(void *)) {
            void **slot = (void **)a;
            if (*slot != orig) continue;
            // cross-verify this is a genuine relocation slot (skip coincidental data words).
            // When reloc parsing was unavailable (nrset<0) we accept the value match as before.
            if (nrset >= 0 && !slot_in_set(a, rset, nrset)) continue;
            if (got_write_slot(slot, wrapper, orig_prot, pagesz)) {
                replaced++; hooked_this_mod = 1;
                g_dbg_slot = a; snprintf(g_dbg_orig_perms, sizeof(g_dbg_orig_perms), "%s", perms);
            }
        }
    }
    free(rset);
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
    g_dbg_slot = 0; g_dbg_orig_perms[0] = 0;
    int replaced = orig ? got_replace("libidh_agent.so", orig, (void *)my_close) : -1;
    // While still hooked: read the hooked slot's page perms. got_write_slot restores the
    // page's original protection after publishing, so RELRO (r--) must read back r-- —
    // proving we don't leave the page rw-flipped (weakened RELRO / integrity-check bait).
    char slotPerms[8] = "?"; if (g_dbg_slot) perms_of_addr(g_dbg_slot, slotPerms, sizeof(slotPerms));
    int restored = (g_dbg_orig_perms[0] && strncmp(slotPerms, g_dbg_orig_perms, 3) == 0) ? 1 : 0;
    int before = g_close_hits;
    // trigger a controlled close() from agent code -> routes through the hooked GOT slot
    int tfd = open("/proc/self/stat", O_RDONLY);
    if (tfd >= 0) close(tfd);
    int after = g_close_hits;
    if (replaced > 0 && orig) got_replace("libidh_agent.so", (void *)my_close, orig);  // restore
    char out[320];
    snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"gothook_selftest\",\"ok\":true,\"replaced\":%d,\"hitsBefore\":%d,\"hitsAfter\":%d,\"fired\":%s,\"origPerms\":\"%s\",\"slotPerms\":\"%s\",\"protRestored\":%s}\n",
        idj, replaced, before, after, (after > before) ? "true" : "false", g_dbg_orig_perms, slotPerms, restored ? "true" : "false");
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
    unsigned long long symtab = 0, strtab = 0, hash = 0, gnuhash = 0;
    unsigned long long *d = (unsigned long long *)(base + dyn_vaddr);
    for (; d[0] != 0; d += 2) {                // Elf64_Dyn: {d_tag, d_val}
        if (d[0] == 6) symtab = d[1];          // DT_SYMTAB
        else if (d[0] == 5) strtab = d[1];     // DT_STRTAB
        else if (d[0] == 4) hash = d[1];       // DT_HASH
        else if (d[0] == 0x6ffffef5ULL) gnuhash = d[1]; // DT_GNU_HASH
    }
    if (!symtab || !strtab) return NULL;
    if (symtab < base) symtab += base;         // link-time vaddr -> runtime
    if (strtab < base) strtab += base;
    if (hash && hash < base) hash += base;
    if (gnuhash && gnuhash < base) gnuhash += base;

    // Dynsym count, preferred sources in order of rigor:
    //  1) DT_HASH: nchain (= number of dynsym entries) is the 2nd word.
    //  2) DT_GNU_HASH: walk the last bucket's chain until the terminator bit.
    //  3) fallback: (strtab - symtab)/sizeof(Elf64_Sym) — assumes .dynstr abuts .dynsym.
    long count = 0;
    if (hash) {
        count = (long)((unsigned int *)hash)[1];         // nchain
    } else if (gnuhash) {
        unsigned int *gh = (unsigned int *)gnuhash;
        unsigned int nbuckets = gh[0], symoffset = gh[1], bloom_size = gh[2];
        unsigned long long *bloom = (unsigned long long *)&gh[4];   // ELF64: 8-byte bloom words
        unsigned int *buckets = (unsigned int *)&bloom[bloom_size];
        unsigned int *chain = &buckets[nbuckets];
        unsigned int last = 0;
        for (unsigned int i = 0; i < nbuckets; i++) if (buckets[i] > last) last = buckets[i];
        if (last < symoffset) count = symoffset;
        else { while (!(chain[last - symoffset] & 1)) last++; count = (long)last + 1; }
    } else {
        if (strtab <= symtab) return NULL;
        count = (long)((strtab - symtab) / 24);
    }
    if (count <= 0 || count > 300000) {
        if (strtab <= symtab) return NULL;               // last-resort sanity fallback
        count = (long)((strtab - symtab) / 24);
        if (count <= 0 || count > 300000) return NULL;
    }
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
// v2.0 WS-C: bounded ring buffer with HONEST accounting. The old fixed g_caps[64] silently
// dropped everything past 64 records — forensic completeness collapsed under load. The
// producer path (capture(), on the target's own crypto/TLS thread) is NON-BLOCKING: it never
// sleeps and never waits on the lock (pthread_mutex_trylock) — a full ring or a busy lock
// just increments g_cap_dropped. Nothing vanishes silently: g_cap_seq counts every capture()
// attempt (atomic), so the invariant
//   g_cap_seq == (records ever drained) + (records still in ring) + g_cap_dropped
// always holds, and idhd surfaces dropped>0 as complete:false.
#define CAP_BYTES 2048
#define CAP_RING  1024          // ~2 MiB; bounded agent memory (architecture red line)
struct CapRec { char func[24]; int inl; int n; int tid; long long ts_ns; unsigned char data[CAP_BYTES]; };
static struct CapRec g_ring[CAP_RING];
static int g_ring_head = 0, g_ring_tail = 0, g_ring_count = 0;   // ring: head=write, tail=read (under g_cap_lock)
static unsigned long long g_cap_seq = 0;       // total capture() attempts — ATOMIC (read/written off-lock)
static unsigned long long g_cap_dropped = 0;   // total dropped (ring full or lock busy) — ATOMIC
static long long g_cap_first_drop_ns = 0, g_cap_last_drop_ns = 0;   // best-effort diagnostic ts
static pthread_mutex_t g_cap_lock = PTHREAD_MUTEX_INITIALIZER;
static long long now_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}
static void capture(const char *func, const unsigned char *in, int inl) {
    if (inl <= 0 || !in) return;
    // Runs on the target's own crypto/TLS thread — must NEVER block or sleep here (any
    // injected latency is an ANR risk and a timing-based anti-debug surface). Count every
    // attempt atomically, then TRY the lock without waiting: if a drain or another producer
    // holds it, account a drop and return immediately instead of stalling the target.
    __atomic_add_fetch(&g_cap_seq, 1, __ATOMIC_RELAXED);
    long long ts = now_ns();
    if (pthread_mutex_trylock(&g_cap_lock) != 0) {
        __atomic_add_fetch(&g_cap_dropped, 1, __ATOMIC_RELAXED);
        if (!g_cap_first_drop_ns) g_cap_first_drop_ns = ts;   // best-effort diagnostic ts
        g_cap_last_drop_ns = ts;
        return;
    }
    if (g_ring_count < CAP_RING) {
        struct CapRec *r = &g_ring[g_ring_head];
        strncpy(r->func, func, sizeof(r->func) - 1); r->func[sizeof(r->func)-1]=0;
        r->inl = inl; r->n = inl < CAP_BYTES ? inl : CAP_BYTES;
        r->tid = (int)gettid(); r->ts_ns = ts;
        memcpy(r->data, in, r->n);
        g_ring_head = (g_ring_head + 1) % CAP_RING;
        g_ring_count++;
    } else {
        __atomic_add_fetch(&g_cap_dropped, 1, __ATOMIC_RELAXED);
        if (!g_cap_first_drop_ns) g_cap_first_drop_ns = ts;
        g_cap_last_drop_ns = ts;
    }
    pthread_mutex_unlock(&g_cap_lock);
}

// Empty the ring (used by the one-shot probes in place of the old `g_ncaps = 0`). Does not
// touch cumulative seq/dropped — those are session lifetime stats.
static void cap_reset(void) {
    pthread_mutex_lock(&g_cap_lock);
    g_ring_head = g_ring_tail = g_ring_count = 0;
    pthread_mutex_unlock(&g_cap_lock);
}
// Emit one record as a JSON object into (out,len,cap); returns new len. Underflow-safe
// (cap>len?cap-len:0 guards snprintf's would-be-length return that the old loops mishandled).
static size_t emit_caprec(char *out, size_t len, size_t cap, const struct CapRec *r, int first) {
    len += snprintf(out + len, cap > len ? cap - len : 0,
        "%s{\"func\":\"%s\",\"inl\":%d,\"tid\":%d,\"tsNs\":%lld,\"hex\":\"", first ? "" : ",", r->func, r->inl, r->tid, r->ts_ns);
    for (int b = 0; b < r->n && len + 3 < cap; b++) len += snprintf(out + len, cap > len ? cap - len : 0, "%02x", r->data[b]);
    len += snprintf(out + len, cap > len ? cap - len : 0, "\"}");
    return len;
}
// Serialize (without popping) every record currently in the ring, tail→head. Used by the
// one-shot probes, which reset → trigger → serialize, producing far fewer than CAP_RING.
// Returns count emitted; *lenp updated. Caller holds no lock (we take it).
static int cap_emit_all(char *out, size_t *lenp, size_t cap) {
    pthread_mutex_lock(&g_cap_lock);
    int n = 0;
    for (int i = 0; i < g_ring_count; i++) {
        struct CapRec *r = &g_ring[(g_ring_tail + i) % CAP_RING];
        *lenp = emit_caprec(out, *lenp, cap, r, n == 0);
        n++;
    }
    pthread_mutex_unlock(&g_cap_lock);
    return n;
}

typedef int (*EVP_CipherUpdate_t)(void *, unsigned char *, int *, const unsigned char *, int);
static EVP_CipherUpdate_t g_evp_cipher_orig = NULL;
static int my_EVP_CipherUpdate(void *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl) {
    capture("EVP_CipherUpdate", in, inl);
    return g_evp_cipher_orig(ctx, out, outl, in, inl);
}

// Digest (MD5/SHA-1/SHA-256/SHA-512 via MessageDigest) and HMAC (via Mac) both route
// through BoringSSL update functions with the same (ctx, data, len) shape — the message
// being hashed/authenticated is the forensic payload.
typedef int (*update3_t)(void *, const void *, size_t);
static update3_t g_orig_evp_digest = NULL, g_orig_hmac = NULL, g_orig_digest_sign = NULL;
static int my_EVP_DigestUpdate(void *ctx, const void *data, size_t len) {
    capture("EVP_DigestUpdate", (const unsigned char *)data, (int)len);
    return g_orig_evp_digest(ctx, data, len);
}
static int my_HMAC_Update(void *ctx, const void *data, size_t len) {
    capture("HMAC_Update", (const unsigned char *)data, (int)len);
    return g_orig_hmac(ctx, data, len);
}
static int my_EVP_DigestSignUpdate(void *ctx, const void *data, size_t len) {
    capture("EVP_DigestSignUpdate", (const unsigned char *)data, (int)len);
    return g_orig_digest_sign(ctx, data, len);
}

// Recon: for each EVP/HMAC function, report which loaded modules' GOT holds its
// pointer (candidate hook sites) and how many slots. Guides where to install hooks.
static void cmd_crypto_probe(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    const char *names[] = { "EVP_CipherUpdate", "EVP_EncryptUpdate", "EVP_DecryptUpdate", "EVP_DigestUpdate", "HMAC_Update", "SSL_read", "SSL_write" };
    const int NF = 7;
    void *addrs[7];
    for (int i = 0; i < 5; i++) addrs[i] = resolve_sym("libcrypto.so", names[i]);
    addrs[5] = resolve_sym("libssl.so", "SSL_read");
    addrs[6] = resolve_sym("libssl.so", "SSL_write");

    // aggregate per-module match counts
    struct Mod { char name[128]; int cnt[7]; };
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
        int hit[7] = {0,0,0,0,0,0,0}, any = 0;
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

// ---- network TLS-plaintext capture (SSL_read/SSL_write in libjavacrypto/Conscrypt) ----
typedef int (*SSL_rw_t)(void *, void *, int);
static SSL_rw_t g_orig_ssl_write = NULL, g_orig_ssl_read = NULL;
static int my_SSL_write(void *ssl, void *buf, int num) {
    if (num > 0) capture("SSL_write", (const unsigned char *)buf, num);   // outgoing plaintext
    return g_orig_ssl_write(ssl, buf, num);
}
static int my_SSL_read(void *ssl, void *buf, int num) {
    int ret = g_orig_ssl_read(ssl, buf, num);
    if (ret > 0) capture("SSL_read", (const unsigned char *)buf, ret);    // incoming plaintext
    return ret;
}

// Hook SSL_write/SSL_read in Conscrypt, trigger an HTTPS request via JNI reflection,
// and report the captured TLS plaintext (request + response).
static void cmd_net_hook_test(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    void *ow = resolve_sym("libssl.so", "SSL_write");
    void *orr = resolve_sym("libssl.so", "SSL_read");
    g_orig_ssl_write = (SSL_rw_t)ow; g_orig_ssl_read = (SSL_rw_t)orr;
    int rw = ow ? got_replace("libjavacrypto.so", ow, (void *)my_SSL_write) : -1;
    int rr = orr ? got_replace("libjavacrypto.so", orr, (void *)my_SSL_read) : -1;
    cap_reset();

    int did = 0, triggered = 0; char result[128] = "";
    JNIEnv *env = attach_env(&did);
    if (env) {
        (*env)->PushLocalFrame(env, 32);
        jclass jc = load_app_class(env, "com.idh.sandbox.Network");
        if (jc) {
            jmethodID run = (*env)->GetStaticMethodID(env, jc, "run", "()Ljava/lang/String;");
            if (run) {
                jstring rs = (jstring)(*env)->CallStaticObjectMethod(env, jc, run);
                triggered = 1;
                if (rs) { const char *s = (*env)->GetStringUTFChars(env, rs, NULL); if (s) { strncpy(result, s, sizeof(result)-1); (*env)->ReleaseStringUTFChars(env, rs, s); } }
            }
        }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->PopLocalFrame(env, NULL);
        detach_env(did);
    }
    if (rw > 0) got_replace("libjavacrypto.so", (void *)my_SSL_write, ow);
    if (rr > 0) got_replace("libjavacrypto.so", (void *)my_SSL_read, orr);

    size_t cap = 1 << 16, len = 0; char *out = malloc(cap); if (!out) return;
    char rj[200]; json_escape(result, rj, sizeof(rj));
    len += snprintf(out + len, cap - len, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"net_hook_test\",\"ok\":true,\"hooked\":{\"write\":%d,\"read\":%d},\"triggered\":%s,\"result\":\"%s\",\"captures\":[", idj, rw, rr, triggered ? "true" : "false", rj);
    int n = cap_emit_all(out, &len, cap);
    snprintf(out + len, cap - len, "],\"count\":%d}\n", n);
    send_line(fd, out);
    free(out);
    LOGI("net_hook_test: hooked w=%d r=%d triggered=%d result=%s captures=%d", rw, rr, triggered, result, n);
}

// ---- file I/O capture (open/openat/read/write/close via a caller module's GOT) ----
// Which module's GOT actually holds these libc pointers for Java FileInputStream/
// FileOutputStream varies by ART/API level (libopenjdk.so on modern Android) — use
// cmd_file_probe to discover it empirically rather than hardcoding a guess.
typedef int (*open_t)(const char *, int, mode_t);
typedef int (*openat_t)(int, const char *, int, mode_t);
typedef ssize_t (*rw_t)(int, void *, size_t);
typedef int (*fclose_t)(int);
static open_t g_orig_open = NULL;
static openat_t g_orig_openat = NULL;
static rw_t g_orig_read = NULL;
static rw_t g_orig_fwrite_sys = NULL;
static fclose_t g_orig_fclose = NULL;
static volatile int g_file_close_hits = 0;

// arm64 ABI always passes a 3rd arg in a register even when the call site omits it
// (open()/openat() only read it when O_CREAT/O_TMPFILE is set) — always read+forward it.
static int my_open(const char *pathname, int flags, ...) {
    va_list ap; va_start(ap, flags); mode_t mode = (mode_t)va_arg(ap, int); va_end(ap);
    if (pathname) capture("open", (const unsigned char *)pathname, (int)strlen(pathname));
    return g_orig_open(pathname, flags, mode);
}
static int my_openat(int dirfd, const char *pathname, int flags, ...) {
    va_list ap; va_start(ap, flags); mode_t mode = (mode_t)va_arg(ap, int); va_end(ap);
    if (pathname) capture("openat", (const unsigned char *)pathname, (int)strlen(pathname));
    return g_orig_openat(dirfd, pathname, flags, mode);
}
static ssize_t my_read(int fd, void *buf, size_t count) {
    ssize_t ret = g_orig_read(fd, buf, count);
    if (ret > 0) capture("read", (const unsigned char *)buf, (int)ret);
    return ret;
}
static ssize_t my_write(int fd, const void *buf, size_t count) {
    if (count > 0) capture("write", (const unsigned char *)buf, (int)count);
    return g_orig_fwrite_sys(fd, (void *)buf, count);
}
static int my_file_close(int fd) {
    __atomic_add_fetch(&g_file_close_hits, 1, __ATOMIC_RELAXED);
    return g_orig_fclose(fd);
}

// libopenjdk.so imports open/openat/read/write/close (confirmed via dynsym), but Android
// libcore's IoBridge/Posix native layer (the actual path behind java.io.FileInputStream/
// FileOutputStream) issues raw syscall(2) directly instead of calling those named symbols
// — verified empirically (named hooks install cleanly but capture nothing) and statically
// (libopenjdk.so also imports "syscall"). Hook syscall() itself and decode the syscall
// number/args to catch what the named-symbol hooks above structurally cannot.
typedef long (*syscall_t)(long, long, long, long, long, long, long);
static syscall_t g_orig_syscall = NULL;
#ifndef __NR_openat
#define __NR_openat 56
#endif
#ifndef __NR_close
#define __NR_close 57
#endif
#ifndef __NR_read
#define __NR_read 63
#endif
#ifndef __NR_write
#define __NR_write 64
#endif

static long my_syscall(long number, ...) {
    va_list ap; va_start(ap, number);
    long a1 = va_arg(ap, long), a2 = va_arg(ap, long), a3 = va_arg(ap, long);
    long a4 = va_arg(ap, long), a5 = va_arg(ap, long), a6 = va_arg(ap, long);
    va_end(ap);
    if (number == __NR_openat) {
        const char *path = (const char *)a2;
        if (path) capture("openat", (const unsigned char *)path, (int)strlen(path));
    } else if (number == __NR_write) {
        if (a3 > 0) capture("write", (const unsigned char *)a2, (int)a3);
    }
    long ret = g_orig_syscall(number, a1, a2, a3, a4, a5, a6);
    if (number == __NR_read && ret > 0) {
        capture("read", (const unsigned char *)a2, (int)ret);
    } else if (number == __NR_close) {
        __atomic_add_fetch(&g_file_close_hits, 1, __ATOMIC_RELAXED);
    }
    return ret;
}

// The module that actually backs java.io.FileInputStream/FileOutputStream on this device
// is libjavacore.so (libcore's Linux.cpp JNI layer), NOT libopenjdk.so — confirmed via
// readelf --dyn-syms on the pulled libjavacore.so: it imports plain open/close (already
// hooked above, and "open" captures the real path when hooked here), but for read/write it
// imports bionic's FORTIFY_SOURCE-wrapped __read_chk(fd,buf,count,buflen) and
// __write_chk(fd,buf,count,buflen) (a differently-versioned symbol, LIBC_N vs read_chk's
// LIBC) instead of plain read()/write() — confirmed live: __read_chk captures real bytes,
// while plain write/writev (also imported, presumably for some other internal use) never
// fire for FileOutputStream.write().
typedef ssize_t (*read_chk_t)(int, void *, size_t, size_t);
typedef ssize_t (*write_chk_t)(int, const void *, size_t, size_t);
static read_chk_t g_orig_read_chk = NULL;
static write_chk_t g_orig_write_chk = NULL;

static ssize_t my_read_chk(int fd, void *buf, size_t count, size_t buflen) {
    ssize_t ret = g_orig_read_chk(fd, buf, count, buflen);
    if (ret > 0) capture("read", (const unsigned char *)buf, (int)ret);
    return ret;
}
static ssize_t my_write_chk(int fd, const void *buf, size_t count, size_t buflen) {
    if (count > 0) capture("write", (const unsigned char *)buf, (int)count);
    return g_orig_write_chk(fd, buf, count, buflen);
}

// Recon: for open/openat/read/write/close (libc.so), report which loaded modules'
// GOT holds each pointer (candidate hook sites) — mirrors cmd_crypto_probe.
static void cmd_file_probe(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    const char *names[] = { "open", "openat", "read", "write", "close" };
    const int NF = 5;
    void *addrs[5];
    for (int i = 0; i < NF; i++) addrs[i] = resolve_sym("libc.so", names[i]);

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
        int mi = -1;
        for (int k = 0; k < nmods; k++) if (strcmp(mods[k].name, base) == 0) { mi = k; break; }
        if (mi < 0 && nmods < 96) { mi = nmods++; strncpy(mods[mi].name, base, sizeof(mods[mi].name) - 1); mods[mi].name[sizeof(mods[mi].name)-1]=0; for (int i=0;i<NF;i++) mods[mi].cnt[i]=0; }
        if (mi >= 0) for (int i = 0; i < NF; i++) mods[mi].cnt[i] += hit[i];
    }
    if (m) fclose(m);

    size_t cap = 1 << 14, len = 0; char *out = malloc(cap); if (!out) { detach_env(0); return; }
    len += snprintf(out + len, cap - len, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"file_probe\",\"ok\":true,\"fns\":{", idj);
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
    LOGI("file_probe: %d modules with open/openat/read/write/close GOT refs", nmods);
}

// Hook open/openat/read/write/close in `module` (default libopenjdk.so; override with
// whatever cmd_file_probe found), trigger com.idh.sandbox.FileIO.run() via JNI
// reflection, and report captured paths + read/write buffer bytes.
static void cmd_file_hook_test(int fd, const char *id, const char *module) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    const char *mod = (module && module[0]) ? module : "libjavacore.so";
    void *oo  = resolve_sym("libc.so", "open");
    void *ooa = resolve_sym("libc.so", "openat");
    void *ord = resolve_sym("libc.so", "read");
    void *owr = resolve_sym("libc.so", "write");
    void *ocl = resolve_sym("libc.so", "close");
    void *osc = resolve_sym("libc.so", "syscall");
    void *orc = resolve_sym("libc.so", "__read_chk");
    void *owv = resolve_sym("libc.so", "__write_chk");
    g_orig_open = (open_t)oo; g_orig_openat = (openat_t)ooa;
    g_orig_read = (rw_t)ord; g_orig_fwrite_sys = (rw_t)owr; g_orig_fclose = (fclose_t)ocl;
    g_orig_syscall = (syscall_t)osc;
    g_orig_read_chk = (read_chk_t)orc; g_orig_write_chk = (write_chk_t)owv;

    int ro  = oo  ? got_replace(mod, oo,  (void *)my_open)  : -1;
    int roa = ooa ? got_replace(mod, ooa, (void *)my_openat) : -1;
    int rr  = ord ? got_replace(mod, ord, (void *)my_read)  : -1;
    int rw  = owr ? got_replace(mod, owr, (void *)my_write) : -1;
    int rc  = ocl ? got_replace(mod, ocl, (void *)my_file_close) : -1;
    int rsc = osc ? got_replace(mod, osc, (void *)my_syscall) : -1;
    int rrc = orc ? got_replace(mod, orc, (void *)my_read_chk) : -1;
    int rwv = owv ? got_replace(mod, owv, (void *)my_write_chk) : -1;
    cap_reset();
    g_file_close_hits = 0;

    int did = 0, triggered = 0; char result[160] = "";
    JNIEnv *env = attach_env(&did);
    if (env) {
        (*env)->PushLocalFrame(env, 32);
        jclass jc = load_app_class(env, "com.idh.sandbox.FileIO");
        if (jc) {
            jmethodID run = (*env)->GetStaticMethodID(env, jc, "run", "()Ljava/lang/String;");
            if (run) {
                jstring rs = (jstring)(*env)->CallStaticObjectMethod(env, jc, run);
                triggered = 1;
                if (rs) { const char *s = (*env)->GetStringUTFChars(env, rs, NULL); if (s) { strncpy(result, s, sizeof(result)-1); (*env)->ReleaseStringUTFChars(env, rs, s); } }
            }
        }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->PopLocalFrame(env, NULL);
        detach_env(did);
    }

    if (ro  > 0) got_replace(mod, (void *)my_open,       oo);
    if (roa > 0) got_replace(mod, (void *)my_openat,     ooa);
    if (rr  > 0) got_replace(mod, (void *)my_read,       ord);
    if (rw  > 0) got_replace(mod, (void *)my_write,      owr);
    if (rc  > 0) got_replace(mod, (void *)my_file_close, ocl);
    if (rsc > 0) got_replace(mod, (void *)my_syscall,    osc);
    if (rrc > 0) got_replace(mod, (void *)my_read_chk,   orc);
    if (rwv > 0) got_replace(mod, (void *)my_write_chk,  owv);

    size_t cap = 1 << 16, len = 0; char *out = malloc(cap); if (!out) return;
    char modj[64]; json_escape(mod, modj, sizeof(modj));
    char rj[220]; json_escape(result, rj, sizeof(rj));
    len += snprintf(out + len, cap - len,
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"file_hook_test\",\"ok\":true,\"module\":\"%s\","
        "\"hooked\":{\"open\":%d,\"openat\":%d,\"read\":%d,\"write\":%d,\"close\":%d,\"syscall\":%d,\"readChk\":%d,\"writeChk\":%d},"
        "\"triggered\":%s,\"result\":\"%s\",\"closeHits\":%d,\"captures\":[",
        idj, modj, ro, roa, rr, rw, rc, rsc, rrc, rwv, triggered ? "true" : "false", rj, g_file_close_hits);
    int n = cap_emit_all(out, &len, cap);
    snprintf(out + len, cap - len, "],\"count\":%d}\n", n);
    send_line(fd, out);
    free(out);
    LOGI("file_hook_test: mod=%s hooked o=%d oa=%d r=%d w=%d c=%d sc=%d triggered=%d captures=%d", mod, ro, roa, rr, rw, rc, rsc, triggered, n);
}

// Correlation flow: hook BOTH EVP_CipherUpdate (encrypt) and SSL_write (send) at
// once, trigger an encrypt-then-send flow, and return all captures with tid+ts so
// idhd can correlate "this plaintext was encrypted then sent" (取证闭环).
static void cmd_flow_watch(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    void *oe = resolve_sym("libcrypto.so", "EVP_CipherUpdate");
    void *ow = resolve_sym("libssl.so", "SSL_write");
    g_evp_cipher_orig = (EVP_CipherUpdate_t)oe;
    g_orig_ssl_write = (SSL_rw_t)ow;
    int re = oe ? got_replace("libjavacrypto.so", oe, (void *)my_EVP_CipherUpdate) : -1;
    int rw = ow ? got_replace("libjavacrypto.so", ow, (void *)my_SSL_write) : -1;
    cap_reset();

    int did = 0, triggered = 0; char result[128] = "";
    JNIEnv *env = attach_env(&did);
    if (env) {
        (*env)->PushLocalFrame(env, 32);
        jclass jc = load_app_class(env, "com.idh.sandbox.CorrelatedFlow");
        if (jc) {
            jmethodID run = (*env)->GetStaticMethodID(env, jc, "run", "()Ljava/lang/String;");
            if (run) {
                jstring rs = (jstring)(*env)->CallStaticObjectMethod(env, jc, run);
                triggered = 1;
                if (rs) { const char *s = (*env)->GetStringUTFChars(env, rs, NULL); if (s) { strncpy(result, s, sizeof(result)-1); (*env)->ReleaseStringUTFChars(env, rs, s); } }
            }
        }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->PopLocalFrame(env, NULL);
        detach_env(did);
    }
    if (re > 0) got_replace("libjavacrypto.so", (void *)my_EVP_CipherUpdate, oe);
    if (rw > 0) got_replace("libjavacrypto.so", (void *)my_SSL_write, ow);

    size_t cap = 1 << 16, len = 0; char *out = malloc(cap); if (!out) return;
    char rj[200]; json_escape(result, rj, sizeof(rj));
    len += snprintf(out + len, cap - len, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"flow_watch\",\"ok\":true,\"hooked\":{\"evp\":%d,\"sslWrite\":%d},\"triggered\":%s,\"result\":\"%s\",\"captures\":[", idj, re, rw, triggered ? "true" : "false", rj);
    int n = cap_emit_all(out, &len, cap);
    snprintf(out + len, cap - len, "],\"count\":%d}\n", n);
    send_line(fd, out);
    free(out);
    LOGI("flow_watch: hooked evp=%d ssl=%d triggered=%d captures=%d", re, rw, triggered, n);
}

// Install EVP_CipherUpdate GOT hook in libjavacrypto (Conscrypt), trigger the
// sandbox's AES via JNI reflection, and return what plaintext the wrapper captured.
static void cmd_crypto_hook_test(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    void *orig = resolve_sym("libcrypto.so", "EVP_CipherUpdate");
    g_evp_cipher_orig = (EVP_CipherUpdate_t)orig;
    int replaced = orig ? got_replace("libjavacrypto.so", orig, (void *)my_EVP_CipherUpdate) : -1;
    cap_reset();

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
    int ncaps = cap_emit_all(out, &len, cap);
    snprintf(out + len, cap - len, "],\"count\":%d}\n", ncaps);
    send_line(fd, out);
    free(out);
    LOGI("crypto_hook_test: replaced=%d triggered=%d captures=%d", replaced, triggered, ncaps);
}

// ---- Java-layer rich capture: the interposing JCE provider (IdhSecurity) reports every
//      Cipher/Mac/MessageDigest op here with algorithm+op+key+iv+input+output. Bound by
//      JNI name to com.idh.sandbox.IdhReport.nReport (no RegisterNatives needed). ---------
#define JCAP_MAX 96
#define JCAP_KEY 64
#define JCAP_IV 32
#define JCAP_DATA 1024
struct JCapRec {
    char algo[56], op[16]; int tid; long long ts_ns;
    int nkey, niv, nin, nout;
    unsigned char key[JCAP_KEY], iv[JCAP_IV], in[JCAP_DATA], out[JCAP_DATA];
};
static struct JCapRec g_jcaps[JCAP_MAX];
static int g_njcaps = 0;
static unsigned long long g_jcap_dropped = 0;   // WS-C: honest drop accounting (Java rich path)
static volatile int g_java_active = 0;

static int copy_jba(JNIEnv *env, jbyteArray a, unsigned char *dst, int cap) {
    if (!a) return 0;
    jsize n = (*env)->GetArrayLength(env, a);
    if (n <= 0) return 0;
    if (n > cap) n = cap;
    (*env)->GetByteArrayRegion(env, a, 0, n, (jbyte *)dst);
    return (int)n;
}

JNIEXPORT void JNICALL Java_com_idh_sandbox_IdhReport_nReport(
        JNIEnv *env, jclass cls, jstring jalgo, jstring jop,
        jbyteArray jkey, jbyteArray jiv, jbyteArray jin, jbyteArray jout) {
    (void)cls;
    g_java_active = 1;
    // Runs on the target's crypto thread — non-blocking like capture(): try the lock, and on
    // contention account a drop instead of stalling the target.
    if (pthread_mutex_trylock(&g_cap_lock) != 0) {
        __atomic_add_fetch(&g_jcap_dropped, 1, __ATOMIC_RELAXED);
        return;
    }
    if (g_njcaps < JCAP_MAX) {
        struct JCapRec *r = &g_jcaps[g_njcaps++];
        memset(r, 0, sizeof(*r));
        const char *a = jalgo ? (*env)->GetStringUTFChars(env, jalgo, NULL) : NULL;
        const char *o = jop ? (*env)->GetStringUTFChars(env, jop, NULL) : NULL;
        if (a) { strncpy(r->algo, a, sizeof(r->algo) - 1); (*env)->ReleaseStringUTFChars(env, jalgo, a); }
        if (o) { strncpy(r->op, o, sizeof(r->op) - 1); (*env)->ReleaseStringUTFChars(env, jop, o); }
        r->tid = (int)gettid();
        r->ts_ns = now_ns();
        r->nkey = copy_jba(env, jkey, r->key, JCAP_KEY);
        r->niv  = copy_jba(env, jiv,  r->iv,  JCAP_IV);
        r->nin  = copy_jba(env, jin,  r->in,  JCAP_DATA);
        r->nout = copy_jba(env, jout, r->out, JCAP_DATA);
    } else {
        __atomic_add_fetch(&g_jcap_dropped, 1, __ATOMIC_RELAXED);   // fail-loud, reported via drain
    }
    pthread_mutex_unlock(&g_cap_lock);
}

// ---- continuous capture: install persistent EVP+SSL hooks, drain accumulated records
//      periodically from idhd (mirrors the ios-decrypt-helper log-store model: hooks
//      stay installed and events stream to the panel, instead of one-shot triggers) ----
static int g_capture_on = 0;
static void cmd_capture_start(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    void *evp = resolve_sym("libcrypto.so", "EVP_CipherUpdate");
    void *dig = resolve_sym("libcrypto.so", "EVP_DigestUpdate");
    void *hm  = resolve_sym("libcrypto.so", "HMAC_Update");
    void *dsu = resolve_sym("libcrypto.so", "EVP_DigestSignUpdate");
    void *ow  = resolve_sym("libssl.so", "SSL_write");
    void *orr = resolve_sym("libssl.so", "SSL_read");
    if (evp) g_evp_cipher_orig = (EVP_CipherUpdate_t)evp;
    if (dig) g_orig_evp_digest = (update3_t)dig;
    if (hm)  g_orig_hmac       = (update3_t)hm;
    if (dsu) g_orig_digest_sign= (update3_t)dsu;
    if (ow)  g_orig_ssl_write  = (SSL_rw_t)ow;
    if (orr) g_orig_ssl_read   = (SSL_rw_t)orr;
    // Persistent hooks in Conscrypt's GOT (not restored — that's what makes it "live").
    // Covers symmetric (EVP_CipherUpdate), digest (EVP_DigestUpdate), HMAC (HMAC_Update
    // and the EVP_PKEY HMAC path EVP_DigestSignUpdate), and TLS (SSL_read/write).
    int re = evp ? got_replace("libjavacrypto.so", evp, (void *)my_EVP_CipherUpdate) : -1;
    int rd = dig ? got_replace("libjavacrypto.so", dig, (void *)my_EVP_DigestUpdate) : -1;
    int rh = hm  ? got_replace("libjavacrypto.so", hm,  (void *)my_HMAC_Update) : -1;
    int rs = dsu ? got_replace("libjavacrypto.so", dsu, (void *)my_EVP_DigestSignUpdate) : -1;
    int rw = ow  ? got_replace("libjavacrypto.so", ow,  (void *)my_SSL_write) : -1;
    int rr = orr ? got_replace("libjavacrypto.so", orr, (void *)my_SSL_read) : -1;
    g_capture_on = 1;
    char out[320];
    snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"capture_start\",\"ok\":true,\"evp\":%d,\"digest\":%d,\"hmac\":%d,\"digestSign\":%d,\"sslWrite\":%d,\"sslRead\":%d,\"on\":true}\n",
        idj, re, rd, rh, rs, rw, rr);
    send_line(fd, out);
    LOGI("capture_start: evp=%d dig=%d hmac=%d dsu=%d sslw=%d sslr=%d", re, rd, rh, rs, rw, rr);
}

// Uninstall the persistent capture hooks and restore the original GOT pointers, so the
// one-shot probe endpoints (crypto_hook_test / net_hook_test / flow_watch) get a clean
// slot to install-and-restore their own hook. idhd suspends continuous capture around
// those probes, then calls capture_start again.
static void cmd_capture_stop(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    int e = 0, w = 0, r = 0, dg = 0, hm = 0, ds = 0;
    if (g_evp_cipher_orig) e  = got_replace("libjavacrypto.so", (void *)my_EVP_CipherUpdate, (void *)g_evp_cipher_orig);
    if (g_orig_evp_digest) dg = got_replace("libjavacrypto.so", (void *)my_EVP_DigestUpdate, (void *)g_orig_evp_digest);
    if (g_orig_hmac)       hm = got_replace("libjavacrypto.so", (void *)my_HMAC_Update, (void *)g_orig_hmac);
    if (g_orig_digest_sign)ds = got_replace("libjavacrypto.so", (void *)my_EVP_DigestSignUpdate, (void *)g_orig_digest_sign);
    if (g_orig_ssl_write)  w  = got_replace("libjavacrypto.so", (void *)my_SSL_write, (void *)g_orig_ssl_write);
    if (g_orig_ssl_read)   r  = got_replace("libjavacrypto.so", (void *)my_SSL_read, (void *)g_orig_ssl_read);
    g_capture_on = 0;
    cap_reset();
    char out[256];
    snprintf(out, sizeof(out), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"capture_stop\",\"ok\":true,\"restored\":{\"evp\":%d,\"digest\":%d,\"hmac\":%d,\"digestSign\":%d,\"sslWrite\":%d,\"sslRead\":%d}}\n", idj, e, dg, hm, ds, w, r);
    send_line(fd, out);
    LOGI("capture_stop: restored evp=%d sslw=%d sslr=%d", e, w, r);
}

// Drain (pop) up to a batch of ring records + rich Java records, and report HONEST WS-C
// stats: seq (total capture attempts), dropped/jdropped (never silent), backlog (still in
// ring), first/last drop ts. idhd streams the records and surfaces dropped>0 as
// complete:false. Buffer grows as needed (the old fixed 64KB could overflow with a full ring).
static void cmd_capture_drain(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    size_t cap = 1 << 16, len = 0; char *out = malloc(cap); if (!out) return;
    len += snprintf(out + len, cap - len,
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"capture_drain\",\"ok\":true,\"on\":%s,\"captures\":[",
        idj, g_capture_on ? "true" : "false");
    const int DRAIN_BATCH = 512;   // bound one response; idhd polls again to clear the backlog
    pthread_mutex_lock(&g_cap_lock);
    int ncaps = 0;
    while (g_ring_count > 0 && ncaps < DRAIN_BATCH) {
        if (len + 4200 > cap) { size_t nc = cap * 2; char *no = realloc(out, nc); if (!no) break; out = no; cap = nc; }
        struct CapRec *r = &g_ring[g_ring_tail];
        len = emit_caprec(out, len, cap, r, ncaps == 0);
        g_ring_tail = (g_ring_tail + 1) % CAP_RING;
        g_ring_count--; ncaps++;
    }
    int backlog = g_ring_count;
    unsigned long long seq = __atomic_load_n(&g_cap_seq, __ATOMIC_RELAXED);
    unsigned long long dropped = __atomic_load_n(&g_cap_dropped, __ATOMIC_RELAXED);
    unsigned long long jdropped = __atomic_load_n(&g_jcap_dropped, __ATOMIC_RELAXED);
    long long fdrop = g_cap_first_drop_ns, ldrop = g_cap_last_drop_ns;
    // rich Java-layer records: algorithm + op + key + iv + input + output
    len += snprintf(out + len, cap > len ? cap - len : 0, "],\"jcaptures\":[");
    for (int k = 0; k < g_njcaps; k++) {
        if (len + 9000 > cap) { size_t nc = cap * 2; char *no = realloc(out, nc); if (!no) break; out = no; cap = nc; }
        struct JCapRec *r = &g_jcaps[k];
        len += snprintf(out + len, cap > len ? cap - len : 0,
            "%s{\"algo\":\"%s\",\"op\":\"%s\",\"tid\":%d,\"tsNs\":%lld,\"key\":\"", k ? "," : "", r->algo, r->op, r->tid, r->ts_ns);
        for (int b = 0; b < r->nkey && len + 3 < cap; b++) len += snprintf(out + len, cap > len ? cap - len : 0, "%02x", r->key[b]);
        len += snprintf(out + len, cap > len ? cap - len : 0, "\",\"iv\":\"");
        for (int b = 0; b < r->niv && len + 3 < cap; b++) len += snprintf(out + len, cap > len ? cap - len : 0, "%02x", r->iv[b]);
        len += snprintf(out + len, cap > len ? cap - len : 0, "\",\"in\":\"");
        for (int b = 0; b < r->nin && len + 3 < cap; b++) len += snprintf(out + len, cap > len ? cap - len : 0, "%02x", r->in[b]);
        len += snprintf(out + len, cap > len ? cap - len : 0, "\",\"out\":\"");
        for (int b = 0; b < r->nout && len + 3 < cap; b++) len += snprintf(out + len, cap > len ? cap - len : 0, "%02x", r->out[b]);
        len += snprintf(out + len, cap > len ? cap - len : 0, "\",\"inl\":%d,\"outl\":%d}", r->nin, r->nout);
    }
    int njcaps = g_njcaps;
    g_njcaps = 0;
    pthread_mutex_unlock(&g_cap_lock);
    snprintf(out + len, cap > len ? cap - len : 0,
        "],\"count\":%d,\"jcount\":%d,\"backlog\":%d,\"seq\":%llu,\"dropped\":%llu,\"jdropped\":%llu,"
        "\"firstDropNs\":%lld,\"lastDropNs\":%lld,\"ring\":%d,\"complete\":%s,\"javaActive\":%s}\n",
        ncaps, njcaps, backlog, seq, dropped, jdropped, fdrop, ldrop, CAP_RING,
        (dropped == 0 && jdropped == 0) ? "true" : "false", g_java_active ? "true" : "false");
    send_line(fd, out);
    free(out);
}

// ---- active triggering (P2): a TRIGGER SOURCE for the CodeItem captor, not recovery
//      itself. Level 1 loads a class (packer may restore on class-load); Level 3 invokes
//      a SAFE no-arg static method (so a refill-type shell fills its code_item, which the
//      next dex snapshot then captures). Strict safety policy; exceptions isolated. --------
static int name_blacklisted(const char *s) {
    // dangerous verbs — skip auto-invoke (payments, deletion, exec, lifecycle, exit, ...)
    static const char *bad[] = { "exit","exec","delete","remove","clear","drop","format","kill",
        "finish","destroy","close","clinit","init","finalize","write","send","post","pay",
        "transfer","order","logout","reset","wipe","shutdown","reboot","uninstall", NULL };
    for (int i = 0; bad[i]; i++) if (strstr(s, bad[i])) return 1;
    return 0;
}
static int class_is_lifecycle(const char *s) {
    static const char *lc[] = { "Activity","Service","Application","Receiver","Provider", NULL };
    for (int i = 0; lc[i]; i++) if (strstr(s, lc[i])) return 1;
    return 0;
}
// Trigger one class/method. level: 1=load only, 3=load + safe static no-arg invoke.
static void cmd_trigger(int fd, const char *id, const char *className, const char *method, int level) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    int loaded = 0, invoked = 0, skipped = 0; const char *reason = "";
    char result[160] = "";
    int did = 0;
    JNIEnv *env = attach_env(&did);
    if (env) {
        (*env)->PushLocalFrame(env, 64);
        jclass jc = load_app_class(env, className);
        if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); reason = "loadClass threw"; }
        else if (jc) {
            loaded = 1;
            if (level >= 3 && method && method[0]) {
                if (name_blacklisted(method)) { skipped = 1; reason = "method on safety blacklist"; }
                else if (class_is_lifecycle(className)) { skipped = 1; reason = "lifecycle class"; }
                else {
                    // reflect: Method m = jc.getMethod(name); check static & !native & !abstract; invoke(null)
                    jclass cClass = (*env)->FindClass(env, "java/lang/Class");
                    jmethodID mGetMethod = (*env)->GetMethodID(env, cClass, "getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");
                    jobjectArray empty = (*env)->NewObjectArray(env, 0, cClass, NULL);
                    jstring mn = (*env)->NewStringUTF(env, method);
                    jobject m = (*env)->CallObjectMethod(env, jc, mGetMethod, mn, empty);
                    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); skipped = 1; reason = "no such no-arg method"; }
                    else if (m) {
                        jclass cMethod = (*env)->FindClass(env, "java/lang/reflect/Method");
                        jmethodID mGetMod = (*env)->GetMethodID(env, cMethod, "getModifiers", "()I");
                        jint mods = (*env)->CallIntMethod(env, m, mGetMod);
                        int is_static = (mods & 0x0008), is_native = (mods & 0x0100), is_abstract = (mods & 0x0400);
                        if (!is_static) { skipped = 1; reason = "not static (needs receiver, level>=4)"; }
                        else if (is_native || is_abstract) { skipped = 1; reason = "native/abstract"; }
                        else {
                            jmethodID mSetAcc = (*env)->GetMethodID(env, cMethod, "setAccessible", "(Z)V");
                            (*env)->CallVoidMethod(env, m, mSetAcc, JNI_TRUE);
                            jclass cObj = (*env)->FindClass(env, "java/lang/Object");
                            jobjectArray args = (*env)->NewObjectArray(env, 0, cObj, NULL);
                            jmethodID mInvoke = (*env)->GetMethodID(env, cMethod, "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
                            jobject ret = (*env)->CallObjectMethod(env, m, mInvoke, NULL, args);   // static → receiver null
                            if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); reason = "invocation threw (isolated)"; }
                            else {
                                invoked = 1;
                                jclass cStr = (*env)->FindClass(env, "java/lang/String");
                                jmethodID mValueOf = (*env)->GetStaticMethodID(env, cStr, "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;");
                                jstring sv = (jstring)(*env)->CallStaticObjectMethod(env, cStr, mValueOf, ret);
                                if (sv) { const char *cs = (*env)->GetStringUTFChars(env, sv, NULL); if (cs) { strncpy(result, cs, sizeof(result)-1); (*env)->ReleaseStringUTFChars(env, sv, cs); } }
                            }
                        }
                    } else { skipped = 1; reason = "method not found"; }
                }
            }
        } else { reason = "class not found"; }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->PopLocalFrame(env, NULL);
        detach_env(did);
    } else { reason = "no JNI env"; }
    char cj[200], rj[200], rej[160];
    json_escape(className, cj, sizeof(cj)); json_escape(result, rj, sizeof(rj)); json_escape(reason, rej, sizeof(rej));
    char out[720];
    snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"trigger\",\"ok\":true,\"class\":\"%s\",\"level\":%d,\"loaded\":%s,\"invoked\":%s,\"skipped\":%s,\"reason\":\"%s\",\"result\":\"%s\"}\n",
        idj, cj, level, loaded?"true":"false", invoked?"true":"false", skipped?"true":"false", rej, rj);
    send_line(fd, out);
    LOGI("trigger %s method=%s level=%d loaded=%d invoked=%d skipped=%d (%s)", className, method?method:"", level, loaded, invoked, skipped, reason);
}

// Load an arbitrary .so into the target process (e.g. frida-gadget, a helper lib). The
// agent is native code inside the target, so dlopen() just works — gadget in script mode
// then auto-runs its JS. Reports the handle + whether an optional probe symbol resolved.
static void cmd_load_so(int fd, const char *id, const char *path, const char *symbol) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    void *h = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
    const char *err = h ? "" : dlerror();
    void *sym = (h && symbol && symbol[0]) ? dlsym(h, symbol) : NULL;
    char pj[300], ej[300]; json_escape(path, pj, sizeof(pj)); json_escape(err ? err : "", ej, sizeof(ej));
    char out[900];
    snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"load_so\",\"ok\":%s,\"path\":\"%s\",\"handle\":\"%llx\",\"symbol\":\"%s\",\"symbolFound\":%s,\"error\":\"%s\"}\n",
        idj, h ? "true" : "false", pj, (unsigned long long)(uintptr_t)h, symbol ? symbol : "", sym ? "true" : "false", ej);
    send_line(fd, out);
    LOGI("load_so path=%s ok=%d symFound=%d err=%s", path, h != NULL, sym != NULL, err ? err : "");
}

// ---- generic native function-call tracer (module I.2, function level) ----
struct TraceRec { long a0, a1, a2, a3; int tid; long long ts; char s0[48]; };
static struct TraceRec g_trace[256];
static int g_ntrace = 0;
static pthread_mutex_t g_trace_lock = PTHREAD_MUTEX_INITIALIZER;
typedef long (*fn4_t)(long, long, long, long);
static fn4_t g_trace_orig = NULL;
static char g_trace_mod[80] = "";
// If addr points to a readable ASCII string, copy a short printable preview (for
// path/string args). Self-contained (untag + /proc/self/mem read).
// Cached read-only /proc/self/mem fd — opened once, never closed. trace_preview() runs in a
// hook wrapper's hot path; opening+closing a fd on every call is fd churn + syscall overhead.
static int g_mem_fd = -1;
static int mem_fd(void) {
    int fd = __atomic_load_n(&g_mem_fd, __ATOMIC_ACQUIRE);
    if (fd >= 0) return fd;
    int nfd = open("/proc/self/mem", O_RDONLY);
    if (nfd < 0) return -1;
    int expected = -1;
    if (!__atomic_compare_exchange_n(&g_mem_fd, &expected, nfd, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        close(nfd);                 // lost the race; use the winner's fd
        return expected;
    }
    return nfd;
}
static void trace_preview(long addr, char *out, int n) {
    out[0] = 0;
    unsigned long long a = (unsigned long long)addr & 0x00FFFFFFFFFFFFFFULL;
    if (a < 0x1000) return;
    int fd = mem_fd(); if (fd < 0) return;
    unsigned char buf[64]; ssize_t r = pread(fd, buf, sizeof(buf), (off_t)a);   // cached fd, no close
    if (r <= 0) return;
    int o = 0; for (int i = 0; i < r && o < n - 1; i++) { unsigned char c = buf[i]; if (c == 0) break; if (c < 0x20 || c >= 0x7f) break; out[o++] = c; }
    out[o] = 0;
}
// Generic 4-arg wrapper: logs args (+ a0 string preview) + tid + ts, then trampolines.
static long idh_trace_wrapper(long a0, long a1, long a2, long a3) {
    int tid = (int)gettid(); long long ts = now_ns();
    char s0[48]; trace_preview(a0, s0, sizeof(s0));
    pthread_mutex_lock(&g_trace_lock);
    if (g_ntrace < 256) { struct TraceRec *r = &g_trace[g_ntrace++]; r->a0 = a0; r->a1 = a1; r->a2 = a2; r->a3 = a3; r->tid = tid; r->ts = ts; strncpy(r->s0, s0, sizeof(r->s0) - 1); r->s0[sizeof(r->s0)-1] = 0; }
    pthread_mutex_unlock(&g_trace_lock);
    return g_trace_orig ? g_trace_orig(a0, a1, a2, a3) : 0;
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

// Generic function trace: hook `symbol` (exported by symLib) in hookModule's GOT,
// trigger the sandbox's Detection.run() (which calls libc detection fns), and return
// the recorded calls (args + tid + ts). Demonstrates tracing an arbitrary native fn.
static void cmd_trace_run(int fd, const char *id, const char *symLib, const char *symbol, const char *hookMod) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    void *orig = resolve_sym(symLib, symbol);
    g_trace_orig = (fn4_t)orig;
    strncpy(g_trace_mod, hookMod, sizeof(g_trace_mod) - 1); g_trace_mod[sizeof(g_trace_mod)-1] = 0;
    int replaced = orig ? got_replace(hookMod, orig, (void *)idh_trace_wrapper) : -1;
    pthread_mutex_lock(&g_trace_lock); g_ntrace = 0; pthread_mutex_unlock(&g_trace_lock);

    int did = 0, triggered = 0;
    JNIEnv *env = attach_env(&did);
    if (env) {
        (*env)->PushLocalFrame(env, 32);
        jclass jc = load_app_class(env, "com.idh.sandbox.Detection");
        if (jc) { jmethodID run = (*env)->GetStaticMethodID(env, jc, "run", "()I");
            if (run) { (*env)->CallStaticIntMethod(env, jc, run); triggered = 1; } }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->PopLocalFrame(env, NULL);
        detach_env(did);
    }
    if (replaced > 0 && orig) got_replace(hookMod, (void *)idh_trace_wrapper, orig);   // restore

    char sj[80]; json_escape(symbol, sj, sizeof(sj));
    size_t cap = 1 << 14, len = 0; char *out = malloc(cap); if (!out) return;
    len += snprintf(out + len, cap - len, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"trace_run\",\"ok\":true,\"symbol\":\"%s\",\"replaced\":%d,\"triggered\":%s,\"calls\":[", idj, sj, replaced, triggered ? "true" : "false");
    pthread_mutex_lock(&g_trace_lock);
    for (int k = 0; k < g_ntrace; k++) { struct TraceRec *r = &g_trace[k]; char s0j[100]; json_escape(r->s0, s0j, sizeof(s0j));
        len += snprintf(out + len, cap - len, "%s{\"a0\":\"%lx\",\"a0str\":\"%s\",\"a1\":\"%lx\",\"a2\":\"%lx\",\"a3\":\"%lx\",\"tid\":%d,\"tsNs\":%lld}", k ? "," : "", (unsigned long)r->a0, s0j, (unsigned long)r->a1, (unsigned long)r->a2, (unsigned long)r->a3, r->tid, r->ts); }
    int n = g_ntrace;
    pthread_mutex_unlock(&g_trace_lock);
    snprintf(out + len, cap - len, "],\"count\":%d}\n", n);
    send_line(fd, out); free(out);
    LOGI("trace_run: sym=%s replaced=%d triggered=%d calls=%d", symbol, replaced, triggered, n);
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

// Rich view of an in-memory dex — enough to snapshot it WITHOUT truncating (DEX 041
// containers reference shared data past file_size; cdex has a separate data range).
struct DexView {
    unsigned long long begin;      // start of the bytes to snapshot (container for 041)
    unsigned int size;             // bytes to snapshot
    unsigned long long logical;    // logical dex header (== begin for 035-040)
    unsigned long long data_begin; // shared/data section start (0 if within [begin,size))
    unsigned int data_size;
    char format[8];                // "dex" | "dex041" | "cdex"
    unsigned int version;          // 35..41
    int confidence;                // 0..100
};

static unsigned int rd_u32(const unsigned char *p, int o) {
    return (unsigned int)p[o] | ((unsigned int)p[o+1] << 8) | ((unsigned int)p[o+2] << 16) | ((unsigned int)p[o+3] << 24);
}

// Given an art::DexFile* candidate, scavenge its first words for the member pointing to
// dex/cdex magic (begin_), validate the header, and compute the FULL snapshot range:
//  - standard dex 035-040 : [begin, begin+file_size)
//  - dex 041 container     : [container_begin, +container_size)  (covers shared data)
//  - cdex                  : [begin, +file_size) + separate data range flagged (P3: reassemble)
// No hardcoded ART struct offsets. Returns 1 on success.
static int resolve_dexfile(int memfd, unsigned long long dexfile_ptr, struct DexView *v) {
    unsigned long long words[24];
    ssize_t got = safe_read_at(memfd, dexfile_ptr, words, sizeof(words));
    int nwords = (int)(got / 8);
    for (int i = 0; i < nwords; i++) {
        unsigned long long b = UNTAG(words[i]);
        unsigned char hdr[120];
        if (safe_read_at(memfd, b, hdr, sizeof(hdr)) < 120) continue;
        int compact = 0;
        if (hdr[0] == 'd' && hdr[1] == 'e' && hdr[2] == 'x' && hdr[3] == '\n') compact = 0;
        else if (hdr[0] == 'c' && hdr[1] == 'd' && hdr[2] == 'e' && hdr[3] == 'x') compact = 1;
        else continue;
        // version = ascii digits at [4..6], e.g. "035".."041"
        if (hdr[4] < '0' || hdr[4] > '9' || hdr[5] < '0' || hdr[5] > '9' || hdr[6] < '0' || hdr[6] > '9') continue;
        unsigned int ver = (hdr[4]-'0')*100 + (hdr[5]-'0')*10 + (hdr[6]-'0');
        unsigned int fsz = rd_u32(hdr, 32);
        unsigned int header_size = rd_u32(hdr, 36);
        unsigned int endian = rd_u32(hdr, 40);
        if (fsz < 0x70 || fsz > (256u << 20)) continue;                 // sane logical size
        if (!compact && endian != 0x12345678u) continue;               // standard dex endian tag
        memset(v, 0, sizeof(*v));
        v->logical = b; v->version = ver; v->confidence = compact ? 60 : 95;
        if (compact) {
            // cdex: snapshot the logical unit; shared data range lives elsewhere (reassembly = P3)
            snprintf(v->format, sizeof(v->format), "cdex");
            v->begin = b; v->size = fsz;
            v->data_begin = 0; v->data_size = 0;
        } else if (ver >= 41 && header_size >= 0x78) {
            // DEX 041 container: header+112 = container_size, header+116 = header_offset.
            unsigned int container_size = rd_u32(hdr, 112);
            unsigned int header_offset  = rd_u32(hdr, 116);
            snprintf(v->format, sizeof(v->format), "dex041");
            if (container_size >= fsz && container_size <= (256u << 20) && header_offset <= container_size) {
                v->begin = b - header_offset;      // physical container start
                v->size = container_size;          // full container — never truncate shared data
                v->confidence = 100;
            } else { v->begin = b; v->size = fsz; v->confidence = 70; }   // fall back, mark uncertain
            v->data_begin = b + rd_u32(hdr, 108); v->data_size = rd_u32(hdr, 104);
        } else {
            snprintf(v->format, sizeof(v->format), "dex");
            v->begin = b; v->size = fsz; v->confidence = 100;
            v->data_begin = b + rd_u32(hdr, 108); v->data_size = rd_u32(hdr, 104);   // data section
        }
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
                                struct DexView dv;
                                if (resolve_dexfile(memfd, p, &dv)) {
                                    int dup = 0; for (int k = 0; k < nseen; k++) if (seen[k] == dv.begin) { dup = 1; break; }
                                    if (dup) continue;
                                    if (nseen < 512) seen[nseen++] = dv.begin;
                                    char lj[160]; json_escape(lname, lj, sizeof(lj));
                                    char rec[520];
                                    int w = snprintf(rec, sizeof(rec),
                                        "%s{\"dexFilePtr\":\"%llx\",\"begin\":\"%llx\",\"size\":%u,\"magic\":\"%s\",\"format\":\"%s\",\"version\":%u,\"logical\":\"%llx\",\"dataBegin\":\"%llx\",\"dataSize\":%u,\"confidence\":%d,\"loader\":\"%s\"}",
                                        nrec ? "," : "", p, dv.begin, dv.size, dv.format, dv.format, dv.version, dv.logical, dv.data_begin, dv.data_size, dv.confidence, lj);
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

// Protocol self-test (WS-D): echo how many bytes of the inbound command frame the
// agent actually received, plus a `tail` sentinel that the daemon places AFTER a large
// `pad` field. If inbound framing still had the old 8192 single-line cap, a >8192-byte
// command would be truncated and `tail` (which sits past byte 8192) would come back
// empty. Pure protocol diagnostic — carries no target knowledge, no sandbox coupling.
static void cmd_frame_echo(int fd, const char *id, const char *line) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    char tail[64] = ""; json_get_str(line, "tail", tail, sizeof(tail));
    char tailj[80]; json_escape(tail, tailj, sizeof(tailj));
    long long padLen = json_get_num(line, "padLen");
    size_t recv = strlen(line);   // whole inbound frame payload the reader delivered
    char out[256];
    snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"frame_echo\",\"ok\":true,"
        "\"recvBytes\":%zu,\"tail\":\"%s\",\"padLen\":%lld}\n",
        idj, recv, tailj, padLen);
    send_line(fd, out);
    LOGI("frame_echo: recvBytes=%zu tail=%s padLen=%lld", recv, tail, padLen);
}

// Read framed commands from idhd and dispatch.
static void command_loop(int fd) {
    for (;;) {
        unsigned char hdr[5];
        if (read_full(fd, hdr, 5) != 0) break;
        size_t len = ((size_t)hdr[0] << 24) | ((size_t)hdr[1] << 16) |
                     ((size_t)hdr[2] << 8)  |  (size_t)hdr[3];
        unsigned char ftype = hdr[4];
        if (len > FRAME_MAX_IN) { LOGE("inbound frame too large: %zu type=%u — closing", len, ftype); break; }
        char *line = (char *)malloc(len + 1);
        if (!line) { LOGE("inbound frame alloc failed (%zu)", len); break; }
        if (len && read_full(fd, (unsigned char *)line, len) != 0) { free(line); break; }
        line[len] = 0;
        if (ftype != FRAME_JSON) { LOGE("unknown inbound frame type %u — skipping", ftype); free(line); continue; }
        {
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
                } else if (strcmp(op, "capture_start") == 0) {
                    cmd_capture_start(fd, id);
                } else if (strcmp(op, "capture_drain") == 0) {
                    cmd_capture_drain(fd, id);
                } else if (strcmp(op, "capture_stop") == 0) {
                    cmd_capture_stop(fd, id);
                } else if (strcmp(op, "trigger") == 0) {
                    char tcls[200] = "", tm[80] = "";
                    json_get_str(line, "className", tcls, sizeof(tcls));
                    json_get_str(line, "method", tm, sizeof(tm));
                    long long lv = json_get_num(line, "level");
                    cmd_trigger(fd, id, tcls, tm, lv > 0 ? (int)lv : 1);
                } else if (strcmp(op, "load_so") == 0) {
                    char lpath[400] = "", lsym[96] = "";
                    json_get_str(line, "path", lpath, sizeof(lpath));
                    json_get_str(line, "symbol", lsym, sizeof(lsym));
                    cmd_load_so(fd, id, lpath, lsym);
                } else if (strcmp(op, "net_hook_test") == 0) {
                    cmd_net_hook_test(fd, id);
                } else if (strcmp(op, "file_probe") == 0) {
                    cmd_file_probe(fd, id);
                } else if (strcmp(op, "file_hook_test") == 0) {
                    char fmod[64] = ""; json_get_str(line, "module", fmod, sizeof(fmod));
                    cmd_file_hook_test(fd, id, fmod);
                } else if (strcmp(op, "flow_watch") == 0) {
                    cmd_flow_watch(fd, id);
                } else if (strcmp(op, "detect_watch") == 0) {
                    cmd_detect_watch(fd, id);
                } else if (strcmp(op, "qbdi_trace") == 0) {
                    char sl[64] = "", sy[80] = "";
                    json_get_str(line, "symLib", sl, sizeof(sl));
                    json_get_str(line, "symbol", sy, sizeof(sy));
                    void *fn = resolve_sym(sl[0] ? sl : "libidhdetect.so", sy[0] ? sy : "idh_trace_target");
                    char idj[64]; json_escape(id, idj, sizeof(idj));
                    if (!fn) { char e[160]; snprintf(e, sizeof(e), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"qbdi_trace\",\"ok\":false,\"error\":\"symbol not found\"}\n", idj); send_line(fd, e); }
                    else { char *ob = malloc(1 << 18); if (ob) { ob[0] = 0; idh_qbdi_trace(fn, ob, (1 << 18) - 64);
                        char *msg = malloc((1 << 18) + 128);
                        if (msg) { snprintf(msg, (1 << 18) + 128, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"qbdi_trace\",%s}\n", idj, ob); send_line(fd, msg); free(msg); }
                        free(ob); LOGI("qbdi_trace %s -> done", sy); } }
                } else if (strcmp(op, "trace_run") == 0) {
                    char sl[64] = "", sy[64] = "", hm[80] = "";
                    json_get_str(line, "symLib", sl, sizeof(sl));
                    json_get_str(line, "symbol", sy, sizeof(sy));
                    json_get_str(line, "hookModule", hm, sizeof(hm));
                    cmd_trace_run(fd, id, sl, sy, hm);
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
                } else if (strcmp(op, "frame_echo") == 0) {
                    cmd_frame_echo(fd, id, line);
                } else if (strcmp(op, "ping") == 0) {
                    char idj[64]; json_escape(id, idj, sizeof(idj));
                    char pong[128];
                    snprintf(pong, sizeof(pong), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"ping\",\"ok\":true}\n", idj);
                    send_line(fd, pong);
                }
            }
        }
        free(line);
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
