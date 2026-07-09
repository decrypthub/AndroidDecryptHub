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
    (void)vm; (void)reserved;
    strncpy(g_entry, "jni_onload", sizeof(g_entry) - 1);
    LOGI("JNI_OnLoad — agent " AGENT_VER " starting");
    pthread_once(&g_once, do_start);
    return JNI_VERSION_1_6;
}
