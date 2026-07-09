// libidh_agent.so — bootstrap (v0.1)
// Dual entry:
//   - JNI_OnLoad()      : fires when a host loads us via System.loadLibrary (模拟注入 / gadget)
//   - idh_agent_start() : exported C symbol for injector-driven load
// Both funnel into agent_start_once(), which connects to idhd over TCP
// (127.0.0.1:8761, reachable from device via `adb reverse`) and reports
// identity + a /proc/self/maps snapshot. Collect-only; no heavy work here.

#include <jni.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/system_properties.h>
#include <android/log.h>

#define AGENT_VER   "0.1.0"
#define IDH_HOST    "127.0.0.1"
#define IDH_PORT    8761
#define TAG         "IDH_AGENT"
#define LOGI(...)   __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...)   __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static char g_entry[16] = "start";

static void prop(const char *key, char *out, size_t n) {
    out[0] = 0;
    char buf[PROP_VALUE_MAX] = {0};
    if (__system_property_get(key, buf) > 0) { strncpy(out, buf, n - 1); out[n - 1] = 0; }
}

// Read the process cmdline (== package/process name for an Android app).
static void read_cmdline(char *out, size_t n) {
    out[0] = 0;
    FILE *f = fopen("/proc/self/cmdline", "rb");
    if (!f) { strncpy(out, "unknown", n - 1); return; }
    size_t r = fread(out, 1, n - 1, f);
    fclose(f);
    out[r > 0 ? r : 0] = 0;               // cmdline is NUL-delimited; first token is the name
}

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

static int send_all(int fd, const char *s) {
    size_t off = 0, len = strlen(s);
    while (off < len) {
        ssize_t w = write(fd, s + off, len - off);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static void json_escape(const char *in, char *out, size_t n) {
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 2 < n; i++) {
        char c = in[i];
        if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = c; }
        else if (c == '\n') { out[o++] = ' '; }
        else if ((unsigned char)c < 0x20) { out[o++] = ' '; }
        else out[o++] = c;
    }
    out[o] = 0;
}

// Send hello, then stream /proc/self/maps as a single maps message.
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
    if (send_all(fd, hello) != 0) { LOGE("send hello failed"); return; }

    // Parse /proc/self/maps: count all lines, sample the first regions.
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) { LOGE("open maps failed"); return; }
    char line[1024];
    int count = 0, sampled = 0;
    // Build a bounded regions[] sample (first 40) to keep v0.1 payload small.
    char sample[8192]; size_t so = 0; sample[0] = 0;
    while (fgets(line, sizeof(line), m)) {
        count++;
        if (sampled < 40) {
            char sa[64], ea[64], perms[8], off[32], dev[16], path[512] = "";
            unsigned long long inode = 0;
            int nf = sscanf(line, "%63[0-9a-f]-%63[0-9a-f] %7s %31s %15s %llu %511[^\n]",
                            sa, ea, perms, off, dev, &inode, path);
            if (nf >= 6) {
                char epath[600]; json_escape(path, epath, sizeof(epath));
                char *p = path; while (*p == ' ') p++;   // trim leading spaces before path
                char epath2[600]; json_escape(p, epath2, sizeof(epath2));
                int w = snprintf(sample + so, sizeof(sample) - so,
                    "%s{\"start\":\"%s\",\"end\":\"%s\",\"perms\":\"%s\",\"offset\":\"%s\",\"dev\":\"%s\",\"inode\":%llu,\"path\":\"%s\"}",
                    sampled ? "," : "", sa, ea, perms, off, dev, inode, epath2);
                (void)epath;
                if (w > 0 && (size_t)w < sizeof(sample) - so) { so += (size_t)w; sampled++; }
            }
        }
    }
    fclose(m);

    char *msg = (char *)malloc(so + 128);
    if (msg) {
        int w = snprintf(msg, so + 128, "{\"t\":\"maps\",\"count\":%d,\"regions\":[%s]}\n", count, sample);
        if (w > 0) send_all(fd, msg);
        free(msg);
    }
    LOGI("reported: pkg=%s pid=%d maps=%d entry=%s", cmd, getpid(), count, g_entry);
}

static void *agent_thread(void *arg) {
    (void)arg;
    for (int attempt = 0; attempt < 30; attempt++) {   // idhd may start slightly after us
        int fd = connect_idhd();
        if (fd >= 0) {
            LOGI("connected to idhd %s:%d", IDH_HOST, IDH_PORT);
            report(fd);
            // Keep the socket open so the dashboard shows us online; drain replies.
            char rbuf[256];
            for (;;) {
                ssize_t r = read(fd, rbuf, sizeof(rbuf));
                if (r <= 0) break;
            }
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
