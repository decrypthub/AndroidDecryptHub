// io.c — connect to adhd over TCP and the WS-D length-framed send path. One send lock so a
// future drain thread and the command-response path never interleave bytes on the same fd.
#include "agent_internal.h"
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

int connect_adhd(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(ADH_PORT);
    inet_pton(AF_INET, ADH_HOST, &a.sin_addr);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(fd); return -1; }
    int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return fd;
}

int send_all(int fd, const char *s, size_t len) {
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
// (WS-C capture batch, chunked dump).
static pthread_mutex_t g_send_lock = PTHREAD_MUTEX_INITIALIZER;

int send_frame(int fd, unsigned char type, const char *payload, size_t len) {
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
// Callers pass a NUL-terminated JSON string (some end in '\n' — harmless inside a framed
// payload, the daemon's JSON.parse ignores it).
int send_line(int fd, const char *s) { return send_frame(fd, FRAME_JSON, s, strlen(s)); }

// Fail-loud OOM reply: a command that can't allocate its response buffer must tell the
// daemon (ok:false) instead of vanishing — a silent return looks like a 10s timeout there.
void send_oom(int fd, const char *idj, const char *op) {
    char e[160]; snprintf(e, sizeof(e), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"%s\",\"ok\":false,\"error\":\"oom\"}\n", idj, op);
    send_line(fd, e);
}

// Read exactly n bytes into buf; 0 = ok, -1 = EOF/error.
int read_full(int fd, unsigned char *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, buf + off, n - off);
        if (r <= 0) return -1;
        off += (size_t)r;
    }
    return 0;
}
