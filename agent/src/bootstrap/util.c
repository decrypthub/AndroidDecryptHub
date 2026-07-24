// util.c — small stateless helpers shared across the agent: JSON escaping/extraction for our
// own controlled protocol, base64, Android system-property reads, /proc/self/cmdline, hex
// decode, and a monotonic nanosecond clock. No globals, no target knowledge.
#include "agent_internal.h"
#include <sys/system_properties.h>
#include <time.h>

void prop(const char *key, char *out, size_t n) {
    out[0] = 0;
    char buf[PROP_VALUE_MAX] = {0};
    if (__system_property_get(key, buf) > 0) { strncpy(out, buf, n - 1); out[n - 1] = 0; }
}

void read_cmdline(char *out, size_t n) {
    out[0] = 0;
    FILE *f = fopen("/proc/self/cmdline", "rb");
    if (!f) { strncpy(out, "unknown", n - 1); return; }
    size_t r = fread(out, 1, n - 1, f);
    fclose(f);
    out[r > 0 ? r : 0] = 0;
}

void json_escape(const char *in, char *out, size_t n) {
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
int json_get_str(const char *json, const char *key, char *out, size_t n) {
    char pat[64]; snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char *p = strstr(json, pat);
    if (!p) { out[0] = 0; return 0; }
    p += strlen(pat);
    size_t o = 0;
    while (*p && *p != '"' && o + 1 < n) out[o++] = *p++;
    out[o] = 0;
    return 1;
}
long long json_get_num(const char *json, const char *key) {
    char pat[64]; snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    return strtoll(p, NULL, 10);
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
size_t b64_encode(const unsigned char *in, size_t len, char *out) {
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

int hex2bytes(const char *hex, unsigned char *out, int maxlen) {
    int n = 0;
    while (hex[0] && hex[1] && n < maxlen) {
        char b[3] = { hex[0], hex[1], 0 };
        out[n++] = (unsigned char)strtol(b, NULL, 16);
        hex += 2;
    }
    return n;
}

long long now_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}
