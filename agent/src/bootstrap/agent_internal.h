// agent_internal.h — shared declarations across the agent's compilation units.
//
// Shared declarations for bootstrap helpers used across focused agent modules.
//
// This header carries the common macros + the cross-module function prototypes. No target
// knowledge lives anywhere in the agent (architecture red line): every class/module name the
// one-shot ops drive is supplied by adhd at runtime.
#ifndef ADH_AGENT_INTERNAL_H
#define ADH_AGENT_INTERNAL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <android/log.h>

// Agent build version. Keep it equal to injector/zygisk/module/module.prop: the module ships this
// .so, so "which agent is flashed?" and "which module is flashed?" must not be two different
// answers. Reported by compat_probe and in the hello; the string is already compiled in either
// way, so surfacing it adds no new string to the release image (v88 unaffected).
#define AGENT_VER   "0.3.12"
#define ADH_HOST    "127.0.0.1"
#define ADH_PORT    8761
#define TAG         "rt.agent"
#define LOGI(...)   __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...)   __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Wire framing (v2.0, WS-D): [u32 len BE][u8 type][payload of len bytes].
#define FRAME_JSON     0x01
#define FRAME_CAPTURE  0x02          // reserved (WS-C)
#define FRAME_MAX_IN   (16u << 20)   // inbound (command) payload cap — fail-loud beyond

// ---- util.c ----
void prop(const char *key, char *out, size_t n);
void read_cmdline(char *out, size_t n);
void json_escape(const char *in, char *out, size_t n);
int json_get_str(const char *json, const char *key, char *out, size_t n);
long long json_get_num(const char *json, const char *key);
size_t b64_encode(const unsigned char *in, size_t len, char *out);
int hex2bytes(const char *hex, unsigned char *out, int maxlen);
int adh_parse_u64_csv(const char *csv, unsigned long long *out, int max,
                       int *count_out, char *error, size_t error_size);
long long now_ns(void);

// ---- io.c ----
int connect_adhd(void);
int send_all(int fd, const char *s, size_t len);
int send_frame(int fd, unsigned char type, const char *payload, size_t len);
int send_line(int fd, const char *s);
void send_oom(int fd, const char *idj, const char *op);
int read_full(int fd, unsigned char *buf, size_t n);

// ---- mem.c ----
char *build_maps_json(int limit, int *total, int *truncated);
void cmd_read(int fd, const char *id, const char *addr_hex, long long size, const char *via);
// win_lo/win_hi bound the scan to [lo, hi) (0 = unbounded); regions outside are skipped, and the
// reply echoes the window so a partial scan cannot read like a full one.
void cmd_scan_magic(int fd, const char *id, unsigned long long win_lo, unsigned long long win_hi);
void cmd_search(int fd, const char *id, const char *pat_hex, int limit,
                unsigned long long win_lo, unsigned long long win_hi);
void cmd_maps(int fd, const char *id);

// ---- mem_read.c ----
// The one memory-read backend. /proc/self/mem when the target is dumpable, a bounds-checked
// direct read otherwise (see mem_read.c). Callers must not open /proc/self/mem themselves.
int adh_mem_fd(void);
void adh_mem_fd_release(void);
ssize_t adh_mem_pread(void *dst, size_t n, unsigned long long addr);
ssize_t adh_mem_read_direct(void *dst, size_t n, unsigned long long addr);
ssize_t adh_mem_read_in_region(void *dst, size_t n, unsigned long long addr,
                               unsigned long long region_end);
int adh_mem_region_end(unsigned long long addr, unsigned long long *end);
int adh_mem_backend(void);
const char *adh_mem_backend_name(void);
int adh_mem_open_errno(void);
const char *adh_mem_set_backend(const char *name);
int adh_mem_forced_direct(void);
void cmd_mem_backend(int fd, const char *id, const char *backend);

// ---- fs.c ----
void cmd_list_dir(int fd, const char *id, const char *path);
void cmd_read_file(int fd, const char *id, const char *path);

#endif
