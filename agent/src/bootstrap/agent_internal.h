// agent_internal.h — shared declarations across the agent's compilation units.
//
// The agent is split into focused modules:
//   util.c  — JSON/base64/property/time helpers (no state)
//   io.c    — socket connect + WS-D length-framed send/recv
//   mem.c   — memory read / magic scan / pattern search / maps commands
//   (hook engine, capture ring + wrappers, and the command dispatch stay in agent_main.c)
//
// This header carries the common macros + the cross-module function prototypes. No target
// knowledge lives anywhere in the agent (architecture red line): every class/module name the
// one-shot ops drive is supplied by idhd at runtime.
#ifndef IDH_AGENT_INTERNAL_H
#define IDH_AGENT_INTERNAL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <android/log.h>

#define AGENT_VER   "0.2.0"
#define IDH_HOST    "127.0.0.1"
#define IDH_PORT    8761
#define TAG         "IDH_AGENT"
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
long long now_ns(void);

// ---- io.c ----
int connect_idhd(void);
int send_all(int fd, const char *s, size_t len);
int send_frame(int fd, unsigned char type, const char *payload, size_t len);
int send_line(int fd, const char *s);
void send_oom(int fd, const char *idj, const char *op);
int read_full(int fd, unsigned char *buf, size_t n);

// ---- mem.c ----
char *build_maps_json(int limit, int *total, int *truncated);
void cmd_read(int fd, const char *id, const char *addr_hex, long long size);
void cmd_scan_magic(int fd, const char *id);
void cmd_search(int fd, const char *id, const char *pat_hex, int limit);
void cmd_maps(int fd, const char *id);

#endif
