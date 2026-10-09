// libadh_agent.so — bootstrap + command loop (v0.2)
// Dual entry:
//   - JNI_OnLoad()      : fires when a host loads us via System.loadLibrary (模拟注入 / gadget)
//   - adh_agent_start() : exported C symbol for injector-driven load
// Both connect to the Host ADH Daemon over TCP (127.0.0.1:8761, via `adb reverse`), report identity +
// an initial maps sample, then serve commands: maps / read (memory). Collect-only.

#include <jni.h>
#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <stdint.h>
#include <sys/system_properties.h>

#include "../hook/got.h"
#include "../capture/capture.h"
#include "../runtime/actions.h"
#include "../runtime/art.h"
#include "../runtime/inspection.h"
#include "../runtime/jni.h"
#include "../runtime/jni_hooks.h"
#include "../runtime/jni_env_hooks.h"
#include "../runtime/jni_onload.h"
#include "../runtime/dlopen_watch.h"
#include "../runtime/java_enum.h"
#include "../trace/commands.h"
#include "../hook/native_hooks.h"
#include "../hook/stealth_pool.h"
#include "../hook/site_hooks.h"

#ifdef ADH_HAVE_LSPLANT
#include "../hook/java_lsplant.h"
#ifndef ADH_LSPLANT_VERSION
#define ADH_LSPLANT_VERSION "unknown"
#endif
#endif

// Common macros (AGENT_VER/ADH_HOST/ADH_PORT/TAG/LOGI/LOGE/FRAME_*) + cross-module prototypes
// Shared bootstrap helpers live in agent_internal.h.
#include "agent_internal.h"

static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static char g_entry[16] = "start";
static char g_package[512] = "";

// ---- report + command loop ------------------------------------------------

static void report(int fd) {
    char cmd[512];
    if (g_package[0]) { strncpy(cmd, g_package, sizeof(cmd) - 1); cmd[sizeof(cmd) - 1] = 0; }
    else read_cmdline(cmd, sizeof(cmd));
    char pkg[1024]; json_escape(cmd, pkg, sizeof(pkg));
    char rel[PROP_VALUE_MAX]; prop("ro.build.version.release", rel, sizeof(rel));
    char sdk[PROP_VALUE_MAX]; prop("ro.build.version.sdk", sdk, sizeof(sdk));
    char abi[PROP_VALUE_MAX]; prop("ro.product.cpu.abi", abi, sizeof(abi));

    // Own-image identity: with the Zygisk memfd loader our copy has no path on disk, and a hardcoded
    // name would report a lie. Report what THIS copy is mapped as (dladdr) plus its base, so the
    // daemon can show "loaded from a memfd" per session without writing anything into the target.
    // Full path our copy was mapped under (dladdr): "/data/adb/modules/adh/libadh_agent.so" for a
    // plain load, "/memfd:jit-cache (deleted)" for the memfd loader. The short name alone would hide
    // which of the two it is.
    Dl_info self;
    const char *selfpath = (dladdr((void *)(uintptr_t)adh_self_module_name, &self) && self.dli_fname)
                               ? self.dli_fname : adh_self_module_name();
    char selfj[512];
    json_escape(selfpath, selfj, sizeof(selfj));
    unsigned long long self_start = 0, self_end = 0;
    if (!adh_self_image_bounds(&self_start, &self_end)) self_start = 0;

    char hello[1600];
    snprintf(hello, sizeof(hello),
        "{\"t\":\"hello\",\"agentVer\":\"%s\",\"pid\":%d,\"uid\":%d,"
        "\"package\":\"%s\",\"process\":\"%s\",\"abi\":\"%s\",\"android\":\"%s\",\"sdk\":%s,"
        "\"entry\":\"%s\",\"selfModule\":\"%s\",\"selfBase\":\"0x%llx\"}\n",
        AGENT_VER, getpid(), getuid(), pkg, pkg,
        abi[0] ? abi : "?", rel[0] ? rel : "?", sdk[0] ? sdk : "0", g_entry,
        selfj, self_start);
    if (send_line(fd, hello) != 0) { LOGE("send hello failed"); return; }

    int total = 0;
    char *sample = build_maps_json(40, &total, NULL);
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

// Probe the optional LSPlant backend without installing a Java hook. This proves the
// static linkage and ART initialization state, and keeps startup footprint unchanged.
static void cmd_javahook_probe(int fd, const char *id) {
    char idj[64];
    json_escape(id, idj, sizeof(idj));
#ifdef ADH_HAVE_LSPLANT
    int did_attach = 0;
    JNIEnv *env = adh_jni_attach(&did_attach);
    if (!env) {
        char out[240];
        snprintf(out, sizeof(out),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"javahook_probe\",\"ok\":false,\"available\":true,\"error\":\"no JavaVM\"}\n", idj);
        send_line(fd, out);
        return;
    }
    int init_ok = adh_javahook_init(env);
    const char *err = adh_javahook_last_error();
    if (did_attach) adh_jni_detach(did_attach);
    char errj[512];
    json_escape(err ? err : "", errj, sizeof(errj));
    char out[1024];
    snprintf(out, sizeof(out),
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"javahook_probe\",\"ok\":%s,\"available\":true,"
             "\"initOk\":%s,\"backend\":\"art\",\"version\":\"%s\",\"error\":\"%s\"}\n",
             idj, init_ok ? "true" : "false", init_ok ? "true" : "false", ADH_LSPLANT_VERSION, errj);
    send_line(fd, out);
    LOGI("javahook_probe: init=%d error=%s", init_ok, err ? err : "");
#else
    char out[240];
    snprintf(out, sizeof(out),
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"javahook_probe\",\"ok\":false,\"available\":false,"
             "\"error\":\"java hook backend not built in this build\"}\n", idj);
    send_line(fd, out);
#endif
}
// Generic single Java-method hook command. All target identity comes from the command;
// the agent has no sandbox/package/class constants.
static void cmd_java_hook(int fd, const char *id, const char *action, const char *class_name,
                          const char *method_name, const char *params, int skip_original,
                          const char *override_return, long long arg_index, const char *arg_value,
                          long long requested_hook_id, int capture_stack_flag, long long max_hooks) {
    char idj[64];
    json_escape(id, idj, sizeof(idj));
#ifdef ADH_HAVE_LSPLANT
    int did_attach = 0;
    JNIEnv *env = adh_jni_attach(&did_attach);
    if (!env) {
        char out[220];
        snprintf(out, sizeof(out),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"java_hook\",\"ok\":false,\"error\":\"no JavaVM\"}\n", idj);
        send_line(fd, out);
        return;
    }

    char error[512] = "";
    int ok = 0;
    int new_hook_id = 0;
    int hook_ids[ADH_JAVA_HOOK_MAX];
    int hook_id_count = 0;
    int matched_count = 0;
    int collect_capped = 0;
    int applied_limit = 0;
    int batch_partial = 0;
    int ids_truncated = 0;
    if (strcmp(action, "hook") == 0) {
        if (!class_name[0] || !method_name[0]) {
            snprintf(error, sizeof(error), "hook requires className and method");
        } else {
            ok = adh_javahook_hook_method(env, class_name, method_name, params, skip_original,
                                             override_return, (int)arg_index, arg_value, capture_stack_flag,
                                             &new_hook_id, error, sizeof(error));
        }
    } else if (strcmp(action, "hook_all") == 0) {
        if (!class_name[0]) {
            snprintf(error, sizeof(error), "hook_all requires className");
        } else {
            applied_limit = (int)((max_hooks > 0 && max_hooks <= ADH_JAVA_HOOK_MAX) ? max_hooks : ADH_JAVA_HOOK_MAX);
            ok = adh_javahook_hook_all(env, class_name, method_name, params, skip_original,
                                       override_return, (int)arg_index, arg_value, capture_stack_flag,
                                       applied_limit, hook_ids, ADH_JAVA_HOOK_MAX, &matched_count,
                                       &collect_capped, error, sizeof(error));
            hook_id_count = ok > 0 ? ok : 0;
            new_hook_id = hook_id_count > 0 ? hook_ids[0] : 0;
            // A batch that installed fewer hooks than it matched is either truncated by the slot
            // limit or partially failed - both must be visible, not inferred from the numbers.
            if (ok > 0 && hook_id_count < matched_count) batch_partial = 1;
            if (error[0]) batch_partial = 1;
        }
    } else if (strcmp(action, "unhook") == 0) {
        ok = adh_javahook_unhook_id(env, (int)requested_hook_id, error, sizeof(error));
    } else if (strcmp(action, "status") == 0) {
        ok = 1;
    } else {
        snprintf(error, sizeof(error), "java_hook requires action: hook | hook_all | unhook | status");
    }

    char *status = (char *)malloc(65536);
    if (!status) {
        if (did_attach) adh_jni_detach(did_attach);
        send_oom(fd, idj, "java_hook");
        return;
    }
    status[0] = 0;
    adh_javahook_status_json(env, status, 65536);
    if (did_attach) adh_jni_detach(did_attach);

    char errj[768];
    json_escape(error, errj, sizeof(errj));
    size_t out_len = strlen(status) + 2048;
    char *out = (char *)malloc(out_len);
    if (!out) {
        free(status);
        send_oom(fd, idj, "java_hook");
        return;
    }
    // hook_all reports every id it installed plus how many methods matched, so a slot-limited or
    // partially failed batch is visible rather than looking like a complete one.
    char ids_json[512] = "";
    if (hook_id_count > 0) {
        size_t used = (size_t)snprintf(ids_json, sizeof(ids_json), ",\"hookIds\":[");
        int written = 0;
        for (int i = 0; i < hook_id_count; i++) {
            int n = snprintf(ids_json + used, sizeof(ids_json) - used, "%s%d", i ? "," : "", hook_ids[i]);
            if (n <= 0 || (size_t)n >= sizeof(ids_json) - used) { ids_truncated = 1; break; }
            used += (size_t)n;
            written++;
        }
        if (written < hook_id_count) ids_truncated = 1;
        size_t tail = strnlen(ids_json, sizeof(ids_json));
        snprintf(ids_json + tail, sizeof(ids_json) - tail, "],\"matched\":%d,\"limit\":%d%s%s%s",
                 matched_count, applied_limit,
                 collect_capped ? ",\"matchedCapped\":true" : "",
                 ids_truncated ? ",\"hookIdsTruncated\":true" : "",
                 batch_partial ? ",\"partial\":true" : "");
    }
    snprintf(out, out_len,
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"java_hook\",\"ok\":%s,\"action\":\"%s\","
             "\"hookId\":%d%s,\"error\":\"%s\",\"status\":%s}\n",
             idj, ok ? "true" : "false", action, new_hook_id, ids_json, errj, status);
    send_line(fd, out);
    free(status);
    free(out);
    LOGI("java_hook: action=%s ok=%d error=%s", action, ok, error);
#else
    (void)action; (void)class_name; (void)method_name; (void)params; (void)skip_original;
    (void)override_return; (void)arg_index; (void)arg_value; (void)requested_hook_id;
    char out[240];
    snprintf(out, sizeof(out),
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"java_hook\",\"ok\":false,"
             "\"error\":\"java hook backend not built in this build\"}\n", idj);
    send_line(fd, out);
#endif
}
static void cmd_java_enum(int fd, const char *id, const char *class_name) {
    char idj[64];
    json_escape(id, idj, sizeof(idj));
    int did_attach = 0;
    JNIEnv *env = adh_jni_attach(&did_attach);
    if (!env) {
        char out[220];
        snprintf(out, sizeof(out),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"java_enum\",\"ok\":false,\"error\":\"no JavaVM\"}\n", idj);
        send_line(fd, out);
        return;
    }
    char error[512] = "";
    char *json = NULL;
    int ok = adh_java_enum_json(env, class_name, &json, error, sizeof(error));
    if (did_attach) adh_jni_detach(did_attach);
    if (ok && json) {
        size_t len = strlen(json) + 512;
        char *out = (char *)malloc(len);
        if (!out) {
            adh_java_enum_free(json);
            send_oom(fd, idj, "java_enum");
            return;
        }
        snprintf(out, len,
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"java_enum\",\"ok\":true,\"result\":%s}\n",
                 idj, json);
        send_line(fd, out);
        free(out);
        adh_java_enum_free(json);
    } else {
        char errj[768];
        json_escape(error, errj, sizeof(errj));
        char out[1024];
        snprintf(out, sizeof(out),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"java_enum\",\"ok\":false,\"error\":\"%s\"}\n",
                 idj, errj);
        send_line(fd, out);
        if (json) adh_java_enum_free(json);
    }
}
static void cmd_java_call(int fd, const char *id, const char *class_name, const char *method_name,
                          const char *params, const char *field_name, const char *args_json) {
    char idj[64];
    json_escape(id, idj, sizeof(idj));
    int did_attach = 0;
    JNIEnv *env = adh_jni_attach(&did_attach);
    if (!env) {
        char out[220];
        snprintf(out, sizeof(out),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"java_call\",\"ok\":false,\"error\":\"no JavaVM\"}\n", idj);
        send_line(fd, out);
        return;
    }
    char error[512] = "";
    char *json = NULL;
    int ok = adh_java_call_json(env, class_name, method_name, params, field_name, args_json,
                                &json, error, sizeof(error));
    if (did_attach) adh_jni_detach(did_attach);
    if (ok && json) {
        size_t len = strlen(json) + 512;
        char *out = (char *)malloc(len);
        if (!out) {
            adh_java_enum_free(json);
            send_oom(fd, idj, "java_call");
            return;
        }
        snprintf(out, len,
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"java_call\",\"ok\":true,\"result\":%s}\n",
                 idj, json);
        send_line(fd, out);
        free(out);
        adh_java_enum_free(json);
    } else {
        char errj[768];
        json_escape(error, errj, sizeof(errj));
        char out[1024];
        snprintf(out, sizeof(out),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"java_call\",\"ok\":false,\"error\":\"%s\"}\n",
                 idj, errj);
        send_line(fd, out);
        if (json) adh_java_enum_free(json);
    }
}
static void cmd_native_hook(int fd, const char *id, const char *action, const char *mode,
                            const char *module, const char *symbol, const char *addr,
                            int skip_original, const char *return_value, long long arg_index,
                            const char *arg_value, long long requested_id, int hard, int max_sites,
                            const char *sites_scope, int allow_writable_slots, int want_backtrace,
                            int throttle_ms) {
    char idj[64];
    json_escape(id, idj, sizeof(idj));
    char error[512] = "";
    int ok = 0;
    int new_id = 0;
    if (strcmp(action, "hook") == 0) {
        ok = adh_native_hook_install(mode, module, symbol, addr, skip_original, return_value[0] ? 1 : 0,
                                    (uint64_t)strtoull(return_value, NULL, 0), (int)arg_index,
                                    (uint64_t)strtoull(arg_value, NULL, 0), max_sites, sites_scope,
                                    allow_writable_slots, want_backtrace, throttle_ms, &new_id, error, sizeof(error));
    } else if (strcmp(action, "unhook") == 0) {
        ok = adh_native_hook_unhook((int)requested_id, hard, error, sizeof(error));
    } else if (strcmp(action, "status") == 0) {
        ok = 1;
    } else {
        snprintf(error, sizeof(error), "native_hook requires action: hook | unhook | status");
    }
    char *status = (char *)malloc(65536);
    if (!status) {
        send_oom(fd, idj, "native_hook");
        return;
    }
    status[0] = 0;
    adh_native_hook_status_json(status, 65536);
    char errj[768];
    json_escape(error, errj, sizeof(errj));
    size_t out_len = strlen(status) + 1024;
    char *out = (char *)malloc(out_len);
    if (!out) {
        send_oom(fd, idj, "native_hook");
        return;
    }
    snprintf(out, out_len,
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"native_hook\",\"ok\":%s,\"action\":\"%s\","
             "\"hookId\":%d,\"error\":\"%s\",\"status\":%s}\n",
             idj, ok ? "true" : "false", action, new_id, errj, status);
    send_line(fd, out);
    free(out);
    free(status);
    LOGI("native_hook: action=%s ok=%d id=%d error=%s", action, ok, new_id, error);
}
static void cmd_got_enum(int fd, const char *id, const char *module, const char *filter) {
    char idj[64];
    json_escape(id, idj, sizeof(idj));
    char error[512] = "";
    char *json = NULL;
    int ok = adh_got_enum_json(module, filter, &json, error, sizeof(error));
    if (ok && json) {
        size_t len = strlen(json) + 512;
        char *out = (char *)malloc(len);
        if (!out) {
            free(json);
            send_oom(fd, idj, "got_enum");
            return;
        }
        snprintf(out, len,
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"got_enum\",\"ok\":true,\"result\":%s}\n",
                 idj, json);
        send_line(fd, out);
        free(out);
        free(json);
    } else {
        char errj[768];
        json_escape(error, errj, sizeof(errj));
        char out[1024];
        snprintf(out, sizeof(out),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"got_enum\",\"ok\":false,\"error\":\"%s\"}\n",
                 idj, errj);
        send_line(fd, out);
        if (json) free(json);
    }
}
// Read framed commands from the Host ADH Daemon and dispatch.
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
                    char addr[40] = "", via[16] = "";
                    json_get_str(line, "addr", addr, sizeof(addr));
                    json_get_str(line, "via", via, sizeof(via));
                    long long size = json_get_num(line, "size");
                    cmd_read(fd, id, addr, size, via);
                } else if (strcmp(op, "jni_hook") == 0) {
                    char jaction[16] = "";
                    json_get_str(line, "action", jaction, sizeof(jaction));
                    adh_cmd_jni_hook(fd, id, jaction);
                } else if (strcmp(op, "jni_onload") == 0) {
                    char oaction[16] = "", omodule[160] = "", oskip[8] = "", oreturn[32] = "";
                    json_get_str(line, "action", oaction, sizeof(oaction));
                    json_get_str(line, "module", omodule, sizeof(omodule));
                    json_get_str(line, "skipOriginal", oskip, sizeof(oskip));
                    json_get_str(line, "returnValue", oreturn, sizeof(oreturn));
                    int oskip_original = (strcmp(oskip, "true") == 0 || strcmp(oskip, "1") == 0);
                    int oreturn_value = oreturn[0] ? (int)strtol(oreturn, NULL, 0) : 0;
                    adh_cmd_jni_onload(fd, id, oaction, omodule, oskip_original, oreturn_value);
                } else if (strcmp(op, "jni_env_hook") == 0) {
                    char eaction[16] = "", efunction[64] = "", esetval[48] = "";
                    json_get_str(line, "action", eaction, sizeof(eaction));
                    json_get_str(line, "function", efunction, sizeof(efunction));
                    json_get_str(line, "setValue", esetval, sizeof(esetval));
                    // setValue rewrites what a Set<Type>Field hook stores. Parsed into both an integer
                    // and a double so the slot wrapper can use the one its field type needs.
                    int eov_active = 0; long long eov_i = 0; double eov_d = 0;
                    if (esetval[0]) {
                        // Strict: the WHOLE string must be a number. strtoll/strtod with a NULL endptr
                        // would turn a typo into 0 and silently rewrite the field (the same bug class
                        // the v4.53 review caught in object_set). A value that only the float parser
                        // accepts (like 1e3) is also mirrored into the integer slot so an int field
                        // does not get a truncated 1.
                        char *end_i = NULL, *end_d = NULL;
                        errno = 0;
                        eov_i = strtoll(esetval, &end_i, 0);
                        int int_ok = (errno == 0 && end_i != esetval && *end_i == '\0');
                        errno = 0;
                        eov_d = strtod(esetval, &end_d);
                        int dbl_ok = (errno == 0 && end_d != esetval && *end_d == '\0');
                        if (!int_ok && !dbl_ok) {
                            char idj[64]; json_escape(id, idj, sizeof(idj));
                            char ej[128]; json_escape(esetval, ej, sizeof(ej));
                            char e[256];
                            snprintf(e, sizeof(e),
                                     "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"jni_env_hook\",\"ok\":false,"
                                     "\"error\":\"setValue must be a number, got '%s'\"}\n", idj, ej);
                            send_line(fd, e);
                            return;
                        }
                        if (int_ok) eov_d = (double)eov_i;
                        else eov_i = (long long)eov_d;
                        eov_active = 1;
                    }
                    adh_cmd_jni_env_hook(fd, id, eaction, efunction, eov_active, eov_i, eov_d);
                } else if (strcmp(op, "java_hook") == 0) {
                    char jaction[16] = "", jcls[256] = "", jmethod[128] = "", jparams[512] = "";
                    char jskip[8] = "", jreturn[512] = "", jargvalue[512] = "", jstack[8] = "";
                    json_get_str(line, "action", jaction, sizeof(jaction));
                    long long jmax_hooks = json_get_num(line, "limit");
                    json_get_str(line, "className", jcls, sizeof(jcls));
                    json_get_str(line, "method", jmethod, sizeof(jmethod));
                    json_get_str(line, "params", jparams, sizeof(jparams));
                    json_get_str(line, "skipOriginal", jskip, sizeof(jskip));
                    json_get_str(line, "returnValue", jreturn, sizeof(jreturn));
                    json_get_str(line, "argValue", jargvalue, sizeof(jargvalue));
                    json_get_str(line, "stack", jstack, sizeof(jstack));
                    long long jhook_id = json_get_num(line, "hookId");
                    int skip_original = (strcmp(jskip, "true") == 0 || strcmp(jskip, "1") == 0);
                    long long jarg_index = json_get_num(line, "argIndex");
                    // Opt-in per-hook caller chain (the Java analogue of the native backtrace).
                    int jcapture_stack = (strcmp(jstack, "true") == 0 || strcmp(jstack, "1") == 0) ? 1 : 0;
                    if (strstr(line, "\"stack\":true") != NULL) jcapture_stack = 1;
                    cmd_java_hook(fd, id, jaction, jcls, jmethod, jparams, skip_original, jreturn, jarg_index, jargvalue, jhook_id, jcapture_stack, jmax_hooks);
                } else if (strcmp(op, "java_enum") == 0) {
                    char jcls[256] = "";
                    json_get_str(line, "className", jcls, sizeof(jcls));
                    cmd_java_enum(fd, id, jcls);
                } else if (strcmp(op, "java_call") == 0) {
                    char jcls[256] = "", jmethod[128] = "", jparams[512] = "", jfield[128] = "", jargs[2048] = "";
                    json_get_str(line, "className", jcls, sizeof(jcls));
                    json_get_str(line, "method", jmethod, sizeof(jmethod));
                    json_get_str(line, "params", jparams, sizeof(jparams));
                    json_get_str(line, "field", jfield, sizeof(jfield));
                    json_get_str(line, "args", jargs, sizeof(jargs));
                    cmd_java_call(fd, id, jcls, jmethod, jparams, jfield, jargs);
                } else if (strcmp(op, "native_hook") == 0) {
                    char naction[16] = "", nmode[16] = "", nmodule[128] = "", nsymbol[160] = "", naddr[32] = "";
                    char nskip[8] = "", nreturn[64] = "", nargvalue[64] = "";
                    json_get_str(line, "action", naction, sizeof(naction));
                    json_get_str(line, "mode", nmode, sizeof(nmode));
                    json_get_str(line, "module", nmodule, sizeof(nmodule));
                    json_get_str(line, "symbol", nsymbol, sizeof(nsymbol));
                    json_get_str(line, "addr", naddr, sizeof(naddr));
                    json_get_str(line, "skipOriginal", nskip, sizeof(nskip));
                    json_get_str(line, "returnValue", nreturn, sizeof(nreturn));
                    json_get_str(line, "argValue", nargvalue, sizeof(nargvalue));
                    long long nid = json_get_num(line, "hookId");
                    long long nargindex = json_get_num(line, "argIndex");
                    int nskip_original = (strcmp(nskip, "true") == 0 || strcmp(nskip, "1") == 0);
                    char nhard[8] = "";
                    json_get_str(line, "hard", nhard, sizeof(nhard));
                    int nhard_flag = (strcmp(nhard, "true") == 0 || strcmp(nhard, "1") == 0);
                    char nscope[96] = "", nslotsrw[8] = "";
                    json_get_str(line, "scope", nscope, sizeof(nscope));
                    json_get_str(line, "slotsWritable", nslotsrw, sizeof(nslotsrw));
                    long long nsites = json_get_num(line, "sites");
                    // Clamp instead of dropping a too-large request back to the default: silently
                    // installing a different number than asked for is exactly what this tool must not do.
                    int nsites_flag = nsites > 64 ? 64 : (nsites > 0 ? (int)nsites : 0);
                    // Accept a JSON boolean too: the daemon sends the string "true"/"false", but a
                    // direct HTTP caller may send a real boolean, and silently treating that as
                    // false would install less than the caller asked for.
                    int slots_writable_flag = (strcmp(nslotsrw, "true") == 0 || strcmp(nslotsrw, "1") == 0) ? 1 : 0;
                    if (strstr(line, "\"slotsWritable\":true") != NULL) slots_writable_flag = 1;
                    // Opt-in per-hook caller chain (x30 + x29 walk) for the host backtrace tool.
                    char nbt[8] = "";
                    json_get_str(line, "backtrace", nbt, sizeof(nbt));
                    int backtrace_flag = (strcmp(nbt, "true") == 0 || strcmp(nbt, "1") == 0) ? 1 : 0;
                    if (strstr(line, "\"backtrace\":true") != NULL) backtrace_flag = 1;
                    // Per-hook event throttle (v4.48): at most one event per window, so a hot site
                    // (read/write/futex) cannot flood the ring. Absent or negative means off
                    // (json_get_num answers -1 for a missing key); a too-large window is clamped to
                    // the same ceiling the agent applies, and status echoes the effective value.
                    long long nthrottle = json_get_num(line, "throttleMs");
                    int nthrottle_ms = nthrottle > ADH_NATIVE_THROTTLE_MAX_MS ? ADH_NATIVE_THROTTLE_MAX_MS
                                       : (nthrottle > 0 ? (int)nthrottle : 0);
                    cmd_native_hook(fd, id, naction, nmode, nmodule, nsymbol, naddr, nskip_original, nreturn, nargindex, nargvalue, nid, nhard_flag, nsites_flag, nscope, slots_writable_flag, backtrace_flag, nthrottle_ms);
                } else if (strcmp(op, "native_call") == 0) {
                    char cmodule[128] = "", csymbol[160] = "", caddr[32] = "", cargs[256] = "";
                    json_get_str(line, "module", cmodule, sizeof(cmodule));
                    json_get_str(line, "symbol", csymbol, sizeof(csymbol));
                    json_get_str(line, "addr", caddr, sizeof(caddr));
                    json_get_str(line, "args", cargs, sizeof(cargs));
                    adh_cmd_native_call(fd, id, cmodule, csymbol, caddr, cargs);
                } else if (strcmp(op, "got_enum") == 0) {
                    char gmodule[128] = "", gfilter[160] = "";
                    json_get_str(line, "module", gmodule, sizeof(gmodule));
                    json_get_str(line, "filter", gfilter, sizeof(gfilter));
                    cmd_got_enum(fd, id, gmodule, gfilter);
                } else if (strcmp(op, "stealth") == 0) {
                    char saction[16] = "";
                    json_get_str(line, "action", saction, sizeof(saction));
                    adh_cmd_stealth(fd, id, saction);
                } else if (strcmp(op, "javahook_probe") == 0) {
                    cmd_javahook_probe(fd, id);
                } else if (strcmp(op, "gothook_selftest") == 0) {
                    adh_cmd_gothook_selftest(fd, id);
                } else if (strcmp(op, "capture_start") == 0) {
                    char cmod[64] = "", fmod[64] = "", smod[64] = "";
                    json_get_str(line, "cryptoModule", cmod, sizeof(cmod));
                    json_get_str(line, "fileModule", fmod, sizeof(fmod));
                    json_get_str(line, "sysModule", smod, sizeof(smod));
                    adh_cmd_capture_start(fd, id, cmod, fmod, smod);
                } else if (strcmp(op, "capture_drain") == 0) {
                    adh_cmd_capture_drain(fd, id);
                } else if (strcmp(op, "capture_stop") == 0) {
                    adh_cmd_capture_stop(fd, id);
                } else if (strcmp(op, "trigger") == 0) {
                    char tcls[200] = "", tm[80] = "";
                    json_get_str(line, "className", tcls, sizeof(tcls));
                    json_get_str(line, "method", tm, sizeof(tm));
                    long long lv = json_get_num(line, "level");
                    adh_cmd_trigger(fd, id, tcls, tm, lv > 0 ? (int)lv : 1);
                } else if (strcmp(op, "load_so") == 0) {
                    char lpath[400] = "", lsym[96] = "";
                    json_get_str(line, "path", lpath, sizeof(lpath));
                    json_get_str(line, "symbol", lsym, sizeof(lsym));
                    adh_cmd_load_so(fd, id, lpath, lsym);
                } else if (strcmp(op, "file_probe") == 0) {
                    adh_cmd_file_probe(fd, id);
                } else if (strcmp(op, "qbdi_trace") == 0) {
                    char sl[64] = "", sy[80] = "", targs[256] = "";
                    json_get_str(line, "symLib", sl, sizeof(sl));
                    json_get_str(line, "symbol", sy, sizeof(sy));
                    json_get_str(line, "args", targs, sizeof(targs));
                    adh_cmd_qbdi_trace(fd, id, sl, sy, targs);
                } else if (strcmp(op, "compat_probe") == 0) {
                    adh_cmd_compat_probe(fd, id);
                } else if (strcmp(op, "object_inspect") == 0) {
                    char cls[160] = "", fld[64] = "";
                    json_get_str(line, "className", cls, sizeof(cls));
                    json_get_str(line, "field", fld, sizeof(fld));
                    adh_cmd_object_inspect(fd, id, cls, fld);
                } else if (strcmp(op, "object_set") == 0) {
                    char scls[256] = "", sholder[128] = "", sfield[128] = "", svalue[512] = "";
                    json_get_str(line, "className", scls, sizeof(scls));
                    json_get_str(line, "field", sholder, sizeof(sholder));
                    json_get_str(line, "targetField", sfield, sizeof(sfield));
                    json_get_str(line, "value", svalue, sizeof(svalue));
                    // json_get_str truncates silently, and writing a TRUNCATED value into a live
                    // target while reporting ok:true is worse than refusing: a full buffer means the
                    // parser had to cut it, so fail loud instead.
                    if (strlen(scls) >= sizeof(scls) - 1 || strlen(sholder) >= sizeof(sholder) - 1 ||
                        strlen(sfield) >= sizeof(sfield) - 1 || strlen(svalue) >= sizeof(svalue) - 1) {
                        char idj[64]; json_escape(id, idj, sizeof(idj));
                        char e[192];
                        snprintf(e, sizeof(e),
                                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_set\",\"ok\":false,"
                                 "\"error\":\"argument too long (the parser would have truncated it)\"}\n", idj);
                        send_line(fd, e);
                    } else {
                        adh_cmd_object_set(fd, id, scls, sholder, sfield, svalue);
                    }
                } else if (strcmp(op, "object_invoke") == 0) {
                    char cls[160] = "", fld[64] = "", mth[64] = "";
                    json_get_str(line, "className", cls, sizeof(cls));
                    json_get_str(line, "field", fld, sizeof(fld));
                    json_get_str(line, "method", mth, sizeof(mth));
                    adh_cmd_object_invoke(fd, id, cls, fld, mth);
                } else if (strcmp(op, "art_dexfiles") == 0) {
                    adh_cmd_art_dexfiles(fd, id);
                } else if (strcmp(op, "list_dir") == 0) {
                    char path[2048] = ""; json_get_str(line, "path", path, sizeof(path));
                    cmd_list_dir(fd, id, path);
                } else if (strcmp(op, "read_file") == 0) {
                    char path[2048] = ""; json_get_str(line, "path", path, sizeof(path));
                    cmd_read_file(fd, id, path);
                } else if (strcmp(op, "scan_magic") == 0) {
                    char lo[24] = "", hi[24] = "";
                    json_get_str(line, "minAddr", lo, sizeof(lo));
                    json_get_str(line, "maxAddr", hi, sizeof(hi));
                    cmd_scan_magic(fd, id, strtoull(lo, NULL, 16), strtoull(hi, NULL, 16));
                } else if (strcmp(op, "mem_backend") == 0) {
                    char mb[32] = ""; json_get_str(line, "backend", mb, sizeof(mb));
                    cmd_mem_backend(fd, id, mb);
                } else if (strcmp(op, "search") == 0) {
                    char pat[520] = "", lo[24] = "", hi[24] = "";
                    json_get_str(line, "pat", pat, sizeof(pat));
                    json_get_str(line, "minAddr", lo, sizeof(lo));
                    json_get_str(line, "maxAddr", hi, sizeof(hi));
                    long long lim = json_get_num(line, "limit");
                    cmd_search(fd, id, pat, (int)lim, strtoull(lo, NULL, 16), strtoull(hi, NULL, 16));
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

// The agent owns the connection and must outlive a host restart: the daemon is restarted on
// every upgrade, and dropping the socket used to orphan the target forever (no captures, no
// commands until the app itself was restarted). Reconnect forever with a mild backoff. The
// first failure and then every ~10s are logged, so a missing `adb reverse` stays visible
// without spamming logcat. Kept deliberately small: one sleeping thread, no queues.
static void *agent_thread(void *arg) {
    (void)arg;
    int failed = 0;
    for (;;) {
        int fd = connect_adhd();
        if (fd >= 0) {
            if (failed) LOGI("reconnected to host daemon %s:%d after %d failed attempts", ADH_HOST, ADH_PORT, failed);
            else LOGI("connected to host daemon %s:%d", ADH_HOST, ADH_PORT);
            failed = 0;
            report(fd);
            command_loop(fd);
            close(fd);
            LOGI("host daemon connection closed; reconnecting");
            usleep(1000 * 1000);   // give a restarting daemon time to bind before re-dialling
            continue;
        }
        if (failed == 0 || failed % 20 == 0)
            LOGE("host daemon unreachable (attempt %d, need: adb reverse tcp:%d tcp:%d)", failed + 1, ADH_PORT, ADH_PORT);
        failed++;
        usleep(500 * 1000);
    }
    return NULL;
}

static void do_start(void) {
    pthread_t t;
    if (pthread_create(&t, NULL, agent_thread, NULL) == 0) pthread_detach(t);
    else LOGE("pthread_create failed");
}

__attribute__((visibility("default")))
void adh_agent_set_package(const char *pkg) {
    if (pkg && pkg[0]) {
        strncpy(g_package, pkg, sizeof(g_package) - 1);
        g_package[sizeof(g_package) - 1] = 0;
    }
}

// More than one backend can load this .so into one process (Zygisk + self-load + Xposed).
// Each copy has its own pthread_once; only the first copy in link-map order may bootstrap.
struct AgentCopyCtx {
    unsigned char own_id[64];   // GNU build ID: identifies "another copy of this exact file"
    size_t own_id_len;
    unsigned long long own_span;  // fallback when either copy has no build ID
    void *first_base;
};

static int find_first_agent_copy(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    struct AgentCopyCtx *ctx = (struct AgentCopyCtx *)data;
    // Never match by name: a memfd copy has no stable name (both copies would read "jit-cache") and
    // dlpi_name may differ from the path dladdr reports. Identity is the GNU build ID - exact for two
    // copies of the same file - falling back to the image span only when a build ID is unavailable.
    // The span is computed inline (a nested dl_iterate_phdr from this callback is undocumented and
    // quadratic). dl_iterate_phdr walks in load order, so the FIRST match - ourselves included - owns
    // the process-global bootstrap; later copies stay inert. Excluding our own base instead would
    // make every copy decide it is not first, i.e. the agent would never start.
    const void *base = (const void *)(uintptr_t)info->dlpi_addr;
    unsigned char id[64];
    size_t id_len = 0;
    int has_id = adh_build_id_from_phdr(base, info->dlpi_phdr, (int)info->dlpi_phnum, id, sizeof(id), &id_len);
    if (ctx->own_id_len && has_id) {
        if (id_len != ctx->own_id_len || memcmp(id, ctx->own_id, id_len) != 0) return 0;
    } else {
        unsigned long long lo = ~0ULL, hi = 0;
        for (int i = 0; i < info->dlpi_phnum; i++) {
            const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
            if (ph->p_type != PT_LOAD || !ph->p_memsz) continue;
            unsigned long long s = (unsigned long long)ph->p_vaddr;
            unsigned long long e = s + (unsigned long long)ph->p_memsz;
            if (s < lo) lo = s;
            if (e > hi) hi = e;
        }
        if (!hi || lo == ~0ULL || hi - lo != ctx->own_span) return 0;
    }
    ctx->first_base = (void *)(uintptr_t)info->dlpi_addr;
    return 1;   // stop at the first copy of our image
}

static int current_agent_copy_is_owner(void) {
    Dl_info self;
    if (!dladdr((void *)(uintptr_t)current_agent_copy_is_owner, &self) || !self.dli_fbase) {
        LOGI("single-instance guard unavailable (dladdr) — continuing");
        return 1;
    }
    struct AgentCopyCtx ctx = {0};
    adh_self_build_id(ctx.own_id, sizeof(ctx.own_id), &ctx.own_id_len);
    unsigned long long self_start = 0, self_end = 0;
    if (adh_image_bounds_of(self.dli_fbase, &self_start, &self_end)) ctx.own_span = self_end - self_start;
    if (!ctx.own_id_len && !ctx.own_span) {
        LOGI("single-instance guard unavailable (no build ID, no PT_LOAD span) — continuing");
        return 1;
    }
    // A build ID only proves "same file": two DIFFERENT builds of the agent loaded together both
    // consider themselves first. That is a deployment error (stale module + fresh sandbox); the span
    // is logged so the duplicate sessions in the daemon can be traced back to it.
    LOGI("single-instance check: id=%s span=%llu", ctx.own_id_len ? "build-id" : "span",
         (unsigned long long)ctx.own_span);
    dl_iterate_phdr(find_first_agent_copy, &ctx);
    if (!ctx.first_base) {
        LOGI("single-instance guard: agent not found in link map — continuing");
        return 1;
    }
    if (ctx.first_base != self.dli_fbase) {
        LOGI("another agent copy was loaded first — skipping bootstrap");
        return 0;
    }
    return 1;
}

static void start_reporter_watch(void);   // defined below

__attribute__((visibility("default")))
void adh_agent_start(void) {
    // Same single-instance rule as JNI_OnLoad: a second copy in this process must stay inert.
    if (!current_agent_copy_is_owner()) return;
    adh_footprint_capture_baseline();
    strncpy(g_entry, "start", sizeof(g_entry) - 1);
    start_reporter_watch();
    pthread_once(&g_once, do_start);
}

// If the target published its Java rich-capture reporter class via the "adh.reporter.class"
// system property, bind adh_nreport_impl onto its nReport method (RegisterNatives). Target-
// agnostic: the agent knows no class name.
static int bind_reporter_from_prop(JNIEnv *env) {
    jclass sysCls = (*env)->FindClass(env, "java/lang/System");
    jmethodID getProp = sysCls ? (*env)->GetStaticMethodID(env, sysCls, "getProperty", "(Ljava/lang/String;)Ljava/lang/String;") : NULL;
    if (!getProp) { if (adh_jni_exception_check(env)) adh_jni_exception_clear(env); return 0; }
    jstring jkey = (*env)->NewStringUTF(env, "adh.reporter.class");
    jstring jval = jkey ? (jstring)(*env)->CallStaticObjectMethod(env, sysCls, getProp, jkey) : NULL;
    if (!jval) {
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
        return 0;
    }
    const char *cls = (*env)->GetStringUTFChars(env, jval, NULL);
    int ok = 0;
    if (cls && cls[0]) {
        ok = adh_capture_register_reporter(env, cls);
        LOGI("rich-capture reporter '%s' bind %s", cls, ok ? "ok" : "FAILED");
    }
    if (cls) (*env)->ReleaseStringUTFChars(env, jval, cls);
    if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
    return ok;
}

// Zygisk starts before the app sets adh.reporter.class; poll briefly from the winning copy so the
// reporter still binds without opening a second agent copy/session.
#define ADH_REPORTER_WATCH_STEP_MS 50
#define ADH_REPORTER_WATCH_TOTAL_MS 10000
static void *reporter_watch_thread(void *arg) {
    (void)arg;
    for (int waited = 0; waited < ADH_REPORTER_WATCH_TOTAL_MS; waited += ADH_REPORTER_WATCH_STEP_MS) {
        int did = 0;
        JNIEnv *env = adh_jni_attach(&did);
        if (env) {
            int ok = bind_reporter_from_prop(env);
            if (did) adh_jni_detach(did);
            if (ok) return NULL;
        }
        usleep(ADH_REPORTER_WATCH_STEP_MS * 1000);
    }
    return NULL;
}

static void start_reporter_watch(void) {
    static int started = 0;
    if (__atomic_exchange_n(&started, 1, __ATOMIC_SEQ_CST)) return;
    pthread_t th;
    if (pthread_create(&th, NULL, reporter_watch_thread, NULL) == 0) {
        pthread_detach(th);
    } else {
        __atomic_store_n(&started, 0, __ATOMIC_SEQ_CST);
        LOGI("reporter watcher thread create failed");
    }
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    if (!current_agent_copy_is_owner()) return JNI_VERSION_1_6;
    adh_footprint_capture_baseline();
    adh_jni_set_vm(vm);
    strncpy(g_entry, "jni_onload", sizeof(g_entry) - 1);
    LOGI("JNI_OnLoad — agent " AGENT_VER " starting");
    // Bind the Java rich-capture reporter (if the target opted in via adh.reporter.class) HERE —
    // before the target installs its JCE provider — so the binding is in place before any report
    // fires. If the target sets the property later, the winning copy's watcher binds it.
    JNIEnv *env = NULL;
    int have_env = ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK && env);
    if (have_env && !bind_reporter_from_prop(env)) start_reporter_watch();
    pthread_once(&g_once, do_start);
    return JNI_VERSION_1_6;
}
