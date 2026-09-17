// libadh_agent.so — bootstrap + command loop (v0.2)
// Dual entry:
//   - JNI_OnLoad()      : fires when a host loads us via System.loadLibrary (模拟注入 / gadget)
//   - adh_agent_start() : exported C symbol for injector-driven load
// Both connect to the Host ADH Daemon over TCP (127.0.0.1:8761, via `adb reverse`), report identity +
// an initial maps sample, then serve commands: maps / read (memory). Collect-only.

#include <jni.h>
#include <pthread.h>
#include <stdio.h>
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
#include "../runtime/java_enum.h"
#include "../trace/commands.h"

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

    char hello[1200];
    snprintf(hello, sizeof(hello),
        "{\"t\":\"hello\",\"agentVer\":\"%s\",\"pid\":%d,\"uid\":%d,"
        "\"package\":\"%s\",\"process\":\"%s\",\"abi\":\"%s\",\"android\":\"%s\",\"sdk\":%s,\"entry\":\"%s\"}\n",
        AGENT_VER, getpid(), getuid(), pkg, pkg,
        abi[0] ? abi : "?", rel[0] ? rel : "?", sdk[0] ? sdk : "0", g_entry);
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
             "\"initOk\":%s,\"backend\":\"lsplant\",\"version\":\"%s\",\"error\":\"%s\"}\n",
             idj, init_ok ? "true" : "false", init_ok ? "true" : "false", ADH_LSPLANT_VERSION, errj);
    send_line(fd, out);
    LOGI("javahook_probe: init=%d error=%s", init_ok, err ? err : "");
#else
    char out[240];
    snprintf(out, sizeof(out),
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"javahook_probe\",\"ok\":false,\"available\":false,"
             "\"error\":\"lsplant not built — run tools/fetch_lsplant.sh\"}\n", idj);
    send_line(fd, out);
#endif
}
// Generic single Java-method hook command. All target identity comes from the command;
// the agent has no sandbox/package/class constants.
static void cmd_java_hook(int fd, const char *id, const char *action, const char *class_name,
                          const char *method_name, const char *params, long long requested_hook_id) {
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
    if (strcmp(action, "hook") == 0) {
        if (!class_name[0] || !method_name[0]) {
            snprintf(error, sizeof(error), "hook requires className and method");
        } else {
            ok = adh_javahook_hook_method(env, class_name, method_name, params, &new_hook_id, error, sizeof(error));
        }
    } else if (strcmp(action, "unhook") == 0) {
        ok = adh_javahook_unhook_id(env, (int)requested_hook_id, error, sizeof(error));
    } else if (strcmp(action, "status") == 0) {
        ok = 1;
    } else {
        snprintf(error, sizeof(error), "java_hook requires action: hook | unhook | status");
    }

    char status[2048] = "{}";
    adh_javahook_status_json(env, status, sizeof(status));
    if (did_attach) adh_jni_detach(did_attach);

    char errj[768];
    json_escape(error, errj, sizeof(errj));
    char out[4096];
    snprintf(out, sizeof(out),
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"java_hook\",\"ok\":%s,\"action\":\"%s\","
             "\"hookId\":%d,\"error\":\"%s\",\"status\":%s}\n",
             idj, ok ? "true" : "false", action, new_hook_id, errj, status);
    send_line(fd, out);
    LOGI("java_hook: action=%s ok=%d error=%s", action, ok, error);
#else
    (void)action; (void)class_name; (void)method_name; (void)params; (void)requested_hook_id;
    char out[240];
    snprintf(out, sizeof(out),
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"java_hook\",\"ok\":false,"
             "\"error\":\"lsplant not built — run tools/fetch_lsplant.sh\"}\n", idj);
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
                    char addr[40] = ""; json_get_str(line, "addr", addr, sizeof(addr));
                    long long size = json_get_num(line, "size");
                    cmd_read(fd, id, addr, size);
                } else if (strcmp(op, "jni_probe") == 0) {
                    adh_cmd_jni_probe(fd, id);
                } else if (strcmp(op, "java_hook") == 0) {
                    char jaction[16] = "", jcls[256] = "", jmethod[128] = "", jparams[512] = "";
                    json_get_str(line, "action", jaction, sizeof(jaction));
                    json_get_str(line, "className", jcls, sizeof(jcls));
                    json_get_str(line, "method", jmethod, sizeof(jmethod));
                    json_get_str(line, "params", jparams, sizeof(jparams));
                    long long jhook_id = json_get_num(line, "id");
                    cmd_java_hook(fd, id, jaction, jcls, jmethod, jparams, jhook_id);
                } else if (strcmp(op, "java_enum") == 0) {
                    char jcls[256] = "";
                    json_get_str(line, "className", jcls, sizeof(jcls));
                    cmd_java_enum(fd, id, jcls);
                } else if (strcmp(op, "javahook_probe") == 0) {
                    cmd_javahook_probe(fd, id);
                } else if (strcmp(op, "gothook_selftest") == 0) {
                    adh_cmd_gothook_selftest(fd, id);
                } else if (strcmp(op, "crypto_probe") == 0) {
                    adh_cmd_crypto_probe(fd, id);
                } else if (strcmp(op, "crypto_hook_test") == 0) {
                    char tcls[200] = ""; json_get_str(line, "className", tcls, sizeof(tcls));
                    adh_cmd_crypto_hook_test(fd, id, tcls);
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
                } else if (strcmp(op, "inline_crypto_test") == 0) {
                    char im[96] = "", is[96] = "", ic[220] = "", it[80] = "";
                    json_get_str(line, "module", im, sizeof(im));
                    json_get_str(line, "symbol", is, sizeof(is));
                    json_get_str(line, "className", ic, sizeof(ic));
                    json_get_str(line, "method", it, sizeof(it));
                    adh_cmd_inline_crypto_test(fd, id, im, is, ic, it);
                } else if (strcmp(op, "load_so") == 0) {
                    char lpath[400] = "", lsym[96] = "";
                    json_get_str(line, "path", lpath, sizeof(lpath));
                    json_get_str(line, "symbol", lsym, sizeof(lsym));
                    adh_cmd_load_so(fd, id, lpath, lsym);
                } else if (strcmp(op, "net_hook_test") == 0) {
                    char tcls[200] = ""; json_get_str(line, "className", tcls, sizeof(tcls));
                    adh_cmd_net_hook_test(fd, id, tcls);
                } else if (strcmp(op, "file_probe") == 0) {
                    adh_cmd_file_probe(fd, id);
                } else if (strcmp(op, "file_hook_test") == 0) {
                    char fmod[64] = "", tcls[200] = "";
                    json_get_str(line, "module", fmod, sizeof(fmod));
                    json_get_str(line, "className", tcls, sizeof(tcls));
                    adh_cmd_file_hook_test(fd, id, fmod, tcls);
                } else if (strcmp(op, "flow_watch") == 0) {
                    char tcls[200] = ""; json_get_str(line, "className", tcls, sizeof(tcls));
                    adh_cmd_flow_watch(fd, id, tcls);
                } else if (strcmp(op, "detect_watch") == 0) {
                    char dmod[64] = "", tcls[200] = "";
                    json_get_str(line, "module", dmod, sizeof(dmod));
                    json_get_str(line, "className", tcls, sizeof(tcls));
                    adh_cmd_detect_watch(fd, id, dmod, tcls);
                } else if (strcmp(op, "qbdi_trace") == 0) {
                    char sl[64] = "", sy[80] = "";
                    json_get_str(line, "symLib", sl, sizeof(sl));
                    json_get_str(line, "symbol", sy, sizeof(sy));
                    adh_cmd_qbdi_trace(fd, id, sl, sy);
                } else if (strcmp(op, "trace_run") == 0) {
                    char sl[64] = "", sy[64] = "", hm[80] = "", tcls[200] = "";
                    json_get_str(line, "symLib", sl, sizeof(sl));
                    json_get_str(line, "symbol", sy, sizeof(sy));
                    json_get_str(line, "hookModule", hm, sizeof(hm));
                    json_get_str(line, "className", tcls, sizeof(tcls));
                    adh_cmd_trace_run(fd, id, sl, sy, hm, tcls);
                } else if (strcmp(op, "compat_probe") == 0) {
                    adh_cmd_compat_probe(fd, id);
                } else if (strcmp(op, "object_inspect") == 0) {
                    char cls[160] = "", fld[64] = "";
                    json_get_str(line, "className", cls, sizeof(cls));
                    json_get_str(line, "field", fld, sizeof(fld));
                    adh_cmd_object_inspect(fd, id, cls, fld);
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
            if (failed) LOGI("reconnected to Host ADH Daemon %s:%d after %d failed attempts", ADH_HOST, ADH_PORT, failed);
            else LOGI("connected to Host ADH Daemon %s:%d", ADH_HOST, ADH_PORT);
            failed = 0;
            report(fd);
            command_loop(fd);
            close(fd);
            LOGI("Host ADH Daemon connection closed; reconnecting");
            usleep(1000 * 1000);   // give a restarting daemon time to bind before re-dialling
            continue;
        }
        if (failed == 0 || failed % 20 == 0)
            LOGE("Host ADH Daemon unreachable (attempt %d, need: adb reverse tcp:%d tcp:%d)", failed + 1, ADH_PORT, ADH_PORT);
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
struct AgentCopyCtx { void *first_base; };

static int find_first_agent_copy(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    struct AgentCopyCtx *ctx = (struct AgentCopyCtx *)data;
    const char *name = info->dlpi_name ? info->dlpi_name : "";
    const char *base = strrchr(name, '/');
    base = base ? base + 1 : name;
    if (strcmp(base, "libadh_agent.so") != 0) return 0;
    ctx->first_base = (void *)(uintptr_t)info->dlpi_addr;
    return 1;   // stop at the first loaded copy
}

static int current_agent_copy_is_owner(void) {
    Dl_info self;
    if (!dladdr((void *)(uintptr_t)current_agent_copy_is_owner, &self) || !self.dli_fbase) {
        LOGI("single-instance guard unavailable (dladdr) — continuing");
        return 1;
    }
    struct AgentCopyCtx ctx = {0};
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
    if (!getProp) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return 0; }
    jstring jkey = (*env)->NewStringUTF(env, "adh.reporter.class");
    jstring jval = jkey ? (jstring)(*env)->CallStaticObjectMethod(env, sysCls, getProp, jkey) : NULL;
    if (!jval) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return 0;
    }
    const char *cls = (*env)->GetStringUTFChars(env, jval, NULL);
    int ok = 0;
    if (cls && cls[0]) {
        ok = adh_capture_register_reporter(env, cls);
        LOGI("rich-capture reporter '%s' bind %s", cls, ok ? "ok" : "FAILED");
    }
    if (cls) (*env)->ReleaseStringUTFChars(env, jval, cls);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
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
