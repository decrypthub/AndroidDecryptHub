// libidh_agent.so — bootstrap + command loop (v0.2)
// Dual entry:
//   - JNI_OnLoad()      : fires when a host loads us via System.loadLibrary (模拟注入 / gadget)
//   - adh_agent_start() : exported C symbol for injector-driven load
//   - idh_agent_start() : legacy ABI alias
// Both connect to the Host ADH Daemon over TCP (127.0.0.1:8761, via `adb reverse`), report identity +
// an initial maps sample, then serve commands: maps / read (memory). Collect-only.

#include <jni.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/system_properties.h>

#ifdef IDH_HAVE_LSPLANT
#include "../hook/java_lsplant.h"   // C-ABI shim over LSPlant (Java method hook, WS-A)
#endif
#include "../hook/got.h"
#include "../capture/capture.h"
#include "../runtime/actions.h"
#include "../runtime/art.h"
#include "../runtime/inspection.h"
#include "../runtime/jni.h"
#include "../trace/commands.h"

// Common macros (AGENT_VER/IDH_HOST/IDH_PORT/TAG/LOGI/LOGE/FRAME_*) + cross-module prototypes
// Shared bootstrap helpers live in agent_internal.h.
#include "agent_internal.h"

static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static char g_entry[16] = "start";

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

// ---- Java method hook (WS-A, LSPlant) deterministic self-test -------------------------
#ifdef IDH_HAVE_LSPLANT
// Init LSPlant, hook the target's `secret(String)` method (className from the Host ADH Daemon) via a
// com.adh.agent.MethodHook callback, call it, and assert: init ok, hook installed, callback
// fired capturing the real arg, and the original still returned its real value (backup.invoke
// worked, no recursion/crash).
static void cmd_java_hook_test(int fd, const char *id, const char *className) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    int did = 0; JNIEnv *env = idh_jni_attach(&did);
    if (!env) { char e[160]; snprintf(e, sizeof(e), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"java_hook_test\",\"ok\":false,\"error\":\"no JNIEnv\"}\n", idj); send_line(fd, e); return; }
    (*env)->PushLocalFrame(env, 128);
    int initOk = idh_javahook_init(env);
    int hooked = 0, fired = 0, origOk = 0, hits = -1;
    char lastArg[128] = "", ret[128] = "";

    jclass clsCls = (*env)->FindClass(env, "java/lang/Class");
    jclass strCls = (*env)->FindClass(env, "java/lang/String");
    jclass htCls  = className[0] ? idh_jni_load_app_class(env, className) : NULL;
    jclass mhCls  = idh_jni_load_app_class(env, "com.adh.agent.MethodHook");
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (initOk && htCls && mhCls && clsCls && strCls) {
        jmethodID gdm = (*env)->GetMethodID(env, clsCls, "getDeclaredMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");
        jobjectArray p1 = (*env)->NewObjectArray(env, 1, clsCls, strCls);
        jobject targetMethod = (*env)->CallObjectMethod(env, htCls, gdm, (*env)->NewStringUTF(env, "secret"), p1);
        jclass objArrCls = (*env)->FindClass(env, "[Ljava/lang/Object;");
        jobjectArray p2 = (*env)->NewObjectArray(env, 1, clsCls, objArrCls);
        jobject cbMethod = (*env)->CallObjectMethod(env, mhCls, gdm, (*env)->NewStringUTF(env, "callback"), p2);
        jmethodID ctor = (*env)->GetMethodID(env, mhCls, "<init>", "()V");
        jobject hooker = ctor ? (*env)->NewObject(env, mhCls, ctor) : NULL;
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        if (targetMethod && cbMethod && hooker) {
            jobject backup = idh_javahook_hook(env, targetMethod, hooker, cbMethod);
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            if (backup) {
                hooked = 1;
                (*env)->SetObjectField(env, hooker, (*env)->GetFieldID(env, mhCls, "backup", "Ljava/lang/reflect/Method;"), backup);
                (*env)->SetBooleanField(env, hooker, (*env)->GetFieldID(env, mhCls, "isStatic", "Z"), JNI_TRUE);
                jmethodID secret = (*env)->GetStaticMethodID(env, htCls, "secret", "(Ljava/lang/String;)Ljava/lang/String;");
                jstring rs = secret ? (jstring)(*env)->CallStaticObjectMethod(env, htCls, secret, (*env)->NewStringUTF(env, "IDH_HOOK_PING")) : NULL;
                if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
                if (rs) { const char *s = (*env)->GetStringUTFChars(env, rs, NULL); if (s) { strncpy(ret, s, sizeof(ret)-1); (*env)->ReleaseStringUTFChars(env, rs, s); } }
                jfieldID fHits = (*env)->GetStaticFieldID(env, mhCls, "hits", "I");
                jfieldID fLast = (*env)->GetStaticFieldID(env, mhCls, "lastArg", "Ljava/lang/String;");
                if (fHits) hits = (*env)->GetStaticIntField(env, mhCls, fHits);
                jstring la = fLast ? (jstring)(*env)->GetStaticObjectField(env, mhCls, fLast) : NULL;
                if (la) { const char *s = (*env)->GetStringUTFChars(env, la, NULL); if (s) { strncpy(lastArg, s, sizeof(lastArg)-1); (*env)->ReleaseStringUTFChars(env, la, s); } }
                fired = (hits >= 1 && strcmp(lastArg, "IDH_HOOK_PING") == 0) ? 1 : 0;
                origOk = (strcmp(ret, "REAL_SECRET:IDH_HOOK_PING") == 0) ? 1 : 0;
                idh_javahook_unhook(env, targetMethod);
            }
        }
    }
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    (*env)->PopLocalFrame(env, NULL);
    idh_jni_detach(did);
    char laj[160], rj[160]; json_escape(lastArg, laj, sizeof(laj)); json_escape(ret, rj, sizeof(rj));
    int ok = initOk && hooked && fired && origOk;
    char out[512];
    snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"java_hook_test\",\"ok\":%s,\"initOk\":%s,\"hooked\":%s,\"fired\":%s,\"origOk\":%s,\"hits\":%d,\"lastArg\":\"%s\",\"ret\":\"%s\"}\n",
        idj, ok?"true":"false", initOk?"true":"false", hooked?"true":"false", fired?"true":"false", origOk?"true":"false", hits, laj, rj);
    send_line(fd, out);
    LOGI("java_hook_test: init=%d hooked=%d fired=%d origOk=%d hits=%d arg=%s ret=%s", initOk, hooked, fired, origOk, hits, lastArg, ret);
}
#else
static void cmd_java_hook_test(int fd, const char *id, const char *className) {
    (void)className;
    char idj[64]; json_escape(id, idj, sizeof(idj));
    char out[220];
    snprintf(out, sizeof(out), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"java_hook_test\",\"ok\":false,\"error\":\"lsplant not built — run tools/fetch_lsplant.sh\"}\n", idj);
    send_line(fd, out);
}
#endif

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
                    idh_cmd_jni_probe(fd, id);
                } else if (strcmp(op, "gothook_selftest") == 0) {
                    idh_cmd_gothook_selftest(fd, id);
                } else if (strcmp(op, "crypto_probe") == 0) {
                    idh_cmd_crypto_probe(fd, id);
                } else if (strcmp(op, "crypto_hook_test") == 0) {
                    char tcls[200] = ""; json_get_str(line, "className", tcls, sizeof(tcls));
                    idh_cmd_crypto_hook_test(fd, id, tcls);
                } else if (strcmp(op, "capture_start") == 0) {
                    char cmod[64] = "", fmod[64] = "", smod[64] = "";
                    json_get_str(line, "cryptoModule", cmod, sizeof(cmod));
                    json_get_str(line, "fileModule", fmod, sizeof(fmod));
                    json_get_str(line, "sysModule", smod, sizeof(smod));
                    idh_cmd_capture_start(fd, id, cmod, fmod, smod);
                } else if (strcmp(op, "capture_drain") == 0) {
                    idh_cmd_capture_drain(fd, id);
                } else if (strcmp(op, "capture_stop") == 0) {
                    idh_cmd_capture_stop(fd, id);
                } else if (strcmp(op, "trigger") == 0) {
                    char tcls[200] = "", tm[80] = "";
                    json_get_str(line, "className", tcls, sizeof(tcls));
                    json_get_str(line, "method", tm, sizeof(tm));
                    long long lv = json_get_num(line, "level");
                    idh_cmd_trigger(fd, id, tcls, tm, lv > 0 ? (int)lv : 1);
                } else if (strcmp(op, "inline_crypto_test") == 0) {
                    char im[96] = "", is[96] = "", ic[220] = "", it[80] = "";
                    json_get_str(line, "module", im, sizeof(im));
                    json_get_str(line, "symbol", is, sizeof(is));
                    json_get_str(line, "className", ic, sizeof(ic));
                    json_get_str(line, "method", it, sizeof(it));
                    idh_cmd_inline_crypto_test(fd, id, im, is, ic, it);
                } else if (strcmp(op, "load_so") == 0) {
                    char lpath[400] = "", lsym[96] = "";
                    json_get_str(line, "path", lpath, sizeof(lpath));
                    json_get_str(line, "symbol", lsym, sizeof(lsym));
                    idh_cmd_load_so(fd, id, lpath, lsym);
                } else if (strcmp(op, "net_hook_test") == 0) {
                    char tcls[200] = ""; json_get_str(line, "className", tcls, sizeof(tcls));
                    idh_cmd_net_hook_test(fd, id, tcls);
                } else if (strcmp(op, "file_probe") == 0) {
                    idh_cmd_file_probe(fd, id);
                } else if (strcmp(op, "file_hook_test") == 0) {
                    char fmod[64] = "", tcls[200] = "";
                    json_get_str(line, "module", fmod, sizeof(fmod));
                    json_get_str(line, "className", tcls, sizeof(tcls));
                    idh_cmd_file_hook_test(fd, id, fmod, tcls);
                } else if (strcmp(op, "flow_watch") == 0) {
                    char tcls[200] = ""; json_get_str(line, "className", tcls, sizeof(tcls));
                    idh_cmd_flow_watch(fd, id, tcls);
                } else if (strcmp(op, "detect_watch") == 0) {
                    char dmod[64] = "", tcls[200] = "";
                    json_get_str(line, "module", dmod, sizeof(dmod));
                    json_get_str(line, "className", tcls, sizeof(tcls));
                    idh_cmd_detect_watch(fd, id, dmod, tcls);
                } else if (strcmp(op, "qbdi_trace") == 0) {
                    char sl[64] = "", sy[80] = "";
                    json_get_str(line, "symLib", sl, sizeof(sl));
                    json_get_str(line, "symbol", sy, sizeof(sy));
                    idh_cmd_qbdi_trace(fd, id, sl, sy);
                } else if (strcmp(op, "trace_run") == 0) {
                    char sl[64] = "", sy[64] = "", hm[80] = "", tcls[200] = "";
                    json_get_str(line, "symLib", sl, sizeof(sl));
                    json_get_str(line, "symbol", sy, sizeof(sy));
                    json_get_str(line, "hookModule", hm, sizeof(hm));
                    json_get_str(line, "className", tcls, sizeof(tcls));
                    idh_cmd_trace_run(fd, id, sl, sy, hm, tcls);
                } else if (strcmp(op, "compat_probe") == 0) {
                    idh_cmd_compat_probe(fd, id);
                } else if (strcmp(op, "object_inspect") == 0) {
                    char cls[160] = "", fld[64] = "";
                    json_get_str(line, "className", cls, sizeof(cls));
                    json_get_str(line, "field", fld, sizeof(fld));
                    idh_cmd_object_inspect(fd, id, cls, fld);
                } else if (strcmp(op, "object_invoke") == 0) {
                    char cls[160] = "", fld[64] = "", mth[64] = "";
                    json_get_str(line, "className", cls, sizeof(cls));
                    json_get_str(line, "field", fld, sizeof(fld));
                    json_get_str(line, "method", mth, sizeof(mth));
                    idh_cmd_object_invoke(fd, id, cls, fld, mth);
                } else if (strcmp(op, "art_dexfiles") == 0) {
                    idh_cmd_art_dexfiles(fd, id);
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
                } else if (strcmp(op, "java_hook_test") == 0) {
                    char tcls[200] = ""; json_get_str(line, "className", tcls, sizeof(tcls));
                    cmd_java_hook_test(fd, id, tcls);
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
            LOGI("connected to Host ADH Daemon %s:%d", IDH_HOST, IDH_PORT);
            report(fd);
            command_loop(fd);
            close(fd);
            LOGI("Host ADH Daemon connection closed");
            return NULL;
        }
        usleep(500 * 1000);
    }
    LOGE("could not reach Host ADH Daemon after retries (need: adb reverse tcp:%d tcp:%d)", IDH_PORT, IDH_PORT);
    return NULL;
}

static void do_start(void) {
    pthread_t t;
    if (pthread_create(&t, NULL, agent_thread, NULL) == 0) pthread_detach(t);
    else LOGE("pthread_create failed");
}

__attribute__((visibility("default")))
void adh_agent_start(void) {
    strncpy(g_entry, "start", sizeof(g_entry) - 1);
    pthread_once(&g_once, do_start);
}

__attribute__((visibility("default")))
void idh_agent_start(void) {
    adh_agent_start();
}

// If the target published its Java rich-capture reporter class via the "adh.reporter.class"
// system property, bind idh_nreport_impl onto its nReport method (RegisterNatives). Target-
// agnostic: the agent knows no class name. The IDH key remains a compatibility fallback.
static void bind_reporter_from_prop(JNIEnv *env) {
    jclass sysCls = (*env)->FindClass(env, "java/lang/System");
    jmethodID getProp = sysCls ? (*env)->GetStaticMethodID(env, sysCls, "getProperty", "(Ljava/lang/String;)Ljava/lang/String;") : NULL;
    if (!getProp) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return; }
    jstring jkey = (*env)->NewStringUTF(env, "adh.reporter.class");
    jstring jval = jkey ? (jstring)(*env)->CallStaticObjectMethod(env, sysCls, getProp, jkey) : NULL;
    if (!jval) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        jkey = (*env)->NewStringUTF(env, "idh.reporter.class");
        jval = jkey ? (jstring)(*env)->CallStaticObjectMethod(env, sysCls, getProp, jkey) : NULL;
    }
    if (jval) {
        const char *cls = (*env)->GetStringUTFChars(env, jval, NULL);
        if (cls && cls[0]) { int ok = idh_capture_register_reporter(env, cls); LOGI("rich-capture reporter '%s' bind %s", cls, ok ? "ok" : "FAILED"); }
        if (cls) (*env)->ReleaseStringUTFChars(env, jval, cls);
    }
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    idh_jni_set_vm(vm);
    strncpy(g_entry, "jni_onload", sizeof(g_entry) - 1);
    LOGI("JNI_OnLoad — agent " AGENT_VER " starting");
    // Bind the Java rich-capture reporter (if the target opted in via adh.reporter.class) HERE —
    // before the target installs its JCE provider — so the binding is in place before any report
    // fires (a later bind would race the target's first crypto op and lose).
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK && env) bind_reporter_from_prop(env);
    pthread_once(&g_once, do_start);
    return JNI_VERSION_1_6;
}
