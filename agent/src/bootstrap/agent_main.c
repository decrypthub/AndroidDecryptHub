// libidh_agent.so — bootstrap + command loop (v0.2)
// Dual entry:
//   - JNI_OnLoad()      : fires when a host loads us via System.loadLibrary (模拟注入 / gadget)
//   - idh_agent_start() : exported C symbol for injector-driven load
// Both connect to idhd over TCP (127.0.0.1:8761, via `adb reverse`), report identity +
// an initial maps sample, then serve commands: maps / read (memory). Collect-only.

#include <jni.h>
#include <pthread.h>
#include <stdint.h>
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

#ifdef IDH_HAVE_LSPLANT
#include "../hook/java_lsplant.h"   // C-ABI shim over LSPlant (Java method hook, WS-A)
#endif
#include "../hook/got.h"
#include "../capture/capture.h"
#include "../runtime/jni.h"

// Common macros (AGENT_VER/IDH_HOST/IDH_PORT/TAG/LOGI/LOGE/FRAME_*) + cross-module prototypes
// Shared bootstrap helpers live in agent_internal.h.
#include "agent_internal.h"

static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static char g_entry[16] = "start";
// QBDI instruction trace (src/trace/qbdi_trace.c) — loads libQBDI.so at runtime.
extern int idh_qbdi_trace(void *func, char *out, int outsz);




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
    JNIEnv *env = idh_jni_attach(&did);
    if (env) {
        (*env)->PushLocalFrame(env, 64);
        jclass jc = idh_jni_load_app_class(env, className);
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
        idh_jni_detach(did);
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
// Detection primitives (det_record + my_ptrace/my_access/my_prop) are defined above, near
// idh_cmd_capture_start, so the persistent capture path can install them too.


// Generic function trace: hook `symbol` (exported by symLib) in hookModule's GOT,
// trigger the sandbox's Detection.run() (which calls libc detection fns), and return
// the recorded calls (args + tid + ts). Demonstrates tracing an arbitrary native fn.
static void cmd_trace_run(int fd, const char *id, const char *symLib, const char *symbol, const char *hookMod, const char *className) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    void *orig = idh_resolve_sym(symLib, symbol);
    g_trace_orig = (fn4_t)orig;
    int replaced = orig ? idh_got_replace(hookMod, orig, (void *)idh_trace_wrapper) : -1;
    pthread_mutex_lock(&g_trace_lock); g_ntrace = 0; pthread_mutex_unlock(&g_trace_lock);

    int did = 0, triggered = 0;
    JNIEnv *env = idh_jni_attach(&did);
    if (env) {
        (*env)->PushLocalFrame(env, 32);
        jclass jc = className[0] ? idh_jni_load_app_class(env, className) : NULL;
        if (jc) { jmethodID run = (*env)->GetStaticMethodID(env, jc, "run", "()I");
            if (run) { (*env)->CallStaticIntMethod(env, jc, run); triggered = 1; } }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->PopLocalFrame(env, NULL);
        idh_jni_detach(did);
    }
    if (replaced > 0 && orig) idh_got_replace(hookMod, (void *)idh_trace_wrapper, orig);   // restore

    char sj[80]; json_escape(symbol, sj, sizeof(sj));
    size_t cap = 1 << 14, len = 0; char *out = malloc(cap); if (!out) { send_oom(fd, idj, "trace_run"); return; }
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
    JNIEnv *env = idh_jni_attach(&did);
    if (!env) { char e[160]; snprintf(e, sizeof(e), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_inspect\",\"ok\":false,\"error\":\"no JavaVM\"}\n", idj); send_line(fd, e); return; }
    (*env)->PushLocalFrame(env, 256);

    size_t cap = 1 << 14; char *out = malloc(cap);
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

    jclass target = idh_jni_load_app_class(env, className);
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
    idh_jni_detach(did);
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
    JNIEnv *env = idh_jni_attach(&did);
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

    jclass target = idh_jni_load_app_class(env, className);
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
    idh_jni_detach(did);
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
    int got_ok = (idh_resolve_sym("libc.so", "access") != NULL);
    int jni_ok = idh_jni_vm_available();
    int module_count = 0, maps_count = 0;
    FILE *m = fopen("/proc/self/maps", "r"); char l[512]; char lastmod[400] = "";
    while (m && fgets(l, sizeof(l), m)) { maps_count++;
        char *p = strstr(l, "/"); if (p) { char *nl = strchr(p, '\n'); if (nl) *nl = 0; if (strcmp(p, lastmod)) { strncpy(lastmod, p, sizeof(lastmod)-1); module_count++; } } }
    if (m) fclose(m);

    // memRead: exercise the real read path (/proc/self/mem pread) on our own code — confirms
    // the mechanism works rather than asserting a hardcoded "true". dlopenSystemLibsBlocked:
    // actually try to dlopen a system lib instead of freezing a one-time observation into code.
    int memread_ok = 0;
    { int mf = open("/proc/self/mem", O_RDONLY);
      if (mf >= 0) { unsigned char mb[4]; memread_ok = (pread(mf, mb, 4, (off_t)(uintptr_t)&cmd_compat_probe) == 4); close(mf); } }
    void *dlprobe = dlopen("libcrypto.so", RTLD_NOW);
    int dlopen_blocked = (dlprobe == NULL);
    if (dlprobe) dlclose(dlprobe);

    char out[640];
    snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"compat_probe\",\"ok\":true,"
        "\"tracerPid\":%d,\"seccomp\":%d,\"backends\":{\"gotHook\":%s,\"jniReflect\":%s,\"artDexCapture\":%s,\"memRead\":%s},"
        "\"mapsCount\":%d,\"moduleMappings\":%d,\"dlopenSystemLibsBlocked\":%s}\n",
        idj, tracer, seccomp, got_ok ? "true" : "false", jni_ok ? "true" : "false",
        idh_jni_vm_available() ? "true" : "false", memread_ok ? "true" : "false",
        maps_count, module_count, dlopen_blocked ? "true" : "false");
    send_line(fd, out);
    LOGI("compat_probe: tracer=%d seccomp=%d got=%d jni=%d", tracer, seccomp, got_ok, jni_ok);
}

// Prove JNI reflection works from the agent's native thread: read Build.VERSION.
static void cmd_jni_probe(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    int did = 0;
    JNIEnv *env = idh_jni_attach(&did);
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
    idh_jni_detach(did);

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
    JNIEnv *env = idh_jni_attach(&did);
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
                                    if (w > 0) {
                                        if (len + (size_t)w + 1 >= cap) {
                                            size_t ncap = cap; while (len + (size_t)w + 1 >= ncap) ncap *= 2;
                                            char *nb = realloc(recs, ncap);
                                            if (!nb) continue;   // OOM: skip this record — recs/cap unchanged (no overflow)
                                            recs = nb; cap = ncap;
                                        }
                                        memcpy(recs + len, rec, (size_t)w); len += (size_t)w; recs[len] = 0; nrec++;
                                    }
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
    idh_jni_detach(did);

    size_t hlen = (recs ? strlen(recs) : 0) + 200;
    char *out = (char *)malloc(hlen);
    if (out) { snprintf(out, hlen, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"art_dexfiles\",\"ok\":true,\"loaders\":%d,\"count\":%d,\"dexfiles\":[%s]}\n", idj, nloaders, nrec, recs ? recs : ""); send_line(fd, out); free(out); }
    free(recs);
    LOGI("art_dexfiles: loaders=%d dexfiles=%d", nloaders, nrec);
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
// Init LSPlant, hook the target's `secret(String)` method (className from idhd) via a
// com.idh.agent.MethodHook callback, call it, and assert: init ok, hook installed, callback
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
    jclass mhCls  = idh_jni_load_app_class(env, "com.idh.agent.MethodHook");
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
                    cmd_trigger(fd, id, tcls, tm, lv > 0 ? (int)lv : 1);
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
                    cmd_load_so(fd, id, lpath, lsym);
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
                    void *fn = idh_resolve_sym(sl[0] ? sl : "libidhdetect.so", sy[0] ? sy : "idh_trace_target");
                    char idj[64]; json_escape(id, idj, sizeof(idj));
                    if (!fn) { char e[160]; snprintf(e, sizeof(e), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"qbdi_trace\",\"ok\":false,\"error\":\"symbol not found\"}\n", idj); send_line(fd, e); }
                    else { char *ob = malloc(1 << 18); if (ob) { ob[0] = 0; idh_qbdi_trace(fn, ob, (1 << 18) - 64);
                        char *msg = malloc((1 << 18) + 128);
                        if (msg) { snprintf(msg, (1 << 18) + 128, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"qbdi_trace\",%s}\n", idj, ob); send_line(fd, msg); free(msg); }
                        free(ob); LOGI("qbdi_trace %s -> done", sy); } }
                } else if (strcmp(op, "trace_run") == 0) {
                    char sl[64] = "", sy[64] = "", hm[80] = "", tcls[200] = "";
                    json_get_str(line, "symLib", sl, sizeof(sl));
                    json_get_str(line, "symbol", sy, sizeof(sy));
                    json_get_str(line, "hookModule", hm, sizeof(hm));
                    json_get_str(line, "className", tcls, sizeof(tcls));
                    cmd_trace_run(fd, id, sl, sy, hm, tcls);
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

// If the target published its Java rich-capture reporter class via the "idh.reporter.class"
// system property, bind idh_nreport_impl onto its nReport method (RegisterNatives). Target-
// agnostic: the agent knows no class name — the target opts in by setting the property.
static void bind_reporter_from_prop(JNIEnv *env) {
    jclass sysCls = (*env)->FindClass(env, "java/lang/System");
    jmethodID getProp = sysCls ? (*env)->GetStaticMethodID(env, sysCls, "getProperty", "(Ljava/lang/String;)Ljava/lang/String;") : NULL;
    if (!getProp) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return; }
    jstring jkey = (*env)->NewStringUTF(env, "idh.reporter.class");
    jstring jval = jkey ? (jstring)(*env)->CallStaticObjectMethod(env, sysCls, getProp, jkey) : NULL;
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
    // Bind the Java rich-capture reporter (if the target opted in via idh.reporter.class) HERE —
    // before the target installs its JCE provider — so the binding is in place before any report
    // fires (a later bind would race the target's first crypto op and lose).
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK && env) bind_reporter_from_prop(env);
    pthread_once(&g_once, do_start);
    return JNI_VERSION_1_6;
}
