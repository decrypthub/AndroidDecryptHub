#include "actions.h"

#include <dlfcn.h>
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include "../bootstrap/agent_internal.h"
#include "../hook/got.h"
#include "jni.h"
#include <errno.h>

static int name_blacklisted(const char *s) {
    static const char *bad[] = {
        "exit", "exec", "delete", "remove", "clear", "drop", "format", "kill",
        "finish", "destroy", "close", "clinit", "init", "finalize", "write", "send",
        "post", "pay", "transfer", "order", "logout", "reset", "wipe", "shutdown",
        "reboot", "uninstall", NULL,
    };
    for (int i = 0; bad[i]; i++) {
        if (strstr(s, bad[i])) return 1;
    }
    return 0;
}

static int class_is_lifecycle(const char *s) {
    static const char *lifecycle[] = {
        "Activity", "Service", "Application", "Receiver", "Provider", NULL,
    };
    for (int i = 0; lifecycle[i]; i++) {
        if (strstr(s, lifecycle[i])) return 1;
    }
    return 0;
}

void adh_cmd_trigger(int fd, const char *id, const char *class_name, const char *method, int level) {
    char idj[64];
    json_escape(id, idj, sizeof(idj));
    int loaded = 0, invoked = 0, skipped = 0;
    const char *reason = "";
    char result[160] = "";
    int did_attach = 0;
    JNIEnv *env = adh_jni_attach(&did_attach);
    if (env) {
        (*env)->PushLocalFrame(env, 64);
        jclass target = adh_jni_load_app_class(env, class_name);
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
            reason = "loadClass threw";
        } else if (target) {
            loaded = 1;
            if (level >= 3 && method && method[0]) {
                if (name_blacklisted(method)) {
                    skipped = 1;
                    reason = "method on safety blacklist";
                } else if (class_is_lifecycle(class_name)) {
                    skipped = 1;
                    reason = "lifecycle class";
                } else {
                    jclass class_class = (*env)->FindClass(env, "java/lang/Class");
                    jmethodID get_method = (*env)->GetMethodID(
                        env, class_class, "getMethod",
                        "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");
                    jobjectArray empty = (*env)->NewObjectArray(env, 0, class_class, NULL);
                    jstring method_name = (*env)->NewStringUTF(env, method);
                    jobject reflected = (*env)->CallObjectMethod(env, target, get_method, method_name, empty);
                    if ((*env)->ExceptionCheck(env)) {
                        (*env)->ExceptionClear(env);
                        skipped = 1;
                        reason = "no such no-arg method";
                    } else if (reflected) {
                        jclass method_class = (*env)->FindClass(env, "java/lang/reflect/Method");
                        jmethodID get_modifiers = (*env)->GetMethodID(env, method_class, "getModifiers", "()I");
                        jint modifiers = (*env)->CallIntMethod(env, reflected, get_modifiers);
                        int is_static = modifiers & 0x0008;
                        int is_native = modifiers & 0x0100;
                        int is_abstract = modifiers & 0x0400;
                        if (!is_static) {
                            skipped = 1;
                            reason = "not static (needs receiver, level>=4)";
                        } else if (is_native || is_abstract) {
                            skipped = 1;
                            reason = "native/abstract";
                        } else {
                            jmethodID set_accessible = (*env)->GetMethodID(env, method_class, "setAccessible", "(Z)V");
                            (*env)->CallVoidMethod(env, reflected, set_accessible, JNI_TRUE);
                            jclass object_class = (*env)->FindClass(env, "java/lang/Object");
                            jobjectArray args = (*env)->NewObjectArray(env, 0, object_class, NULL);
                            jmethodID invoke = (*env)->GetMethodID(
                                env, method_class, "invoke",
                                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
                            jobject ret = (*env)->CallObjectMethod(env, reflected, invoke, NULL, args);
                            if ((*env)->ExceptionCheck(env)) {
                                (*env)->ExceptionClear(env);
                                reason = "invocation threw (isolated)";
                            } else {
                                invoked = 1;
                                jclass string_class = (*env)->FindClass(env, "java/lang/String");
                                jmethodID value_of = (*env)->GetStaticMethodID(
                                    env, string_class, "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;");
                                jstring value = (jstring)(*env)->CallStaticObjectMethod(env, string_class, value_of, ret);
                                if (value) {
                                    const char *chars = (*env)->GetStringUTFChars(env, value, NULL);
                                    if (chars) {
                                        strncpy(result, chars, sizeof(result) - 1);
                                        (*env)->ReleaseStringUTFChars(env, value, chars);
                                    }
                                }
                            }
                        }
                    } else {
                        skipped = 1;
                        reason = "method not found";
                    }
                }
            }
        } else {
            reason = "class not found";
        }
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->PopLocalFrame(env, NULL);
        adh_jni_detach(did_attach);
    } else {
        reason = "no JNI env";
    }

    char classj[200], resultj[200], reasonj[160];
    json_escape(class_name, classj, sizeof(classj));
    json_escape(result, resultj, sizeof(resultj));
    json_escape(reason, reasonj, sizeof(reasonj));
    char out[720];
    snprintf(out, sizeof(out),
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"trigger\",\"ok\":true,"
             "\"class\":\"%s\",\"level\":%d,\"loaded\":%s,\"invoked\":%s,\"skipped\":%s,"
             "\"reason\":\"%s\",\"result\":\"%s\"}\n",
             idj, classj, level, loaded ? "true" : "false", invoked ? "true" : "false",
             skipped ? "true" : "false", reasonj, resultj);
    send_line(fd, out);
    LOGI("trigger %s method=%s level=%d loaded=%d invoked=%d skipped=%d (%s)",
         class_name, method ? method : "", level, loaded, invoked, skipped, reason);
}

void adh_cmd_load_so(int fd, const char *id, const char *path, const char *symbol) {
    char idj[64];
    json_escape(id, idj, sizeof(idj));
    void *handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
    const char *error = handle ? "" : dlerror();
    void *resolved = (handle && symbol && symbol[0]) ? dlsym(handle, symbol) : NULL;
    char pathj[300], errorj[300];
    json_escape(path, pathj, sizeof(pathj));
    json_escape(error ? error : "", errorj, sizeof(errorj));
    char out[900];
    snprintf(out, sizeof(out),
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"load_so\",\"ok\":%s,"
             "\"path\":\"%s\",\"handle\":\"%llx\",\"symbol\":\"%s\",\"symbolFound\":%s,"
             "\"error\":\"%s\"}\n",
             idj, handle ? "true" : "false", pathj,
             (unsigned long long)(uintptr_t)handle, symbol ? symbol : "",
             resolved ? "true" : "false", errorj);
    send_line(fd, out);
    LOGI("load_so path=%s ok=%d symFound=%d err=%s", path, handle != NULL,
         resolved != NULL, error ? error : "");
}

// Generic integer/pointer native invocation by module+symbol or absolute address.
// This is intentionally not policy-enforcing in the agent: the Host requires confirm:true
// before dispatching the command, while the agent only resolves and calls.

// Implemented in fp_call.S: x0-x7 come from ints[], d0-d7 from fps[] (AAPCS64 assigns the two banks
// independently); the FP return register d0 is written through fp_result_out. That is a per-call
// slot on purpose: a shared global would let two concurrent native_call requests read each other's
// result in the window between one call returning and its result being read.
extern unsigned long long adh_fp_call(void *target, const unsigned long long *ints,
                                      const unsigned long long *fps,
                                      unsigned long long *fp_result_out);

// Argument syntax: "f:<float>" and "d:<double>" fill the FP bank in order, anything else is an
// integer/pointer in x0-x7. Both banks hold at most 8 arguments; unknown or malformed tokens are
// rejected instead of being silently coerced to 0.
static int parse_typed_args(const char *csv, unsigned long long *ints, int *int_count,
                            unsigned long long *fps, int *fp_count, int *total_count,
                            char *error, size_t error_size) {
    *int_count = 0; *fp_count = 0; *total_count = 0;
    if (!csv || !csv[0]) return 1;
    const char *p = csv;
    for (;;) {
        while (*p == ' ' || *p == '\t') p++;
        const char *start = p;
        while (*p && *p != ',') p++;
        size_t len = (size_t)(p - start);
        char token[96];
        if (len >= sizeof(token)) { snprintf(error, error_size, "argument too long"); return 0; }
        memcpy(token, start, len);
        token[len] = 0;
        char *t = token;
        while (*t == ' ' || *t == '\t') t++;
        char *te = t + strlen(t);
        while (te > t && (te[-1] == ' ' || te[-1] == '\t')) *--te = 0;
        // A separator with nothing next to it ("1,,2", leading/trailing comma) is a typo, not a
        // shorter argument list: dropping it silently shifts every later argument by one register,
        // so the target would be called with arguments the caller never asked for. Fail loud.
        if (!*t) {
            snprintf(error, error_size, "empty argument in '%s' (leading, trailing or doubled comma)", csv);
            return 0;
        }
        int is_fp = (t[0] == 'f' || t[0] == 'd' || t[0] == 'F' || t[0] == 'D') && t[1] == ':';
        if (is_fp) {
            if (*fp_count >= 8) { snprintf(error, error_size, "at most 8 floating-point arguments (d0-d7)"); return 0; }
            const char *value = t + 2;
            char *endp = NULL;
            errno = 0;
            double d = strtod(value, &endp);
            if (!value[0] || endp == value || *endp) { snprintf(error, error_size, "bad floating-point argument: %s", t); return 0; }
            // strtod quietly clamps overflow to +-HUGE_VAL; a silent inf is exactly the kind of
            // "looks like it worked" answer this tool must not produce.
            if (errno == ERANGE) { snprintf(error, error_size, "floating-point argument out of range: %s", t); return 0; }
            if (t[0] == 'f' || t[0] == 'F') {
                // (float)d is undefined behaviour when d is outside float range, and NaN fails both
                // comparisons, so this single check covers overflow and "f:nan" alike.
                if (!(d >= -3.4028234663852886e38 && d <= 3.4028234663852886e38)) {
                    snprintf(error, error_size, "float argument out of range: %s", t);
                    return 0;
                }
                float f = (float)d;
                uint32_t bits = 0;
                memcpy(&bits, &f, sizeof(bits));
                fps[*fp_count] = bits;
            } else {
                memcpy(&fps[*fp_count], &d, sizeof(d));
            }
            (*fp_count)++;
        } else {
            if (*int_count >= 8) { snprintf(error, error_size, "at most 8 integer arguments (x0-x7)"); return 0; }
            if (strchr(t, ':')) {
                snprintf(error, error_size,
                         "unknown argument type in '%s' (use f:<float>, d:<double>, or an integer/pointer)", t);
                return 0;
            }
            char *endp = NULL;
            errno = 0;
            unsigned long long v = strtoull(t, &endp, 0);
            if (endp == t || *endp) { snprintf(error, error_size, "bad integer argument: %s", t); return 0; }
            if (errno == ERANGE) { snprintf(error, error_size, "integer argument out of range: %s", t); return 0; }
            ints[*int_count] = v;
            (*int_count)++;
        }
        (*total_count)++;
        if (*p != ',') break;
        p++;
    }
    return 1;
}

void adh_cmd_native_call(int fd, const char *id, const char *module, const char *symbol,
                         const char *addr_hex, const char *args_csv) {
    char idj[64];
    json_escape(id, idj, sizeof(idj));
    // The echoed args pass through a fixed 320-byte JSON buffer: a longer list would be silently cut
    // and reported as if that had been the request. Refuse it before the target runs at all.
    if (strlen(args_csv ? args_csv : "") >= 280) {
        char out[260];
        snprintf(out, sizeof(out),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"native_call\",\"ok\":false,"
                 "\"error\":\"native_call args string too long (max 279 bytes)\"}\n", idj);
        send_line(fd, out);
        return;
    }
    void *target = NULL;
    const char *source = "";
    if (addr_hex && addr_hex[0]) {
        target = (void *)(uintptr_t)strtoull(addr_hex, NULL, 0);
        source = "addr";
    } else if (module && module[0] && symbol && symbol[0]) {
        target = adh_resolve_sym(module, symbol);
        source = "symbol";
    }
    if (!target) {
        char out[420];
        snprintf(out, sizeof(out),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"native_call\",\"ok\":false,"
                 "\"error\":\"native_call needs addr or module+symbol (target not found)\"}\n", idj);
        send_line(fd, out);
        return;
    }

    // Typed arguments: "f:<float>" / "d:<double>" go to the FP register bank (s0../d0..), everything
    // else is an integer/pointer in x0-x7. AAPCS64 assigns the banks independently, so the counts
    // are tracked separately; integers are always loaded into x0-x7 too, so pointer/handle
    // arguments can be combined with FP ones.
    unsigned long long ints[8] = {0};
    // fps[0..7] are loaded into d0-d7; the FP return lands in g_adh_fp_call_result.
    unsigned long long fps[8] __attribute__((aligned(16))) = {0};
    int int_argc = 0, fp_argc = 0, argc = 0;
    char error[256] = "";
    if (!parse_typed_args(args_csv ? args_csv : "", ints, &int_argc, fps, &fp_argc, &argc, error, sizeof(error))) {
        char errorj[320];
        json_escape(error, errorj, sizeof(errorj));
        char out[520];
        snprintf(out, sizeof(out),
                 "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"native_call\",\"ok\":false,"
                 "\"error\":\"%s\"}\n", idj, errorj);
        send_line(fd, out);
        return;
    }

    long long start_ns = now_ns();
    unsigned long long result = 0;
    unsigned long long fp_result = 0;
    if (fp_argc > 0) {
        LOGI("native_call fp: target=%p ints=%p fps=%p fp_argc=%d int_argc=%d",
             target, (void *)ints, (void *)fps, fp_argc, int_argc);
        result = adh_fp_call(target, ints, fps, &fp_result);
    } else {
        typedef unsigned long long (*fn8_t)(unsigned long long, unsigned long long,
                                            unsigned long long, unsigned long long,
                                            unsigned long long, unsigned long long,
                                            unsigned long long, unsigned long long);
        result = ((fn8_t)target)(ints[0], ints[1], ints[2], ints[3], ints[4], ints[5], ints[6], ints[7]);
    }
    long long duration_ns = now_ns() - start_ns;
    double fp_double = 0;
    memcpy(&fp_double, &fp_result, sizeof(fp_double));

    char modulej[160], symbolj[200], argsj[320];
    json_escape(module ? module : "", modulej, sizeof(modulej));
    json_escape(symbol ? symbol : "", symbolj, sizeof(symbolj));
    json_escape(args_csv ? args_csv : "", argsj, sizeof(argsj));
    char fpjson[320] = "";
    if (fp_argc > 0) {
        // x0 is only the return value for integer-returning targets; an FP-returning target leaves
        // it stale, so name the bank the numbers actually came from (d0).
        uint32_t flow = (uint32_t)(fp_result & 0xffffffffu);
        float fp_float = 0;
        memcpy(&fp_float, &flow, sizeof(fp_float));
        char dnum[32], fnum[32];
        // %.17g round-trips a double exactly: reporting a rounded value would hide the last few
        // bits of what the target actually returned (a float32-rounded argument, for one).
        if (isfinite(fp_double)) snprintf(dnum, sizeof(dnum), "%.17g", fp_double);
        else snprintf(dnum, sizeof(dnum), "null");
        if (isfinite(fp_float)) snprintf(fnum, sizeof(fnum), "%.9g", (double)fp_float);
        else snprintf(fnum, sizeof(fnum), "null");
        snprintf(fpjson, sizeof(fpjson),
                 ",\"fpResult\":\"0x%llx\",\"fpResultDouble\":%s,\"fpResultFloat\":%s,"
                 "\"fpArgCount\":%d,\"intArgCount\":%d,\"returnBank\":\"d0\","
                 // A double return fills d0; a float return fills only its low 32 bits (s0).
                 // x0 is the integer-bank return and is only meaningful when the target returns an
                 // int, so say so instead of letting result look like the answer for an FP target.
                 "\"x0MayBeStale\":true",
                 fp_result, dnum, fnum, fp_argc, int_argc);
    }
    char out[1400];
    snprintf(out, sizeof(out),
             "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"native_call\",\"ok\":true,"
             "\"source\":\"%s\",\"module\":\"%s\",\"symbol\":\"%s\",\"target\":\"0x%llx\","
             "\"args\":\"[%s]\",\"argCount\":%d,\"result\":\"0x%llx\",\"resultDecimal\":%llu,"
             "\"durationUs\":%lld,\"fpSupported\":true%s}\n",
             idj, source, modulej, symbolj, (unsigned long long)(uintptr_t)target,
             argsj, argc, result, result, duration_ns / 1000, fpjson);
    send_line(fd, out);
    LOGI("native_call src=%s target=%p args=%d fp=%d result=0x%llx", source, target, argc, fp_argc, result);
}

