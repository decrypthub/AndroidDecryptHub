#include "inspection.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <jni.h>
#include <stdint.h>
#include <pthread.h>

#include "../bootstrap/agent_internal.h"
#include "../hook/got.h"
#include "jni.h"

// Resolve a live object through a caller-supplied static field and enumerate its
// declared fields without embedding target class knowledge in the agent.
void idh_cmd_object_inspect(int fd, const char *id, const char *class_name,
                            const char *field_name) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    int did = 0;
    JNIEnv *env = idh_jni_attach(&did);
    if (!env) { char e[160]; snprintf(e, sizeof(e), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_inspect\",\"ok\":false,\"error\":\"no JavaVM\"}\n", idj); send_line(fd, e); return; }
    (*env)->PushLocalFrame(env, 256);

    size_t cap = 1 << 14; char *out = malloc(cap);
    int ok = 0; char err[128] = ""; char obj_class[160] = ""; int nfields = 0;
    char *recs = malloc(1 << 13); if (recs) recs[0] = 0; size_t rlen = 0, rcap = 1 << 13;

    jclass cls_class = (*env)->FindClass(env, "java/lang/Class");
    jclass field_class = (*env)->FindClass(env, "java/lang/reflect/Field");
    jclass str_class = (*env)->FindClass(env, "java/lang/String");
    jmethodID get_field = (*env)->GetMethodID(env, cls_class, "getDeclaredField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
    jmethodID get_fields = (*env)->GetMethodID(env, cls_class, "getDeclaredFields", "()[Ljava/lang/reflect/Field;");
    jmethodID get_name = (*env)->GetMethodID(env, cls_class, "getName", "()Ljava/lang/String;");
    jmethodID set_accessible = (*env)->GetMethodID(env, field_class, "setAccessible", "(Z)V");
    jmethodID field_get = (*env)->GetMethodID(env, field_class, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
    jmethodID field_get_name = (*env)->GetMethodID(env, field_class, "getName", "()Ljava/lang/String;");
    jmethodID value_of = (*env)->GetStaticMethodID(env, str_class, "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;");

    jclass target = idh_jni_load_app_class(env, class_name);
    if (!target) { strncpy(err, "class not found", sizeof(err)-1); goto done; }

    jstring field_name_value = (*env)->NewStringUTF(env, field_name);
    jobject field_obj = (*env)->CallObjectMethod(env, target, get_field, field_name_value);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); strncpy(err, "field not found", sizeof(err)-1); goto done; }
    (*env)->CallVoidMethod(env, field_obj, set_accessible, JNI_TRUE);
    jobject obj = (*env)->CallObjectMethod(env, field_obj, field_get, NULL);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); strncpy(err, "field.get failed (not static?)", sizeof(err)-1); goto done; }
    if (!obj) { strncpy(err, "field value is null", sizeof(err)-1); goto done; }

    jclass object_class = (*env)->GetObjectClass(env, obj);
    jstring object_class_name = (jstring)(*env)->CallObjectMethod(env, object_class, get_name);
    if (object_class_name) { const char *s = (*env)->GetStringUTFChars(env, object_class_name, NULL); if (s) { strncpy(obj_class, s, sizeof(obj_class)-1); (*env)->ReleaseStringUTFChars(env, object_class_name, s); } }

    jobjectArray fields = (jobjectArray)(*env)->CallObjectMethod(env, object_class, get_fields);
    jsize field_count = fields ? (*env)->GetArrayLength(env, fields) : 0;
    for (jsize i = 0; i < field_count && recs; i++) {
        jobject field = (*env)->GetObjectArrayElement(env, fields, i);
        (*env)->CallVoidMethod(env, field, set_accessible, JNI_TRUE);
        jstring name = (jstring)(*env)->CallObjectMethod(env, field, field_get_name);
        jobject value = (*env)->CallObjectMethod(env, field, field_get, obj);
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        jstring value_string = (jstring)(*env)->CallStaticObjectMethod(env, str_class, value_of, value);
        char name_buf[96] = "", value_buf[300] = "";
        if (name) { const char *s = (*env)->GetStringUTFChars(env, name, NULL); if (s) { strncpy(name_buf, s, sizeof(name_buf)-1); (*env)->ReleaseStringUTFChars(env, name, s); } }
        if (value_string) { const char *s = (*env)->GetStringUTFChars(env, value_string, NULL); if (s) { strncpy(value_buf, s, sizeof(value_buf)-1); (*env)->ReleaseStringUTFChars(env, value_string, s); } }
        char namej[120], valuej[600]; json_escape(name_buf, namej, sizeof(namej)); json_escape(value_buf, valuej, sizeof(valuej));
        char rec[760]; int written = snprintf(rec, sizeof(rec), "%s{\"name\":\"%s\",\"value\":\"%s\"}", nfields ? "," : "", namej, valuej);
        if (written > 0 && rlen + (size_t)written + 1 < rcap) { memcpy(recs + rlen, rec, written); rlen += written; recs[rlen] = 0; nfields++; }
        (*env)->DeleteLocalRef(env, field);
    }
    ok = 1;

done:
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    (*env)->PopLocalFrame(env, NULL);
    idh_jni_detach(did);
    if (out) {
        char classj[160], errorj[160]; json_escape(obj_class, classj, sizeof(classj)); json_escape(err, errorj, sizeof(errorj));
        if (ok) snprintf(out, cap, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_inspect\",\"ok\":true,\"objectClass\":\"%s\",\"fieldCount\":%d,\"fields\":[%s]}\n", idj, classj, nfields, recs ? recs : "");
        else snprintf(out, cap, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_inspect\",\"ok\":false,\"error\":\"%s\"}\n", idj, errorj);
        send_line(fd, out);
        free(out);
    }
    free(recs);
    LOGI("object_inspect: %s.%s -> %s fields=%d ok=%d", class_name, field_name, obj_class, nfields, ok);
}

// Invoke only a caller-selected no-arg method on the object reached through the same
// static-field path. Policy and confirmation stay with the Host ADH Daemon.
void idh_cmd_object_invoke(int fd, const char *id, const char *class_name,
                           const char *field_name, const char *method_name) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    int did = 0;
    JNIEnv *env = idh_jni_attach(&did);
    if (!env) { char e[160]; snprintf(e, sizeof(e), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_invoke\",\"ok\":false,\"error\":\"no JavaVM\"}\n", idj); send_line(fd, e); return; }
    (*env)->PushLocalFrame(env, 128);
    int ok = 0; char err[128] = "", result[400] = "";

    jclass cls_class = (*env)->FindClass(env, "java/lang/Class");
    jclass field_class = (*env)->FindClass(env, "java/lang/reflect/Field");
    jclass method_class = (*env)->FindClass(env, "java/lang/reflect/Method");
    jclass str_class = (*env)->FindClass(env, "java/lang/String");
    jmethodID get_field = (*env)->GetMethodID(env, cls_class, "getDeclaredField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
    jmethodID get_method = (*env)->GetMethodID(env, cls_class, "getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");
    jmethodID set_accessible = (*env)->GetMethodID(env, field_class, "setAccessible", "(Z)V");
    jmethodID field_get = (*env)->GetMethodID(env, field_class, "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
    jmethodID invoke = (*env)->GetMethodID(env, method_class, "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
    jmethodID value_of = (*env)->GetStaticMethodID(env, str_class, "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;");

    jclass target = idh_jni_load_app_class(env, class_name);
    if (!target) { strncpy(err, "class not found", sizeof(err)-1); goto done; }
    jobject field_obj = (*env)->CallObjectMethod(env, target, get_field, (*env)->NewStringUTF(env, field_name));
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); strncpy(err, "field not found", sizeof(err)-1); goto done; }
    (*env)->CallVoidMethod(env, field_obj, set_accessible, JNI_TRUE);
    jobject obj = (*env)->CallObjectMethod(env, field_obj, field_get, NULL);
    if (!obj || (*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); strncpy(err, "field value null", sizeof(err)-1); goto done; }

    jclass object_class = (*env)->GetObjectClass(env, obj);
    jobject method = (*env)->CallObjectMethod(env, object_class, get_method, (*env)->NewStringUTF(env, method_name), NULL);
    if (!method || (*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); strncpy(err, "method not found (no-arg only)", sizeof(err)-1); goto done; }
    jobject ret = (*env)->CallObjectMethod(env, method, invoke, obj, NULL);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); strncpy(err, "invoke threw", sizeof(err)-1); goto done; }
    jstring value_string = (jstring)(*env)->CallStaticObjectMethod(env, str_class, value_of, ret);
    if (value_string) { const char *s = (*env)->GetStringUTFChars(env, value_string, NULL); if (s) { strncpy(result, s, sizeof(result)-1); (*env)->ReleaseStringUTFChars(env, value_string, s); } }
    ok = 1;

done:
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    (*env)->PopLocalFrame(env, NULL);
    idh_jni_detach(did);
    char resultj[500], errorj[160]; json_escape(result, resultj, sizeof(resultj)); json_escape(err, errorj, sizeof(errorj));
    char out[800];
    if (ok) snprintf(out, sizeof(out), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_invoke\",\"ok\":true,\"result\":\"%s\"}\n", idj, resultj);
    else snprintf(out, sizeof(out), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"object_invoke\",\"ok\":false,\"error\":\"%s\"}\n", idj, errorj);
    send_line(fd, out);
    LOGI("object_invoke: %s.%s.%s() -> %s ok=%d", class_name, field_name, method_name, result, ok);
}

// Runtime footprint. These are observation counters only: no hiding, no fake VMA
// names, no policy decisions. The baseline is captured when the agent is first
// entered (JNI_OnLoad or adh_agent_start), before any hook/trace command runs.
struct footprint_counts {
    int maps;
    int exec;
    int file_exec;
    int memfd_exec;
    int anon_exec;
    int anon_named_exec;
    int rwx;
    int agent_exec;
    int zygisk_exec;
    unsigned long long exec_bytes;
    unsigned long long memfd_exec_bytes;
    unsigned long long anon_exec_bytes;
    unsigned long long anon_named_exec_bytes;
};

static int footprint_scan(struct footprint_counts *c, int *module_count) {
    memset(c, 0, sizeof(*c));
    if (module_count) *module_count = 0;
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;

    char line[1024];
    char last_module[600] = "";
    while (fgets(line, sizeof(line), maps)) {
        c->maps++;
        unsigned long long start = 0, end = 0, offset = 0, inode = 0;
        char perms[5] = {0}, dev[8] = {0}, path[600] = {0};
        int n = sscanf(line, "%llx-%llx %4s %llx %7s %llu %599[^\n]",
                       &start, &end, perms, &offset, dev, &inode, path);
        if (n < 6) continue;

        char *pth = path;
        while (*pth == ' ' || *pth == '\t') pth++;

        if (module_count && pth[0] == '/' && strcmp(pth, last_module) != 0) {
            strncpy(last_module, pth, sizeof(last_module) - 1);
            last_module[sizeof(last_module) - 1] = 0;
            (*module_count)++;
        }
        if (strlen(perms) < 4 || perms[2] != 'x') continue;

        unsigned long long bytes = end > start ? end - start : 0;
        c->exec++;
        c->exec_bytes += bytes;
        if (perms[1] == 'w') c->rwx++;

        if (pth[0] == '/') {
            if (strstr(pth, "/memfd:")) {
                c->memfd_exec++;
                c->memfd_exec_bytes += bytes;
            } else {
                c->file_exec++;
            }
        } else if (strncmp(pth, "[anon:", 6) == 0) {
            c->anon_named_exec++;
            c->anon_named_exec_bytes += bytes;
        } else if (pth[0] == 0 && strcmp(dev, "00:00") == 0 && inode == 0) {
            c->anon_exec++;
            c->anon_exec_bytes += bytes;
        }

        // Either file name: the shipped lib is libadh_agent.so, a not-yet-reflashed module dir still has libidh_agent.so.
        if (strstr(pth, "libadh_agent.so") || strstr(pth, "libidh_agent.so")) c->agent_exec++;
        if (strstr(pth, "/zygisk/") || strstr(pth, "libzygisk.so") || strstr(pth, "zygisk_"))
            c->zygisk_exec++;
    }
    fclose(maps);
    return 1;
}

static struct footprint_counts g_footprint_baseline;
static int g_footprint_baseline_valid = 0;
static pthread_once_t g_footprint_once = PTHREAD_ONCE_INIT;

static void footprint_capture_baseline_once(void) {
    g_footprint_baseline_valid = footprint_scan(&g_footprint_baseline, NULL);
}

void adh_footprint_capture_baseline(void) {
    pthread_once(&g_footprint_once, footprint_capture_baseline_once);
}

// Report observed runtime constraints instead of claiming a backend is available from
// compile-time configuration alone. The footprint block exposes both the bootstrap
// baseline and the current counts; a positive anonExec delta means the process gained a
// true anonymous executable mapping after bootstrap (correlate with the command that ran;
// Dobby/QBDI are known producers, ART JIT/other runtimes may also add one).
void idh_cmd_compat_probe(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    adh_footprint_capture_baseline();

    int tracer = -1, seccomp = -1;
    FILE *status = fopen("/proc/self/status", "r");
    if (status) { char line[256];
        while (fgets(line, sizeof(line), status)) {
            if (strncmp(line, "TracerPid:", 10) == 0) tracer = atoi(line + 10);
            else if (strncmp(line, "Seccomp:", 8) == 0) seccomp = atoi(line + 8);
        }
        fclose(status);
    }
    int got_ok = (idh_resolve_sym("libc.so", "access") != NULL);
    int jni_ok = idh_jni_vm_available();

    struct footprint_counts cur;
    int module_count = 0;
    int maps_read_ok = footprint_scan(&cur, &module_count);
    int bv = g_footprint_baseline_valid;
    const struct footprint_counts *base = bv ? &g_footprint_baseline : NULL;

    int memread_ok = 0;
    { int mem_fd = open("/proc/self/mem", O_RDONLY);
      if (mem_fd >= 0) { unsigned char bytes[4]; memread_ok = (pread(mem_fd, bytes, 4, (off_t)(uintptr_t)&idh_cmd_compat_probe) == 4); close(mem_fd); } }
    void *dlprobe = dlopen("libcrypto.so", RTLD_NOW);
    int dlopen_blocked = (dlprobe == NULL);
    if (dlprobe) dlclose(dlprobe);

    char out[3072];
    snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"compat_probe\",\"ok\":true,"
        "\"tracerPid\":%d,\"seccomp\":%d,\"backends\":{\"gotHook\":%s,\"jniReflect\":%s,\"artDexCapture\":%s,\"memRead\":%s},"
        "\"mapsReadOk\":%s,\"mapsCount\":%d,\"moduleMappings\":%d,"
        "\"execMappings\":%d,\"fileExecMappings\":%d,\"memfdExecMappings\":%d,"
        "\"anonExecMappings\":%d,\"anonNamedExecMappings\":%d,\"rwxMappings\":%d,"
        "\"execKiB\":%llu,\"memfdExecKiB\":%llu,\"anonExecKiB\":%llu,\"anonNamedExecKiB\":%llu,"
        "\"agentExecMappings\":%d,\"zygiskExecMappings\":%d,"
        "\"baselineValid\":%s,"
        "\"baseline\":{\"execMappings\":%d,\"anonExecMappings\":%d,\"anonNamedExecMappings\":%d,\"memfdExecMappings\":%d,\"rwxMappings\":%d,\"agentExecMappings\":%d,\"zygiskExecMappings\":%d},"
        "\"delta\":{\"execMappings\":%d,\"anonExecMappings\":%d,\"anonNamedExecMappings\":%d,\"memfdExecMappings\":%d,\"rwxMappings\":%d},"
        "\"dlopenSystemLibsBlocked\":%s}\n",
        idj, tracer, seccomp, got_ok ? "true" : "false", jni_ok ? "true" : "false",
        idh_jni_vm_available() ? "true" : "false", memread_ok ? "true" : "false",
        maps_read_ok ? "true" : "false", cur.maps, module_count,
        cur.exec, cur.file_exec, cur.memfd_exec, cur.anon_exec, cur.anon_named_exec, cur.rwx,
        (unsigned long long)(cur.exec_bytes / 1024),
        (unsigned long long)(cur.memfd_exec_bytes / 1024),
        (unsigned long long)(cur.anon_exec_bytes / 1024),
        (unsigned long long)(cur.anon_named_exec_bytes / 1024),
        cur.agent_exec, cur.zygisk_exec,
        bv ? "true" : "false",
        bv ? base->exec : -1, bv ? base->anon_exec : -1, bv ? base->anon_named_exec : -1,
        bv ? base->memfd_exec : -1, bv ? base->rwx : -1,
        bv ? base->agent_exec : -1, bv ? base->zygisk_exec : -1,
        bv ? (cur.exec - base->exec) : 0,
        bv ? (cur.anon_exec - base->anon_exec) : 0,
        bv ? (cur.anon_named_exec - base->anon_named_exec) : 0,
        bv ? (cur.memfd_exec - base->memfd_exec) : 0,
        bv ? (cur.rwx - base->rwx) : 0,
        dlopen_blocked ? "true" : "false");
    send_line(fd, out);
    LOGI("compat_probe: tracer=%d seccomp=%d got=%d jni=%d exec=%d anon=%d rwx=%d",
         tracer, seccomp, got_ok, jni_ok, cur.exec, cur.anon_exec, cur.rwx);
}

void idh_cmd_jni_probe(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    int did = 0;
    JNIEnv *env = idh_jni_attach(&did);
    if (!env) {
        char error[160]; snprintf(error, sizeof(error), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"jni_probe\",\"ok\":false,\"error\":\"no JavaVM\"}\n", idj);
        send_line(fd, error); return;
    }
    jint sdk = -1; char release[64] = "";
    jclass version = (*env)->FindClass(env, "android/os/Build$VERSION");
    if (version) {
        jfieldID sdk_field = (*env)->GetStaticFieldID(env, version, "SDK_INT", "I");
        if (sdk_field) sdk = (*env)->GetStaticIntField(env, version, sdk_field);
        jfieldID release_field = (*env)->GetStaticFieldID(env, version, "RELEASE", "Ljava/lang/String;");
        if (release_field) {
            jstring value = (jstring)(*env)->GetStaticObjectField(env, version, release_field);
            if (value) {
                const char *s = (*env)->GetStringUTFChars(env, value, NULL);
                if (s) { strncpy(release, s, sizeof(release) - 1); (*env)->ReleaseStringUTFChars(env, value, s); }
                (*env)->DeleteLocalRef(env, value);
            }
        }
        (*env)->DeleteLocalRef(env, version);
    }
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    idh_jni_detach(did);

    char out[256], releasej[128]; json_escape(release, releasej, sizeof(releasej));
    snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"jni_probe\",\"ok\":true,\"sdk_int\":%d,\"release\":\"%s\",\"attached\":%d}\n",
        idj, sdk, releasej, did);
    send_line(fd, out);
    LOGI("jni_probe: sdk=%d release=%s", sdk, release);
}
