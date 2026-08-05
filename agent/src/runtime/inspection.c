#include "inspection.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <jni.h>
#include <stdint.h>

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

// Report observed runtime constraints instead of claiming a backend is available from
// compile-time configuration alone.
void idh_cmd_compat_probe(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
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
    int module_count = 0, maps_count = 0;
    FILE *maps = fopen("/proc/self/maps", "r"); char line[512]; char last_module[400] = "";
    while (maps && fgets(line, sizeof(line), maps)) { maps_count++;
        char *path = strstr(line, "/"); if (path) { char *newline = strchr(path, '\n'); if (newline) *newline = 0; if (strcmp(path, last_module)) { strncpy(last_module, path, sizeof(last_module)-1); module_count++; } } }
    if (maps) fclose(maps);

    int memread_ok = 0;
    { int mem_fd = open("/proc/self/mem", O_RDONLY);
      if (mem_fd >= 0) { unsigned char bytes[4]; memread_ok = (pread(mem_fd, bytes, 4, (off_t)(uintptr_t)&idh_cmd_compat_probe) == 4); close(mem_fd); } }
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
