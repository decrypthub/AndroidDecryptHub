#include "actions.h"

#include <dlfcn.h>
#include <jni.h>
#include <stdint.h>

#include "../bootstrap/agent_internal.h"
#include "jni.h"

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

void idh_cmd_trigger(int fd, const char *id, const char *class_name, const char *method, int level) {
    char idj[64];
    json_escape(id, idj, sizeof(idj));
    int loaded = 0, invoked = 0, skipped = 0;
    const char *reason = "";
    char result[160] = "";
    int did_attach = 0;
    JNIEnv *env = idh_jni_attach(&did_attach);
    if (env) {
        (*env)->PushLocalFrame(env, 64);
        jclass target = idh_jni_load_app_class(env, class_name);
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
        idh_jni_detach(did_attach);
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

void idh_cmd_load_so(int fd, const char *id, const char *path, const char *symbol) {
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
