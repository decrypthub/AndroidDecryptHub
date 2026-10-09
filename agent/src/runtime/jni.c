// JavaVM discovery and app-class loading shared by command modules.

#include "jni.h"
#include "jni_env_hooks.h"
#include "../hook/got.h"

#include <dlfcn.h>
#include <string.h>

static JavaVM *g_vm = NULL;

void adh_jni_set_vm(JavaVM *vm) {
    g_vm = vm;
}

int adh_jni_vm_available(void) {
    return g_vm != NULL;
}

JavaVM *adh_jni_get_vm(void) {
    return g_vm;
}

// JNI_GetCreatedJavaVMs, taken from the libart.so that is ALREADY loaded.
//
// dlopen("libart.so") is not a reliable way to reach it. Under Zygisk the agent is mapped from a
// memfd, and the linker refuses: `library "libart.so" needed or dlopened by "/memfd:jit-cache
// (deleted)" is not accessible for the namespace "(default)"` — the bare name is not on the app
// namespace's search path either. The agent then had no JavaVM at all, so art_dexfiles, java_hook,
// trigger and every object_* command answered "no JavaVM" on a real injected target while all of
// them passed in the sandbox (which gets its VM from JNI_OnLoad).
//
// Reading the symbol straight out of the loaded image sidesteps the namespace question and works
// for the gadget and Xposed backends too. dlopen stays as a last resort.
static void *libart_jni_get_created_vms(void) {
    void *f = adh_resolve_sym("libart.so", "JNI_GetCreatedJavaVMs");
    if (f) return f;
    const char *fallbacks[] = { "libart.so", "libnativehelper.so", "libartbase.so" };
    for (size_t i = 0; i < sizeof(fallbacks) / sizeof(fallbacks[0]); i++) {
        void *lib = dlopen(fallbacks[i], RTLD_NOW);
        if (!lib) continue;
        f = dlsym(lib, "JNI_GetCreatedJavaVMs");
        if (f) return f;
    }
    return NULL;
}

// Does the in-memory lookup find it? Reported by compat_probe so the "no JavaVM" case is
// diagnosable instead of just being a wall.
int adh_jni_libart_symbol_resolves(void) {
    return adh_resolve_sym("libart.so", "JNI_GetCreatedJavaVMs") != NULL;
}

JNIEnv *adh_jni_attach(int *did_attach) {
    *did_attach = 0;
    if (!g_vm) {
        typedef jint (*GetVMs)(JavaVM **, jsize, jsize *);
        GetVMs f = (GetVMs)libart_jni_get_created_vms();
        if (f) {
            JavaVM *vm = NULL;
            jsize n = 0;
            if (f(&vm, 1, &n) == 0 && n > 0) g_vm = vm;
        }
        if (!g_vm) return NULL;
    }

    JNIEnv *env = NULL;
    jint st = (*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6);
    if (st == JNI_EDETACHED) {
        if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != 0) return NULL;
        *did_attach = 1;
    } else if (st != JNI_OK) {
        return NULL;
    }
    return env;
}

void adh_jni_detach(int did_attach) {
    if (did_attach && g_vm) (*g_vm)->DetachCurrentThread(g_vm);
}

jobject adh_jni_app_class_loader(JNIEnv *env) {
    if (!env) return NULL;
    int ours = adh_jni_ours_enter();          // resolving a loader is ADH's own JNI work
    jobject result = NULL;
    jclass at = (*env)->FindClass(env, "android/app/ActivityThread");
    if (at) {
        jmethodID cur = (*env)->GetStaticMethodID(env, at, "currentApplication",
                                                  "()Landroid/app/Application;");
        jobject app = cur ? (*env)->CallStaticObjectMethod(env, at, cur) : NULL;
        jclass ctx = (*env)->FindClass(env, "android/content/Context");
        jmethodID gcl = ctx ? (*env)->GetMethodID(env, ctx, "getClassLoader",
                                                  "()Ljava/lang/ClassLoader;") : NULL;
        if (app && gcl) result = (*env)->CallObjectMethod(env, app, gcl);
    }
    if (!result) {
        if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
        jclass thread = (*env)->FindClass(env, "java/lang/Thread");
        jmethodID current = thread ? (*env)->GetStaticMethodID(env, thread, "currentThread",
                                                               "()Ljava/lang/Thread;") : NULL;
        jobject t = current ? (*env)->CallStaticObjectMethod(env, thread, current) : NULL;
        jmethodID get = t ? (*env)->GetMethodID(env, thread, "getContextClassLoader",
                                                "()Ljava/lang/ClassLoader;") : NULL;
        if (get) result = (*env)->CallObjectMethod(env, t, get);
        if (!result && adh_jni_exception_check(env)) adh_jni_exception_clear(env);
    }
    adh_jni_ours_leave(ours);
    return result;
}

void adh_jni_class_name(JNIEnv *env, jclass clazz, char *out, size_t out_size) {
    if (!out || out_size == 0) return;
    out[0] = 0;
    if (!env || !clazz) return;
    int ours = adh_jni_ours_enter();
    // The caller may already have a pending exception (a failed member-ID lookup is a normal
    // path in real targets). Park it: clearing or overwriting it here would silently change the
    // target's control flow, so the same throwable is re-thrown before we return.
    jthrowable pending = (*env)->ExceptionOccurred(env);
    if (pending) adh_jni_exception_clear(env);
    if ((*env)->PushLocalFrame(env, 8) != 0) {
        if (pending) { (*env)->Throw(env, pending); (*env)->DeleteLocalRef(env, pending); }
        adh_jni_ours_leave(ours);
        return;
    }
    jclass class_class = (*env)->GetObjectClass(env, clazz);
    jmethodID get_name = class_class
        ? (*env)->GetMethodID(env, class_class, "getName", "()Ljava/lang/String;") : NULL;
    jstring name = get_name ? (jstring)(*env)->CallObjectMethod(env, clazz, get_name) : NULL;
    if (name) {
        const char *chars = (*env)->GetStringUTFChars(env, name, NULL);
        if (chars) {
            strncpy(out, chars, out_size - 1);
            out[out_size - 1] = 0;
            (*env)->ReleaseStringUTFChars(env, name, chars);
        }
        (*env)->DeleteLocalRef(env, name);
    }
    if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);   // ours, not the caller's
    (*env)->PopLocalFrame(env, NULL);
    if (pending) {
        if (!adh_jni_exception_check(env)) (*env)->Throw(env, pending);
        (*env)->DeleteLocalRef(env, pending);
    }
    adh_jni_ours_leave(ours);
}

jclass adh_jni_load_app_class(JNIEnv *env, const char *dotname) {
    if (!env) return NULL;
    int ours = adh_jni_ours_enter();
    jclass result = NULL;
    jclass at = (*env)->FindClass(env, "android/app/ActivityThread");
    jmethodID cur = at ? (*env)->GetStaticMethodID(env, at, "currentApplication", "()Landroid/app/Application;") : NULL;
    jobject app = cur ? (*env)->CallStaticObjectMethod(env, at, cur) : NULL;
    if (app) {
        jclass ctx = (*env)->FindClass(env, "android/content/Context");
        jmethodID gcl = ctx ? (*env)->GetMethodID(env, ctx, "getClassLoader", "()Ljava/lang/ClassLoader;") : NULL;
        jobject loader = gcl ? (*env)->CallObjectMethod(env, app, gcl) : NULL;
        jclass clc = (*env)->FindClass(env, "java/lang/ClassLoader");
        jmethodID load = clc ? (*env)->GetMethodID(env, clc, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;") : NULL;
        jstring cn = (*env)->NewStringUTF(env, dotname);
        if (loader && load && cn) result = (jclass)(*env)->CallObjectMethod(env, loader, load, cn);
    }
    adh_jni_ours_leave(ours);
    return result;
}
