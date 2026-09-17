// JavaVM discovery and app-class loading shared by command modules.

#include "jni.h"

#include <dlfcn.h>

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

JNIEnv *adh_jni_attach(int *did_attach) {
    *did_attach = 0;
    if (!g_vm) {
        typedef jint (*GetVMs)(JavaVM **, jsize, jsize *);
        void *lib = dlopen("libart.so", RTLD_NOW);
        GetVMs f = lib ? (GetVMs)dlsym(lib, "JNI_GetCreatedJavaVMs") : NULL;
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
    jclass at = (*env)->FindClass(env, "android/app/ActivityThread");
    if (at) {
        jmethodID cur = (*env)->GetStaticMethodID(env, at, "currentApplication",
                                                  "()Landroid/app/Application;");
        jobject app = cur ? (*env)->CallStaticObjectMethod(env, at, cur) : NULL;
        jclass ctx = (*env)->FindClass(env, "android/content/Context");
        jmethodID gcl = ctx ? (*env)->GetMethodID(env, ctx, "getClassLoader",
                                                  "()Ljava/lang/ClassLoader;") : NULL;
        if (app && gcl) {
            jobject loader = (*env)->CallObjectMethod(env, app, gcl);
            if (loader) return loader;
        }
    }
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);

    jclass thread = (*env)->FindClass(env, "java/lang/Thread");
    jmethodID current = thread ? (*env)->GetStaticMethodID(env, thread, "currentThread",
                                                          "()Ljava/lang/Thread;") : NULL;
    jobject t = current ? (*env)->CallStaticObjectMethod(env, thread, current) : NULL;
    jmethodID get = t ? (*env)->GetMethodID(env, thread, "getContextClassLoader",
                                            "()Ljava/lang/ClassLoader;") : NULL;
    if (get) return (*env)->CallObjectMethod(env, t, get);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    return NULL;
}
jclass adh_jni_load_app_class(JNIEnv *env, const char *dotname) {
    jclass at = (*env)->FindClass(env, "android/app/ActivityThread");
    jmethodID cur = at ? (*env)->GetStaticMethodID(env, at, "currentApplication", "()Landroid/app/Application;") : NULL;
    jobject app = cur ? (*env)->CallStaticObjectMethod(env, at, cur) : NULL;
    if (!app) return NULL;
    jclass ctx = (*env)->FindClass(env, "android/content/Context");
    jmethodID gcl = (*env)->GetMethodID(env, ctx, "getClassLoader", "()Ljava/lang/ClassLoader;");
    jobject loader = (*env)->CallObjectMethod(env, app, gcl);
    jclass clc = (*env)->FindClass(env, "java/lang/ClassLoader");
    jmethodID load = (*env)->GetMethodID(env, clc, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    jstring cn = (*env)->NewStringUTF(env, dotname);
    return loader ? (jclass)(*env)->CallObjectMethod(env, loader, load, cn) : NULL;
}
