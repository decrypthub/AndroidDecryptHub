// JavaVM discovery and app-class loading shared by command modules.

#include "jni.h"

#include <dlfcn.h>

static JavaVM *g_vm = NULL;

void idh_jni_set_vm(JavaVM *vm) {
    g_vm = vm;
}

int idh_jni_vm_available(void) {
    return g_vm != NULL;
}

JNIEnv *idh_jni_attach(int *did_attach) {
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

void idh_jni_detach(int did_attach) {
    if (did_attach && g_vm) (*g_vm)->DetachCurrentThread(g_vm);
}

jclass idh_jni_load_app_class(JNIEnv *env, const char *dotname) {
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
