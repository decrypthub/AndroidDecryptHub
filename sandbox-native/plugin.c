// Runtime-loaded plugin fixture for the load-time JNI_OnLoad watch (v4.30).
//
// Built twice (ADH_PLUGIN_SYMBOL = adh_plugin_a_count / adh_plugin_b_count) into libadhplugin_a.so
// and libadhplugin_b.so. The sandbox loads them *after* startup (System.loadLibrary from a trigger
// method), so the agent's dlopen watch can patch JNI_OnLoad before ART calls it - and, with
// skipOriginal, prove the interception by keeping the counter at zero.

#include <jni.h>
#include <stdint.h>
#include <android/log.h>

#ifndef ADH_PLUGIN_SYMBOL
#error "ADH_PLUGIN_SYMBOL must be defined"
#endif

#define TAG "ADH_PLUGIN"

static volatile int g_onload_calls = 0;

// v4.34 fixture: this library is a DIFFERENT module from the one that defines adh_add_target, so
// the call below is a cross-module B/BL through this library's own PLT stub - the case the
// call-site backend has to resolve when it is asked to scan outside the target module.
extern long adh_add_target(long a, long b);

__attribute__((noinline, used, visibility("default")))
long adh_plugin_call_adder(void) {
    return adh_add_target(20, 22);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    int calls = __atomic_add_fetch(&g_onload_calls, 1, __ATOMIC_RELAXED) + 1;
    __android_log_print(ANDROID_LOG_INFO, TAG, "JNI_OnLoad ran (calls=%d)", calls);
    return JNI_VERSION_1_6;
}

// v4.34: JNI entry so the verifier can drive the cross-module call from Java (this method is looked
// up in the loaded plugin, not in the sandbox library).
JNIEXPORT jint JNICALL Java_com_adh_sandbox_Detection_pluginProbe(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    return (jint)adh_plugin_call_adder();
}

// Lets the verifier read how many times the real JNI_OnLoad executed (0 proves skipOriginal).
JNIEXPORT jint JNICALL ADH_PLUGIN_SYMBOL(void) {
    return (jint)__atomic_load_n(&g_onload_calls, __ATOMIC_RELAXED);
}