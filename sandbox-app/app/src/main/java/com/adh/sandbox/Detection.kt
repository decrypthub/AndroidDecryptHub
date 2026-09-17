package com.adh.sandbox

import android.util.Log

// Bridge to libadhdetect.so — the mock native anti-analysis lib. Loaded at startup
// so its GOT exists; the agent installs GOT hooks then invokes run() reflectively.
object Detection {
    private const val TAG = "ADH_SANDBOX"
    @JvmStatic external fun run(): Int
    @JvmStatic external fun staticCrypto(): Int
    @JvmStatic external fun nativeHookProbe(): Int
    @JvmStatic external fun jniRegisterProbe(): Int
    @JvmStatic external fun jniRegisteredProbe(): Int
    // v4.18 JNIEnv table probe: native code calls FindClass / GetMethodID / GetStaticMethodID /
    // NewStringUTF / GetStringUTFChars through this JNIEnv, so one trigger exercises every
    // JNIEnv table hook. jniEnvValue exists only to be resolved by GetStaticMethodID.
    @JvmStatic external fun jniEnvProbe(): Int
    @JvmStatic fun jniEnvValue(): String = "ADH_JNI_ENV_VALUE"

    fun load() {
        try {
            System.loadLibrary("adhdetect")
            Log.i(TAG, "adhdetect loaded")
        } catch (t: Throwable) {
            Log.w(TAG, "adhdetect not loaded: ${t.message}")
        }
    }
}
