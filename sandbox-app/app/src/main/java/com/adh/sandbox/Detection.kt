package com.adh.sandbox

import android.util.Log

// Bridge to libadhdetect.so — the mock native anti-analysis lib. Loaded at startup
// so its GOT exists; the agent installs GOT hooks then invokes run() reflectively.
object Detection {
    private const val TAG = "ADH_SANDBOX"
    @JvmStatic external fun run(): Int
    @JvmStatic external fun staticCrypto(): Int
    @JvmStatic external fun nativeHookProbe(): Int    @JvmStatic external fun jniRegisterProbe(): Int
    @JvmStatic external fun jniRegisteredProbe(): Int

    fun load() {
        try {
            System.loadLibrary("adhdetect")
            Log.i(TAG, "adhdetect loaded")
        } catch (t: Throwable) {
            Log.w(TAG, "adhdetect not loaded: ${t.message}")
        }
    }
}
