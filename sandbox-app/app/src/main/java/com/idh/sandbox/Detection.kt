package com.idh.sandbox

import android.util.Log

// Bridge to libidhdetect.so — the mock native anti-analysis lib. Loaded at startup
// so its GOT exists; the agent installs GOT hooks then invokes run() reflectively.
object Detection {
    private const val TAG = "IDH_SANDBOX"
    @JvmStatic external fun run(): Int
    @JvmStatic external fun staticCrypto(): Int

    fun load() {
        try {
            System.loadLibrary("idhdetect")
            Log.i(TAG, "idhdetect loaded")
        } catch (t: Throwable) {
            Log.w(TAG, "idhdetect not loaded: ${t.message}")
        }
    }
}
