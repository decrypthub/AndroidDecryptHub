package com.adh.sandbox

import android.util.Log

// A live object with known field values — ground truth for v0.6 Runtime Object
// Inspector. The agent reads HeapProbe.sConfig's fields reflectively and asserts them.
object HeapProbe {
    private const val TAG = "ADH_SANDBOX"

    class Config(val token: String, val count: Int, val note: String)

    @JvmStatic
    var sConfig: Config? = null

    @JvmStatic
    fun init() {
        sConfig = Config("IDH_TOKEN_abc123", 42, "live-object")
        Log.i(TAG, "HeapProbe.sConfig initialized")
    }
}
