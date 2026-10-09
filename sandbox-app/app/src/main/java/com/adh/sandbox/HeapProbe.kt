package com.adh.sandbox

import android.util.Log

// A live object with known field values — ground truth for v0.6 Runtime Object
// Inspector. The agent reads HeapProbe.sConfig's fields reflectively and asserts them.
object HeapProbe {
    private const val TAG = "ADH_SANDBOX"

    class Config(val token: String, val count: Int, val note: String) {
        // v4.53 object_set fixture: the write path needs fields that are NOT final (a Kotlin val
        // compiles to a final field, and reflection cannot patch those). The values here are the
        // ground truth the acceptance script flips and reads back.
        @JvmField var flag: Boolean = false
        @JvmField var counter: Int = 7
        @JvmField var label: String = "before"
    }

    @JvmStatic
    var sConfig: Config? = null

    // v4.53b fixture: the field to patch is declared on the SUPERCLASS, so the agent has to walk the
    // chain (getDeclaredField alone reports "not found" for it).
    open class InheritBase {
        @JvmField var inherited: Int = 5
    }

    class InheritChild : InheritBase() {
        @JvmField var own: Int = 1
    }

    @JvmStatic
    var sInherited: InheritChild? = null

    // v4.55 fixture for the JNIEnv FIELD accessor slots: a mutable STATIC int the native probe can
    // read and write through Get/SetStaticIntField.
    @JvmStatic
    var sCounter: Int = 11

    @JvmStatic
    fun init() {
        sConfig = Config("ADH_TOKEN_abc123", 42, "live-object")
        sInherited = InheritChild()
        Log.i(TAG, "HeapProbe.sConfig initialized")
    }
}
