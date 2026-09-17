package com.adh.sandbox

/** Deterministic target for the LSPlant java_hook acceptance test. */
object HookProbe {
    @JvmField
    var marker: String = "ADH_ENUM_FIELD"

    @JvmStatic
    fun ping(input: String): String = "REAL_HOOK:$input"

    @JvmStatic
    fun ping(input: String, repeat: Int): String = "REAL_HOOK:$input*$repeat"

    @Volatile
    private var lastPing: String = ""

    @JvmStatic
    fun recordPing(input: String): String {
        val result = ping(input)
        lastPing = result
        return result
    }

    @JvmStatic
    fun lastPingResult(): String = lastPing

    fun instancePing(input: String): String = "REAL_INSTANCE:$input"
}