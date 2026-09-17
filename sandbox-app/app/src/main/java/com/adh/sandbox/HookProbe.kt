package com.adh.sandbox

/** Deterministic target for the LSPlant java_hook acceptance test. */
object HookProbe {
    @JvmField
    var marker: String = "ADH_ENUM_FIELD"

    @JvmStatic
    fun ping(input: String): String = "REAL_HOOK:$input"

    @JvmStatic
    fun ping(input: String, repeat: Int): String = "REAL_HOOK:$input*$repeat"
    fun instancePing(input: String): String = "REAL_INSTANCE:$input"
}