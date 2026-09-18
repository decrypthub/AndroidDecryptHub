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

    /**
     * Caller-chain fixture for the Java-side stack capture (v4.40): stackOuter -> stackMiddle ->
     * ping. Both frames must show up in the JAVA_HOOK event when the hook is installed with
     * stack:true, and the chain must be absent when it is not.
     */
    @JvmStatic
    fun stackMiddle(input: String): String = ping(input)

    @JvmStatic
    fun stackOuter(input: String): String = stackMiddle(input)

    fun instancePing(input: String): String = "REAL_INSTANCE:$input"
}