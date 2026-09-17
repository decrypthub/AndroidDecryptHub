package com.adh.sandbox

/** Deterministic target for the LSPlant java_hook acceptance test. */
object HookProbe {
    @JvmStatic
    fun ping(input: String): String = "REAL_HOOK:$input"
}