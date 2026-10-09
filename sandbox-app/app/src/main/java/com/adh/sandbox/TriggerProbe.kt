package com.adh.sandbox

// Target for the active-trigger scheduler (P2). safeCompute() is a safe static no-arg
// method the agent may invoke to force code paths (a refill-type shell would restore its
// CodeItem here). deleteAll()'s name is on the safety blacklist, so the scheduler must
// SKIP it — proving the policy actually protects against dangerous auto-invocation.
object TriggerProbe {
    @JvmStatic @Volatile var invokedSafe = false
    @JvmStatic @Volatile var invokedDanger = false

    @JvmStatic
    fun safeCompute(): String { invokedSafe = true; return "ADH_TRIGGER_OK" }

    // Dangerous by name ("delete") — must never be auto-invoked by the scheduler.
    @JvmStatic
    fun deleteAll() { invokedDanger = true }

    @JvmStatic
    fun reset() { invokedSafe = false; invokedDanger = false }
}
