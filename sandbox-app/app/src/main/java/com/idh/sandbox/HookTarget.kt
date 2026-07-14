package com.idh.sandbox

// Victim class for the LSPlant Java-method-hook self-test (WS-A). A static method with a
// known input→output so the hook test can assert both that the callback fired (captured
// the real arg) and that the original still ran (backup.invoke returned the real value).
object HookTarget {
    @JvmStatic
    fun secret(input: String): String = "REAL_SECRET:$input"
}
