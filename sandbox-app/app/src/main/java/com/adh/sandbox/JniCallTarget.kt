package com.adh.sandbox

// v4.24 fixture for the JNIEnv Call*Method hooks. Native code creates an instance and then
// calls instance + static methods through the varargs, V and A table entries, so the agent's
// table hooks can be checked against known labels and argument values.
class JniCallTarget {
    @JvmField var counter: Int = 41

    fun combine(label: String, count: Int): String = "$label:$count"

    fun counterValue(): Int = counter

    fun note(label: String) { counter += label.length }
}

object JniCallStatics {
    @JvmStatic fun staticCombine(label: String, count: Int): String = "S:$label:$count"
}