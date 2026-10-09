package com.adh.sandbox

// v4.24 fixture for the JNIEnv Call*Method hooks. Native code creates an instance and then
// calls instance + static methods through the varargs, V and A table entries, so the agent's
// table hooks can be checked against known labels and argument values.
class JniCallTarget {
    @JvmField var counter: Int = 41

    fun combine(label: String, count: Int): String = "$label:$count"

    fun counterValue(): Int = counter

    fun note(label: String) { counter += label.length }

    // v4.27 fixture: one method per remaining return type so every Call* family has a target.
    fun flag(): Boolean = true
    fun byteValue(): Byte = 0x2A
    fun charValue(): Char = 'Z'
    fun shortValue(): Short = 1234
    fun longValue(): Long = 1234567890123L
    fun floatValue(): Float = 2.5f
    fun doubleValue(): Double = 1.25
}

object JniCallStatics {
    @JvmStatic fun staticCombine(label: String, count: Int): String = "S:$label:$count"
    @JvmStatic fun staticFlag(): Boolean = true
    @JvmStatic fun staticByte(): Byte = 0x37
    @JvmStatic fun staticChar(): Char = 'Q'
    @JvmStatic fun staticShort(): Short = 4321
    @JvmStatic fun staticLong(): Long = 9876543210L
    @JvmStatic fun staticFloat(): Float = 3.5f
    @JvmStatic fun staticDouble(): Double = 6.25
}