package com.adh.sandbox

object ReflectionProbe {
    const val TARGET = "com.adh.sandbox.JavaCrypto"

    @JvmStatic
    fun load(): String = Class.forName(TARGET).name
}
