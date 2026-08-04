package com.idh.sandbox

object ReflectionProbe {
    const val TARGET = "com.idh.sandbox.JavaCrypto"

    @JvmStatic
    fun load(): String = Class.forName(TARGET).name
}
