package com.adh.sandbox

// v4.83 fixture for the CallNonvirtual* hooks: the child overrides describe(), so a call through the
// BASE class with CallNonvirtualObjectMethod must return the base implementation while a virtual call
// would return the child's. That difference is what lets the probe tell whether nonvirtual dispatch
// still works while the entry is hooked.
open class JniNonvirtualBase {
    open fun describe(tag: String): String = "base:$tag"
}

class JniNonvirtualChild : JniNonvirtualBase() {
    override fun describe(tag: String): String = "child:$tag"
}
