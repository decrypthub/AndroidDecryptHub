package com.adh.sandbox

// v4.28 fixtures for the java_hook completeness slice.
//
// JniCtorTarget: a constructor with an argument whose effect is observable (total = seed * 2), so
// a constructor hook can prove both that the callback saw the arguments and that the object was
// still constructed correctly.
class JniCtorTarget(val seed: Int) {
    @JvmField var total: Int = seed * 2

    fun totalValue(): Int = total
}

// JniDerived extends JniBase: baseValue() is declared by the superclass, so hooking it through
// JniDerived requires resolving inherited members.
open class JniBase {
    fun baseValue(): Int = 7
}

class JniDerived : JniBase() {
    fun derivedValue(): Int = 3
}

object JniInheritStatics {
    @JvmStatic fun derivedBaseValue(): Int = JniDerived().baseValue()
}