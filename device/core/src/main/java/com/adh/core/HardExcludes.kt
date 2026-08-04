package com.adh.core

/**
 * Hard-exclude process / package names that must never receive the agent.
 * Zygisk C++ mirrors this list in injector/zygisk/jni/main.cpp.
 */
object HardExcludes {
    val PACKAGES: Set<String> = setOf(
        "system_server",
        "zygote",
        "zygote64",
        AdhPaths.MANAGER_PKG,
    )

    fun isExcluded(pkg: String?): Boolean =
        pkg.isNullOrBlank() || PACKAGES.contains(pkg)
}
