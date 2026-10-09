package com.adh.core

/**
 * Injection scope contract shared by Manager, Device Daemon, and (by path) Zygisk.
 * mode is always allowlist in v1 — denylist is out of scope for this foundation.
 */
data class ScopeConfig(
    val version: Int = 1,
    val mode: String = MODE_ALLOWLIST,
    val packages: Set<String> = emptySet(),
) {
    companion object {
        const val MODE_ALLOWLIST = "allowlist"
        val EMPTY = ScopeConfig()
    }

    fun withPackage(pkg: String, enabled: Boolean): ScopeConfig {
        if (pkg.isBlank() || pkg == AdhPaths.MANAGER_PKG) return this
        val next = packages.toMutableSet()
        if (enabled) next.add(pkg) else next.remove(pkg)
        return copy(packages = next)
    }

    fun contains(pkg: String): Boolean = packages.contains(pkg)
}
