package com.adh.core

/**
 * Injection scope contract shared by Manager, Device Daemon, and (by path) Zygisk.
 * mode is always allowlist in v1 — denylist is out of scope for this foundation.
 *
 * [policy] carries per-package behaviour on top of the plain allowlist: today only which crypto
 * hook families the agent installs for that package. A package with no entry is DEFAULT (all
 * families on), so an empty map is exactly the pre-policy behaviour.
 */
data class ScopeConfig(
    val version: Int = CURRENT_VERSION,
    val mode: String = MODE_ALLOWLIST,
    val packages: Set<String> = emptySet(),
    val policy: Map<String, CaptureFamilies> = emptyMap(),
) {
    companion object {
        const val MODE_ALLOWLIST = "allowlist"
        /** Bumped to 2 when per-package policy was added; the field is informational for readers. */
        const val CURRENT_VERSION = 2
        val EMPTY = ScopeConfig()
    }

    fun withPackage(pkg: String, enabled: Boolean): ScopeConfig {
        if (pkg.isBlank() || pkg == AdhPaths.MANAGER_PKG) return this
        val next = packages.toMutableSet()
        if (enabled) next.add(pkg) else next.remove(pkg)
        // A package that leaves the scope cannot keep a policy: it would otherwise be applied to
        // whatever the user picks next under the same name, or sit in the file forever.
        return copy(packages = next, policy = if (enabled) policy else policy - pkg)
    }

    /** Set (or with [families] == null, drop) the hook policy of one already-scoped package. */
    fun withPolicy(pkg: String, families: CaptureFamilies?): ScopeConfig {
        if (pkg.isBlank() || pkg == AdhPaths.MANAGER_PKG || !packages.contains(pkg)) return this
        val next = policy.toMutableMap()
        if (families == null) next.remove(pkg) else next[pkg] = families
        return copy(policy = next, version = CURRENT_VERSION)
    }

    fun familiesFor(pkg: String): CaptureFamilies = policy[pkg] ?: CaptureFamilies.DEFAULT

    fun contains(pkg: String): Boolean = packages.contains(pkg)
}
