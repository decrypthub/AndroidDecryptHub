package com.adh.manager.data

import com.adh.core.ScopeConfig

data class ModuleStatus(
    val daemonAvailable: Boolean? = null,
    val installed: Boolean = false,
    val loaderActive: Boolean = false,
    val version: String? = null,
)

/**
 * Scope access boundary for the Compose UI.
 * Manager never reads `/data/adb` or invokes `su`; all privileged operations go
 * through [DaemonScopeRepository].
 */
interface ScopeRepository {
    fun load(): ScopeConfig
    fun save(config: ScopeConfig): Result<Unit>
    fun isModulePresent(): Boolean
    fun moduleStatus(): ModuleStatus = ModuleStatus(installed = isModulePresent())
}
