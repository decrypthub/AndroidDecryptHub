package com.adh.manager.data

import com.adh.core.InstalledApp
import com.adh.core.PackageControl
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
 * through [DaemonScopeRepository]. The installed-app catalog also comes from
 * the root Device Daemon — not from this process's PackageManager.
 */
interface ScopeRepository {
    fun load(): ScopeConfig
    fun save(config: ScopeConfig): Result<Unit>
    fun listApplications(): List<InstalledApp>
    fun applicationIcon(packageName: String): ByteArray? = null
    fun supportsPackageControl(): Boolean = false
    fun controlPackage(packageName: String, restart: Boolean): String =
        PackageControl.RESULT_FAILED
    fun isModulePresent(): Boolean
    fun moduleStatus(): ModuleStatus = ModuleStatus(installed = isModulePresent())
}
