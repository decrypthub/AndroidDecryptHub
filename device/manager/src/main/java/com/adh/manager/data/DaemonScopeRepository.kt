package com.adh.manager.data

import com.adh.core.AdhProtocol
import com.adh.core.InstalledApp
import com.adh.core.InstalledAppsJson
import com.adh.core.PackageControl
import com.adh.core.ScopeConfig
import com.adh.core.ScopeJson
import com.adh.core.XposedStatus
import com.adh.core.XposedStatusJson
import com.adh.manager.ipc.DaemonBinderProvider

interface DaemonClient {
    val protocolVersion: Int
    val scopeJson: String
    fun setScopeJson(json: String): Boolean
    val listApplicationsJson: String
    fun applicationIconPng(packageName: String): ByteArray
    fun controlPackage(packageName: String, action: String): String
    val modulePresent: Boolean
    val loaderActive: Boolean
    val moduleVersion: String
    val xposedStatusJson: String
    fun setXposedEnabled(enabled: Boolean): Boolean
    fun setXposedScope(packages: List<String>): Boolean
}

class DaemonScopeRepository(
    private val clientProvider: (Long) -> DaemonClient? = DaemonBinderProvider::awaitClient,
) : ScopeRepository {
    override fun load(): ScopeConfig {
        val client = requireClient()
        return ScopeJson.decode(client.scopeJson)
    }

    override fun save(config: ScopeConfig): Result<Unit> = runCatching {
        val client = requireClient()
        check(client.setScopeJson(ScopeJson.encode(config))) { "daemon rejected scope update" }
        // Keep the optional Xposed backend in step with the ADH allowlist: the Manager stays the
        // single place that decides which apps are in scope. Failure here is reported (the file
        // write already happened) so the UI does not silently claim success.
        val xposed = xposedStatusOf(client)
        if (xposed?.enabled == true) {
            check(client.setXposedScope(config.packages.sorted())) { "xposed scope sync failed" }
        }
    }

    override fun xposedStatus(): XposedStatus? =
        clientProvider(CONNECT_TIMEOUT_MS)?.let { xposedStatusOf(it) }

    override fun setXposedEnabled(enabled: Boolean): Result<Unit> = runCatching {
        val client = requireClient()
        check(client.protocolVersion >= AdhProtocol.MIN_XPOSED_VERSION) {
            "daemon protocol ${client.protocolVersion} has no Xposed backend surface"
        }
        check(client.setXposedEnabled(enabled)) { "framework rejected the module state change" }
        if (enabled) {
            check(client.setXposedScope(load().packages.sorted())) { "xposed scope sync failed" }
        }
    }

    override fun setXposedScope(packages: List<String>): Result<Unit> = runCatching {
        val client = requireClient()
        check(client.protocolVersion >= AdhProtocol.MIN_XPOSED_VERSION) {
            "daemon protocol ${client.protocolVersion} has no Xposed backend surface"
        }
        check(client.setXposedScope(packages.map { it.trim() }.filter { it.isNotEmpty() })) {
            "framework rejected the scope update"
        }
    }

    private fun xposedStatusOf(client: DaemonClient): XposedStatus? {
        if (client.protocolVersion < AdhProtocol.MIN_XPOSED_VERSION) return null
        return runCatching { XposedStatusJson.decode(client.xposedStatusJson) }.getOrNull()
    }

    override fun listApplications(): List<InstalledApp> {
        val client = clientProvider(CONNECT_TIMEOUT_MS) ?: return emptyList()
        if (client.protocolVersion < AdhProtocol.MIN_CATALOG_VERSION) return emptyList()
        return runCatching { InstalledAppsJson.decode(client.listApplicationsJson) }
            .getOrDefault(emptyList())
    }

    override fun applicationIcon(packageName: String): ByteArray? {
        val pkg = packageName.trim()
        if (pkg.isEmpty()) return null
        iconCache[pkg]?.let { return it.takeIf { bytes -> bytes.isNotEmpty() } }
        val client = clientProvider(CONNECT_TIMEOUT_MS) ?: return null
        if (client.protocolVersion < AdhProtocol.MIN_ICON_VERSION) return null
        val bytes = runCatching { client.applicationIconPng(pkg) }.getOrNull() ?: return null
        iconCache[pkg] = bytes
        return bytes.takeIf { it.isNotEmpty() }
    }

    override fun supportsPackageControl(): Boolean {
        val client = clientProvider(CONNECT_TIMEOUT_MS) ?: return false
        return client.protocolVersion >= AdhProtocol.MIN_PROCESS_VERSION
    }

    override fun controlPackage(packageName: String, restart: Boolean): String {
        val pkg = packageName.trim()
        if (!PackageControl.mayControl(pkg)) return PackageControl.RESULT_DENIED
        val client = clientProvider(CONNECT_TIMEOUT_MS) ?: return PackageControl.RESULT_FAILED
        if (client.protocolVersion < AdhProtocol.MIN_PROCESS_VERSION) return PackageControl.RESULT_FAILED
        val action = if (restart) PackageControl.ACTION_RESTART else PackageControl.ACTION_STOP
        return runCatching { client.controlPackage(pkg, action) }
            .getOrDefault(PackageControl.RESULT_FAILED)
            .ifBlank { PackageControl.RESULT_FAILED }
    }

    override fun isModulePresent(): Boolean =
        runCatching { requireClient().modulePresent }.getOrDefault(false)

    override fun moduleStatus(): ModuleStatus {
        val client = clientProvider(CONNECT_TIMEOUT_MS)
            ?: return ModuleStatus(daemonAvailable = false)
        return runCatching {
            check(client.protocolVersion >= AdhProtocol.MIN_SCOPE_VERSION) {
                "unsupported daemon protocol ${client.protocolVersion}"
            }
            val installed = client.modulePresent
            ModuleStatus(
                daemonAvailable = true,
                installed = installed,
                loaderActive = installed && client.loaderActive,
                version = client.moduleVersion.takeIf { it.isNotBlank() },
            )
        }.getOrElse { ModuleStatus(daemonAvailable = false) }
    }

    private fun requireClient(): DaemonClient {
        val client = clientProvider(CONNECT_TIMEOUT_MS)
            ?: throw IllegalStateException("ADH Device Daemon is unavailable")
        check(client.protocolVersion >= AdhProtocol.MIN_SCOPE_VERSION) {
            "unsupported daemon protocol ${client.protocolVersion}"
        }
        return client
    }

    companion object {
        private const val CONNECT_TIMEOUT_MS = 3_000L
        private val iconCache = java.util.concurrent.ConcurrentHashMap<String, ByteArray>()
    }
}
