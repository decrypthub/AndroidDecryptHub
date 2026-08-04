package com.adh.manager.data

import com.adh.core.ScopeConfig
import com.adh.core.ScopeJson
import com.adh.manager.ipc.DaemonBinderProvider

interface DaemonClient {
    val protocolVersion: Int
    val scopeJson: String
    fun setScopeJson(json: String): Boolean
    val modulePresent: Boolean
    val loaderActive: Boolean
    val moduleVersion: String
}

class DaemonScopeRepository(
    private val clientProvider: (Long) -> DaemonClient? = DaemonBinderProvider::awaitClient,
) : ScopeRepository {
    override fun load(): ScopeConfig {
        val client = requireClient()
        check(client.protocolVersion == SUPPORTED_PROTOCOL) { "unsupported daemon protocol" }
        return ScopeJson.decode(client.scopeJson)
    }

    override fun save(config: ScopeConfig): Result<Unit> = runCatching {
        val client = requireClient()
        check(client.protocolVersion == SUPPORTED_PROTOCOL) { "unsupported daemon protocol" }
        check(client.setScopeJson(ScopeJson.encode(config))) { "daemon rejected scope update" }
    }

    override fun isModulePresent(): Boolean =
        runCatching { requireClient().modulePresent }.getOrDefault(false)

    override fun moduleStatus(): ModuleStatus {
        val client = clientProvider(CONNECT_TIMEOUT_MS)
            ?: return ModuleStatus(daemonAvailable = false)
        return runCatching {
            check(client.protocolVersion == SUPPORTED_PROTOCOL) { "unsupported daemon protocol" }
            val installed = client.modulePresent
            ModuleStatus(
                daemonAvailable = true,
                installed = installed,
                loaderActive = installed && client.loaderActive,
                version = client.moduleVersion.takeIf { it.isNotBlank() },
            )
        }.getOrElse { ModuleStatus(daemonAvailable = false) }
    }

    private fun requireClient(): DaemonClient =
        clientProvider(CONNECT_TIMEOUT_MS)
            ?: throw IllegalStateException("ADH Device Daemon is unavailable")

    companion object {
        private const val SUPPORTED_PROTOCOL = 1
        private const val CONNECT_TIMEOUT_MS = 3_000L
    }
}
