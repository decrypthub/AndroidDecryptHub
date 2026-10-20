package com.adh.manager.data

import com.adh.core.ScopeConfig
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Writes the injection scope. A newer edit that arrives while a write is in
 * flight supersedes the older one, so a slow save cannot put the previous
 * checkbox state back on disk.
 */
class ScopeWriter(
    private val save: suspend (ScopeConfig) -> Result<Unit>,
) {
    private val mutex = Mutex()
    private var latest: ScopeConfig? = null

    suspend fun submit(config: ScopeConfig): Result<Unit>? {
        latest = config
        return mutex.withLock {
            val snapshot = latest ?: return@withLock null
            if (snapshot != config) return@withLock null
            val result = save(snapshot)
            if (latest != snapshot) null else result
        }
    }
}
