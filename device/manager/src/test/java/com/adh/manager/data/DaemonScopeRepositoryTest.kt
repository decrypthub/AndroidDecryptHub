package com.adh.manager.data

import com.adh.core.ScopeConfig
import com.adh.core.ScopeJson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DaemonScopeRepositoryTest {
    @Test
    fun unavailableDaemonIsReportedWithoutRootFallback() {
        val repository = DaemonScopeRepository { null }

        val status = repository.moduleStatus()

        assertEquals(false, status.daemonAvailable)
        assertFalse(status.installed)
        assertTrue(repository.save(ScopeConfig.EMPTY).isFailure)
    }

    @Test
    fun readsAndWritesThroughDaemonClient() {
        val client = FakeDaemonClient()
        val repository = DaemonScopeRepository { client }
        val config = ScopeConfig(packages = setOf("com.example.target"))

        assertTrue(repository.save(config).isSuccess)
        assertEquals(config, repository.load())
        assertEquals(true, repository.moduleStatus().daemonAvailable)
        assertEquals("v0.3.0", repository.moduleStatus().version)
    }

    private class FakeDaemonClient : DaemonClient {
        override val protocolVersion = 1
        override var scopeJson = ScopeJson.encode(ScopeConfig.EMPTY)
        override fun setScopeJson(json: String): Boolean {
            scopeJson = json
            return true
        }
        override val modulePresent = true
        override val loaderActive = true
        override val moduleVersion = "v0.3.0"
    }
}
