package com.adh.manager.data

import com.adh.core.AdhPaths
import com.adh.core.AdhProtocol
import com.adh.core.InstalledApp
import com.adh.core.InstalledAppsJson
import com.adh.core.PackageControl
import com.adh.core.ScopeConfig
import com.adh.core.ScopeJson
import com.adh.core.XposedStatus
import com.adh.core.XposedStatusJson
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
        assertTrue(repository.listApplications().isEmpty())
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
        assertEquals(
            listOf(InstalledApp("com.example.target", "Target", false)),
            repository.listApplications(),
        )
    }

    @Test
    fun catalogIsEmptyOnProtocolV1Daemon() {
        val client = FakeDaemonClient(protocol = 1)
        val repository = DaemonScopeRepository { client }
        assertEquals(ScopeConfig.EMPTY, repository.load())
        assertTrue(repository.listApplications().isEmpty())
    }

    @Test
    fun iconsRequireProtocolV3() {
        val v2 = DaemonScopeRepository { FakeDaemonClient(protocol = 2) }
        assertEquals(
            listOf(InstalledApp("com.example.target", "Target", false)),
            v2.listApplications(),
        )
        assertEquals(null, v2.applicationIcon("com.example.target"))

        val v3 = DaemonScopeRepository { FakeDaemonClient() }
        assertTrue(v3.applicationIcon("com.example.target").contentEquals(byteArrayOf(1, 2, 3)))
        assertEquals(null, v3.applicationIcon("com.missing.app"))
    }

    @Test
    fun packageControlRequiresProtocolV4() {
        val v3 = DaemonScopeRepository { FakeDaemonClient(protocol = 3) }
        assertFalse(v3.supportsPackageControl())
        assertEquals(
            PackageControl.RESULT_FAILED,
            v3.controlPackage("com.example.target", restart = false),
        )

        val client = FakeDaemonClient()
        val v4 = DaemonScopeRepository { client }
        assertTrue(v4.supportsPackageControl())
        assertEquals(
            PackageControl.RESULT_OK,
            v4.controlPackage("com.example.target", restart = true),
        )
        assertEquals("com.example.target" to PackageControl.ACTION_RESTART, client.lastControl)
        assertEquals(
            PackageControl.RESULT_DENIED,
            v4.controlPackage(AdhPaths.MANAGER_PKG, restart = false),
        )
        assertEquals(
            PackageControl.RESULT_DENIED,
            v4.controlPackage("android", restart = false),
        )
        assertEquals("com.example.target" to PackageControl.ACTION_RESTART, client.lastControl)
    }

    @Test
    fun xposedBackendRequiresProtocolV5() {
        val v4 = DaemonScopeRepository { FakeDaemonClient(protocol = 4) }

        assertEquals(null, v4.xposedStatus())
        assertTrue(v4.setXposedEnabled(true).isFailure)
        assertTrue(v4.setXposedScope(listOf("com.example.target")).isFailure)
    }

    @Test
    fun enablingXposedMirrorsTheCurrentAdhScope() {
        val client = FakeDaemonClient()
        val repository = DaemonScopeRepository { client }

        assertTrue(repository.save(ScopeConfig(packages = setOf("com.example.target"))).isSuccess)
        assertTrue(repository.setXposedEnabled(true).isSuccess)

        assertTrue(client.xposedEnabled)
        assertEquals(listOf("com.example.target"), client.xposedScope)
        assertEquals(true, repository.xposedStatus()?.enabled)
        assertEquals(listOf("com.example.target"), repository.xposedStatus()?.scope)
    }

    @Test
    fun savingScopeMirrorsIntoAnEnabledXposedBackend() {
        val client = FakeDaemonClient()
        val repository = DaemonScopeRepository { client }
        client.xposedEnabled = true

        assertTrue(repository.save(ScopeConfig(packages = setOf("com.example.target"))).isSuccess)
        assertEquals(listOf("com.example.target"), client.xposedScope)

        // A framework rejection must surface even though the ADH scope file was written.
        client.rejectXposedScope = true
        assertTrue(repository.save(ScopeConfig(packages = setOf("com.other.target"))).isFailure)
    }

    @Test
    fun disabledXposedBackendIsNotMirrored() {
        val client = FakeDaemonClient()
        val repository = DaemonScopeRepository { client }

        assertTrue(repository.save(ScopeConfig(packages = setOf("com.example.target"))).isSuccess)

        assertEquals(emptyList<String>(), client.xposedScope)
        assertEquals(false, repository.xposedStatus()?.enabled)
    }

    private class FakeDaemonClient(
        protocol: Int = AdhProtocol.VERSION,
    ) : DaemonClient {
        override val protocolVersion = protocol
        override var scopeJson = ScopeJson.encode(ScopeConfig.EMPTY)
        override fun setScopeJson(json: String): Boolean {
            scopeJson = json
            return true
        }
        override val listApplicationsJson =
            InstalledAppsJson.encode(listOf(InstalledApp("com.example.target", "Target", false)))
        override fun applicationIconPng(packageName: String): ByteArray =
            if (protocolVersion >= AdhProtocol.MIN_ICON_VERSION && packageName == "com.example.target") {
                byteArrayOf(1, 2, 3)
            } else {
                ByteArray(0)
            }
        var lastControl: Pair<String, String>? = null
        override fun controlPackage(packageName: String, action: String): String {
            lastControl = packageName to action
            return if (protocolVersion >= AdhProtocol.MIN_PROCESS_VERSION &&
                packageName == "com.example.target"
            ) {
                PackageControl.RESULT_OK
            } else {
                PackageControl.RESULT_FAILED
            }
        }
        override val modulePresent = true
        override val loaderActive = true
        override val moduleVersion = "v0.3.0"
        var xposedEnabled = false
        var xposedScope: List<String> = emptyList()
        var rejectXposedScope = false
        override val xposedStatusJson: String
            get() = XposedStatusJson.encode(
                XposedStatus(
                    present = true,
                    installed = true,
                    enabled = xposedEnabled,
                    scope = xposedScope,
                ),
            )
        override fun setXposedEnabled(enabled: Boolean): Boolean {
            if (protocolVersion < AdhProtocol.MIN_XPOSED_VERSION) return false
            xposedEnabled = enabled
            return true
        }
        override fun setXposedScope(packages: List<String>): Boolean {
            if (protocolVersion < AdhProtocol.MIN_XPOSED_VERSION || rejectXposedScope) return false
            xposedScope = packages.sorted()
            return true
        }
    }
}
