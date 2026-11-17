package com.adh.manager.data

import com.adh.core.AdhPaths
import com.adh.core.AdhProtocol
import com.adh.core.CaCertStore
import com.adh.core.CaptureFamilies
import com.adh.core.InstalledApp
import com.adh.core.InstalledAppsJson
import com.adh.core.PackageControl
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
    fun perAppPolicySurvivesTheDaemonRoundTrip() {
        val client = FakeDaemonClient()
        val repository = DaemonScopeRepository { client }
        val trimmed = CaptureFamilies(digest = true, hmac = false, symmetric = true, asymmetric = false, tls = true, aead = false, system = false)
        val config = ScopeConfig(packages = setOf("com.example.target"))
            .withPolicy("com.example.target", trimmed)

        assertTrue(repository.save(config).isSuccess)
        assertEquals(trimmed, repository.load().familiesFor("com.example.target"))
        // A package with no entry stays at the default (every family on).
        assertEquals(CaptureFamilies.DEFAULT, repository.load().familiesFor("com.other.target"))
    }

    @Test
    fun policyIsRefusedOnADaemonThatCannotStoreIt() {
        // A v14 daemon decodes into its own :core and re-encodes from it, so it would drop the
        // policy AND answer true — the UI would show "saved" for a policy that does not exist.
        val client = FakeDaemonClient(protocol = 14)
        val repository = DaemonScopeRepository { client }
        val withPolicy = ScopeConfig(packages = setOf("com.example.target"))
            .withPolicy("com.example.target", CaptureFamilies(hmac = false))

        assertTrue(repository.save(withPolicy).isFailure)
        // The same daemon still accepts a config that carries no policy.
        assertTrue(repository.save(ScopeConfig(packages = setOf("com.example.target"))).isSuccess)
    }

    @Test
    fun remembersTheComputerAnInjectedProcessShouldDial() {
        val client = FakeDaemonClient()
        val repository = DaemonScopeRepository { client }

        assertEquals(HostRemember.Saved, repository.rememberHostEndpoint("192.168.200.108", 8761))
        assertEquals("192.168.200.108:8761", client.savedEndpoint)
    }

    @Test
    fun anOlderDaemonCannotStoreTheCallbackAddress() {
        val client = FakeDaemonClient(protocol = 16)
        val repository = DaemonScopeRepository { client }

        assertEquals(HostRemember.Unsupported, repository.rememberHostEndpoint("192.168.200.108", 8761))
        assertEquals(null, client.savedEndpoint)
    }

    @Test
    fun aLoopbackAddressIsNotRemembered() {
        val client = FakeDaemonClient()
        val repository = DaemonScopeRepository { client }

        assertEquals(HostRemember.Unavailable, repository.rememberHostEndpoint("127.0.0.1", 8761))
        assertEquals(null, client.savedEndpoint)
    }

    @Test
    fun caCertsRequireProtocolV18() {
        val oldClient = FakeDaemonClient(protocol = 17)
        val old = DaemonScopeRepository { oldClient }
        assertFalse(old.supportsCaCerts())
        assertTrue(old.listCaCerts().isEmpty())
        assertEquals(-1, old.putCaCert(byteArrayOf(1)))
        assertFalse(old.deleteCaCert("01234567.0"))
        assertFalse(old.rebootDevice())
        assertEquals(null, oldClient.lastPut)

        val client = FakeDaemonClient()
        val repository = DaemonScopeRepository { client }
        client.caCertsJson = """[{"f":"b4b34236.0","s":"CN=ADH Test CA","b":1,"e":2,"a":false}]"""
        assertTrue(repository.supportsCaCerts())
        assertEquals("b4b34236.0", repository.listCaCerts().single().fileName)
        assertEquals(1, repository.putCaCert(byteArrayOf(9)))
        assertTrue(client.lastPut.contentEquals(byteArrayOf(9)))
        assertTrue(repository.deleteCaCert("b4b34236.0"))
        assertEquals("b4b34236.0", client.deletedCa)
        assertTrue(repository.rebootDevice())
        assertTrue(client.rebooted)
        assertEquals(-1, repository.putCaCert(ByteArray(CaCertStore.MAX_BUNDLE_BYTES + 1)))
    }

    @Test fun hostPlanManagerUsesFrozenVersionsAndPackageOnlyPatch() {
        val base=FakeDaemonClient(protocol=20)
        val original=org.json.JSONObject().put("version",20).put("mode","allowlist").put("packages",org.json.JSONArray().put("com.example.target")).put("policy",org.json.JSONObject().put("com.example.target",org.json.JSONObject().put("c",org.json.JSONObject().put("d",false))))
        var revision=3L;var snapshot=org.json.JSONObject().put("document",original).put("scopeRevision","scope-before").put("stateRevision",revision)
        var legacyWrites=0;var packagePatches=0
        val client=object:DaemonClient by base {
            override val scopeSnapshotJson:String get()=snapshot.toString()
            override fun setScopeJson(json:String):Boolean {legacyWrites++;return false}
            override fun patchScopePackages(packagesJson:String,scopeRevision:String,stateRevision:Long):String {
                packagePatches++;if(stateRevision!=revision||scopeRevision!=snapshot.getString("scopeRevision"))return org.json.JSONObject().put("state","failed").put("code","STALE_SCOPE").toString()
                original.put("packages",org.json.JSONArray(packagesJson));revision++;snapshot=org.json.JSONObject().put("document",original).put("scopeRevision","scope-after").put("stateRevision",revision)
                return org.json.JSONObject().put("state","succeeded").put("stateRevision",revision).put("result",snapshot).toString()
            }
            override fun hookPlanState(packageName:String)="{\"entry\":null,\"cacheRevision\":2,\"stateRevision\":4}"
            override fun revokeHookPlan(packageName:String,deploymentId:String,cacheRevision:Long,stateRevision:Long):String {assertEquals(2L,cacheRevision);assertEquals(4L,stateRevision);return "{\"state\":\"succeeded\"}"}
        }
        val repository=DaemonScopeRepository{client};val loaded=repository.load()
        assertTrue(repository.save(loaded.copy(packages=setOf("com.example.target","com.example.other"))).isSuccess)
        assertFalse(original.getJSONObject("policy").getJSONObject("com.example.target").getJSONObject("c").getBoolean("d"))
        revision++
        assertTrue(repository.save(loaded).isFailure);assertEquals(0,legacyWrites);assertEquals(2,packagePatches)
        assertTrue(repository.hookPlanState("com.example.target")!!.contains("cacheRevision"));assertTrue(repository.revokeHookPlan("com.example.target","fixture",2,4).isSuccess)
    }

    private class FakeDaemonClient(
        protocol: Int = 19,
    ) : DaemonClient {
        override val protocolVersion = protocol
        override var scopeJson = ScopeJson.encode(ScopeConfig.EMPTY)
        // Models the real daemon (RootScopeBinder.setScopeJson): it decodes into its own :core and
        // re-encodes from it, so anything that build does not understand is dropped on the way
        // through. Storing the raw string instead would hide that loss entirely.
        override fun setScopeJson(json: String): Boolean {
            scopeJson = ScopeJson.encode(ScopeJson.decode(json))
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
        var savedEndpoint: String? = null
        override fun getHostEndpoint(): String = savedEndpoint.orEmpty()
        override fun setHostEndpoint(endpoint: String): Boolean {
            savedEndpoint = endpoint
            return true
        }
        var caCertsJson: String = "[]"
        var lastPut: ByteArray? = null
        var deletedCa: String? = null
        var rebooted: Boolean = false
        override fun listCaCertsJson(): String = caCertsJson
        override fun putCaCert(encoded: ByteArray): Int {
            lastPut = encoded
            return 1
        }
        override fun deleteCaCert(fileName: String): Boolean {
            deletedCa = fileName
            return true
        }
        override fun rebootDevice(): Boolean {
            rebooted = true
            return true
        }
    }
}
