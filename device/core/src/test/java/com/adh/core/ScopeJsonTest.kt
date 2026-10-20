package com.adh.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScopeJsonTest {
    @Test
    fun encodeDecodeRoundTrip() {
        val cfg = ScopeConfig(
            mode = ScopeConfig.MODE_ALLOWLIST,
            packages = setOf("com.adh.sandbox", "com.example.target"),
        )
        val json = ScopeJson.encode(cfg)
        val back = ScopeJson.decode(json)
        assertEquals(ScopeConfig.CURRENT_VERSION, back.version)
        assertEquals(ScopeConfig.MODE_ALLOWLIST, back.mode)
        assertTrue(back.contains("com.adh.sandbox"))
        assertTrue(back.contains("com.example.target"))
        assertEquals(2, back.packages.size)
    }

    @Test
    fun perPackagePolicyRoundTrips() {
        val cfg = ScopeConfig(packages = setOf("com.example.target"))
            .withPolicy("com.example.target", CaptureFamilies(digest = true, hmac = false, symmetric = true, asymmetric = false, tls = true, aead = false))
        val back = ScopeJson.decode(ScopeJson.encode(cfg))
        assertEquals(
            CaptureFamilies(digest = true, hmac = false, symmetric = true, asymmetric = false, tls = true, aead = false, system = false),
            back.familiesFor("com.example.target"),
        )
        // The flag line the Zygisk companion hands the target process must agree with the JSON.
        assertEquals("d=1,h=0,s=1,a=0,t=1,e=0,y=0", back.familiesFor("com.example.target").toFlagString())
        assertEquals(back.familiesFor("com.example.target"), CaptureFamilies.fromFlagString("d=1,h=0,s=1,a=0,t=1,e=0,y=0"))
    }

    @Test
    fun systemDetectionDefaultsOffAndRoundTrips() {
        assertFalse(CaptureFamilies.DEFAULT.system)
        assertEquals(CaptureFamilies.DEFAULT, CaptureFamilies.fromFlagString("d=1,h=1,s=1,a=1,t=1,e=1"))
        assertEquals(CaptureFamilies(system = true), CaptureFamilies.fromFlagString("y=1"))
        val cfg = ScopeConfig(packages = setOf("com.example.target"))
            .withPolicy("com.example.target", CaptureFamilies(system = true))
        val back = ScopeJson.decode(ScopeJson.encode(cfg))
        assertTrue(back.familiesFor("com.example.target").system)
        assertEquals("d=1,h=1,s=1,a=1,t=1,e=1,y=1", back.familiesFor("com.example.target").toFlagString())
    }

    @Test
    fun absentPolicyMeansEveryFamilyOn() {
        // An old scope file (no policy section) must keep the pre-policy behaviour exactly.
        val old = """{"version":1,"mode":"allowlist","packages":["com.example.target"]}"""
        val cfg = ScopeJson.decode(old)
        assertEquals(CaptureFamilies.DEFAULT, cfg.familiesFor("com.example.target"))
        assertTrue(cfg.familiesFor("com.example.target").isDefault)
        // ...and a default entry is never written back, so the section stays absent.
        assertFalse(ScopeJson.encode(cfg).contains("policy"))
    }

    @Test
    fun policyForAPackageThatLeftTheScopeIsDropped() {
        val inScope = ScopeConfig(packages = setOf("com.example.target"))
            .withPolicy("com.example.target", CaptureFamilies(hmac = false))
        val dropped = inScope.withPackage("com.example.target", false)
        assertTrue(dropped.policy.isEmpty())
        assertFalse(ScopeJson.encode(dropped).contains("policy"))
        // A policy cannot be attached to a package that is not in scope in the first place.
        assertTrue(ScopeConfig.EMPTY.withPolicy("com.example.other", CaptureFamilies(hmac = false)).policy.isEmpty())
    }

    @Test
    fun policyToleratesMissingAndUnknownFamilyKeys() {
        // Missing keys default to ON; an unknown key is ignored — a newer writer never breaks a reader.
        val json = """
            {"version":2,"mode":"allowlist","packages":["com.example.target"],
             "policy":{"com.example.target":{"c":{"h":false,"zz":true}}}}
        """.trimIndent()
        val families = ScopeJson.decode(json).familiesFor("com.example.target")
        assertEquals(CaptureFamilies(hmac = false), families)
        // A truncated flag line can only ever mean "hook more", never "hook less".
        assertEquals(CaptureFamilies.DEFAULT, CaptureFamilies.fromFlagString(""))
        assertEquals(CaptureFamilies.DEFAULT, CaptureFamilies.fromFlagString("garbage"))
        assertEquals(CaptureFamilies(hmac = false), CaptureFamilies.fromFlagString("h=0"))
    }

    @Test
    fun leftoverBypassSectionIsDroppedOnReEncode() {
        val json = """
            {"version":2,"mode":"allowlist","packages":["com.example.target"],
             "policy":{"com.example.target":{"c":{"h":false},"b":{"s":true}}}}
        """.trimIndent()
        val decoded = ScopeJson.decode(json)
        assertEquals(CaptureFamilies(hmac = false), decoded.familiesFor("com.example.target"))
        val roundTripped = ScopeJson.encode(decoded)
        assertFalse(roundTripped.contains("\"b\""))
        assertTrue(roundTripped.contains("\"h\": false"))
    }

    @Test
    fun blankIsEmpty() {
        assertEquals(ScopeConfig.EMPTY, ScopeJson.decode(""))
        assertEquals(ScopeConfig.EMPTY, ScopeJson.decode("   "))
    }

    @Test
    fun stripsManagerPackage() {
        val json = """{"version":1,"mode":"allowlist","packages":["com.adh.manager","com.foo"]}"""
        val cfg = ScopeJson.decode(json)
        assertFalse(cfg.contains(AdhPaths.MANAGER_PKG))
        assertTrue(cfg.contains("com.foo"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun malformedFailsLoud() {
        ScopeJson.decode("{not-json")
    }

    @Test
    fun decodeOrEmptySoft() {
        assertEquals(ScopeConfig.EMPTY, ScopeJson.decodeOrEmpty("{bad"))
    }

    @Test
    fun installedAppsRoundTripAndDropsExcluded() {
        val json = InstalledAppsJson.encode(
            listOf(
                InstalledApp("com.example.target", "Target", false),
                InstalledApp(AdhPaths.MANAGER_PKG, "Manager", false),
                InstalledApp("com.android.settings", "Settings", true),
            ),
        )
        val apps = InstalledAppsJson.decode(json)
        assertEquals(2, apps.size)
        assertEquals("com.example.target", apps[0].packageName)
        assertEquals("Target", apps[0].label)
        assertFalse(apps[0].system)
        assertEquals("com.android.settings", apps[1].packageName)
        assertTrue(apps[1].system)
        assertEquals(AdhProtocol.VERSION, 18)
        assertEquals(AdhProtocol.MIN_HOST_ENDPOINT_VERSION, 17)
        assertEquals(AdhProtocol.MIN_CA_CERT_VERSION, 18)
        assertEquals(AdhProtocol.MIN_PROCESS_VERSION, 4)
        assertEquals(AdhProtocol.MIN_APP_OPEN_VERSION, 6)
    }

    @Test
    fun packageControlAllowsTargetsAndBlocksCriticalPackages() {
        assertTrue(PackageControl.mayControl("com.adh.sandbox"))
        assertTrue(PackageControl.mayControl("com.example.target"))
        assertFalse(PackageControl.mayControl(""))
        assertFalse(PackageControl.mayControl("not a package"))
        assertFalse(PackageControl.mayControl("system_server"))
        assertFalse(PackageControl.mayControl(AdhPaths.MANAGER_PKG))
        assertFalse(PackageControl.mayControl(AdhPaths.DAEMON_PKG))
        assertFalse(PackageControl.mayControl("android"))
        assertFalse(PackageControl.mayControl("com.android.systemui"))
        assertTrue(PackageControl.isAction(PackageControl.ACTION_OPEN))
        assertTrue(PackageControl.isAction(PackageControl.ACTION_STOP))
        assertTrue(PackageControl.isAction(PackageControl.ACTION_RESTART))
        assertFalse(PackageControl.isAction("kill"))
    }

    @Test
    fun pathsAreStableContract() {
        assertEquals("/data/adb/adh/scope.json", AdhPaths.SCOPE_PATH)
        assertEquals("/data/adb/adh/cacerts", AdhPaths.CACERTS_DIR)
        assertEquals("/data/adb/adh/zygisk_loaded", AdhPaths.LOADER_MARKER)
        assertEquals("/data/adb/modules/adh", AdhPaths.MODULE_DIR)
        assertEquals("com.adh.manager", AdhPaths.MANAGER_PKG)
        assertEquals("com.adh.daemon", AdhPaths.DAEMON_PKG)
        assertTrue(HardExcludes.isExcluded("system_server"))
        assertTrue(HardExcludes.isExcluded(AdhPaths.MANAGER_PKG))
        assertFalse(HardExcludes.isExcluded("com.adh.sandbox"))
    }
}
