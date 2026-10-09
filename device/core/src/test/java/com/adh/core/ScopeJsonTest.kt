package com.adh.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScopeJsonTest {
    @Test
    fun encodeDecodeRoundTrip() {
        val cfg = ScopeConfig(
            version = 1,
            mode = ScopeConfig.MODE_ALLOWLIST,
            packages = setOf("com.adh.sandbox", "com.example.target"),
        )
        val json = ScopeJson.encode(cfg)
        val back = ScopeJson.decode(json)
        assertEquals(1, back.version)
        assertEquals(ScopeConfig.MODE_ALLOWLIST, back.mode)
        assertTrue(back.contains("com.adh.sandbox"))
        assertTrue(back.contains("com.example.target"))
        assertEquals(2, back.packages.size)
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
        assertEquals(AdhProtocol.VERSION, 13)
        assertEquals(AdhProtocol.MIN_PROCESS_VERSION, 4)
        assertEquals(AdhProtocol.MIN_XPOSED_VERSION, 5)
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
        assertEquals("/data/adb/adh/zygisk_loaded", AdhPaths.LOADER_MARKER)
        assertEquals("/data/adb/modules/adh", AdhPaths.MODULE_DIR)
        assertEquals("com.adh.manager", AdhPaths.MANAGER_PKG)
        assertEquals("com.adh.daemon", AdhPaths.DAEMON_PKG)
        assertTrue(HardExcludes.isExcluded("system_server"))
        assertTrue(HardExcludes.isExcluded(AdhPaths.MANAGER_PKG))
        assertFalse(HardExcludes.isExcluded("com.adh.sandbox"))
    }
}
