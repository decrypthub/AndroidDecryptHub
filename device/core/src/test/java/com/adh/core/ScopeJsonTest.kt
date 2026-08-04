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
            packages = setOf("com.idh.sandbox", "com.example.target"),
        )
        val json = ScopeJson.encode(cfg)
        val back = ScopeJson.decode(json)
        assertEquals(1, back.version)
        assertEquals(ScopeConfig.MODE_ALLOWLIST, back.mode)
        assertTrue(back.contains("com.idh.sandbox"))
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
    fun pathsAreStableContract() {
        assertEquals("/data/adb/adh/scope.json", AdhPaths.SCOPE_PATH)
        assertEquals("/data/adb/adh/zygisk_loaded", AdhPaths.LOADER_MARKER)
        assertEquals("/data/adb/modules/adh", AdhPaths.MODULE_DIR)
        assertEquals("com.adh.manager", AdhPaths.MANAGER_PKG)
        assertTrue(HardExcludes.isExcluded("system_server"))
        assertTrue(HardExcludes.isExcluded(AdhPaths.MANAGER_PKG))
        assertFalse(HardExcludes.isExcluded("com.idh.sandbox"))
    }
}
