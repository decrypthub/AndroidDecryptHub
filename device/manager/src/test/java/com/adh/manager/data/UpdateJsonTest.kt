package com.adh.manager.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateJsonTest {
    @Test
    fun parsesThePublishedShape() {
        val raw = """
            {"version":"v0.4.0","versionCode":23,"zipUrl":"https://example/a.zip","changelog":"https://example/tag"}
        """.trimIndent()
        val update = UpdateJson.parse(raw)
        assertEquals("0.4.0", update?.version)
        assertEquals(23, update?.versionCode)
        assertEquals("https://example/tag", update?.changelog)
    }

    @Test
    fun rejectsAManifestWithoutAVersion() {
        assertNull(UpdateJson.parse("{not-json"))
        assertNull(UpdateJson.parse("""{"version":"","versionCode":1}"""))
        assertNull(UpdateJson.parse("""{"version":"v0.4.0"}"""))
    }

    @Test
    fun newerMeansAHigherVersionCode() {
        val remote = RemoteUpdate("0.4.1", 24, "")
        assertTrue(UpdateJson.isNewer(23, remote))
        assertFalse(UpdateJson.isNewer(24, remote))
        assertFalse(UpdateJson.isNewer(25, remote))
    }
}
