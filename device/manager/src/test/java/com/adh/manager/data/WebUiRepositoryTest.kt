package com.adh.manager.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class WebUiRepositoryTest {
    @Test
    fun prefersFirstReportedLanAddress() {
        val status = parseWebUiStatus(
            """{"ok":true,"web":{"local":"http://127.0.0.1:8088","lan":["http://192.168.1.8:8088"]}}""",
        )

        assertTrue(status.reachable)
        assertEquals("http://192.168.1.8:8088", status.primaryUrl)
        assertEquals("http://127.0.0.1:8088", status.localUrl)
    }

    @Test
    fun fallsBackToLocalAddressWhenLanIsMissing() {
        val status = parseWebUiStatus(
            """{"ok":true,"web":{"local":"http://127.0.0.1:9876","lan":[]}}""",
        )

        assertEquals("http://127.0.0.1:9876", status.primaryUrl)
    }
}
