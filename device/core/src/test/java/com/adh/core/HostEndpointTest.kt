package com.adh.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class HostEndpointTest {
    @Test
    fun formatsALanAddressAsOneLine() {
        assertEquals("192.168.200.108:8761\n", HostEndpoint.format("192.168.200.108", 8761))
    }

    @Test
    fun parsesTheLineTheAgentWillDial() {
        assertEquals("192.168.200.108" to 8761, HostEndpoint.parse("192.168.200.108:8761\n"))
        assertEquals("10.0.0.8" to 9000, HostEndpoint.parse("  10.0.0.8:9000  "))
    }

    @Test
    fun rejectsLoopbackLinkLocalAndGarbage() {
        assertNull(HostEndpoint.format("127.0.0.1", 8761))
        assertNull(HostEndpoint.format("169.254.1.1", 8761))
        assertNull(HostEndpoint.format("0.0.0.0", 8761))
        assertNull(HostEndpoint.format("192.168.200.108", 0))
        assertNull(HostEndpoint.format("not-an-ip", 8761))
        assertNull(HostEndpoint.parse("192.168.200.108"))
        assertNull(HostEndpoint.parse("127.0.0.1:8761"))
        assertNull(HostEndpoint.parse("192.168.200.108:0"))
    }
}
