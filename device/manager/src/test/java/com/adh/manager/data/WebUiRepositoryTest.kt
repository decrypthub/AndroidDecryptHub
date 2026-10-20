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

    @Test
    fun prefersLanOnTheSameSubnetAsThePhone() {
        val body = """{"ok":true,"service":"adhd","web":{"local":"http://127.0.0.1:8088","lan":["http://192.168.150.1:8088","http://192.168.200.108:8088","http://192.168.159.1:8088"]}}"""

        val status = parseWebUiStatus(body, deviceIpv4 = "192.168.200.178")

        assertEquals("http://192.168.200.108:8088", status.primaryUrl)
        assertEquals("http://192.168.200.108:8088", status.lanUrl)
    }

    @Test
    fun reachedLanHostWinsWhenReportedLanIsOnAnotherSubnet() {
        val body = """{"ok":true,"service":"adhd","web":{"local":"http://127.0.0.1:8088","lan":["http://192.168.150.1:8088"]}}"""

        val status = statusFromHealth(body, deviceIpv4 = "192.168.200.178", reachedHost = "192.168.200.108")

        assertEquals("http://192.168.200.108:8088", status?.primaryUrl)
        assertEquals("http://192.168.200.108:8088", status?.lanUrl)
    }

    @Test
    fun ignoresAHealthBodyThatIsNotTheDaemon() {
        val status = statusFromHealth(
            """{"ok":true,"service":"other"}""",
            deviceIpv4 = "192.168.200.178",
            reachedHost = "192.168.200.1",
        )

        assertEquals(null, status)
    }

    @Test
    fun subnetHostsSkipThePhoneItself() {
        val hosts = subnetHosts("192.168.200.178")

        assertEquals(253, hosts.size)
        assertTrue("192.168.200.108" in hosts)
        assertTrue("192.168.200.178" !in hosts)
        assertTrue("192.168.200.0" !in hosts)
        assertTrue("192.168.200.255" !in hosts)
    }

    @Test
    fun deviceAddressPrefersWifiOverOtherInterfaces() {
        val ip = preferredDeviceIpv4(
            listOf(
                "rmnet0" to "10.8.0.2",
                "wlan0" to "192.168.200.178",
                "wlan0" to "169.254.1.1",
            ),
        )

        assertEquals("192.168.200.178", ip)
    }

    @Test
    fun callbackUsesTheReachedComputerAndTheAgentPort() {
        val body = """{"ok":true,"service":"adhd","agent":{"port":8761},"web":{"local":"http://127.0.0.1:8088","lan":["http://192.168.150.1:8088"]}}"""

        val status = statusFromHealth(body, deviceIpv4 = "192.168.200.178", reachedHost = "192.168.200.108")

        assertEquals("192.168.200.108", status?.callbackHost)
        assertEquals(8761, status?.callbackPort)
    }

    @Test
    fun loopbackProbeStillRemembersTheReportedLan() {
        val body = """{"ok":true,"service":"adhd","agent":{"port":9000},"web":{"local":"http://127.0.0.1:8088","lan":["http://192.168.200.108:8088"]}}"""

        val status = statusFromHealth(body, deviceIpv4 = "192.168.200.178", reachedHost = "127.0.0.1")

        assertEquals("192.168.200.108", status?.callbackHost)
        assertEquals(9000, status?.callbackPort)
    }

    @Test
    fun noLanAddressMeansTheProcessCanOnlyUseUsbReverse() {
        val body = """{"ok":true,"service":"adhd","web":{"local":"http://127.0.0.1:8088","lan":[]}}"""

        val status = statusFromHealth(body, deviceIpv4 = null, reachedHost = "127.0.0.1")

        assertEquals(null, status?.callbackHost)
        assertEquals(8761, status?.callbackPort)
    }
}
