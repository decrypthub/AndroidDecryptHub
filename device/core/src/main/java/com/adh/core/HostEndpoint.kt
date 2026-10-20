package com.adh.core

/**
 * One line the injected process can dial when `127.0.0.1:8761` (adb reverse) is not there.
 * Written by the root Device Daemon, read by the Zygisk companion. Not a URL and not a hostname:
 * an IPv4 address plus a TCP port, so the agent never does a DNS lookup inside the target.
 */
object HostEndpoint {
    fun format(host: String, port: Int): String? {
        val normalized = canonicalIpv4(host) ?: return null
        if (port !in 1..65535) return null
        return "$normalized:$port\n"
    }

    fun parse(text: String): Pair<String, Int>? {
        val line = text.trim()
        val colon = line.lastIndexOf(':')
        if (colon <= 0 || colon == line.lastIndex) return null
        val host = canonicalIpv4(line.substring(0, colon)) ?: return null
        val port = line.substring(colon + 1).toIntOrNull() ?: return null
        if (port !in 1..65535) return null
        return host to port
    }

    fun isUsefulIpv4(host: String): Boolean = canonicalIpv4(host) != null

    /** Drops loopback, unspecified, and link-local. Returns the address without leading zeros. */
    private fun canonicalIpv4(host: String): String? {
        val parts = host.trim().split('.')
        if (parts.size != 4) return null
        val octets = parts.map { part ->
            if (part.isEmpty() || part.any { it !in '0'..'9' }) return null
            if (part.length > 1 && part.startsWith('0')) return null
            part.toIntOrNull()?.takeIf { it in 0..255 } ?: return null
        }
        if (octets[0] == 0 || octets[0] == 127 || (octets[0] == 169 && octets[1] == 254)) return null
        return octets.joinToString(".")
    }
}
