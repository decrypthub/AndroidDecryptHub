package com.adh.manager.data

import com.adh.core.HostEndpoint
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.URL
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

data class WebUiStatus(
    val reachable: Boolean,
    val primaryUrl: String,
    val lanUrl: String? = null,
    val localUrl: String = HostWebUiRepository.LOCAL_URL,
    /** Computer the injected process should dial. Null when only loopback is known. */
    val callbackHost: String? = null,
    val callbackPort: Int = 8761,
)

interface WebUiRepository {
    fun probe(): WebUiStatus
}

class HostWebUiRepository : WebUiRepository {
    override fun probe(): WebUiStatus {
        val deviceIp = localDeviceIpv4()
        cachedLanUrl?.let { cached ->
            readHealth("$cached/health", FAST_TIMEOUT_MS, FAST_TIMEOUT_MS)?.let { body ->
                statusFromHealth(body, deviceIp, hostOf(cached))?.takeIf { it.reachable }?.let {
                    remember(it)
                    return it
                }
            }
        }
        readHealth("${LOCAL_URL}/health", LOCAL_TIMEOUT_MS, LOCAL_TIMEOUT_MS)?.let { body ->
            statusFromHealth(body, deviceIp, "127.0.0.1")?.let {
                remember(it)
                return it
            }
        }
        // 127.0.0.1 on the phone is the phone. Without adb reverse the browser cannot
        // open the PC that way, so look for the daemon on the same Wi-Fi subnet.
        if (deviceIp != null) {
            discoverOnSubnet(deviceIp)?.let {
                remember(it)
                return it
            }
        }
        return WebUiStatus(reachable = false, primaryUrl = LOCAL_URL)
    }

    private fun discoverOnSubnet(deviceIp: String): WebUiStatus? {
        val hosts = subnetHosts(deviceIp)
        if (hosts.isEmpty()) return null
        val found = AtomicReference<WebUiStatus?>()
        val latch = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(SCAN_PARALLELISM)
        try {
            for (host in hosts) {
                pool.execute {
                    try {
                        if (found.get() != null || Thread.currentThread().isInterrupted) return@execute
                        val body = readHealth("http://$host:$HTTP_PORT/health", SCAN_TIMEOUT_MS, SCAN_TIMEOUT_MS)
                            ?: return@execute
                        val status = statusFromHealth(body, deviceIp, host) ?: return@execute
                        if (!status.reachable) return@execute
                        if (found.compareAndSet(null, status)) latch.countDown()
                    } catch (_: Exception) {
                    }
                }
            }
            latch.await(SCAN_BUDGET_MS, TimeUnit.MILLISECONDS)
        } finally {
            pool.shutdownNow()
        }
        return found.get()
    }

    private fun remember(status: WebUiStatus) {
        val lan = status.lanUrl ?: return
        if (hostOf(lan) == null || hostOf(lan) == "127.0.0.1") return
        cachedLanUrl = lan.trimEnd('/')
    }

    companion object {
        const val LOCAL_URL = "http://127.0.0.1:8088"
        private const val HTTP_PORT = 8088
        private const val LOCAL_TIMEOUT_MS = 800
        private const val FAST_TIMEOUT_MS = 400
        private const val SCAN_TIMEOUT_MS = 280
        private const val SCAN_BUDGET_MS = 2_500L
        private const val SCAN_PARALLELISM = 32

        @Volatile
        private var cachedLanUrl: String? = null
    }
}

internal fun readHealth(url: String, connectTimeoutMs: Int, readTimeoutMs: Int): String? {
    return runCatching {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = connectTimeoutMs
            readTimeout = readTimeoutMs
            requestMethod = "GET"
            instanceFollowRedirects = false
        }
        try {
            if (connection.responseCode != HttpURLConnection.HTTP_OK) {
                null
            } else {
                connection.inputStream.bufferedReader().use { it.readText() }
            }
        } finally {
            connection.disconnect()
        }
    }.getOrNull()
}

internal fun isAdhDaemonHealth(body: String): Boolean {
    return runCatching { JSONObject(body).optString("service") == "adhd" }.getOrDefault(false)
}

internal fun statusFromHealth(body: String, deviceIpv4: String?, reachedHost: String?): WebUiStatus? {
    if (!isAdhDaemonHealth(body)) return null
    var parsed = parseWebUiStatus(body, deviceIpv4)
    if (!reachedHost.isNullOrBlank() && reachedHost != "127.0.0.1" && reachedHost != "localhost" &&
        hostOf(parsed.lanUrl.orEmpty()) != reachedHost
    ) {
        val port = portOf(parsed.localUrl) ?: portOf(parsed.primaryUrl) ?: 8088
        val reached = "http://$reachedHost:$port"
        parsed = parsed.copy(primaryUrl = reached, lanUrl = reached)
    }
    val callbackHost = when {
        HostEndpoint.isUsefulIpv4(reachedHost.orEmpty()) -> reachedHost
        else -> hostOf(parsed.lanUrl.orEmpty())?.takeIf { HostEndpoint.isUsefulIpv4(it) }
    }
    return parsed.copy(callbackHost = callbackHost)
}

internal fun parseWebUiStatus(body: String, deviceIpv4: String? = null): WebUiStatus {
    val health = JSONObject(body)
    val web = health.optJSONObject("web")
    val lans = web?.optJSONArray("lan")
        ?.let { urls ->
            (0 until urls.length()).map { urls.optString(it) }.filter { it.isNotBlank() }
        }
        .orEmpty()
    val local = web?.optString("local").orEmpty().ifBlank { HostWebUiRepository.LOCAL_URL }
    val lan = preferredLanUrl(lans, deviceIpv4)
    val callbackHost = lan?.let { hostOf(it) }?.takeIf { HostEndpoint.isUsefulIpv4(it) }
    return WebUiStatus(
        reachable = health.optBoolean("ok", true),
        primaryUrl = lan ?: local,
        lanUrl = lan,
        localUrl = local,
        callbackHost = callbackHost,
        callbackPort = agentPortOf(body),
    )
}

internal fun agentPortOf(body: String): Int {
    val port = runCatching { JSONObject(body).optJSONObject("agent")?.optInt("port", 0) ?: 0 }.getOrDefault(0)
    return if (port in 1..65535) port else 8761
}

/** Prefer the address the phone can actually open: same IPv4 subnet, else the first reported LAN. */
internal fun preferredLanUrl(urls: List<String>, deviceIpv4: String?): String? {
    if (urls.isEmpty()) return null
    val prefix = subnetPrefix(deviceIpv4)
    if (prefix != null) {
        urls.firstOrNull { hostOf(it)?.let(::subnetPrefix) == prefix }?.let { return it }
    }
    return urls.first()
}

internal fun subnetHosts(deviceIpv4: String): List<String> {
    val parts = deviceIpv4.split('.')
    if (parts.size != 4 || parts.any { it.toIntOrNull() !in 0..255 }) return emptyList()
    val self = parts[3].toInt()
    val prefix = parts.take(3).joinToString(".")
    return (1..254).filter { it != self }.map { "$prefix.$it" }
}

internal fun preferredDeviceIpv4(addresses: List<Pair<String, String>>): String? {
    val usable = addresses.filter { (_, ip) ->
        val parts = ip.split('.')
        parts.size == 4 &&
            parts.all { it.toIntOrNull() in 0..255 } &&
            !ip.startsWith("127.") &&
            !ip.startsWith("169.254.")
    }
    val wifi = usable.firstOrNull { (name, _) ->
        val normalized = name.lowercase()
        normalized.contains("wlan") || normalized.contains("wifi") || normalized.startsWith("eth")
    }
    return wifi?.second
}

internal fun hostOf(url: String): String? {
    return Regex("""^https?://([^/:]+)""", RegexOption.IGNORE_CASE).find(url)?.groupValues?.get(1)
}

internal fun portOf(url: String): Int? {
    return Regex("""^https?://[^/:]+:(\d+)""").find(url)?.groupValues?.get(1)?.toIntOrNull()
}

private fun subnetPrefix(ipv4: String?): String? {
    if (ipv4.isNullOrBlank()) return null
    val parts = ipv4.split('.')
    if (parts.size != 4 || parts.any { it.toIntOrNull() !in 0..255 }) return null
    return parts.take(3).joinToString(".")
}

private fun localDeviceIpv4(): String? {
    val found = mutableListOf<Pair<String, String>>()
    val interfaces = NetworkInterface.getNetworkInterfaces() ?: return null
    for (nif in interfaces.asSequence()) {
        if (!nif.isUp || nif.isLoopback) continue
        for (addr in nif.inetAddresses) {
            if (addr is Inet4Address) {
                val host = addr.hostAddress ?: continue
                found += nif.name to host
            }
        }
    }
    return preferredDeviceIpv4(found)
}
