package com.adh.daemon.device

import org.json.JSONObject
import java.io.File
import java.net.InetAddress
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

/** Opt-in TLS transport. All device methods still dispatch through the same DeviceOperations. */
internal class DeviceNetwork(private val operations: DeviceOperations, private val files: DeviceFiles, private val allowEphemeral: Boolean = false) : AutoCloseable {
    val pairings = DevicePairings(files)
    private val configFile = File(files.directory, "lan.json")
    private var config = JSONObject().put("schemaVersion", 1).put("enabled", false).put("address", "0.0.0.0").put("port", 8762)
    private val tls by lazy { DeviceTls.context(operations.identity, files) }
    private class Listener(val socket: SSLServerSocket, val clients: java.util.concurrent.ConcurrentHashMap<SSLSocket, String>)
    private var listener: Listener? = null
    private var startupError: String? = null
    private val workers = ThreadPoolExecutor(4, 4, 30, TimeUnit.SECONDS, ArrayBlockingQueue(4))
    private val allClients = java.util.concurrent.ConcurrentHashMap<SSLSocket, String>()
    val methods = setOf("lan.status", "lan.configure", "pairings.list", "pairings.grant", "pairings.revoke")
    init {
        operations.network = this
        if (configFile.exists()) { check(configFile.length() <= 4096); config = JSONObject(configFile.readText()); check(config.getInt("schemaVersion") == 1); validateConfig(config) }
        pairings.revoked = { grant -> allClients.entries.filter { it.value == grant }.forEach { runCatching { it.key.close() } } }
        if (config.getBoolean("enabled")) try { listener = open(config); accept(checkNotNull(listener)) } catch (_: Exception) { startupError = "LAN_START_FAILED" }
    }
    private fun validateConfig(value: JSONObject) {
        require(value.get("enabled") is Boolean)
        val address = value.getString("address")
        val ipv4 = Regex("(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}").matches(address) && address.split('.').all { it.toInt() <= 255 }
        require(ipv4 || address.contains(':') && Regex("[0-9a-fA-F:]{2,64}").matches(address)); InetAddress.getByName(address)
        val port = value.get("port"); require(port is Number && port !is Double && port !is Float && port.toLong() in (if (allowEphemeral) 0L else 1L)..65535L)
    }
    fun validate(method: String, params: JSONObject) {
        when (method) {
            "lan.configure" -> try { validateConfig(params) } catch (_: Exception) { throw DeviceFault("INVALID_ARGUMENT", "explicit enabled, numeric bind address and port required") }
            "pairings.grant" -> pairings.validateGrant(params)
            "pairings.revoke" -> if (!Regex("[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}").matches(params.optString("grantId"))) throw DeviceFault("INVALID_ARGUMENT", "explicit grantId required")
        }
    }
    @Synchronized fun execute(method: String, params: JSONObject): JSONObject = when (method) {
        "lan.status" -> JSONObject().put("configured", JSONObject(config.toString())).put("listening", listener != null)
            .put("port", listener?.socket?.localPort ?: JSONObject.NULL).put("startupError", startupError ?: JSONObject.NULL)
            .put("tls", "TLSv1.2+").put("identityFingerprint", operations.identity.fingerprint).put("pairing", "trusted USB enrollment; client RSA challenge proof")
        "lan.configure" -> configure(params)
        "pairings.list" -> pairings.list()
        "pairings.grant" -> pairings.grant(params)
        "pairings.revoke" -> pairings.revoke(params)
        else -> throw DeviceFault("UNSUPPORTED_METHOD", "network capability unsupported")
    }
    private fun configure(params: JSONObject): JSONObject {
        validate("lan.configure", params)
        val candidate = JSONObject().put("schemaVersion", 1).put("enabled", params.getBoolean("enabled")).put("address", params.getString("address")).put("port", params.getInt("port"))
        if (candidate.getBoolean("enabled") == config.getBoolean("enabled") && candidate.getString("address") == config.getString("address") && candidate.getInt("port") == config.getInt("port") && (!candidate.getBoolean("enabled") || listener != null)) return execute("lan.status", JSONObject()).put("ok", true)
        val prepared = if (candidate.getBoolean("enabled")) try { open(candidate) } catch (_: Exception) { throw DeviceFault("LAN_START_FAILED", "TLS listener could not start; previous configuration retained") } else null
        try { files.write(configFile, candidate.toString()) } catch (error: Exception) { prepared?.socket?.close(); throw error }
        val previous = listener; listener = prepared; config = candidate; startupError = null
        previous?.let { stop(it) }; prepared?.let { accept(it) }
        return execute("lan.status", JSONObject()).put("ok", true)
    }
    private fun open(value: JSONObject): Listener {
        val socket = tls.serverSocketFactory.createServerSocket() as SSLServerSocket
        try {
            socket.enabledProtocols = socket.supportedProtocols.filter { it in setOf("TLSv1.3", "TLSv1.2") }.toTypedArray()
            socket.enabledCipherSuites = socket.supportedCipherSuites.filter { it.startsWith("TLS_AES_") || it.startsWith("TLS_CHACHA20_") || it.contains("ECDHE_RSA") && (it.contains("GCM") || it.contains("CHACHA20")) }.toTypedArray()
            check(socket.enabledProtocols.isNotEmpty() && socket.enabledCipherSuites.isNotEmpty())
            socket.reuseAddress = true; socket.bind(java.net.InetSocketAddress(InetAddress.getByName(value.getString("address")), value.getInt("port")), 8)
            return Listener(socket, java.util.concurrent.ConcurrentHashMap())
        } catch (error: Exception) { socket.close(); throw error }
    }
    private fun accept(current: Listener) {
        Thread({
            while (!current.socket.isClosed) {
                val client = try { current.socket.accept() as SSLSocket } catch (_: Exception) { break }
                current.clients[client] = ""; allClients[client] = ""
                try { workers.execute {
                    try {
                        client.soTimeout = 5000; client.startHandshake()
                        DeviceRpcSession(operations).serve(client.inputStream, client.outputStream, pairings, { grant ->
                            current.clients[client] = grant; allClients[client] = grant; client.soTimeout = 30_000
                        })
                    } catch (_: Exception) { /* broken/TLS/auth streams close; no replay */ }
                    finally { current.clients.remove(client); allClients.remove(client); runCatching { client.close() } }
                } } catch (_: java.util.concurrent.RejectedExecutionException) { current.clients.remove(client); allClients.remove(client); client.close() }
            }
        }, "adh-device-tls").apply { isDaemon = true; start() }
    }
    private fun stop(current: Listener) { current.socket.close(); current.clients.keys.forEach { runCatching { it.close() } } }
    @Synchronized override fun close() { listener?.let { stop(it) }; listener = null; workers.shutdownNow() }
}
