package com.adh.manager.automation

import android.util.Log
import org.json.JSONObject
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * Narrow, opt-in bridge from the user-enabled AccessibilityService to the Host ADH Daemon.
 * The device is always the client: the Host listens for it and there is no HTTP/MCP server here.
 *
 * Two transports are supported, in preference order:
 *  1. "127.0.0.1:8763" via adb reverse — the dev setup, no extra host configuration.
 *  2. The host's LAN address, discovered from GET /health (web.lan) once per reconnect
 *     cycle — so the phone keeps working when the cable is unplugged or adb reverse is gone.
 * The last address that worked is remembered and tried first on the next reconnect.
 *
 * Command execution is deliberately decoupled from the socket reader. A slow Accessibility
 * traversal must not stop reconnects or turn the whole bridge into a black hole.
 */
class AutomationBridgeClient(
    private val deviceId: String,
    private val model: String,
    private val sdk: Int,
    private val handler: (String, JSONObject) -> JSONObject,
    private val host: String = "127.0.0.1",
    private val port: Int = PORT,
    /** LAN addresses that worked before, so a cable-free start can reach the host directly. */
    rememberedHosts: List<String> = emptyList(),
    /** Called with the LAN addresses the host advertises in its helloAck. */
    private val onLanHosts: (List<String>) -> Unit = {},
    /** Called with "connecting:<host>", "connected:<host>" or "error:<message>". */
    private val onState: (String) -> Unit = {},
) {
    private val running = AtomicBoolean(false)
    private val commandBusy = AtomicBoolean(false)
    private val commandSince = AtomicLong(0L)
    private val inFlight = AtomicInteger(0)
    private val timeouts = AtomicInteger(0)
    private val writeLock = Any()
    private val commandExecutor = Executors.newCachedThreadPool { runnable ->
        Thread(runnable, "adh-automation-command").apply { isDaemon = true }
    }

    @Volatile private var socket: Socket? = null
    @Volatile private var worker: Thread? = null
    @Volatile private var watchdog: Thread? = null

    // Endpoint memory: the configured (usually loopback) address first, discovered LAN hosts next,
    // and whichever connected last moves to the front.
    private val endpoints = java.util.concurrent.CopyOnWriteArrayList<Endpoint>().apply {
        add(Endpoint(host, port))
        rememberedHosts.map { it.trim() }.filter { it.isNotEmpty() }.forEach { address ->
            val endpoint = Endpoint(address, port)
            if (!contains(endpoint)) add(endpoint)
        }
    }
    @Volatile private var candidateCursor = 0
    @Volatile private var lanDiscoveryAt = 0L

    fun start() {
        if (!running.compareAndSet(false, true)) return
        watchdog = thread(name = "adh-automation-watchdog", isDaemon = true) { watchdogLoop() }
        worker = thread(name = "adh-automation-bridge", isDaemon = true) { runLoop() }
    }

    fun stop() {
        running.set(false)
        runCatching { socket?.close() }
        worker?.interrupt()
        watchdog?.interrupt()
        commandExecutor.shutdownNow()
        worker = null
        watchdog = null
    }

    private fun runLoop() {
        while (running.get()) {
            try {
                val endpoint = nextEndpoint()
                onState("connecting:" + endpoint.host)
                Socket().use { connection ->
                    socket = connection
                    connection.tcpNoDelay = true
                    connection.connect(InetSocketAddress(endpoint.host, endpoint.port), CONNECT_TIMEOUT_MS)
                    val reader = BufferedReader(InputStreamReader(connection.getInputStream(), Charsets.UTF_8))
                    val writer = BufferedWriter(OutputStreamWriter(connection.getOutputStream(), Charsets.UTF_8))
                    writeJson(writer, hello())
                    // A TCP accept is not proof that the host daemon is on the other side: another
                    // device on the LAN may answer. Wait for the host's hello_ack before treating
                    // this endpoint as good, otherwise keep rotating.
                    val ack = awaitHelloAck(connection, reader)
                    if (ack != null) rememberLanHosts(ack)
                    if (ack == null) {
                        onState("error:no helloAck from " + endpoint.host)
                        Log.d(TAG, "no hello_ack from " + endpoint.host + ":" + endpoint.port + " - trying the next endpoint")
                        return@use
                    }
                    remember(endpoint)
                    onState("connected:" + endpoint.host)
                    while (running.get()) {
                        val line = reader.readLine() ?: break
                        handleLine(line, writer)
                    }
                }
            } catch (error: Exception) {
                if (running.get()) {
                    val reason = error.message ?: error.javaClass.simpleName
                    onState("error:" + reason)
                    Log.d(TAG, "bridge reconnect: " + reason)
                }
            } finally {
                socket = null
            }
            if (running.get()) {
                runCatching { Thread.sleep(RECONNECT_DELAY_MS) }
            }
        }
    }

    // A stuck command used to be "handled" by releasing the gate without ever answering the host:
    // the host waited out its own timeout, and every later command hit the same blocked window.
    // Instead, every command now runs with a hard deadline, always gets an answer, and a timed-out
    // command also drops the socket so the host never stays half-attached to a suspect connection.
    private fun watchdogLoop() {
        while (running.get()) {
            val stuck = commandBusy.get() && commandSince.get() > 0 &&
                System.currentTimeMillis() - commandSince.get() > COMMAND_STUCK_MS
            if (stuck) Log.w(TAG, "a command is still running after ${COMMAND_STUCK_MS}ms (in-flight=${inFlight.get()}, timeouts=${timeouts.get()})")
            runCatching { Thread.sleep(WATCHDOG_INTERVAL_MS) }
        }
    }

    fun stats(): JSONObject = JSONObject()
        .put("inFlight", inFlight.get())
        .put("timeouts", timeouts.get())
        .put("commandActive", commandBusy.get())

    private fun hello(): JSONObject = JSONObject()
        .put("t", "hello")
        .put("deviceId", deviceId)
        .put("model", model)
        .put("sdk", sdk)
        .put(
            "caps",
            JSONObject()
                .put("tree", true)
                .put("screenshot", sdk >= 30)
                .put("gestures", true)
                .put("setText", true)
                .put("maxNodes", 2000),
        )

    private fun handleLine(line: String, writer: BufferedWriter) {
        val message = runCatching { JSONObject(line) }.getOrNull() ?: return
        if (message.optString("t") != "cmd") return
        val id = message.optString("id")
        val op = message.optString("op")
        val args = message.optJSONObject("args") ?: JSONObject()
        inFlight.incrementAndGet()
        val task = commandExecutor.submit<JSONObject> {
            if (!commandBusy.compareAndSet(false, true)) {
                throw AutomationException("automation_busy", "previous automation command is still running")
            }
            commandSince.set(System.currentTimeMillis())
            try {
                handler(op, args)
            } finally {
                commandSince.set(0L)
                commandBusy.set(false)
            }
        }
        try {
            writeResult(writer, id, task.get(COMMAND_DEADLINE_MS, TimeUnit.MILLISECONDS))
        } catch (timeout: TimeoutException) {
            timeouts.incrementAndGet()
            commandBusy.set(false)          // the abandoned worker may never return; let others run
            commandSince.set(0L)
            task.cancel(true)
            Log.w(TAG, "command '$op' exceeded ${COMMAND_DEADLINE_MS}ms — answering command_timeout (in-flight=${inFlight.get()})")
            writeError(
                writer,
                id,
                "command_timeout",
                "device did not answer '$op' within ${COMMAND_DEADLINE_MS}ms; the target window is probably frozen — retry, or restart that app",
            )
            // One stuck command is not a reason to drop a healthy connection (the AI can retry and
            // land on a fresh thread). Only a pile-up means the device itself is wedged.
            if (inFlight.get() >= 3) {
                Log.w(TAG, "${inFlight.get()} commands are in flight — recycling the bridge socket")
                runCatching { socket?.close() }
            }
        } catch (failure: ExecutionException) {
            val cause = failure.cause
            writeError(
                writer,
                id,
                (cause as? AutomationException)?.code ?: "automation_error",
                cause?.message ?: cause?.javaClass?.simpleName ?: "automation failed",
            )
        } catch (error: Throwable) {
            writeError(writer, id, "automation_error", error.message ?: error.javaClass.simpleName)
        } finally {
            inFlight.decrementAndGet()
        }
    }

    private fun writeResult(writer: BufferedWriter, id: String, result: JSONObject) {
        runCatching {
            writeJson(writer, JSONObject().put("t", "result").put("id", id).put("ok", true).put("result", result))
        }
    }

    private fun writeError(writer: BufferedWriter, id: String, code: String, message: String) {
        runCatching {
            writeJson(
                writer,
                JSONObject()
                    .put("t", "error")
                    .put("id", id)
                    .put("ok", false)
                    .put("error", JSONObject().put("code", code).put("message", message)),
            )
        }
    }

    private fun writeJson(writer: BufferedWriter, value: JSONObject) {
        synchronized(writeLock) {
            writer.write(value.toString())
            writer.newLine()
            writer.flush()
        }
    }

    private data class Endpoint(val host: String, val port: Int)

    /** Rotates through known endpoints; discovers LAN candidates when the local one keeps failing. */
    private fun nextEndpoint(): Endpoint {
        val list = endpoints.toList()
        val now = System.currentTimeMillis()
        if (list.size <= 1 && now - lanDiscoveryAt > LAN_PROBE_INTERVAL_MS) {
            lanDiscoveryAt = now
            discoverLanEndpoints()
        }
        val current = endpoints.toList()
        val index = candidateCursor % current.size
        candidateCursor = (candidateCursor + 1) % Int.MAX_VALUE
        return current[index]
    }

    /** Reads the host's helloAck (or any first line) with a bounded wait. */
    private fun awaitHelloAck(connection: Socket, reader: BufferedReader): String? {
        val previous = connection.soTimeout
        connection.soTimeout = HELLO_ACK_TIMEOUT_MS
        return try {
            reader.readLine()
        } catch (_: Exception) {
            null
        } finally {
            connection.soTimeout = previous
        }
    }

    /**
     * The host tells us its LAN addresses in the ack. Remembering them lets the next app start
     * connect over Wi-Fi (or another route) instead of requiring adb reverse to be set up again.
     */
    private fun rememberLanHosts(ack: String) {
        runCatching {
            val hosts = JSONObject(ack).optJSONArray("lanHosts") ?: return@runCatching
            val discovered = mutableListOf<String>()
            for (index in 0 until hosts.length()) {
                val address = hosts.optString(index).trim()
                if (address.isBlank()) continue
                discovered.add(address)
                val endpoint = Endpoint(address, port)
                if (!endpoints.contains(endpoint)) endpoints.add(endpoint)
            }
            // Keep the list short: a stale address only costs one connect timeout per cycle.
            while (endpoints.size > 1 + MAX_REMEMBERED_HOSTS) endpoints.removeAt(endpoints.size - 1)
            if (discovered.isNotEmpty()) onLanHosts(discovered)
        }
    }

    /** Moves the endpoint that just connected to the front so later reconnects retry it first. */
    private fun remember(endpoint: Endpoint) {
        if (endpoints.firstOrNull() == endpoint) return
        endpoints.remove(endpoint)
        endpoints.add(0, endpoint)
    }

    /**
     * Reads the host's /health over the loopback reverse tunnel and remembers every LAN address the
     * host advertises. Any failure is silent: the loopback endpoint stays the only candidate.
     */
    private fun discoverLanEndpoints() {
        runCatching {
            val url = java.net.URL("http://127.0.0.1:$HEALTH_PORT/health")
            val connection = (url.openConnection() as java.net.HttpURLConnection).apply {
                connectTimeout = 1_500
                readTimeout = 1_500
                requestMethod = "GET"
            }
            val body = connection.inputStream.bufferedReader().use { it.readText() }
            connection.disconnect()
            val lan = JSONObject(body).optJSONObject("web")?.optJSONArray("lan") ?: return@runCatching
            for (index in 0 until lan.length()) {
                val raw = lan.optString(index)
                val host = raw.substringAfter("://", raw).substringBefore(':').substringBefore('/')
                if (host.isNotBlank()) {
                    val endpoint = Endpoint(host, port)
                    if (!endpoints.contains(endpoint)) endpoints.add(endpoint)
                }
            }
        }
    }

    companion object {
        const val PORT = 8763
        private const val HEALTH_PORT = 8088
        private const val LAN_PROBE_INTERVAL_MS = 30_000L
        private const val TAG = "AdhAutomationBridge"
        private const val CONNECT_TIMEOUT_MS = 2_000
        private const val HELLO_ACK_TIMEOUT_MS = 3_000
        private const val MAX_REMEMBERED_HOSTS = 4
        private const val RECONNECT_DELAY_MS = 2_000L
        // The host's own per-op timeouts are 20-25s, so answering first at 10s keeps the host
        // from treating a recoverable stall as an unanswerable command.
        private const val COMMAND_DEADLINE_MS = 10_000L
        private const val COMMAND_STUCK_MS = 12_000L
        private const val WATCHDOG_INTERVAL_MS = 1_000L
    }
}

class AutomationException(val code: String, message: String) : IllegalStateException(message)
