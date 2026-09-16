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
 * The device is always the client: the Host listens on loopback and adb reverse forwards
 * tcp:8763 into the daemon. No HTTP/MCP server runs here.
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
                Socket().use { connection ->
                    socket = connection
                    connection.tcpNoDelay = true
                    connection.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
                    val reader = BufferedReader(InputStreamReader(connection.getInputStream(), Charsets.UTF_8))
                    val writer = BufferedWriter(OutputStreamWriter(connection.getOutputStream(), Charsets.UTF_8))
                    writeJson(writer, hello())
                    while (running.get()) {
                        val line = reader.readLine() ?: break
                        handleLine(line, writer)
                    }
                }
            } catch (error: Exception) {
                if (running.get()) Log.d(TAG, "bridge reconnect: ${error.message}")
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

    companion object {
        const val PORT = 8763
        private const val TAG = "AdhAutomationBridge"
        private const val CONNECT_TIMEOUT_MS = 2_000
        private const val RECONNECT_DELAY_MS = 2_000L
        // The host's own per-op timeouts are 20-25s, so answering first at 10s keeps the host
        // from treating a recoverable stall as an unanswerable command.
        private const val COMMAND_DEADLINE_MS = 10_000L
        private const val COMMAND_STUCK_MS = 12_000L
        private const val WATCHDOG_INTERVAL_MS = 1_000L
    }
}

class AutomationException(val code: String, message: String) : IllegalStateException(message)
