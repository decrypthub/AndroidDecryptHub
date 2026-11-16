package com.adh.daemon.device

import org.json.JSONObject
import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import java.util.UUID
import java.util.concurrent.Executors

/** Runs the production domain/codec on loopback JVM sockets, never Android/ADB or a real app. */
object DeviceRpcFixture {
    @JvmStatic fun main(args: Array<String>) {
        require(args.size == 1)
        val root = File(args[0]); check(root.isDirectory && root.name.startsWith("adh-p3-jvm-"))
        val bootFile = File(root, "boot.txt"); if (!bootFile.exists()) bootFile.writeText(UUID.randomUUID().toString())
        val files = DeviceFiles(root); val identity = DeviceIdentity(files, bootFile.readText().trim())
        val scopes = ScopeDocuments(File(root, "scope.json"), files)
        val counter = java.util.concurrent.atomic.AtomicInteger()
        val backend = DeviceBackend { method, params ->
            when (method) {
                "device.info" -> JSONObject().put("model", "JVM fixture").put("synthetic", true)
                "scope.get" -> scopes.snapshot()
                "scope.patch" -> scopes.patch(params)
                "scope.replace" -> scopes.replace(params.getJSONObject("document").toString(), params.getString("scopeRevision"))
                "module.status" -> JSONObject().put("synthetic", true).put("calls", counter.get())
                "applications.list" -> JSONObject().put("applications", org.json.JSONArray()).put("total", 0)
                "process.control" -> { counter.incrementAndGet(); Thread.sleep(params.optLong("delayMs", 0).coerceIn(0, 5000)); JSONObject().put("ok", true).put("synthetic", true).put("calls", counter.get()) }
                else -> throw DeviceFault("UNSUPPORTED_METHOD", "fixture method not implemented")
            }
        }
        val operations = DeviceOperations(identity, files, backend)
        val server = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1")); val workers = Executors.newFixedThreadPool(4)
        File(root, "ready.json").writeText(JSONObject().put("port", server.localPort).put("deviceId", identity.deviceId).toString())
        Runtime.getRuntime().addShutdownHook(Thread { server.close(); workers.shutdownNow() })
        while (!server.isClosed) { val client = server.accept(); workers.execute { client.use { try { DeviceRpcSession(operations).serve(it.getInputStream(), it.getOutputStream()) } catch (_: Exception) { } } } }
    }
}
