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
        val countFile = File(root, "dispatch-count.txt")
        val counter = java.util.concurrent.atomic.AtomicInteger(if (countFile.exists()) countFile.readText().toInt() else 0)
        var endpoint = ""
        val certificates = org.json.JSONArray()
        var cache:HookPlanCache?=null
        val backend = DeviceBackend { method, params ->
            when (method) {
                "device.info" -> JSONObject().put("model", "JVM fixture").put("synthetic", true)
                "scope.get" -> scopes.snapshot()
                "scope.patch" -> scopes.patch(params)
                "scope.replace" -> scopes.replace(params.getJSONObject("document").toString(), params.getString("scopeRevision"))
                "module.status" -> JSONObject().put("synthetic", true).put("calls", counter.get()).put("earlyEligible",params.optString("package").takeIf{it.isNotEmpty()}?.let{cache?.forProcess(it,params.optInt("uid"))!=null}?:false)
                "applications.list" -> JSONObject().put("applications", org.json.JSONArray()).put("total", 0)
                "processes.list" -> JSONObject().put("processes", org.json.JSONArray()).put("complete", true).put("total", 0)
                "host.get" -> JSONObject().put("endpoint", endpoint)
                "host.set" -> { endpoint = params.getString("endpoint"); JSONObject().put("ok", true) }
                "certificates.list" -> JSONObject().put("certificates", org.json.JSONArray(certificates.toString()))
                "certificates.put" -> { certificates.put("fixture-ca"); JSONObject().put("ok", true).put("stored", 1).put("pendingReboot", true) }
                "certificates.delete" -> { if (certificates.length() > 0) certificates.remove(0); JSONObject().put("ok", true).put("pendingReboot", true) }
                "process.control" -> { countFile.writeText(counter.incrementAndGet().toString()); Thread.sleep(params.optLong("delayMs", 0).coerceIn(0, 5000)); JSONObject().put("ok", true).put("synthetic", true).put("calls", counter.get()) }
                else -> throw DeviceFault("UNSUPPORTED_METHOD", "fixture method not implemented")
            }
        }
        val operations = DeviceOperations(identity, files, backend)
        cache=HookPlanCache(operations,files,scopes,HookBindingProbe { name ->
            val bindingFile=File(root,"hook-binding.json")
            if(bindingFile.exists())JSONObject(bindingFile.readText()) else JSONObject().put("package",name).put("uid",10001).put("versionCode","1").put("signers",org.json.JSONArray().put("b".repeat(64))).put("source",org.json.JSONArray().put(JSONObject().put("path","fixture.apk").put("size",100).put("inode",1).put("mtime",1))).put("agentSha256","a".repeat(64)).put("earlySupported",true)
        })
        val network = DeviceNetwork(operations, files, allowEphemeral = true)
        val server = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1")); val workers = Executors.newFixedThreadPool(4)
        File(root, "ready.json").writeText(JSONObject().put("port", server.localPort).put("deviceId", identity.deviceId).put("lanPort", network.execute("lan.status", JSONObject()).opt("port")).toString())
        Runtime.getRuntime().addShutdownHook(Thread { server.close(); network.close(); workers.shutdownNow() })
        while (!server.isClosed) { val client = server.accept(); workers.execute { client.use { try { DeviceRpcSession(operations).serve(it.getInputStream(), it.getOutputStream()) } catch (_: Exception) { } } } }
    }
}
