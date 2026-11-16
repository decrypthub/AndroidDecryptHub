package com.adh.daemon.device

import com.adh.core.DeviceRpc
import org.json.JSONObject
import java.io.InputStream
import java.io.OutputStream

/** Framing/dispatch can be reused by a future authenticated TLS transport unchanged. */
internal class DeviceRpcSession(private val operations: DeviceOperations) {
    fun serve(input: InputStream, output: OutputStream, pairings: DevicePairings? = null, authenticated: (String) -> Unit = {}) {
        var hello = DeviceRpc.read(input) ?: return
        var challenge = ""
        if (pairings != null) {
            val challengeId = validEnvelope(hello)
            if (hello.optString("method") != "device.challenge") { DeviceRpc.write(output, DeviceRpc.failure(challengeId, "AUTH_FAILED", "LAN challenge required")); return }
            challenge = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
            DeviceRpc.write(output, DeviceRpc.response(challengeId, operations.identity.descriptor().put("challenge", challenge)))
            hello = DeviceRpc.read(input) ?: return // one challenge per TLS stream, 5 second socket deadline
        }
        val helloId = validEnvelope(hello)
        val params = hello.optJSONObject("params") ?: JSONObject()
        val auth = params.optJSONObject("authentication") ?: JSONObject()
        val nonce = params.optString("clientNonce")
        var grantId: String? = null
        val authorized = try {
            require(hello.optString("method") == "device.hello" && Regex("[a-f0-9]{64}").matches(nonce))
            if (pairings == null) { require(auth.optString("type") == "usb-token" && operations.identity.authenticated(auth.optString("credential"))) }
            else {
                require(auth.optString("type") == "client-signature")
                val identity = operations.identity
                val proof = DeviceRpc.lanProof(listOf(DeviceRpc.PROTOCOL, "lan-auth/1", identity.deviceId, identity.bootId, identity.instanceId, challenge, nonce, helloId, auth.getString("clientId"), auth.getString("grantId")))
                grantId = pairings.authenticate(auth, proof); authenticated(checkNotNull(grantId))
            }
            true
        } catch (_: Exception) { false }
        if (!authorized) {
            DeviceRpc.write(output, DeviceRpc.failure(helloId, "AUTH_FAILED", "device authentication failed")); return
        }
        fun check(method: String) { if (grantId != null) pairings!!.authorize(grantId!!, method) }
        fun capabilities(): JSONObject {
            val value = operations.capabilities(); val methods = value.getJSONObject("methods"); val denied = org.json.JSONArray()
            for (method in methods.keys().asSequence().toList()) if (runCatching { check(method) }.isFailure) { methods.remove(method); denied.put(method) }
            return value.put("deniedMethods", denied).put("connection", JSONObject().put("transport", if (pairings == null) "adb" else "lan").put("grantId", grantId ?: JSONObject.NULL))
        }
        DeviceRpc.write(output, DeviceRpc.response(helloId, operations.identity.signHello(helloId, nonce, operations.read("device.info", authorize = { check("device.info") }), capabilities())))
        while (true) {
            val request = DeviceRpc.read(input) ?: return
            val received = System.nanoTime()
            var id = "invalid"
            val reply = try {
                id = validEnvelope(request)
                val target = request.getJSONObject("target")
                val identity = operations.identity
                if (target.optString("deviceId") != identity.deviceId || target.optString("bootId") != identity.bootId || target.optString("daemonInstanceId") != identity.instanceId) throw DeviceFault("TARGET_CHANGED", "device/boot/daemon generation differs")
                val method = request.getString("method")
                val arguments = request.optJSONObject("params") ?: JSONObject()
                val result = when (method) {
                    in DeviceRpc.READ_METHODS -> operations.read(method, arguments, authorize = { check(method) }).let { if (method == "device.capabilities") capabilities().put("stateRevision", it.getLong("stateRevision")) else it }
                    in DeviceRpc.WRITE_METHODS -> {
                        val meta = request.getJSONObject("meta")
                        val budget = meta.getLong("budgetMs"); require(budget in 1..DeviceRpc.MAX_BUDGET_MS)
                        // A full replacement must carry scope CAS, even on authenticated RPC.
                        if (method in setOf("scope.patch", "scope.replace")) require(Regex("[a-f0-9]{64}").matches(arguments.optString("scopeRevision")))
                        operations.write(method, arguments, meta.getString("operationId"), meta.getLong("expectedRevision"), meta.optString("actor", "ai"), budget, received, authorize = { check(method) },sourceGrant=grantId)
                    }
                    else -> throw DeviceFault("UNSUPPORTED_METHOD", "method not advertised by this device protocol")
                }
                DeviceRpc.response(id, result)
            } catch (error: DeviceFault) { DeviceRpc.failure(id, error.code, error.message, error.uncertain) }
            catch (_: IllegalArgumentException) { DeviceRpc.failure(id, "INVALID_ARGUMENT", "invalid device RPC arguments") }
            catch (_: org.json.JSONException) { DeviceRpc.failure(id, "INVALID_ARGUMENT", "missing or malformed device RPC field") }
            catch (_: Exception) { DeviceRpc.failure(id, "DEVICE_UNAVAILABLE", "device request could not be confirmed", true) }
            DeviceRpc.write(output, reply)
        }
    }
    private fun validEnvelope(value: JSONObject): String {
        require(value.optString("protocol") == DeviceRpc.PROTOCOL)
        val id = value.getString("id"); require(Regex("[A-Za-z0-9_-]{1,128}").matches(id)); return id
    }
}
