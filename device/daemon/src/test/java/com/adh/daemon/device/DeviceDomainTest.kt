package com.adh.daemon.device

import com.adh.core.DeviceRpc
import org.json.JSONObject
import org.json.JSONArray
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.util.UUID
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

class DeviceDomainTest {
    private fun root() = Files.createTempDirectory("adh-p3-unit-").toFile()
    private fun identity(root: File, boot: String = "00000000-0000-4000-8000-000000000001") = DeviceIdentity(DeviceFiles(root), boot)
    private fun frame(value: JSONObject) = ByteArrayOutputStream().apply { DeviceRpc.write(this, value) }.toByteArray()
    @Test fun identityPersistsAcrossRestartAndBootWithoutUsingAnAdbSerial() {
        val dir = root(); val one = identity(dir); val two = identity(dir); val reboot = identity(dir, "00000000-0000-4000-8000-000000000002")
        assertEquals(one.deviceId, two.deviceId); assertEquals(one.deviceId, reboot.deviceId); assertEquals(one.fingerprint, reboot.fingerprint)
        assertNotEquals(one.instanceId, two.instanceId); assertNotEquals(one.bootId, reboot.bootId)
        val access = File(dir, "usb-access.json").readText(); assertFalse(access.contains("privateKey")); assertFalse(access.contains(one.publicKey))
        File(dir, "identity.json").writeText("corrupt")
        assertTrue(runCatching { identity(dir) }.isFailure); assertEquals("corrupt", File(dir, "identity.json").readText())
    }
    @Test fun signedHelloBindsNonceIdentityAndCapabilitiesWithoutExposingCredentials() {
        val id = identity(root()); val response = id.signHello("hello-1", "a".repeat(64), JSONObject().put("model", "fixture"), JSONObject().put("methods", JSONObject()))
        val payload = Base64.getDecoder().decode(response.getString("payload"))
        val key = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(response.getString("publicKey"))))
        assertTrue(Signature.getInstance("SHA256withRSA").run { initVerify(key); update(payload); verify(Base64.getDecoder().decode(response.getString("signature"))) })
        val decoded = JSONObject(String(payload)); assertEquals("a".repeat(64), decoded.getString("clientNonce")); assertEquals(id.deviceId, decoded.getString("deviceId"))
        assertFalse(String(payload).contains(id.token)); assertFalse(id.authenticated("wrong")); assertTrue(id.authenticated(id.token))
    }
    @Test fun managerAndRpcMutationsShareOneRevisionAndDeviceOperationIdsNeverReplay() {
        val dir = root(); var calls = 0
        val ops = DeviceOperations(identity(dir), DeviceFiles(dir), DeviceBackend { _, _ -> calls++; JSONObject().put("ok", true) })
        val manager = ops.managerWrite("host.set", JSONObject().put("endpoint", "192.0.2.1:8761")); assertEquals("succeeded", manager.getString("state"))
        val stale = runCatching { ops.write("host.set", JSONObject(), "old-intent", 0, "ai", 10000) }.exceptionOrNull() as DeviceFault
        assertEquals("STALE_DEVICE_STATE", stale.code); assertEquals(1, calls)
        val args = JSONObject().put("privateFixture", "synthetic-secret-payload")
        val first = ops.write("host.set", args, "same-intent", 1, "ai", 10000)
        val again = ops.write("host.set", args, "same-intent", 1, "ai", 10000)
        assertEquals(first.getString("operationId"), again.getString("operationId")); assertEquals(2, calls)
        assertEquals("IDEMPOTENCY_CONFLICT", (runCatching { ops.write("host.set", JSONObject(), "same-intent", 2, "ai", 10000) }.exceptionOrNull() as DeviceFault).code)
        assertFalse(File(dir, "operations.json").readText().contains("synthetic-secret-payload"))
    }
    @Test fun crashReservationsBecomeUnknownAndRequireExplicitOperatorReconciliation() {
        val dir = root(); val id = identity(dir)
        val backend = DeviceBackend { _, _ -> JSONObject().put("ok", true) }
        val ops = DeviceOperations(id, DeviceFiles(dir), backend)
        ops.write("host.set", JSONObject(), "crashed", 0, "ai", 10000)
        val file = File(dir, "operations.json"); val stored = JSONObject(file.readText()); stored.getJSONObject("operations").getJSONObject("crashed").put("state", "running"); file.writeText(stored.toString())
        val restored = DeviceOperations(identity(dir), DeviceFiles(dir), backend)
        assertEquals("unknown", restored.read("operations.get", JSONObject().put("operationId", "crashed")).getString("state"))
        assertEquals("UNKNOWN_EXECUTION", (runCatching { restored.write("host.set", JSONObject(), "new", 1, "ai", 10000) }.exceptionOrNull() as DeviceFault).code)
        assertEquals("OPERATOR_REQUIRED", (runCatching { restored.write("operations.resolve", JSONObject().put("operationId", "crashed").put("acknowledge", true), "ack-ai", 1, "ai", 10000) }.exceptionOrNull() as DeviceFault).code)
        restored.write("operations.resolve", JSONObject().put("operationId", "crashed").put("acknowledge", true), "ack-human", 1, "operator", 10000)
        val original = restored.read("operations.get", JSONObject().put("operationId", "crashed")); assertEquals("unknown", original.getString("state")); assertTrue(original.has("resolvedAt"))
    }
    @Test fun scopePatchRetainsFullPolicyAndRejectsAnExternalWriterOrMalformedArray() {
        val dir = root(); val file = File(dir, "scope.json")
        file.writeText("""{"version":2,"mode":"allowlist","packages":["com.example.old"],"future":{"x":3},"policy":{"com.example.old":{"c":{"h":false,"future":7}}}}""")
        val scopes = ScopeDocuments(file, DeviceFiles(dir)); val original = scopes.snapshot()
        val after = scopes.patch(JSONObject().put("scopeRevision", original.getString("scopeRevision")).put("set", JSONArray().put("com.example.next")))
        assertEquals(7, after.getJSONObject("document").getJSONObject("policy").getJSONObject("com.example.old").getJSONObject("c").getInt("future"))
        assertEquals(3, after.getJSONObject("document").getJSONObject("future").getInt("x"))
        assertEquals("STALE_SCOPE", (runCatching { scopes.patch(JSONObject().put("scopeRevision", original.getString("scopeRevision"))) }.exceptionOrNull() as DeviceFault).code)
        assertEquals("INVALID_ARGUMENT", (runCatching { scopes.patch(JSONObject().put("scopeRevision", after.getString("scopeRevision")).put("set", "not-an-array")) }.exceptionOrNull() as DeviceFault).code)
    }
    @Test fun managerResetOfKnownPolicyDoesNotLoseFutureFields() {
        val dir = root(); val file = File(dir, "scope.json")
        file.writeText("""{"version":2,"packages":["com.example.old"],"future":8,"policy":{"com.example.old":{"c":{"h":false,"future":7}}}}""")
        val value = ScopeDocuments(file, DeviceFiles(dir)).replace("""{"version":2,"packages":["com.example.old"]}""").getJSONObject("document")
        assertEquals(8, value.getInt("future")); val c = value.getJSONObject("policy").getJSONObject("com.example.old").getJSONObject("c"); assertEquals(7, c.getInt("future")); assertFalse(c.has("h"))
        val updated = ScopeDocuments(file, DeviceFiles(dir)).replace("""{"version":2,"packages":["com.example.old"],"future":9,"newField":true,"policy":{"com.example.old":{"newPolicy":4,"c":{"h":false,"another":2}}}}""").getJSONObject("document")
        assertEquals(9, updated.getInt("future")); assertTrue(updated.getBoolean("newField")); assertEquals(2, updated.getJSONObject("policy").getJSONObject("com.example.old").getJSONObject("c").getInt("another"))
    }
    @Test fun framingIsBoundedAndTruncatedFramesDoNotBecomeRequests() {
        val stream = ByteArrayInputStream(frame(JSONObject().put("x", 1)) + frame(JSONObject().put("x", 2)))
        assertEquals(1, DeviceRpc.read(stream)!!.getInt("x")); assertEquals(2, DeviceRpc.read(stream)!!.getInt("x")); assertNull(DeviceRpc.read(stream))
        assertTrue(runCatching { DeviceRpc.read(ByteArrayInputStream(byteArrayOf(127, 127, 127, 127))) }.isFailure)
        assertTrue(runCatching { DeviceRpc.read(ByteArrayInputStream(frame(JSONObject().put("x", 1)).dropLast(1).toByteArray())) }.isFailure)
    }
    @Test fun sessionRejectsWrongCredentialAndWrongBootBeforeCallingBackend() {
        val dir = root(); val id = identity(dir); var hits = 0
        val ops = DeviceOperations(id, DeviceFiles(dir), DeviceBackend { _, _ -> hits++; JSONObject().put("ok", true) })
        fun hello(token: String) = JSONObject().put("protocol", DeviceRpc.PROTOCOL).put("id", "hello").put("method", "device.hello").put("params", JSONObject().put("clientNonce", "a".repeat(64)).put("authentication", JSONObject().put("type", "usb-token").put("credential", token)))
        val bad = ByteArrayOutputStream(); DeviceRpcSession(ops).serve(ByteArrayInputStream(frame(hello("wrong"))), bad)
        assertEquals("AUTH_FAILED", DeviceRpc.read(ByteArrayInputStream(bad.toByteArray()))!!.getJSONObject("error").getString("code")); assertEquals(0, hits)
        val request = JSONObject().put("protocol", DeviceRpc.PROTOCOL).put("id", "read").put("method", "scope.get").put("target", id.descriptor().put("bootId", UUID.randomUUID().toString()))
        val out = ByteArrayOutputStream(); DeviceRpcSession(ops).serve(ByteArrayInputStream(frame(hello(id.token)) + frame(request)), out)
        val replies = ByteArrayInputStream(out.toByteArray()); assertTrue(DeviceRpc.read(replies)!!.getBoolean("ok")); assertEquals("TARGET_CHANGED", DeviceRpc.read(replies)!!.getJSONObject("error").getString("code")); assertEquals(1, hits) // hello info only
    }
    @Test fun invalidParametersAreRejectedBeforeRevisionOrEffects() {
        val dir = root(); var calls = 0
        val ops = DeviceOperations(identity(dir), DeviceFiles(dir), object : DeviceBackend {
            override fun execute(method: String, params: JSONObject): JSONObject { calls++; return JSONObject().put("ok", true) }
            override fun validate(method: String, params: JSONObject) { DeviceArguments.validate(method, params) }
        })
        for ((method, params) in listOf("scope.patch" to JSONObject().put("set", "bad"), "process.control" to JSONObject().put("package", "com.example.fixture").put("action", "stop"), "host.set" to JSONObject().put("endpoint", "no endpoint"), "certificates.delete" to JSONObject().put("fileName", "../escape"))) {
            assertEquals("INVALID_ARGUMENT", (runCatching { ops.write(method, params, UUID.randomUUID().toString(), 0, "ai", 1000) }.exceptionOrNull() as DeviceFault).code)
        }
        assertEquals(0, calls); assertEquals(0L, ops.revision())
    }
    @Test fun reservationFailureDisablesWritesWithoutDispatchingAndResultFailureRemainsUnknown() {
        val dir = root(); val id = identity(dir); var fail = false; var calls = 0
        val files = DeviceFiles(dir, { _, _ -> if (fail) throw java.io.IOException("synthetic disk failure") })
        val backend = DeviceBackend { _, _ -> calls++; JSONObject().put("ok", true) }
        val ops = DeviceOperations(id, files, backend); fail = true
        val error = runCatching { ops.write("host.set", JSONObject(), "no-dispatch", 0, "ai", 10000) }.exceptionOrNull() as DeviceFault
        assertEquals("DEVICE_LEDGER_UNAVAILABLE", error.code); assertFalse(error.uncertain); assertEquals(0, calls); assertEquals(0L, ops.revision())
        fail = false
        assertEquals("DEVICE_LEDGER_UNAVAILABLE", (runCatching { ops.write("host.set", JSONObject(), "no-retry", 0, "ai", 10000) }.exceptionOrNull() as DeviceFault).code)
        val recovered = DeviceOperations(id, files, DeviceBackend { _, _ -> calls++; fail = true; JSONObject().put("ok", true) })
        val after = runCatching { recovered.write("host.set", JSONObject(), "uncertain", 0, "ai", 10000) }.exceptionOrNull() as DeviceFault
        assertTrue(after.uncertain); assertEquals(1, calls); assertEquals("unknown", recovered.read("operations.get", JSONObject().put("operationId", "uncertain")).getString("state"))
        fail = false
        val restarted = DeviceOperations(identity(dir), files, backend)
        assertEquals("unknown", restarted.read("operations.get", JSONObject().put("operationId", "uncertain")).getString("state")); assertEquals(1, calls)
    }
    @Test fun bulkIconReadDoesNotHoldTheWriterLock() {
        val dir = root(); val iconStarted = CountDownLatch(1); val finishIcon = CountDownLatch(1); val writeFinished = CountDownLatch(1)
        val ops = DeviceOperations(identity(dir), DeviceFiles(dir), DeviceBackend { method, _ ->
            if (method == "legacy.icon") { iconStarted.countDown(); assertTrue(finishIcon.await(2, TimeUnit.SECONDS)) }
            JSONObject().put("ok", true)
        })
        val iconThread = Thread { ops.read("legacy.icon", JSONObject().put("package", "com.example.fixture")) }
        iconThread.start(); assertTrue(iconStarted.await(1, TimeUnit.SECONDS))
        val writeThread = Thread {
            ops.write("host.set", JSONObject(), "during-bulk-read", 0, "ai", 10000)
            writeFinished.countDown()
        }
        writeThread.start(); assertTrue(writeFinished.await(500, TimeUnit.MILLISECONDS))
        finishIcon.countDown(); iconThread.join(1000); writeThread.join(1000)
    }
}
