package com.adh.core

import org.json.JSONObject
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest

/** Transport-independent device RPC; deliberately unrelated to the legacy target agent framing. */
object DeviceRpc {
    const val PROTOCOL = "adh.device/1"
    const val SOCKET_NAME = "adh_device_rpc_v1"
    const val MAX_FRAME = 1024 * 1024
    const val MAX_BUDGET_MS = 60_000L
    val READ_METHODS = setOf("device.info", "device.capabilities", "device.state", "module.status", "scope.get", "applications.list", "processes.list", "certificates.list", "host.get", "operations.get")
    val WRITE_METHODS = setOf("scope.patch", "scope.replace", "process.control", "certificates.put", "certificates.delete", "host.set", "operations.resolve")
    // Reboot and arbitrary shell/helper execution are NOT remote RPC capabilities in P3.
    fun read(input: InputStream): JSONObject? {
        val first = input.read()
        if (first < 0) return null
        val data = DataInputStream(input)
        val length = (first shl 24) or (data.readUnsignedByte() shl 16) or (data.readUnsignedByte() shl 8) or data.readUnsignedByte()
        require(length in 1..MAX_FRAME) { "invalid device RPC frame length" }
        val payload = ByteArray(length)
        data.readFully(payload)
        return JSONObject(String(payload, Charsets.UTF_8))
    }
    fun write(output: OutputStream, value: JSONObject) {
        val payload = value.toString().toByteArray(Charsets.UTF_8)
        require(payload.size in 1..MAX_FRAME) { "device RPC response exceeds frame limit" }
        DataOutputStream(output).apply { writeInt(payload.size); write(payload); flush() }
    }
    fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    fun canonical(value: Any?): String = when (value) {
        null, JSONObject.NULL -> "null"
        is JSONObject -> value.keys().asSequence().toList().sorted().joinToString(",", "{", "}") { JSONObject.quote(it) + ":" + canonical(value.get(it)) }
        is org.json.JSONArray -> (0 until value.length()).joinToString(",", "[", "]") { canonical(value.get(it)) }
        is String -> JSONObject.quote(value)
        is Boolean, is Number -> value.toString()
        else -> throw IllegalArgumentException("unsupported JSON value")
    }
    fun response(id: String, result: JSONObject): JSONObject = JSONObject().put("protocol", PROTOCOL).put("id", id).put("ok", true).put("result", result)
    fun failure(id: String, code: String, message: String, uncertain: Boolean = false): JSONObject = JSONObject().put("protocol", PROTOCOL).put("id", id).put("ok", false)
        .put("error", JSONObject().put("code", code).put("message", message).put("uncertain", uncertain))
}
