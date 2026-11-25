package com.adh.daemon.device

import com.adh.core.DeviceRpc
import org.json.JSONObject
import java.io.File
import java.util.UUID

internal class DeviceFault(val code: String, override val message: String, val uncertain: Boolean = false) : RuntimeException(message)
internal fun interface DeviceBackend {
    fun execute(method: String, params: JSONObject): JSONObject
    fun validate(method: String, params: JSONObject) {} // no effects; reject invalid intent before reservation
}

/** Single writer shared by authenticated Binder and RPC; device coordination, never analysis. */
internal class DeviceOperations(val identity: DeviceIdentity, private val files: DeviceFiles, private val backend: DeviceBackend) {
    private val stateFile = File(files.directory, "operations.json")
    private val lock = Any()
    private var state: JSONObject
    private var storageUnavailable = false
    var network: DeviceNetwork? = null
    var hookCache: HookPlanCache? = null
    init {
        check(!stateFile.exists() || stateFile.length() <= 2 * 1024 * 1024) { "device operation ledger exceeds limit" }
        state = if (stateFile.exists()) JSONObject(stateFile.readText()) else JSONObject().put("schemaVersion", 1).put("revision", 0L).put("operations", JSONObject())
        check(state.getInt("schemaVersion") == 1 && state.getLong("revision") >= 0)
        check(records().length() <= 1024)
        for (id in records().keys()) {
            val record = records().getJSONObject(id)
            if (record.getString("state") == "running") record.put("state", "unknown").put("code", "DAEMON_RESTARTED").put("uncertain", true)
        }
        save()
    }
    private fun records() = state.getJSONObject("operations")
    private fun encoded(value: JSONObject): String { val text = value.toString(); if (text.toByteArray().size > 2 * 1024 * 1024) throw DeviceFault("LEDGER_FULL", "device operation ledger full; no automatic pruning"); return text }
    private fun save() { files.write(stateFile, encoded(state)) }
    fun revision(): Long = synchronized(lock) { state.getLong("revision") }
    fun capabilities(): JSONObject = JSONObject().put("protocol", DeviceRpc.PROTOCOL).put("maxFrameBytes", DeviceRpc.MAX_FRAME).put("maxBudgetMs", DeviceRpc.MAX_BUDGET_MS)
        .put("methods", JSONObject().also { methods -> DeviceRpc.READ_METHODS.filter { available(it) }.forEach { methods.put(it, "read") }; DeviceRpc.WRITE_METHODS.filter { available(it) }.forEach { methods.put(it, "write") } })
        .put("transports", JSONObject().put("usb", true).put("lanTls", network != null))
        .put("unsupported", JSONObject().put("agent.route", "legacy target channel retained; not associated by serial").put("agent.hook", "target agent routing not migrated").put("agent.memory", "target agent routing not migrated").put("agent.trace", "target agent routing not migrated").put("diagnostics", "legacy ADB-only; no LAN fallback").put("fs", "not migrated").put("root.helper", "not migrated").put("shell", "no arbitrary remote root shell").put("reboot", "Manager-only").put("bulk", "not implemented"))
    private fun available(method: String) = if(method.startsWith("early.")||method.startsWith("hooks.migration."))hookCache!=null else method !in setOf("lan.status", "lan.configure", "pairings.list", "pairings.grant", "pairings.revoke") || network != null
    private fun execute(method: String, params: JSONObject,sourceGrant:String?=null): JSONObject = if(method in(hookCache?.methods?:emptySet()))hookCache!!.execute(method,params,sourceGrant)else if (method in (network?.methods ?: emptySet())) network!!.execute(method, params) else backend.execute(method, params)
    fun read(method: String, params: JSONObject = JSONObject(), authorize: () -> Unit = {}): JSONObject {
        // Bulk package metadata does not touch the operation ledger. Keep it out
        // of the writer lock so icon/catalog traffic cannot block scope or control.
        if (method in setOf("legacy.icon", "applications.icon", "applications.list")) {
            authorize()
            return execute(method, params).put("stateRevision", revision())
        }
        return synchronized(lock) {
            authorize()
            when (method) {
                "device.info" -> identity.descriptor().put("info", backend.execute(method, params)).put("stateRevision", revision())
                "device.capabilities" -> capabilities().put("stateRevision", revision())
                "device.state" -> identity.descriptor().put("stateRevision", revision())
                "operations.get" -> {
                    val id = params.getString("operationId")
                    val record = records().optJSONObject(id) ?: throw DeviceFault("OPERATION_NOT_FOUND", "no recorded device operation")
                    JSONObject(record.toString()).put("stateRevision", revision())
                }
                "operations.reconcile" -> {
                    val ids = params.getJSONArray("operationIds"); require(ids.length() in 1..100)
                    val rows = org.json.JSONArray()
                    for (n in 0 until ids.length()) { val id = ids.getString(n); require(Regex("[A-Za-z0-9_-]{1,128}").matches(id))
                        rows.put(records().optJSONObject(id)?.let { JSONObject(it.toString()).put("found", true) } ?: JSONObject().put("operationId", id).put("found", false))
                    }
                    JSONObject().put("operations", rows).put("notFoundDoesNotProveUnsent", true).put("replayed", false).put("stateRevision", revision())
                }
                else -> execute(method, params).put("stateRevision", revision())
            }
        }
    }
    fun write(method: String, params: JSONObject, operationId: String, expectedRevision: Long, actor: String, budgetMs: Long, receivedAt: Long = System.nanoTime(), authorize: () -> Unit = {},sourceGrant:String?=null): JSONObject = synchronized(lock) {
        authorize()
        require(Regex("[A-Za-z0-9_-]{1,128}").matches(operationId))
        if (storageUnavailable) throw DeviceFault("DEVICE_LEDGER_UNAVAILABLE", "ledger persistence failed; writes disabled until inspected restart")
        val fingerprint = DeviceRpc.sha256(DeviceRpc.canonical(JSONObject().put("method", method).put("params", params).put("bootId", identity.bootId).put("expectedRevision", expectedRevision)).toByteArray())
        val existing = records().optJSONObject(operationId)
        if (existing != null) {
            if (existing.getString("fingerprint") != fingerprint) throw DeviceFault("IDEMPOTENCY_CONFLICT", "device operation id identifies another intent")
            return JSONObject(existing.toString()).put("stateRevision", revision())
        }
        if ((System.nanoTime() - receivedAt) / 1_000_000 >= budgetMs) throw DeviceFault("DEADLINE_EXCEEDED", "expired before device dispatch")
        if (expectedRevision != revision()) throw DeviceFault("STALE_DEVICE_STATE", "device was modified; observe again, do not retry old intent")
        val unresolved = records().keys().asSequence().map { records().getJSONObject(it) }.filter { it.optString("state") == "unknown" && !it.has("resolvedAt") }.toList()
        val securityOnly = method=="early.revoke"||method == "pairings.revoke" || method == "lan.configure" && params.opt("enabled") == false
        if (unresolved.isNotEmpty() && method != "operations.resolve" && !securityOnly) throw DeviceFault("UNKNOWN_EXECUTION", "device has unresolved side effects")
        if (method == "operations.resolve" && (actor != "operator" || !params.optBoolean("acknowledge"))) throw DeviceFault("OPERATOR_REQUIRED", "explicit operator inspection required")
        if (method == "operations.resolve") {
            val old = records().optJSONObject(params.optString("operationId")) ?: throw DeviceFault("OPERATION_NOT_FOUND", "no uncertain operation")
            if (old.optString("state") != "unknown" || old.has("resolvedAt")) throw DeviceFault("INVALID_STATE", "operation is not unresolved unknown")
        } else if(method in(hookCache?.methods?:emptySet()))hookCache!!.validate(method,params)else if (method in (network?.methods ?: emptySet())) network!!.validate(method, params) else backend.validate(method, params)
        if (records().length() >= 1024) throw DeviceFault("LEDGER_FULL", "device ledger needs explicit archival; nothing dispatched")
        val record = JSONObject().put("operationId", operationId).put("method", method).put("bootId", identity.bootId).put("fingerprint", fingerprint)
            .put("actor", actor).put("state", "running").put("mayHaveExecuted", true).put("startedAt", System.currentTimeMillis())
        val candidate = JSONObject(state.toString()).put("revision", revision() + 1)
        candidate.getJSONObject("operations").put(operationId, record)
        val reservation = encoded(candidate) // capacity rejection must not advance in-memory state
        try { files.write(stateFile, reservation) } catch (_: Exception) {
            storageUnavailable = true // rename/fsync may have reached disk; never retry a reservation
            throw DeviceFault("DEVICE_LEDGER_UNAVAILABLE", "reservation persistence failed; no business operation dispatched")
        }
        state = candidate // durable reservation BEFORE side effects
        try {
            val result = if (method == "operations.resolve") {
                val old = records().optJSONObject(params.getString("operationId")) ?: throw DeviceFault("OPERATION_NOT_FOUND", "no uncertain operation")
                if (old.optString("state") != "unknown") throw DeviceFault("INVALID_STATE", "operation is not unknown")
                old.put("resolvedAt", System.currentTimeMillis()); JSONObject().put("ok", true).put("originalState", "unknown")
            } else execute(method, params,sourceGrant)
            val encoded = result.toString().toByteArray()
            record.put("result", if (encoded.size <= 32 * 1024) result else JSONObject().put("omitted", true).put("bytes", encoded.size).put("sha256", DeviceRpc.sha256(encoded)))
            record.put("state", if (result.optBoolean("ok", true)) "succeeded" else "failed")
        } catch (error: DeviceFault) {
            record.put("state", if (error.uncertain) "unknown" else "failed").put("code", error.code).put("uncertain", error.uncertain)
        } catch (_: Exception) {
            record.put("state", "unknown").put("code", "DEVICE_EFFECT_UNCONFIRMED").put("uncertain", true)
        }
        record.put("finishedAt", System.currentTimeMillis())
        try { save() } catch (_: Exception) {
            storageUnavailable = true
            record.put("state", "unknown").put("code", "DEVICE_LEDGER_UNAVAILABLE").put("uncertain", true)
            throw DeviceFault("DEVICE_LEDGER_UNAVAILABLE", "effect dispatched but result persistence is unconfirmed", true)
        }
        JSONObject(record.toString()).put("stateRevision", revision())
    }
    fun managerRead(method: String, params: JSONObject = JSONObject()) = read(method, params)
    fun managerWrite(method: String, params: JSONObject): JSONObject = synchronized(lock) { write(method, params, UUID.randomUUID().toString(), revision(), "operator", DeviceRpc.MAX_BUDGET_MS) }
}
