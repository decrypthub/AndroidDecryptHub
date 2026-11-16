package com.adh.daemon.device

import com.adh.core.DeviceRpc
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.UUID

internal class DevicePairings(private val files: DeviceFiles) {
    private val file = File(files.directory, "pairings.json")
    private var state: JSONObject
    var revoked: (String) -> Unit = {}
    private var unavailable = false
    init {
        check(!file.exists() || file.length() <= 512 * 1024)
        state = if (file.exists()) JSONObject(file.readText()) else JSONObject().put("schemaVersion", 1).put("grants", JSONObject())
        check(state.getInt("schemaVersion") == 1 && state.getJSONObject("grants").length() <= 256)
        for (id in grants().keys()) { val grant = grants().getJSONObject(id); check(id == grant.getString("grantId") && UUID.fromString(id).toString() == id)
            check(DeviceRpc.sha256(key(grant.getString("publicKey")).encoded) == grant.getString("clientId")); permissions(grant.getJSONArray("permissions")) }
    }
    private fun grants() = state.getJSONObject("grants")
    private fun key(encoded: String): java.security.PublicKey {
        require(encoded.length <= 2048)
        val key = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(encoded)))
        require((key as java.security.interfaces.RSAPublicKey).modulus.bitLength() in 2048..4096); return key
    }
    private fun permissions(values: JSONArray): Set<String> {
        require(values.length() in 1..3)
        val result = (0 until values.length()).map { values.getString(it) }.toSet()
        require(result.all { it in setOf("read", "write", "manage") } && "read" in result); return result
    }
    private fun persist(candidate: JSONObject) {
        if (unavailable) throw DeviceFault("AUTH_STORAGE_UNAVAILABLE", "authorization storage requires inspection")
        try { files.write(file, candidate.toString()); state = candidate } catch (_: Exception) { unavailable = true; throw DeviceFault("AUTH_STORAGE_UNAVAILABLE", "authorization persistence unconfirmed", true) }
    }
    @Synchronized fun list(): JSONObject = JSONObject().put("grants", JSONArray(grants().keys().asSequence().map { id ->
        JSONObject(grants().getJSONObject(id).toString()).apply { remove("publicKey") }
    }.toList()))
    @Synchronized fun validateGrant(params: JSONObject) {
        try { key(params.getString("publicKey")); permissions(params.getJSONArray("permissions")); require(params.optString("label").length <= 128) }
        catch (_: Exception) { throw DeviceFault("INVALID_ARGUMENT", "RSA public key, label and explicit read/write/manage permissions required") }
    }
    @Synchronized fun grant(params: JSONObject): JSONObject {
        validateGrant(params)
        if (grants().length() >= 256) throw DeviceFault("PAIRING_LIMIT", "explicit pairing archival required")
        val publicKey = key(params.getString("publicKey")); val clientId = DeviceRpc.sha256(publicKey.encoded)
        if (grants().keys().asSequence().any { val g = grants().getJSONObject(it); g.getString("clientId") == clientId && !g.has("revokedAt") }) throw DeviceFault("PAIRING_EXISTS", "client already paired; inspect existing grant, do not create a duplicate")
        val id = UUID.randomUUID().toString()
        val grant = JSONObject().put("grantId", id).put("clientId", clientId).put("publicKey", Base64.getEncoder().encodeToString(publicKey.encoded))
            .put("permissions", JSONArray(permissions(params.getJSONArray("permissions")).sorted())).put("label", params.optString("label")).put("createdAt", System.currentTimeMillis())
        val candidate = JSONObject(state.toString()); candidate.getJSONObject("grants").put(id, grant); persist(candidate)
        return JSONObject(grant.toString()).apply { remove("publicKey"); put("ok", true) }
    }
    @Synchronized fun revoke(params: JSONObject): JSONObject {
        val id = params.getString("grantId")
        val existing = grants().optJSONObject(id) ?: throw DeviceFault("PAIRING_NOT_FOUND", "grant not found")
        if (!existing.has("revokedAt")) { val candidate = JSONObject(state.toString()); candidate.getJSONObject("grants").getJSONObject(id).put("revokedAt", System.currentTimeMillis()); persist(candidate) }
        revoked(id) // close existing authenticated streams after durable revocation
        return JSONObject().put("ok", true).put("grantId", id).put("revoked", true).put("alreadyDispatchedMayComplete", true)
    }
    @Synchronized fun authorize(grantId: String, method: String) {
        if (unavailable) throw DeviceFault("AUTH_STORAGE_UNAVAILABLE", "authorization storage requires inspection")
        val grant = grants().optJSONObject(grantId) ?: throw DeviceFault("AUTH_REVOKED", "grant unavailable")
        if (grant.has("revokedAt")) throw DeviceFault("AUTH_REVOKED", "grant revoked")
        val needed = if (method in setOf("lan.configure", "pairings.list", "pairings.grant", "pairings.revoke", "operations.resolve")) "manage" else if (method in DeviceRpc.WRITE_METHODS) "write" else "read"
        if (needed !in permissions(grant.getJSONArray("permissions"))) throw DeviceFault("PERMISSION_DENIED", "grant does not permit this capability")
    }
    @Synchronized fun authenticate(auth: JSONObject, message: ByteArray): String {
        try {
            val id = auth.getString("grantId"); authorize(id, "device.info")
            val grant = grants().getJSONObject(id); require(grant.getString("clientId") == auth.getString("clientId"))
            val proof = Base64.getDecoder().decode(auth.getString("signature")); require(proof.size <= 512)
            require(Signature.getInstance("SHA256withRSA").run { initVerify(key(grant.getString("publicKey"))); update(message); verify(proof) }); return id
        } catch (_: Exception) { throw DeviceFault("AUTH_FAILED", "LAN client authentication failed") }
    }
}
