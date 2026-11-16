package com.adh.daemon.device

import com.adh.core.DeviceRpc
import org.json.JSONObject
import java.io.File
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.UUID

/** Installation identity survives daemon restart, USB replug and reboot; never derived from serial. */
internal class DeviceIdentity(private val files: DeviceFiles, val bootId: String, val instanceId: String = UUID.randomUUID().toString()) {
    val deviceId: String
    val publicKey: String
    val fingerprint: String
    val token: String
    private val privateKey: java.security.PrivateKey
    init {
        require(Regex("[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}").matches(bootId)) { "a real kernel boot_id is required" }
        files.initialize()
        val identityFile = File(files.directory, "identity.json")
        if (!identityFile.exists()) {
            check(!File(files.directory, "usb-access.json").exists()) { "identity missing while credentials exist; refusing identity reset" }
            val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
            files.write(identityFile, JSONObject().put("schemaVersion", 1).put("deviceId", UUID.randomUUID().toString())
                .put("publicKey", Base64.getEncoder().encodeToString(pair.public.encoded)).put("privateKey", Base64.getEncoder().encodeToString(pair.private.encoded)).toString())
        }
        val identity = JSONObject(identityFile.readText())
        check(identity.getInt("schemaVersion") == 1)
        deviceId = identity.getString("deviceId"); UUID.fromString(deviceId)
        publicKey = identity.getString("publicKey")
        val factory = KeyFactory.getInstance("RSA")
        val pub = factory.generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(publicKey)))
        privateKey = factory.generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(identity.getString("privateKey"))))
        fingerprint = DeviceRpc.sha256(pub.encoded)
        val proof = "identity-key-check".toByteArray()
        val signed = Signature.getInstance("SHA256withRSA").run { initSign(privateKey); update(proof); sign() }
        check(Signature.getInstance("SHA256withRSA").run { initVerify(pub); update(proof); verify(signed) }) { "identity key mismatch" }
        val accessFile = File(files.directory, "usb-access.json")
        if (!accessFile.exists()) {
            val secret = ByteArray(32).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
            files.write(accessFile, JSONObject().put("schemaVersion", 1).put("deviceId", deviceId).put("identityFingerprint", fingerprint).put("token", secret).toString())
        }
        val access = JSONObject(accessFile.readText())
        check(access.getInt("schemaVersion") == 1 && access.getString("deviceId") == deviceId && access.getString("identityFingerprint") == fingerprint) { "USB bootstrap identity mismatch" }
        token = access.getString("token"); check(Regex("[a-f0-9]{64}").matches(token))
    }
    fun authenticated(candidate: String): Boolean = java.security.MessageDigest.isEqual(token.toByteArray(), candidate.toByteArray())
    fun sign(bytes: ByteArray): ByteArray = Signature.getInstance("SHA256withRSA").run { initSign(privateKey); update(bytes); sign() }
    fun tlsKey(): java.security.PrivateKey = privateKey // internal TLS key manager only; never an RPC field
    fun descriptor(): JSONObject = JSONObject().put("deviceId", deviceId).put("bootId", bootId).put("daemonInstanceId", instanceId).put("identityFingerprint", fingerprint)
    fun signHello(requestId: String, nonce: String, info: JSONObject, capabilities: JSONObject): JSONObject {
        val payload = descriptor().put("protocol", DeviceRpc.PROTOCOL).put("requestId", requestId).put("clientNonce", nonce).put("info", info).put("capabilities", capabilities).toString().toByteArray(Charsets.UTF_8)
        val signature = Signature.getInstance("SHA256withRSA").run { initSign(privateKey); update(payload); sign() }
        return JSONObject().put("payload", Base64.getEncoder().encodeToString(payload)).put("signature", Base64.getEncoder().encodeToString(signature)).put("publicKey", publicKey)
    }
}
