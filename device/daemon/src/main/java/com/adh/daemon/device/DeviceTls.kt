package com.adh.daemon.device

import java.io.ByteArrayInputStream
import java.io.File
import java.math.BigInteger
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Base64
import java.util.Date
import java.util.TimeZone
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext

/** Public JCA/JSSE only: Android has no supported sun.security.x509 API. Pin the installation SPKI. */
internal object DeviceTls {
    private fun der(tag: Int, data: ByteArray): ByteArray {
        val length = if (data.size < 128) byteArrayOf(data.size.toByte()) else {
            val bytes = BigInteger.valueOf(data.size.toLong()).toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
            byteArrayOf((128 + bytes.size).toByte()) + bytes
        }
        return byteArrayOf(tag.toByte()) + length + data
    }
    private fun seq(vararg data: ByteArray) = der(48, data.fold(byteArrayOf()) { a, b -> a + b })
    private fun oid(hex: String) = der(6, hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
    fun context(identity: DeviceIdentity, files: DeviceFiles): SSLContext {
        val file = File(files.directory, "tls-certificate.der.b64")
        val factory = CertificateFactory.getInstance("X.509")
        if (!file.exists()) {
            val algorithm = seq(oid("2a864886f70d01010b"), der(5, byteArrayOf())) // sha256WithRSAEncryption
            val name = seq(der(49, seq(oid("550403"), der(12, ("ADH-" + identity.deviceId).toByteArray()))))
            val format = SimpleDateFormat("yyyyMMddHHmmss'Z'", java.util.Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }
            val now = System.currentTimeMillis()
            val serial = BigInteger(128, SecureRandom()).abs().add(BigInteger.ONE).toByteArray()
            val extensions = der(163, seq(
                seq(oid("551d13"), der(1, byteArrayOf(-1)), der(4, seq())), // critical basicConstraints CA=false
                seq(oid("551d25"), der(4, seq(oid("2b06010505070301")))), // serverAuth
            ))
            val body = seq(der(160, der(2, byteArrayOf(2))), der(2, serial), algorithm, name,
                seq(der(24, format.format(Date(now - 86_400_000)).toByteArray()), der(24, format.format(Date(now + 315_360_000_000L)).toByteArray())),
                name, Base64.getDecoder().decode(identity.publicKey), extensions)
            val certificate = seq(body, algorithm, der(3, byteArrayOf(0) + identity.sign(body)))
            files.write(file, Base64.getEncoder().encodeToString(certificate))
        }
        check(file.length() <= 16384)
        val certificate = factory.generateCertificate(ByteArrayInputStream(Base64.getDecoder().decode(file.readText()))) as X509Certificate
        certificate.verify(certificate.publicKey); certificate.checkValidity()
        check(com.adh.core.DeviceRpc.sha256(certificate.publicKey.encoded) == identity.fingerprint) { "TLS identity mismatch" }
        val password = CharArray(32) { 'x' }
        val store = KeyStore.getInstance("PKCS12").apply { load(null, null); setKeyEntry("device", identity.tlsKey(), password, arrayOf(certificate)) }
        val manager = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, password) }
        return SSLContext.getInstance("TLS").apply { init(manager.keyManagers, null, SecureRandom()) }
    }
}
