package com.adh.core

import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * User-imported CA certificates stored for the boot-time trust-store mount.
 * The filename is OpenSSL `subject_hash_old` (`hhhhhhhh.N`), which is what Conscrypt looks up.
 * Only certificates with Basic Constraints CA are kept. Private keys are never written.
 */
object CaCertStore {
    const val MAX_BUNDLE_BYTES = 256 * 1024
    const val MAX_CERT_BYTES = 16 * 1024

    private val FILE_NAME = Regex("^[0-9a-f]{8}\\.[0-9]{1,2}$")
    private val PEM_CERT = Regex(
        """-+BEGIN CERTIFICATE-+\s*([A-Za-z0-9+/=\r\n]+)-+END CERTIFICATE-+""",
    )

    fun install(dir: File, encoded: ByteArray): Int {
        if (encoded.isEmpty()) return 0
        if (encoded.size > MAX_BUNDLE_BYTES) return -1
        val cas = caCertificates(encoded)
        if (cas.isEmpty()) return 0
        var stored = 0
        var oversized = false
        for (cert in cas) {
            val der = cert.encoded
            if (der.size > MAX_CERT_BYTES) {
                oversized = true
                continue
            }
            val name = allocate(dir, cert, der)
            val dest = File(dir, name)
            if (dest.isFile && dest.readBytes().contentEquals(der)) {
                stored++
                continue
            }
            writeAtomic(dest, der)
            stored++
        }
        if (stored == 0 && oversized) return -1
        return stored
    }

    fun delete(dir: File, fileName: String?): Boolean {
        val name = fileName?.trim().orEmpty()
        if (!FILE_NAME.matches(name)) return false
        val file = File(dir, name)
        val parent = runCatching { file.canonicalFile.parentFile }.getOrNull() ?: return false
        val root = runCatching { dir.canonicalFile }.getOrNull() ?: return false
        if (parent != root) return false
        if (!file.isFile) return false
        return file.delete()
    }

    fun list(dir: File, active: (String) -> Boolean = { false }): List<CaCert> {
        val files = dir.listFiles() ?: return emptyList()
        return files
            .filter { it.isFile && FILE_NAME.matches(it.name) }
            .sortedBy { it.name }
            .mapNotNull { file ->
                val cert = runCatching { caCertificates(file.readBytes()).singleOrNull() }.getOrNull()
                    ?: return@mapNotNull null
                CaCert(
                    fileName = file.name,
                    subject = cert.subjectX500Principal.name,
                    notBeforeMs = cert.notBefore.time,
                    notAfterMs = cert.notAfter.time,
                    active = runCatching { active(file.name) }.getOrDefault(false),
                )
            }
    }

    fun encode(certs: List<CaCert>): String {
        val arr = JSONArray()
        for (cert in certs.sortedBy { it.fileName }) {
            arr.put(
                JSONObject()
                    .put("f", cert.fileName)
                    .put("s", cert.subject)
                    .put("b", cert.notBeforeMs)
                    .put("e", cert.notAfterMs)
                    .put("a", cert.active),
            )
        }
        return arr.toString()
    }

    fun decode(raw: String): List<CaCert> {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return emptyList()
        val arr = JSONArray(trimmed)
        val out = ArrayList<CaCert>(arr.length())
        for (i in 0 until arr.length()) {
            val obj = arr.optJSONObject(i) ?: continue
            val name = obj.optString("f")
            if (!FILE_NAME.matches(name)) continue
            out.add(
                CaCert(
                    fileName = name,
                    subject = obj.optString("s"),
                    notBeforeMs = obj.optLong("b"),
                    notAfterMs = obj.optLong("e"),
                    active = obj.optBoolean("a", false),
                ),
            )
        }
        return out
    }

    /** CA certificates inside a PEM bundle or a single DER encoding. Leaves and keys are dropped. */
    fun caCertificates(encoded: ByteArray): List<X509Certificate> {
        if (encoded.isEmpty() || encoded.size > MAX_BUNDLE_BYTES) return emptyList()
        val factory = CertificateFactory.getInstance("X.509")
        val text = encoded.toString(Charsets.ISO_8859_1)
        val parsed = if (text.contains("-----BEGIN CERTIFICATE-----")) {
            PEM_CERT.findAll(text).mapNotNull { match ->
                runCatching {
                    val der = Base64.getMimeDecoder().decode(match.groupValues[1])
                    factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
                }.getOrNull()
            }.toList()
        } else {
            runCatching {
                factory.generateCertificates(ByteArrayInputStream(encoded))
                    .filterIsInstance<X509Certificate>()
            }.getOrDefault(emptyList())
        }
        return parsed.filter { it.basicConstraints >= 0 }
    }

    /**
     * OpenSSL `X509_NAME_hash_old`: MD5 of the subject Name DER, first four bytes, little-endian.
     */
    internal fun subjectHashOld(cert: X509Certificate): String {
        val digest = MessageDigest.getInstance("MD5").digest(cert.subjectX500Principal.encoded)
        val value = (digest[0].toInt() and 0xff) or
            ((digest[1].toInt() and 0xff) shl 8) or
            ((digest[2].toInt() and 0xff) shl 16) or
            ((digest[3].toInt() and 0xff) shl 24)
        return "%08x".format(value)
    }

    private fun allocate(dir: File, cert: X509Certificate, der: ByteArray): String {
        check(dir.exists() || dir.mkdirs()) { "cannot create ${dir.path}" }
        val hash = subjectHashOld(cert)
        for (n in 0..32) {
            val name = "$hash.$n"
            val file = File(dir, name)
            if (!file.exists()) return name
            if (file.isFile && file.readBytes().contentEquals(der)) return name
        }
        throw IllegalStateException("too many certificates share $hash")
    }

    private fun writeAtomic(target: File, bytes: ByteArray) {
        val parent = target.parentFile ?: throw IllegalStateException("missing parent")
        check(parent.exists() || parent.mkdirs()) { "cannot create ${parent.path}" }
        val temp = File(parent, ".${target.name}.${System.nanoTime()}.tmp")
        try {
            FileChannel.open(
                temp.toPath(),
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING,
            ).use { channel ->
                channel.write(ByteBuffer.wrap(bytes))
                runCatching { channel.force(true) }
            }
            try {
                Files.move(
                    temp.toPath(),
                    target.toPath(),
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
            } catch (_: Exception) {
                if (target.exists() && !target.delete()) {
                    throw IllegalStateException("replace ${target.path} failed")
                }
                check(temp.renameTo(target)) { "rename ${temp.path} -> ${target.path} failed" }
            }
            runCatching {
                Files.setPosixFilePermissions(
                    target.toPath(),
                    setOf(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.GROUP_READ,
                        PosixFilePermission.OTHERS_READ,
                    ),
                )
            }
        } finally {
            if (temp.exists()) temp.delete()
        }
    }
}

data class CaCert(
    val fileName: String,
    val subject: String,
    val notBeforeMs: Long,
    val notAfterMs: Long,
    val active: Boolean,
)
