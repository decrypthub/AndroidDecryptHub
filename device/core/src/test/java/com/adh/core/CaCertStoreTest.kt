package com.adh.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.Base64

class CaCertStoreTest {
    @Test
    fun subjectHashMatchesOpenSslOldHash() {
        val cert = CaCertStore.caCertificates(resource("adh-test-ca.der")).single()
        assertEquals("b4b34236", CaCertStore.subjectHashOld(cert))
        assertTrue(cert.subjectX500Principal.name.contains("ADH Test CA"))
    }

    @Test
    fun installKeepsOnlyTheCaAndUsesTheHashFileName() {
        val dir = tempDir()
        val pem = buildString {
            append("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
            append(pemBlock(resource("adh-test-leaf.der")))
            append("\nnot a certificate\n")
            append(pemBlock(resource("adh-test-ca.der")))
        }

        assertEquals(1, CaCertStore.install(dir, pem.toByteArray()))
        assertEquals(1, CaCertStore.install(dir, resource("adh-test-ca.der")))
        val stored = dir.listFiles()?.filter { it.isFile && !it.name.startsWith(".") }.orEmpty()
        assertEquals(listOf("b4b34236.0"), stored.map { it.name })
    }

    @Test
    fun aLeafAloneIsNotInstalled() {
        val dir = tempDir()
        assertEquals(0, CaCertStore.install(dir, resource("adh-test-leaf.der")))
        assertEquals(0, CaCertStore.install(dir, ByteArray(0)))
        assertEquals(-1, CaCertStore.install(dir, ByteArray(CaCertStore.MAX_BUNDLE_BYTES + 1)))
    }

    @Test
    fun collisionUsesTheNextSuffixAndDeleteRejectsTraversal() {
        val dir = tempDir()
        val blocker = File(dir, "b4b34236.0")
        check(dir.mkdirs() || dir.isDirectory)
        blocker.writeBytes(byteArrayOf(1, 2, 3))

        assertEquals(1, CaCertStore.install(dir, resource("adh-test-ca.der")))
        assertTrue(File(dir, "b4b34236.1").isFile)
        assertFalse(CaCertStore.delete(dir, "../scope.json"))
        assertFalse(CaCertStore.delete(dir, "B4B34236.0"))
        assertFalse(CaCertStore.delete(dir, "b4b34236.9"))
        assertTrue(CaCertStore.delete(dir, "b4b34236.1"))
        assertFalse(File(dir, "b4b34236.1").exists())
        assertTrue(blocker.isFile)
    }

    @Test
    fun catalogRoundTripMarksTheCertActive() {
        val dir = tempDir()
        assertEquals(1, CaCertStore.install(dir, resource("adh-test-ca.der")))
        val listed = CaCertStore.list(dir) { it == "b4b34236.0" }
        assertEquals(1, listed.size)
        assertEquals("b4b34236.0", listed[0].fileName)
        assertTrue(listed[0].active)
        assertTrue(listed[0].notAfterMs > listed[0].notBeforeMs)

        val decoded = CaCertStore.decode(CaCertStore.encode(listed))
        assertEquals(listed, decoded)
        assertTrue(CaCertStore.decode("").isEmpty())
        assertTrue(CaCertStore.decode("""[{"f":"not a name","s":"x"}]""").isEmpty())
    }

    private fun pemBlock(der: ByteArray): String {
        val body = Base64.getMimeEncoder(64, byteArrayOf('\n'.code.toByte())).encodeToString(der)
        return "-----BEGIN CERTIFICATE-----\n$body\n-----END CERTIFICATE-----\n"
    }

    private fun resource(name: String): ByteArray =
        checkNotNull(javaClass.classLoader).getResourceAsStream(name)?.use { it.readBytes() }
            ?: error("missing test resource $name")

    private fun tempDir(): File = File(
        System.getProperty("java.io.tmpdir"),
        "adh-cacert-${System.nanoTime()}",
    )
}
