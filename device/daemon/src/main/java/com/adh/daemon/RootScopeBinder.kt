package com.adh.daemon

import android.content.Context
import android.system.Os
import com.adh.core.AdhPaths
import com.adh.core.AdhProtocol
import com.adh.core.CaCertStore
import com.adh.core.HostEndpoint
import com.adh.core.ScopeConfig
import com.adh.core.ScopeJson
import java.io.File
import java.io.FileOutputStream
import java.io.StringReader
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.Properties

internal class RootScopeBinder(
    private val verifier: ManagerCallerVerifier,
    private val context: Context,
) : IAdhScopeService.Stub() {
    override fun getProtocolVersion(): Int {
        verifier.enforce()
        return AdhProtocol.VERSION
    }

    override fun getScopeJson(): String {
        verifier.enforce()
        val file = File(AdhPaths.SCOPE_PATH)
        if (!file.exists()) return ScopeJson.encode(ScopeConfig.EMPTY)
        return ScopeJson.encode(ScopeJson.decode(file.readText()))
    }

    override fun setScopeJson(json: String?): Boolean {
        verifier.enforce()
        if (json.isNullOrBlank()) return false
        val encoded = ScopeJson.encode(ScopeJson.decode(json))
        return runCatching { atomicWrite(File(AdhPaths.SCOPE_PATH), encoded) }.isSuccess
    }

    override fun isModulePresent(): Boolean {
        verifier.enforce()
        return File(AdhPaths.MODULE_DIR).isDirectory || File(AdhPaths.MODULE_PROP).isFile
    }

    override fun isLoaderActive(): Boolean {
        verifier.enforce()
        return File(AdhPaths.LOADER_MARKER).isFile
    }

    override fun getModuleVersion(): String {
        verifier.enforce()
        val raw = runCatching { File(AdhPaths.MODULE_PROP).readText() }.getOrNull() ?: return ""
        val properties = Properties()
        return runCatching {
            properties.load(StringReader(raw))
            properties.getProperty("version").orEmpty()
        }.getOrDefault("")
    }

    override fun listApplications(): String {
        verifier.enforce()
        return PackageCatalog.listJson(context)
    }

    override fun getApplicationIconPng(packageName: String?): ByteArray {
        verifier.enforce()
        return PackageCatalog.iconPng(context, packageName)
    }

    override fun controlPackage(packageName: String?, action: String?): String {
        verifier.enforce()
        return AppProcessControl.run(context, packageName, action)
    }

    override fun getHostEndpoint(): String {
        verifier.enforce()
        val text = runCatching { File(AdhPaths.HOST_ENDPOINT_PATH).readText() }.getOrNull() ?: return ""
        val parsed = HostEndpoint.parse(text) ?: return ""
        return "${parsed.first}:${parsed.second}"
    }

    override fun setHostEndpoint(endpoint: String?): Boolean {
        verifier.enforce()
        val parsed = HostEndpoint.parse(endpoint ?: return false) ?: return false
        val body = HostEndpoint.format(parsed.first, parsed.second) ?: return false
        return runCatching { atomicWrite(File(AdhPaths.HOST_ENDPOINT_PATH), body) }.isSuccess
    }

    override fun listCaCerts(): String {
        verifier.enforce()
        return runCatching {
            CaCertStore.encode(CaCertStore.list(File(AdhPaths.CACERTS_DIR), ::caVisible))
        }.getOrDefault("[]")
    }

    override fun putCaCert(encoded: ByteArray?): Int {
        verifier.enforce()
        if (encoded == null || encoded.size > CaCertStore.MAX_BUNDLE_BYTES) return -1
        val dir = File(AdhPaths.CACERTS_DIR)
        val count = runCatching { CaCertStore.install(dir, encoded) }.getOrElse { return -1 }
        if (count > 0) {
            runCatching {
                Os.chmod(dir.path, 0b111101101)
                dir.listFiles()?.forEach { file ->
                    if (file.isFile) Os.chmod(file.path, 0b110100100)
                }
            }
        }
        return count
    }

    override fun deleteCaCert(fileName: String?): Boolean {
        verifier.enforce()
        return CaCertStore.delete(File(AdhPaths.CACERTS_DIR), fileName)
    }

    override fun rebootDevice(): Boolean {
        verifier.enforce()
        return runCatching {
            Runtime.getRuntime().exec(arrayOf("/system/bin/reboot"))
            true
        }.getOrDefault(false)
    }

    private fun caVisible(name: String): Boolean =
        File("/apex/com.android.conscrypt/cacerts", name).isFile ||
            File("/system/etc/security/cacerts", name).isFile

    private fun atomicWrite(target: File, content: String) {
        target.parentFile?.mkdirs()
        val temp = File(target.parentFile, ".${target.name}.${android.os.Process.myPid()}.tmp")
        try {
            FileOutputStream(temp).use { output ->
                output.write(content.toByteArray(Charsets.UTF_8))
                output.fd.sync()
            }
            try {
                Files.move(
                    temp.toPath(),
                    target.toPath(),
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
            } catch (_: Exception) {
                check(temp.renameTo(target)) { "rename ${temp.path} -> ${target.path} failed" }
            }
            Os.chmod(target.path, 0b110100100)
        } finally {
            temp.delete()
        }
    }

}
