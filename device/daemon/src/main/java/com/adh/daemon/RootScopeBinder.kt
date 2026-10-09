package com.adh.daemon

import android.content.Context
import android.system.Os
import com.adh.core.AdhPaths
import com.adh.core.AdhProtocol
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

    override fun getXposedStatus(): String {
        verifier.enforce()
        return XposedBackend.statusJson()
    }

    override fun setXposedEnabled(enabled: Boolean): Boolean {
        verifier.enforce()
        return XposedBackend.setEnabled(enabled)
    }

    override fun setXposedScope(packages: MutableList<String>?): Boolean {
        verifier.enforce()
        return XposedBackend.setScope(packages ?: emptyList())
    }

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
