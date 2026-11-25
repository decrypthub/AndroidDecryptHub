package com.adh.daemon

import android.content.Context
import android.system.Os
import com.adh.core.AdhPaths
import com.adh.core.AdhProtocol
import com.adh.core.CaCertStore
import com.adh.core.HostEndpoint
import com.adh.core.PackageControl
import com.adh.daemon.device.DeviceBackend
import com.adh.daemon.device.DeviceFiles
import com.adh.daemon.device.DeviceFault
import com.adh.daemon.device.DeviceArguments
import com.adh.daemon.device.ScopeDocuments
import com.adh.daemon.device.ProcessCatalog
import org.json.JSONObject
import org.json.JSONArray
import android.os.Build
import java.util.Base64
import java.io.File
import java.io.StringReader
import java.util.Properties
import java.security.MessageDigest

internal class AndroidDeviceBackend(
    private val context: Context,
    private val files: DeviceFiles,
) : DeviceBackend {
    private val scopes = ScopeDocuments(File(AdhPaths.SCOPE_PATH), files)
    private val processes = ProcessCatalog()
    override fun validate(method: String, params: JSONObject) {
        DeviceArguments.validate(method, params)
        if (method == "process.control") {
            val pkg = params.getString("package")
            val app = try { context.packageManager.getApplicationInfo(pkg, 0) } catch (_: android.content.pm.PackageManager.NameNotFoundException) { throw DeviceFault("TARGET_NOT_FOUND", "package no longer installed") }
            if (app.flags and (android.content.pm.ApplicationInfo.FLAG_SYSTEM or android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0) throw DeviceFault("TARGET_DENIED", "remote process control is third-party only")
            processes.verify(pkg, params.getJSONArray("expectedProcesses"))
        }
    }
    override fun execute(method: String, params: JSONObject): JSONObject = when (method) {
        "device.info" -> JSONObject().put("model", Build.MODEL).put("manufacturer", Build.MANUFACTURER).put("android", Build.VERSION.RELEASE).put("sdk", Build.VERSION.SDK_INT).put("abi", Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown").put("binderProtocol", AdhProtocol.VERSION)
        "module.status" -> JSONObject().put("present", isModulePresent()).put("loaderActive", isLoaderActive()).put("version", getModuleVersion())
        "scope.get" -> scopes.snapshot()
        "scope.patch" -> scopes.patch(params)
        "scope.replace" -> scopes.replace(params.getJSONObject("document").toString(), params.optString("scopeRevision").takeIf { it.isNotEmpty() })
        "applications.list" -> {
            val snapshot = PackageCatalog.snapshot(context)
            val requestedRevision = params.optLong("revision", 0)
            if (requestedRevision != 0L && requestedRevision != snapshot.revision) throw DeviceFault("STALE_CATALOG", "application catalog changed during pagination; restart the listing")
            val all = JSONArray(snapshot.json); val offset = params.optInt("offset", 0).coerceIn(0, 100000); val limit = params.optInt("limit", 200).coerceIn(1, 500)
            JSONObject().put("applications", JSONArray((offset until minOf(offset + limit, all.length())).map { all.get(it) })).put("total", all.length()).put("revision", snapshot.revision).put("nextOffset", if (offset + limit < all.length()) offset + limit else JSONObject.NULL)
        }
        "processes.list" -> processes.list(params.optString("package"), params.optInt("offset").coerceIn(0, 100000), params.optInt("limit", 200).coerceIn(1, 500))
        "process.control" -> {
            val pkg = params.getString("package"); val action = params.getString("action")
            if (!PackageControl.mayControl(pkg) || !PackageControl.isAction(action)) throw DeviceFault("TARGET_DENIED", "third-party package and known action required")
            val app = context.packageManager.getApplicationInfo(pkg, 0)
            if (app.flags and (android.content.pm.ApplicationInfo.FLAG_SYSTEM or android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0) throw DeviceFault("TARGET_DENIED", "remote process control is third-party only")
            processes.verify(pkg, params.getJSONArray("expectedProcesses"))
            val verdict = controlPackage(pkg, action)
            JSONObject().put("ok", verdict == "ok").put("verdict", verdict).put("mayHaveExecuted", true)
        }
        "host.get" -> JSONObject().put("endpoint", getHostEndpoint())
        "host.set" -> { val endpoint = checkNotNull(HostEndpoint.parse(params.getString("endpoint"))); files.write(File(AdhPaths.HOST_ENDPOINT_PATH), checkNotNull(HostEndpoint.format(endpoint.first, endpoint.second)), 420); JSONObject().put("ok", true) }
        "certificates.list" -> { val rows = JSONArray(listCaCerts()); JSONObject().put("certificates", rows).put("pendingReboot", (0 until rows.length()).any { !rows.getJSONObject(it).optBoolean("a") }) }
        "certificates.put" -> { val count = putCaCert(Base64.getDecoder().decode(params.getString("base64"))); JSONObject().put("ok", count >= 0).put("stored", count).put("pendingReboot", count > 0) }
        "certificates.delete" -> JSONObject().put("ok", deleteCaCert(params.getString("fileName"))).put("pendingReboot", true)
        "applications.icon" -> applicationIcon(params)
        "legacy.icon" -> JSONObject().put("base64", Base64.getEncoder().encodeToString(getApplicationIconPng(params.getString("package"))))
        "legacy.applications" -> JSONObject().put("applications", JSONArray(listApplications()))
        "legacy.process" -> controlPackage(params.getString("package"), params.getString("action")).let { JSONObject().put("verdict", it).put("ok", it == "ok") }
        "legacy.reboot" -> JSONObject().put("ok", rebootDevice())
        else -> throw DeviceFault("UNSUPPORTED_METHOD", "device capability is not implemented")
    }

    private fun applicationIcon(params: JSONObject): JSONObject {
        val pkg = params.getString("package")
        val size = params.optInt("size", 96).coerceIn(24, 256)
        val format = params.optString("format", "png").ifBlank { "png" }
        if (format != "png") throw DeviceFault("UNSUPPORTED_FORMAT", "only png icons are currently supported")
        val bytes = PackageCatalog.iconPng(context, pkg, size)
        if (bytes.isEmpty()) return JSONObject()
            .put("missing", true)
            .put("missingReason", "NO_RENDERABLE_ICON")
            .put("format", format)
            .put("width", size)
            .put("height", size)
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        return JSONObject()
            .put("missing", false)
            .put("base64", Base64.getEncoder().encodeToString(bytes))
            .put("format", format)
            .put("width", size)
            .put("height", size)
            .put("sha256", digest)
    }

    fun isModulePresent(): Boolean {
        return File(AdhPaths.MODULE_DIR).isDirectory || File(AdhPaths.MODULE_PROP).isFile
    }

    fun isLoaderActive(): Boolean {
        return File(AdhPaths.LOADER_MARKER).isFile
    }

    fun getModuleVersion(): String {
        val raw = runCatching { File(AdhPaths.MODULE_PROP).readText() }.getOrNull() ?: return ""
        val properties = Properties()
        return runCatching {
            properties.load(StringReader(raw))
            properties.getProperty("version").orEmpty()
        }.getOrDefault("")
    }

    fun listApplications(): String {
        return PackageCatalog.listJson(context)
    }

    fun getApplicationIconPng(packageName: String?): ByteArray {
        return PackageCatalog.iconPng(context, packageName)
    }

    fun controlPackage(packageName: String?, action: String?): String {
        return AppProcessControl.run(context, packageName, action)
    }

    fun getHostEndpoint(): String {
        val text = runCatching { File(AdhPaths.HOST_ENDPOINT_PATH).readText() }.getOrNull() ?: return ""
        val parsed = HostEndpoint.parse(text) ?: return ""
        return "${parsed.first}:${parsed.second}"
    }

    fun listCaCerts(): String {
        return runCatching {
            CaCertStore.encode(CaCertStore.list(File(AdhPaths.CACERTS_DIR), ::caVisible))
        }.getOrDefault("[]")
    }

    fun putCaCert(encoded: ByteArray?): Int {
        if (encoded == null || encoded.size > CaCertStore.MAX_BUNDLE_BYTES) return -1
        val dir = File(AdhPaths.CACERTS_DIR)
        val count = CaCertStore.install(dir, encoded)
        if (count > 0) {
            Os.chmod(dir.path, 0b111101101)
            dir.listFiles()?.forEach { file ->
                if (file.isFile) Os.chmod(file.path, 0b110100100)
            }
        }
        return count
    }

    fun deleteCaCert(fileName: String?): Boolean {
        return CaCertStore.delete(File(AdhPaths.CACERTS_DIR), fileName)
    }

    fun rebootDevice(): Boolean {
        return runCatching {
            Runtime.getRuntime().exec(arrayOf("/system/bin/reboot"))
            true
        }.getOrDefault(false)
    }

    private fun caVisible(name: String): Boolean =
        File("/apex/com.android.conscrypt/cacerts", name).isFile ||
            File("/system/etc/security/cacerts", name).isFile

}
