package com.adh.daemon

import com.adh.core.AdhProtocol
import com.adh.daemon.device.DeviceOperations
import org.json.JSONObject
import java.util.Base64

/** Binder authentication stays here; business operations are shared with device RPC. */
internal class RootScopeBinder(private val verifier: ManagerCallerVerifier, private val operations: DeviceOperations) : IAdhScopeService.Stub() {
    private fun read(method: String, params: JSONObject = JSONObject()): JSONObject { verifier.enforce(); return operations.managerRead(method, params) }
    private fun write(method: String, params: JSONObject): JSONObject {
        verifier.enforce()
        val record = operations.managerWrite(method, params)
        check(record.getString("state") == "succeeded") { "device operation ${record.optString("code", "failed")}" }
        return record.getJSONObject("result")
    }
    override fun getProtocolVersion(): Int { verifier.enforce(); return AdhProtocol.VERSION }
    override fun getScopeJson(): String = read("scope.get").getJSONObject("document").toString()
    override fun setScopeJson(json: String?): Boolean { verifier.enforce(); return runCatching { write("scope.replace", JSONObject().put("document", JSONObject(json ?: ""))).getBoolean("ok") }.getOrDefault(false) }
    override fun isModulePresent(): Boolean = read("module.status").getBoolean("present")
    override fun isLoaderActive(): Boolean = read("module.status").getBoolean("loaderActive")
    override fun getModuleVersion(): String = read("module.status").getString("version")
    override fun listApplications(): String = read("legacy.applications").getJSONArray("applications").toString()
    override fun getApplicationIconPng(packageName: String?): ByteArray = Base64.getDecoder().decode(read("legacy.icon", JSONObject().put("package", packageName ?: "")).getString("base64"))
    override fun controlPackage(packageName: String?, action: String?): String { verifier.enforce(); return runCatching { write("legacy.process", JSONObject().put("package", packageName ?: "").put("action", action ?: "")).getString("verdict") }.getOrDefault("failed") }
    override fun getHostEndpoint(): String = read("host.get").getString("endpoint")
    override fun setHostEndpoint(endpoint: String?): Boolean { verifier.enforce(); return runCatching { write("host.set", JSONObject().put("endpoint", endpoint ?: "")).getBoolean("ok") }.getOrDefault(false) }
    override fun listCaCerts(): String = read("certificates.list").getJSONArray("certificates").toString()
    override fun putCaCert(encoded: ByteArray?): Int { verifier.enforce(); return runCatching { write("certificates.put", JSONObject().put("base64", Base64.getEncoder().encodeToString(encoded ?: byteArrayOf()))).getInt("stored") }.getOrDefault(-1) }
    override fun deleteCaCert(fileName: String?): Boolean { verifier.enforce(); return runCatching { write("certificates.delete", JSONObject().put("fileName", fileName ?: "")).getBoolean("ok") }.getOrDefault(false) }
    override fun rebootDevice(): Boolean { verifier.enforce(); return runCatching { write("legacy.reboot", JSONObject()).getBoolean("ok") }.getOrDefault(false) }
    override fun getDeviceInfoJson(): String = read("device.info").toString()
    override fun getDeviceCapabilitiesJson(): String = read("device.capabilities").toString()
    override fun getScopeSnapshotJson(): String = read("scope.get").toString()
    override fun getHookPlanStateJson(packageName:String?):String = read("early.status",JSONObject().put("package",packageName?:"")).toString()
    override fun revokeHookPlanJson(packageName:String?,deploymentId:String?,cacheRevision:Long,stateRevision:Long):String {
        verifier.enforce();return operations.write("early.revoke",JSONObject().put("package",packageName?:"").put("deploymentId",deploymentId?:"").put("expectedCacheRevision",cacheRevision),java.util.UUID.randomUUID().toString(),stateRevision,"operator",60000).toString()
    }
    override fun patchScopePackagesJson(packagesJson:String?,scopeRevision:String?,stateRevision:Long):String {
        verifier.enforce();return operations.write("scope.patch",JSONObject().put("set",org.json.JSONArray(packagesJson?:"[]")).put("scopeRevision",scopeRevision?:""),java.util.UUID.randomUUID().toString(),stateRevision,"operator",60000).toString()
    }
    override fun setScopeVersionedJson(json: String?, scopeRevision: String?, stateRevision: Long): String {
        verifier.enforce()
        return runCatching { operations.write("scope.replace", JSONObject().put("document", JSONObject(json ?: "")).put("scopeRevision", scopeRevision ?: ""), java.util.UUID.randomUUID().toString(), stateRevision, "operator", 60000).toString() }
            .getOrElse { JSONObject().put("state", "failed").put("code", (it as? com.adh.daemon.device.DeviceFault)?.code ?: "DEVICE_ERROR").toString() }
    }
}
