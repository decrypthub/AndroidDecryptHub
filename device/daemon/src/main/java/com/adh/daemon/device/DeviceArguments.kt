package com.adh.daemon.device

import com.adh.core.HostEndpoint
import com.adh.core.CaCertStore
import com.adh.core.PackageControl
import org.json.JSONObject
import java.util.Base64

/** Pure, effect-free validation used before journal reservation or Android dispatch. */
internal object DeviceArguments {
    fun validate(method: String, params: JSONObject) {
        try {
            when (method) {
                "scope.patch", "scope.replace" -> {
                    if (method == "scope.replace") packages(params.getJSONObject("document"), "packages")
                    else for (key in listOf("set", "add", "remove")) if (params.has(key)) packages(params, key)
                }
                "process.control", "legacy.process" -> {
                    require(PackageControl.mayControl(params.getString("package")) && PackageControl.isAction(params.getString("action")))
                    if (method == "process.control") {
                        val rows = params.getJSONArray("expectedProcesses"); require(rows.length() <= 128)
                        for (n in 0 until rows.length()) { val row = rows.getJSONObject(n)
                            require(row.getInt("pid") > 0 && row.getInt("uid") >= 0 && Regex("[0-9]{1,24}").matches(row.getString("starttimeTicks")))
                        }
                    }
                }
                "host.set" -> require(HostEndpoint.parse(params.getString("endpoint")) != null)
                "certificates.put" -> { val bytes = Base64.getDecoder().decode(params.getString("base64")); require(bytes.size <= CaCertStore.MAX_BUNDLE_BYTES) }
                "certificates.delete" -> require(Regex("[0-9a-f]{8}\\.[0-9]{1,2}").matches(params.getString("fileName")))
            }
        } catch (_: Exception) { throw DeviceFault("INVALID_ARGUMENT", "invalid device operation parameters; nothing dispatched") }
    }
    private fun packages(params: JSONObject, key: String) {
        val values = params.getJSONArray(key); require(values.length() <= 4096)
        for (n in 0 until values.length()) { val pkg = values.getString(n)
            require(Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+").matches(pkg) && pkg != "com.adh.manager" && pkg != "com.adh.daemon")
        }
    }
}
