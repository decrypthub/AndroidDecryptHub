package com.adh.manager.data

import org.json.JSONObject
import java.net.HttpURLConnection

/**
 * The published module update manifest. Same URL as `injector/zygisk/module/module.prop` `updateJson`.
 */
data class RemoteUpdate(
    val version: String,
    val versionCode: Int,
    val changelog: String,
)

object UpdateJson {
    const val URL = "https://raw.githubusercontent.com/decrypthub/AndroidDecryptHub/main/injector/zygisk/update.json"

    fun parse(raw: String): RemoteUpdate? {
        val obj = try {
            JSONObject(raw)
        } catch (_: Exception) {
            return null
        }
        val version = obj.optString("version").trim().removePrefix("v")
        val code = obj.optInt("versionCode", -1)
        if (version.isEmpty() || code < 0) return null
        return RemoteUpdate(version, code, obj.optString("changelog").trim())
    }

    /** True when the published manifest is newer than this build. */
    fun isNewer(localVersionCode: Int, remote: RemoteUpdate): Boolean = remote.versionCode > localVersionCode

    fun fetch(url: String = URL, timeoutMs: Int = 8000): RemoteUpdate? {
        val body = runCatching {
            val conn = java.net.URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.instanceFollowRedirects = true
            conn.inputStream.bufferedReader().use { it.readText() }
        }.getOrNull() ?: return null
        return parse(body)
    }
}
