package com.adh.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * Framework state of the optional Xposed/LSPosed backend (module W).
 *
 * [present] framework CLI available · [installed] ADH module APK installed · [enabled] module
 * enabled in the framework · [scope] packages the framework injects the module into.
 */
data class XposedStatus(
    val present: Boolean = false,
    val installed: Boolean = false,
    val enabled: Boolean = false,
    val scope: List<String> = emptyList(),
) {
    /** True when ADH can actually drive this backend. */
    val controllable: Boolean get() = present && installed

    companion object {
        val UNAVAILABLE = XposedStatus()
    }
}

/** JSON encode/decode for [XposedStatus] — shared by the Device Daemon and the Manager. */
object XposedStatusJson {
    fun encode(status: XposedStatus): String = JSONObject()
        .put("present", status.present)
        .put("installed", status.installed)
        .put("enabled", status.enabled)
        .put("scope", JSONArray(status.scope.filter { it.isNotBlank() }.sorted()))
        .toString()

    /** Blank → [XposedStatus.UNAVAILABLE]; malformed JSON throws (fail-loud, callers decide). */
    fun decode(raw: String): XposedStatus {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return XposedStatus.UNAVAILABLE
        val obj = try {
            JSONObject(trimmed)
        } catch (e: Exception) {
            throw IllegalArgumentException("invalid xposed status JSON: ${e.message}", e)
        }
        val arr = obj.optJSONArray("scope") ?: JSONArray()
        val scope = linkedSetOf<String>()
        for (i in 0 until arr.length()) {
            val pkg = arr.optString(i).trim()
            if (pkg.isNotEmpty()) scope.add(pkg)
        }
        return XposedStatus(
            present = obj.optBoolean("present", false),
            installed = obj.optBoolean("installed", false),
            enabled = obj.optBoolean("enabled", false),
            scope = scope.toList(),
        )
    }
}