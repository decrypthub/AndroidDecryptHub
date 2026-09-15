package com.adh.core

import org.json.JSONArray
import org.json.JSONObject

/** Compact installed-app row for the Manager scope UI. Icons stay on the Manager. */
data class InstalledApp(
    val packageName: String,
    val label: String,
    val system: Boolean,
)

/**
 * Binder-safe catalog JSON. Keep this small: never ship ApplicationInfo or icons.
 * Shape: [{"p":"pkg","l":"label","s":false}]
 */
object InstalledAppsJson {
    fun encode(apps: List<InstalledApp>): String {
        val arr = JSONArray()
        for (app in apps) {
            val pkg = app.packageName.trim()
            if (pkg.isEmpty() || HardExcludes.isExcluded(pkg)) continue
            val label = app.label.trim().ifBlank { pkg }.take(80)
            arr.put(
                JSONObject()
                    .put("p", pkg)
                    .put("l", label)
                    .put("s", app.system),
            )
        }
        return arr.toString()
    }

    fun decode(raw: String): List<InstalledApp> {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return emptyList()
        val arr = try {
            JSONArray(trimmed)
        } catch (e: Exception) {
            throw IllegalArgumentException("invalid installed-apps JSON: ${e.message}", e)
        }
        val out = ArrayList<InstalledApp>(arr.length())
        val seen = HashSet<String>()
        for (i in 0 until arr.length()) {
            val obj = arr.optJSONObject(i) ?: continue
            val pkg = obj.optString("p").ifBlank { obj.optString("packageName") }.trim()
            if (pkg.isEmpty() || HardExcludes.isExcluded(pkg) || !seen.add(pkg)) continue
            val label = obj.optString("l").ifBlank { obj.optString("label") }.trim().ifBlank { pkg }
            val system = obj.optBoolean("s", obj.optBoolean("system", false))
            out.add(InstalledApp(pkg, label, system))
        }
        return out
    }
}
