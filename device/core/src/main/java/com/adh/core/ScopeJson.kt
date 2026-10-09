package com.adh.core

import org.json.JSONArray
import org.json.JSONObject

/** JSON encode/decode for [ScopeConfig]. Fail-loud parse → [ScopeConfig.EMPTY] only on blank input. */
object ScopeJson {
    fun encode(config: ScopeConfig): String {
        val pkgs = config.packages
            .filter { it.isNotBlank() && it != AdhPaths.MANAGER_PKG }
            .sorted()
        val obj = JSONObject()
            .put("version", config.version)
            .put("mode", config.mode.ifBlank { ScopeConfig.MODE_ALLOWLIST })
            .put("packages", JSONArray(pkgs))
        return obj.toString(2)
    }

    /**
     * Parse scope JSON. Blank → EMPTY.
     * Malformed JSON throws [IllegalArgumentException] (fail-loud; callers decide).
     */
    fun decode(raw: String): ScopeConfig {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return ScopeConfig.EMPTY
        val obj = try {
            JSONObject(trimmed)
        } catch (e: Exception) {
            throw IllegalArgumentException("invalid scope JSON: ${e.message}", e)
        }
        val version = obj.optInt("version", 1)
        val mode = obj.optString("mode", ScopeConfig.MODE_ALLOWLIST).ifBlank { ScopeConfig.MODE_ALLOWLIST }
        val arr = obj.optJSONArray("packages") ?: JSONArray()
        val pkgs = linkedSetOf<String>()
        for (i in 0 until arr.length()) {
            val p = arr.optString(i).trim()
            if (p.isNotEmpty() && p != AdhPaths.MANAGER_PKG) pkgs.add(p)
        }
        return ScopeConfig(version = version, mode = mode, packages = pkgs)
    }

    /** Soft parse for UI: malformed → EMPTY (and optional onError). */
    fun decodeOrEmpty(raw: String, onError: ((Exception) -> Unit)? = null): ScopeConfig {
        return try {
            decode(raw)
        } catch (e: Exception) {
            onError?.invoke(e)
            ScopeConfig.EMPTY
        }
    }
}
