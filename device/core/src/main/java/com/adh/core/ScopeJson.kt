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
            .put("version", ScopeConfig.CURRENT_VERSION)
            .put("mode", config.mode.ifBlank { ScopeConfig.MODE_ALLOWLIST })
            .put("packages", JSONArray(pkgs))
        val policy = encodePolicy(config, pkgs.toHashSet())
        if (policy.length() > 0) obj.put("policy", policy)
        return obj.toString(2)
    }

    /**
     * Per-package policy, short-keyed (`c` = capture, `d/h/s/a/t/e/y` = families) for the same reason
     * [InstalledAppsJson] is: the same blob crosses Binder. Entries that are DEFAULT or whose
     * package left the scope are dropped, so the section only ever holds non-defaults.
     *
     * A leftover `b` object from the removed SSL-bypass switch is not written back.
     */
    private fun encodePolicy(config: ScopeConfig, inScope: Set<String>): JSONObject {
        val policy = JSONObject()
        for (pkg in config.policy.keys.toSortedSet()) {
            val key = pkg.trim()
            if (key.isEmpty() || key == AdhPaths.MANAGER_PKG || !inScope.contains(key)) continue
            val families = config.familiesFor(key)
            if (families.isDefault) continue
            policy.put(
                key,
                JSONObject().put(
                    "c",
                    JSONObject()
                        .put("d", families.digest)
                        .put("h", families.hmac)
                        .put("s", families.symmetric)
                        .put("a", families.asymmetric)
                        .put("t", families.tls)
                        .put("e", families.aead)
                        .put("y", families.system),
                ),
            )
        }
        return policy
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
        return ScopeConfig(
            version = version,
            mode = mode,
            packages = pkgs,
            policy = decodePolicy(obj, pkgs),
        )
    }

    /**
     * Missing section, missing package, or a missing crypto family key all mean DEFAULT (crypto on,
     * system off) — an old scope file and an old daemon both stay correct by simply not writing the
     * section. Missing `y` means system OFF. A leftover `b` object is ignored.
     */
    private fun decodePolicy(obj: JSONObject, inScope: Set<String>): Map<String, CaptureFamilies> {
        val raw = obj.optJSONObject("policy") ?: return emptyMap()
        val families = linkedMapOf<String, CaptureFamilies>()
        for (pkg in raw.keys()) {
            val key = pkg.trim()
            if (key.isEmpty() || key == AdhPaths.MANAGER_PKG || !inScope.contains(key)) continue
            val entry = raw.optJSONObject(pkg) ?: continue
            entry.optJSONObject("c")?.let { capture ->
                families[key] = CaptureFamilies(
                    digest = capture.optBoolean("d", true),
                    hmac = capture.optBoolean("h", true),
                    symmetric = capture.optBoolean("s", true),
                    asymmetric = capture.optBoolean("a", true),
                    tls = capture.optBoolean("t", true),
                    aead = capture.optBoolean("e", true),
                    system = capture.optBoolean("y", false),
                )
            }
        }
        return families
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
