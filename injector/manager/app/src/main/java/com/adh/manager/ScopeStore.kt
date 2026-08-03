package com.adh.manager

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/** Device-side allowlist shared with the Zygisk module. */
object ScopeStore {
    const val SCOPE_PATH = "/data/adb/adh/scope.json"
    const val MODULE_DIR = "/data/adb/modules/adh"
    const val MANAGER_PKG = "com.adh.manager"

    data class Scope(val packages: MutableSet<String> = linkedSetOf())

    fun modulePresent(): Boolean = rootExists(MODULE_DIR) || rootExists("$MODULE_DIR/module.prop")

    fun load(): Scope {
        val raw = rootRead(SCOPE_PATH) ?: return Scope()
        return try {
            val obj = JSONObject(raw)
            val arr = obj.optJSONArray("packages") ?: JSONArray()
            val pkgs = linkedSetOf<String>()
            for (i in 0 until arr.length()) {
                val p = arr.optString(i)
                if (p.isNotBlank() && p != MANAGER_PKG) pkgs.add(p)
            }
            Scope(pkgs)
        } catch (_: Exception) {
            Scope()
        }
    }

    fun save(scope: Scope): Result<Unit> {
        scope.packages.remove(MANAGER_PKG)
        val obj = JSONObject()
            .put("version", 1)
            .put("mode", "allowlist")
            .put("packages", JSONArray(scope.packages.toList().sorted()))
        val json = obj.toString(2)
        val b64 = Base64.encodeToString(json.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
        val script =
            "mkdir -p /data/adb/adh && echo '$b64' | base64 -d > '$SCOPE_PATH' && chmod 644 '$SCOPE_PATH' && echo OK"
        return rootExec(script).map { }
    }

    private fun rootExists(path: String): Boolean {
        val r = rootExec("test -e '$path' && echo YES || echo NO")
        return r.getOrNull()?.contains("YES") == true || File(path).exists()
    }

    private fun rootRead(path: String): String? {
        try {
            val f = File(path)
            if (f.canRead()) return f.readText()
        } catch (_: Exception) {
        }
        return rootExec("cat '$path' 2>/dev/null").getOrNull()?.takeIf { it.isNotBlank() }
    }

    private fun rootExec(script: String): Result<String> {
        return try {
            val pb = ProcessBuilder("su", "-c", script)
            pb.redirectErrorStream(true)
            val p = pb.start()
            val out = BufferedReader(InputStreamReader(p.inputStream)).readText()
            val code = p.waitFor()
            if (code == 0) Result.success(out.trim())
            else Result.failure(IllegalStateException("su exit $code: $out"))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
