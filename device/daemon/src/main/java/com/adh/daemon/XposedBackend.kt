package com.adh.daemon

import android.util.Log
import com.adh.core.XposedStatus
import com.adh.core.XposedStatusJson
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Optional Xposed/LSPosed backend control (module W).
 *
 * The framework owns the injection itself. ADH only drives the two things the framework keeps
 * in its own database — whether the ADH module is enabled, and which packages it is scoped to —
 * and it does so through the framework's own CLI (`/data/adb/lspd/cli`, the same surface its
 * manager app uses) instead of poking at the sqlite schema.
 *
 * Keeping this on the Device Daemon (root) means the Manager stays the single place where
 * "which apps" is configured: ADH's allowlist is mirrored into the framework scope.
 */
internal object XposedBackend {
    private const val TAG = "AdhXposed"
    private const val CLI = "/data/adb/lspd/cli"
    const val MODULE_PKG = "com.adh.xposed"
    private const val CLI_TIMEOUT_SEC = 25L

    data class CliResult(val ok: Boolean, val out: String)

    fun frameworkPresent(): Boolean = File(CLI).exists()

    /** Compact status JSON: {present,installed,enabled,scope:[pkg,...]}. */
    fun statusJson(): String {
        val present = frameworkPresent()
        var installed = false
        var enabled = false
        val scope = ArrayList<String>()
        if (present) {
            val modules = runCli("modules", "ls", "--json")
            if (modules.ok) {
                runCatching {
                    val data = JSONObject(modules.out).optJSONArray("data") ?: JSONArray()
                    for (i in 0 until data.length()) {
                        val m = data.optJSONObject(i) ?: continue
                        if (m.optString("PACKAGE") == MODULE_PKG) {
                            installed = true
                            enabled = m.optString("STATUS").equals("enabled", ignoreCase = true)
                        }
                    }
                }.onFailure { Log.w(TAG, "modules ls parse failed: ${it.message}") }
            }
            val scoped = runCli("scope", "ls", "--json", MODULE_PKG)
            if (scoped.ok) scope.addAll(parseScope(scoped.out))
        }
        return XposedStatusJson.encode(
            XposedStatus(
                present = present,
                installed = installed,
                enabled = enabled,
                scope = scope,
            ),
        )
    }

    fun isEnabled(): Boolean {
        val status = runCatching { JSONObject(statusJson()) }.getOrNull() ?: return false
        return status.optBoolean("enabled")
    }

    fun setEnabled(enabled: Boolean): Boolean {
        if (!frameworkPresent()) return false
        val verb = if (enabled) "enable" else "disable"
        val result = runCli("modules", verb, MODULE_PKG)
        if (!result.ok) Log.w(TAG, "modules $verb failed: ${result.out.trim()}")
        return runCli("modules", "ls", "--json").let { check ->
            check.ok && runCatching {
                val data = JSONObject(check.out).optJSONArray("data") ?: JSONArray()
                (0 until data.length()).any { i ->
                    val m = data.optJSONObject(i) ?: return@any false
                    m.optString("PACKAGE") == MODULE_PKG &&
                        m.optString("STATUS").equals(if (enabled) "enabled" else "disabled", ignoreCase = true)
                }
            }.getOrDefault(false)
        }
    }

    /**
     * Replace the module's framework scope with [packages] (order-insensitive, one user id per
     * package). The CLI has no "clear" form — `scope set <module>` with no apps throws — so an
     * empty list is expressed as removing the current entries one by one.
     */
    fun setScope(packages: List<String>): Boolean {
        if (!frameworkPresent()) return false
        val desired = packages.map { it.trim() }.filter { it.isNotEmpty() }.distinct().sorted()
        val current = runCli("scope", "ls", "--json", MODULE_PKG).let { result ->
            if (result.ok) parseScope(result.out) else emptyList()
        }.sorted()

        if (desired == current) return true

        var ok = true
        for (entry in current - desired.toSet()) {
            val result = runCli("scope", "rm", MODULE_PKG, "$entry/0")
            if (!result.ok) {
                Log.w(TAG, "scope rm $entry failed: ${result.out.trim()}")
                ok = false
            }
        }
        if (desired.isNotEmpty()) {
            val args = ArrayList<String>(desired.size + 3)
            args.add("scope"); args.add("set"); args.add(MODULE_PKG)
            desired.forEach { args.add("$it/0") }
            val result = runCli(*args.toTypedArray())
            if (!result.ok) {
                Log.w(TAG, "scope set failed: ${result.out.trim()}")
                ok = false
            }
        }
        val after = runCli("scope", "ls", "--json", MODULE_PKG).let { result ->
            if (result.ok) parseScope(result.out) else emptyList()
        }.sorted()
        return ok && after == desired
    }

    private fun parseScope(json: String): List<String> = runCatching {
        val data = JSONObject(json).optJSONArray("data") ?: JSONArray()
        (0 until data.length()).mapNotNull { i ->
            when (val entry = data.opt(i)) {
                is JSONObject -> entry.optString("APP_PACKAGE").takeIf { it.isNotBlank() }
                is String -> entry.substringBefore('/').takeIf { it.isNotBlank() }
                else -> null
            }
        }
    }.getOrElse {
        Log.w(TAG, "scope ls parse failed: ${it.message}")
        emptyList()
    }

    private fun runCli(vararg args: String): CliResult = runCatching {
        // The CLI is a /system/bin/sh script that execs app_process; on some ROMs a root
        // "unshare -m" helper is needed for it to start, so mirror the module launcher's shape.
        val command = ArrayList<String>(args.size + 1)
        command.add(CLI)
        command.addAll(args)
        val process = ProcessBuilder(command)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().use { it.readText() }
        val finished = process.waitFor(CLI_TIMEOUT_SEC, TimeUnit.SECONDS)
        if (!finished) {
            process.destroyForcibly()
            CliResult(false, "$output\n(timed out)")
        } else {
            CliResult(process.exitValue() == 0 && !output.contains("Exception", ignoreCase = true), output)
        }
    }.getOrElse { CliResult(false, "cli failed: ${it.message}") }
}