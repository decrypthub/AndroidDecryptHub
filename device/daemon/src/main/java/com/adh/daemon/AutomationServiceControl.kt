package com.adh.daemon

import android.content.Context
import android.provider.Settings
import android.util.Log
import com.adh.core.AutomationServiceSettings
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Root-only control of ADH's optional AccessibilityService.
 *
 * This is only called after the user explicitly flips the Manager automation switch. It preserves
 * every other enabled accessibility service and falls back to the platform `settings` binary if
 * direct secure-settings writes are rejected by the ROM.
 */
internal object AutomationServiceControl {
    private const val TAG = "AdhAutomationControl"
    private const val ENABLED_SERVICES = "enabled_accessibility_services"
    private const val ACCESSIBILITY_ENABLED = "accessibility_enabled"

    fun isEnabled(context: Context): Boolean {
        if (AutomationServiceSettings.contains(readSetting(context, ENABLED_SERVICES))) return true
        return AutomationServiceSettings.contains(readBinary(ENABLED_SERVICES))
    }

    fun setEnabled(context: Context, enabled: Boolean): Boolean {
        val next = AutomationServiceSettings.update(readSetting(context, ENABLED_SERVICES), enabled)
        val direct = runCatching {
            Settings.Secure.putString(context.contentResolver, ENABLED_SERVICES, next)
            if (enabled) Settings.Secure.putInt(context.contentResolver, ACCESSIBILITY_ENABLED, 1)
            true
        }.onFailure { Log.w(TAG, "direct secure settings write failed", it) }.getOrDefault(false)

        if (!direct || isEnabled(context) != enabled) {
            if (!writeBinary(ENABLED_SERVICES, next)) return false
            if (enabled) writeBinary(ACCESSIBILITY_ENABLED, "1")
            runCatching { Thread.sleep(150) }
        }
        return isEnabled(context) == enabled
    }

    private fun readSetting(context: Context, key: String): String? =
        runCatching { Settings.Secure.getString(context.contentResolver, key) }.getOrNull()

    private fun readBinary(key: String): String? {
        val process = runCatching {
            ProcessBuilder("/system/bin/settings", "get", "secure", key)
                .directory(File("/"))
                .redirectErrorStream(true)
                .start()
        }.getOrNull() ?: return null
        val output = runCatching { process.inputStream.bufferedReader().use { it.readText() } }.getOrNull()
        val finished = runCatching { process.waitFor(5, TimeUnit.SECONDS) }.getOrDefault(false)
        if (!finished) {
            process.destroyForcibly()
            return null
        }
        return if (runCatching { process.exitValue() }.getOrDefault(-1) == 0) output?.trim() else null
    }

    private fun writeBinary(key: String, value: String): Boolean {
        val process = runCatching {
            ProcessBuilder("/system/bin/settings", "put", "secure", key, value)
                .directory(File("/"))
                .redirectErrorStream(true)
                .start()
        }.getOrElse {
            Log.w(TAG, "settings binary failed to start: $key", it)
            return false
        }
        val output = runCatching { process.inputStream.bufferedReader().use { it.readText() } }.getOrDefault("")
        val finished = runCatching { process.waitFor(5, TimeUnit.SECONDS) }.getOrDefault(false)
        if (!finished) {
            process.destroyForcibly()
            Log.w(TAG, "settings binary timed out: $key")
            return false
        }
        val code = runCatching { process.exitValue() }.getOrDefault(-1)
        if (code != 0) Log.w(TAG, "settings binary exit $code: $key ${output.take(200)}")
        return code == 0
    }
}
