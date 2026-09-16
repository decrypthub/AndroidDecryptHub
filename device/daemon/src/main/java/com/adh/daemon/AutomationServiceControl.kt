package com.adh.daemon

import android.content.Context
import android.provider.Settings
import android.system.Os
import android.util.Log
import com.adh.core.AdhPaths
import com.adh.core.AutomationServiceSettings
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Root-only control of ADH's optional AccessibilityService.
 *
 * The Manager switch is the only thing that writes the durable opt-in marker. When the marker is
 * present, the Device Daemon may repair the service after an OEM/OS cleanup without asking again.
 * The user can always turn the switch off, which removes the marker and the service entry.
 */
internal object AutomationServiceControl {
    private const val TAG = "AdhAutomationControl"
    private const val ENABLED_SERVICES = "enabled_accessibility_services"
    private const val ACCESSIBILITY_ENABLED = "accessibility_enabled"

    fun isEnabled(context: Context): Boolean {
        if (AutomationServiceSettings.contains(readSetting(context, ENABLED_SERVICES))) return true
        return AutomationServiceSettings.contains(readBinary(ENABLED_SERVICES))
    }

    fun desiredEnabled(): Boolean = runCatching { File(AdhPaths.AUTOMATION_ENABLED_MARKER).isFile }.getOrDefault(false)

    fun setEnabled(context: Context, enabled: Boolean): Boolean {
        if (enabled) writeMarker() else deleteMarker()
        if (!applyEnabled(context, enabled)) return false
        return isEnabled(context) == enabled
    }

    fun ensureEnabled(context: Context): Boolean {
        if (!desiredEnabled() || isEnabled(context)) return true
        Log.i(TAG, "automation service missing but user opt-in is present; repairing")
        return applyEnabled(context, true)
    }

    private fun applyEnabled(context: Context, enabled: Boolean): Boolean {
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

    private fun writeMarker() {
        runCatching {
            val marker = File(AdhPaths.AUTOMATION_ENABLED_MARKER)
            marker.parentFile?.mkdirs()
            marker.writeText("1\n")
            Os.chmod(marker.path, 0b110100100)
        }.onFailure { Log.w(TAG, "failed to persist automation opt-in marker", it) }
    }

    private fun deleteMarker() {
        runCatching { File(AdhPaths.AUTOMATION_ENABLED_MARKER).delete() }
            .onFailure { Log.w(TAG, "failed to delete automation opt-in marker", it) }
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
