package com.adh.daemon

import android.app.KeyguardManager
import android.content.Context
import android.os.PowerManager
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Root-only device power state. Wake/dismiss-keyguard are only used after the user explicitly
 * enables phone automation; a secure credential is never bypassed.
 */
internal object DevicePowerControl {
    private const val TAG = "AdhDevicePower"
    private const val KEYCODE_WAKEUP = "224"

    fun statusJson(context: Context): String {
        val power = context.getSystemService(PowerManager::class.java)
        val keyguard = context.getSystemService(KeyguardManager::class.java)
        return JSONObject()
            .put("interactive", power?.isInteractive ?: false)
            .put("locked", keyguard?.isKeyguardLocked ?: false)
            .toString()
    }

    fun wake(context: Context): Boolean {
        val power = context.getSystemService(PowerManager::class.java)
        if (power?.isInteractive == true) return true
        if (!runCommand("/system/bin/input", "keyevent", KEYCODE_WAKEUP)) return false
        return waitInteractive(power)
    }

    fun dismissKeyguard(context: Context): Boolean {
        val keyguard = context.getSystemService(KeyguardManager::class.java) ?: return false
        if (!keyguard.isKeyguardLocked) return true
        if (!runCommand("/system/bin/wm", "dismiss-keyguard")) return false
        repeat(10) {
            if (!keyguard.isKeyguardLocked) return true
            runCatching { Thread.sleep(100) }
        }
        return !keyguard.isKeyguardLocked
    }

    private fun waitInteractive(power: PowerManager?): Boolean {
        repeat(15) {
            if (power?.isInteractive == true) return true
            runCatching { Thread.sleep(100) }
        }
        return power?.isInteractive == true
    }

    private fun runCommand(vararg args: String): Boolean {
        val process = runCatching {
            ProcessBuilder(*args)
                .directory(File("/"))
                .redirectErrorStream(true)
                .start()
        }.getOrElse {
            Log.w(TAG, "command failed to start: ${args.joinToString(" ")}", it)
            return false
        }
        val output = runCatching { process.inputStream.bufferedReader().use { it.readText() } }.getOrDefault("")
        val finished = runCatching { process.waitFor(5, TimeUnit.SECONDS) }.getOrDefault(false)
        if (!finished) {
            process.destroyForcibly()
            Log.w(TAG, "command timed out: ${args.joinToString(" ")}")
            return false
        }
        val code = runCatching { process.exitValue() }.getOrDefault(-1)
        if (code != 0) Log.w(TAG, "command exit $code: ${args.joinToString(" ")} ${output.take(200)}")
        return code == 0
    }
}
