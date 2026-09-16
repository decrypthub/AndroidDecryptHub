package com.adh.daemon

import android.util.Log
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Raw input injection through the system `input` binary, executed by the root Device Daemon.
 *
 * This is the fallback for the one real gap in the accessibility executor: a few Compose UIs
 * (SukiSU Ultra, Vector/LSPosed manager) swallow `AccessibilityService.dispatchGesture` taps
 * without cancelling them, so the gesture reports success while the screen never changes.
 * `input tap` goes through the system input pipeline instead and does reach those windows.
 *
 * Deliberately bounded: this is not a shell. Only absolute-pixel tap/swipe reach a fixed
 * executable with validated, clamped integer arguments.
 */
internal object DeviceInputControl {
    private const val TAG = "AdhDeviceInput"
    private const val CMD_TIMEOUT_MS = 8_000L
    private const val MAX_DURATION_MS = 3_000
    private const val MAX_COORD = 100_000

    fun tap(x: Int, y: Int): Boolean {
        val px = x.coerceIn(0, MAX_COORD)
        val py = y.coerceIn(0, MAX_COORD)
        return runInput("tap", px.toString(), py.toString())
    }

    fun swipe(x1: Int, y1: Int, x2: Int, y2: Int, durationMs: Int): Boolean {
        val duration = durationMs.coerceIn(1, MAX_DURATION_MS)
        return runInput(
            "swipe",
            x1.coerceIn(0, MAX_COORD).toString(),
            y1.coerceIn(0, MAX_COORD).toString(),
            x2.coerceIn(0, MAX_COORD).toString(),
            y2.coerceIn(0, MAX_COORD).toString(),
            duration.toString(),
        )
    }

    private fun runInput(vararg args: String): Boolean {
        val command = arrayOf("/system/bin/input") + args
        val proc = runCatching {
            ProcessBuilder(*command)
                .directory(File("/"))
                .redirectErrorStream(true)
                .start()
        }.getOrElse {
            Log.w(TAG, "input failed to start: ${command.joinToString(" ")}", it)
            return false
        }
        val output = runCatching { proc.inputStream.bufferedReader().use { it.readText() } }.getOrDefault("")
        val finished = runCatching { proc.waitFor(CMD_TIMEOUT_MS, TimeUnit.MILLISECONDS) }.getOrDefault(false)
        if (!finished) {
            proc.destroyForcibly()
            Log.w(TAG, "input timed out: ${command.joinToString(" ")}")
            return false
        }
        val code = runCatching { proc.exitValue() }.getOrDefault(-1)
        if (code != 0) Log.w(TAG, "input exit $code: ${command.joinToString(" ")} ${output.take(200)}")
        return code == 0
    }
}
