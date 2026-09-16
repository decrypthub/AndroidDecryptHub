package com.adh.daemon

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.util.Log
import com.adh.core.PackageControl
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Privileged stop/restart of a target app. Runs as uid 0 via the Device Daemon.
 * Needed so Zygisk can re-inject after the user changes injection scope.
 */
internal object AppProcessControl {
    private const val TAG = "AdhAppControl"
    private const val SETTLE_MS = 300L

    fun run(context: Context, packageName: String?, action: String?): String {
        val pkg = packageName?.trim().orEmpty()
        if (!PackageControl.isAction(action) || !PackageControl.mayControl(pkg)) {
            return PackageControl.RESULT_DENIED
        }
        return when (action) {
            PackageControl.ACTION_OPEN ->
                if (open(context, pkg)) PackageControl.RESULT_OK else PackageControl.RESULT_NO_LAUNCHER
            PackageControl.ACTION_STOP ->
                if (stop(context, pkg)) PackageControl.RESULT_OK else PackageControl.RESULT_FAILED
            PackageControl.ACTION_RESTART -> restart(context, pkg)
            else -> PackageControl.RESULT_DENIED
        }
    }

    private fun open(context: Context, pkg: String): Boolean {
        val launch = launchIntent(context, pkg) ?: return false
        return start(context, launch, pkg)
    }

    private fun restart(context: Context, pkg: String): String {
        val launch = launchIntent(context, pkg)
        if (!stop(context, pkg)) return PackageControl.RESULT_FAILED
        if (launch == null) return PackageControl.RESULT_NO_LAUNCHER
        runCatching { Thread.sleep(SETTLE_MS) }
        return if (start(context, launch, pkg)) {
            PackageControl.RESULT_OK
        } else {
            PackageControl.RESULT_FAILED
        }
    }

    private fun stop(context: Context, pkg: String): Boolean {
        val viaAm = runCatching { forceStopViaActivityManager(context, pkg) }.getOrDefault(false)
        if (viaAm) return true
        val viaCmd = runCmd("/system/bin/cmd", "activity", "force-stop", pkg)
        if (!viaCmd) Log.w(TAG, "force-stop failed for $pkg")
        return viaCmd
    }

    private fun start(context: Context, intent: Intent, pkg: String): Boolean {
        val started = runCatching {
            context.startActivity(intent)
            true
        }.getOrDefault(false)
        if (started) return true
        val component = intent.component?.flattenToShortString()
        if (component.isNullOrBlank()) {
            Log.w(TAG, "no launch component for $pkg")
            return false
        }
        return runCmd(
            "/system/bin/cmd", "activity", "start",
            "--user", "0",
            "-n", component,
        )
    }

    private fun launchIntent(context: Context, pkg: String): Intent? {
        val pm = context.packageManager
        val intent = runCatching { pm.getLaunchIntentForPackage(pkg) }.getOrNull()
            ?: runCatching { pm.getLeanbackLaunchIntentForPackage(pkg) }.getOrNull()
        intent?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return intent
    }

    private fun forceStopViaActivityManager(context: Context, pkg: String): Boolean {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager ?: return false
        val method = ActivityManager::class.java.getMethod("forceStopPackage", String::class.java)
        method.invoke(am, pkg)
        return true
    }

    private fun runCmd(vararg args: String): Boolean {
        val proc = runCatching {
            ProcessBuilder(*args)
                .directory(File("/"))
                .redirectErrorStream(true)
                .start()
        }.getOrElse {
            Log.w(TAG, "cmd failed to start: ${args.joinToString(" ")}", it)
            return false
        }
        val output = runCatching {
            proc.inputStream.bufferedReader().use { it.readText() }
        }.getOrDefault("")
        val finished = runCatching { proc.waitFor(8, TimeUnit.SECONDS) }.getOrDefault(false)
        if (!finished) {
            proc.destroyForcibly()
            Log.w(TAG, "cmd timed out: ${args.joinToString(" ")}")
            return false
        }
        val code = runCatching { proc.exitValue() }.getOrDefault(-1)
        if (code != 0) {
            Log.w(TAG, "cmd exit $code: ${args.joinToString(" ")} ${output.take(200)}")
        }
        return code == 0
    }
}
