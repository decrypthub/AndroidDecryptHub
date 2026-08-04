package com.adh.daemon

import android.app.ActivityManager
import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.util.Log
import com.adh.core.AdhPaths
import java.io.File

object AdhDeviceDaemon {
    private const val TAG = "AdhDeviceDaemon"
    private const val BRIDGE_AUTHORITY = "com.adh.manager.daemon-bridge"
    private const val METHOD_PUBLISH = "publishDaemonBinder"
    private const val EXTRA_BINDER = "daemonBinder"
    private const val PUBLISH_INTERVAL_MS = 1_000L

    @JvmStatic
    fun main(args: Array<String>) {
        Thread.setDefaultUncaughtExceptionHandler { _, error ->
            Log.e(TAG, "fatal daemon error", error)
            runCatching { File(com.adh.core.AdhPaths.DAEMON_READY_MARKER).delete() }
            Process.killProcess(Process.myPid())
        }
        check(Process.myUid() == Process.ROOT_UID) { "ADH Device Daemon must run as root" }
        check(BuildConfig.MANAGER_CERT_SHA256.isNotBlank()) { "manager certificate digest is missing" }

        Looper.prepareMainLooper()
        val context = SystemContext.create()
        val service = RootScopeBinder(ManagerCallerVerifier(context))
        File(AdhPaths.SCOPE_DIR).mkdirs()
        File(AdhPaths.DAEMON_PID_PATH).writeText(Process.myPid().toString())
        File(AdhPaths.DAEMON_READY_MARKER).writeText("1\n")

        val handler = Handler(Looper.getMainLooper())
        var publishedPid = -1
        val publisher = object : Runnable {
            override fun run() {
                val managerPid = findManagerPid(context)
                if (managerPid > 0 && managerPid != publishedPid) {
                    val extras = Bundle().apply { putBinder(EXTRA_BINDER, service) }
                    val published = runCatching {
                        context.contentResolver.call(
                            Uri.parse("content://$BRIDGE_AUTHORITY"),
                            METHOD_PUBLISH,
                            null,
                            extras,
                        )?.getBoolean("accepted") == true
                    }.onFailure { Log.w(TAG, "binder publish failed", it) }.getOrDefault(false)
                    if (published) publishedPid = managerPid
                } else if (managerPid <= 0) {
                    publishedPid = -1
                }
                handler.postDelayed(this, PUBLISH_INTERVAL_MS)
            }
        }
        handler.post(publisher)
        Log.i(TAG, "ADH Device Daemon ready pid=${Process.myPid()}")
        Looper.loop()
    }

    private fun findManagerPid(context: Context): Int {
        val activityManager = context.getSystemService(ActivityManager::class.java) ?: return -1
        val reported = activityManager.runningAppProcesses
            ?.firstOrNull { it.processName == AdhPaths.MANAGER_PKG }
            ?.pid ?: -1
        if (reported > 0) return reported
        return File("/proc").listFiles()
            ?.asSequence()
            ?.filter { it.name.all(Char::isDigit) }
            ?.firstOrNull { processDir ->
                runCatching {
                    File(processDir, "cmdline").readText().trimEnd('\u0000') == AdhPaths.MANAGER_PKG
                }.getOrDefault(false)
            }
            ?.name?.toIntOrNull() ?: -1
    }
}
