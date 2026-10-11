package com.adh.daemon

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.util.Log
import com.adh.core.AdhPaths
import java.io.File

object AdhDeviceDaemon {
    private const val TAG = "AdhDeviceDaemon"
    private const val PUBLISH_INTERVAL_MS = 1_000L

    @JvmStatic
    fun main(args: Array<String>) {
        // app_process invokes main([Ljava/lang/String;)V, so the parameter stays even though the
        // daemon takes no arguments.
        Thread.setDefaultUncaughtExceptionHandler { _, error ->
            Log.e(TAG, "fatal daemon error", error)
            runCatching { File(com.adh.core.AdhPaths.DAEMON_READY_MARKER).delete() }
            Process.killProcess(Process.myPid())
        }
        check(Process.myUid() == Process.ROOT_UID) { "ADH Device Daemon must run as root" }
        check(BuildConfig.MANAGER_CERT_SHA256.isNotBlank()) { "manager certificate digest is missing" }

        Looper.prepareMainLooper()
        val context = SystemContext.create()
        val service = RootScopeBinder(ManagerCallerVerifier(context), context)
        File(AdhPaths.SCOPE_DIR).mkdirs()
        File(AdhPaths.DAEMON_PID_PATH).writeText(Process.myPid().toString())
        File(AdhPaths.DAEMON_READY_MARKER).writeText("1\n")
        val handler = Handler(Looper.getMainLooper())
        var publishedPid = -1
        val publisher = object : Runnable {
            override fun run() {
                val managerPid = findManagerPid()
                if (managerPid > 0 && managerPid != publishedPid) {
                    val published = ExternalProviderPublisher.publish(service)
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

    private fun findManagerPid(): Int = File("/proc").listFiles()
        ?.asSequence()
        ?.filter { it.name.all(Char::isDigit) }
        ?.firstOrNull { processDir ->
            runCatching {
                File(processDir, "cmdline").readText().trimEnd('\u0000') == AdhPaths.MANAGER_PKG
            }.getOrDefault(false)
        }
        ?.name?.toIntOrNull() ?: -1
}
