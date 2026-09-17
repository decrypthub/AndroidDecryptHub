package com.adh.daemon

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.os.SystemClock
import android.util.Log
import com.adh.core.AdhPaths
import java.io.File
import kotlin.system.exitProcess

object AdhDeviceDaemon {
    private const val TAG = "AdhDeviceDaemon"
    private const val PUBLISH_INTERVAL_MS = 1_000L
    private const val AUTOMATION_ENSURE_INTERVAL_MS = 5_000L

    @JvmStatic
    fun main(args: Array<String>) {
        // Root-only one-shot CLI for the optional Xposed backend: it runs exactly the code paths
        // the AIDL surface calls, so operators and tools/verify_v32_backend_control.sh can drive
        // and inspect it without the Manager UI (and without a reboot).
        when (args.firstOrNull()) {
            "--xposed-status" -> { requireRoot(); println(XposedBackend.statusJson()); return }
            "--xposed-enable" -> { requireRoot(); exitProcess(if (XposedBackend.setEnabled(true)) 0 else 1) }
            "--xposed-disable" -> { requireRoot(); exitProcess(if (XposedBackend.setEnabled(false)) 0 else 1) }
            "--xposed-scope" -> { requireRoot(); exitProcess(if (XposedBackend.setScope(args.drop(1))) 0 else 1) }
            "--automation-status" -> {
                requireRoot()
                Looper.prepareMainLooper()
                val context = SystemContext.create()
                println(if (AutomationServiceControl.isEnabled(context)) "enabled" else "disabled")
                return
            }
            "--automation-enable" -> {
                requireRoot()
                Looper.prepareMainLooper()
                val context = SystemContext.create()
                exitProcess(if (AutomationServiceControl.setEnabled(context, true)) 0 else 1)
            }
            "--automation-disable" -> {
                requireRoot()
                Looper.prepareMainLooper()
                val context = SystemContext.create()
                exitProcess(if (AutomationServiceControl.setEnabled(context, false)) 0 else 1)
            }
            "--automation-ensure" -> {
                requireRoot()
                Looper.prepareMainLooper()
                val context = SystemContext.create()
                exitProcess(if (AutomationServiceControl.ensureEnabled(context)) 0 else 1)
            }
            "--device-status" -> {
                requireRoot()
                Looper.prepareMainLooper()
                println(DevicePowerControl.statusJson(SystemContext.create()))
                return
            }
            "--device-wake" -> {
                requireRoot()
                Looper.prepareMainLooper()
                exitProcess(if (DevicePowerControl.wake(SystemContext.create())) 0 else 1)
            }
            "--device-dismiss-keyguard" -> {
                requireRoot()
                Looper.prepareMainLooper()
                exitProcess(if (DevicePowerControl.dismissKeyguard(SystemContext.create())) 0 else 1)
            }
            "--input-tap" -> {
                requireRoot()
                val x = args.getOrNull(1)?.toIntOrNull() ?: exitProcess(2)
                val y = args.getOrNull(2)?.toIntOrNull() ?: exitProcess(2)
                exitProcess(if (DeviceInputControl.tap(x, y)) 0 else 1)
            }
            "--volume-status" -> {
                requireRoot()
                Looper.prepareMainLooper()
                println(DeviceAudioControl.statusJson(SystemContext.create()))
                return
            }
            "--volume-set" -> {
                requireRoot()
                Looper.prepareMainLooper()
                val stream = args.getOrNull(1) ?: exitProcess(2)
                val index = args.getOrNull(2)?.toIntOrNull() ?: exitProcess(2)
                exitProcess(if (DeviceAudioControl.setVolume(SystemContext.create(), stream, index)) 0 else 1)
            }
            "--input-swipe" -> {
                requireRoot()
                val values = args.drop(1).mapNotNull { it.toIntOrNull() }
                if (values.size < 5) exitProcess(2)
                exitProcess(if (DeviceInputControl.swipe(values[0], values[1], values[2], values[3], values[4])) 0 else 1)
            }
        }
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
        runCatching { AutomationServiceControl.ensureEnabled(context) }
            .onFailure { Log.w(TAG, "initial automation service ensure failed", it) }

        val handler = Handler(Looper.getMainLooper())
        var publishedPid = -1
        var lastAutomationEnsure = 0L
        val publisher = object : Runnable {
            override fun run() {
                val now = SystemClock.uptimeMillis()
                if (now - lastAutomationEnsure >= AUTOMATION_ENSURE_INTERVAL_MS) {
                    lastAutomationEnsure = now
                    runCatching { AutomationServiceControl.ensureEnabled(context) }
                        .onFailure { Log.w(TAG, "automation service ensure failed", it) }
                }
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

    private fun requireRoot() {
        check(Process.myUid() == Process.ROOT_UID) { "ADH Device Daemon CLI must run as root" }
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
