package com.adh.daemon

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.util.Log
import com.adh.core.AdhPaths
import java.io.File
import com.adh.daemon.device.DeviceFiles
import com.adh.daemon.device.DeviceIdentity
import com.adh.daemon.device.DeviceOperations
import com.adh.daemon.device.LocalDeviceRpcServer
import android.system.Os

object AdhDeviceDaemon {
    private const val TAG = "AdhDeviceDaemon"
    private const val PUBLISH_INTERVAL_MS = 1_000L
    private var rpc: LocalDeviceRpcServer? = null
    private var domainLock: java.nio.channels.FileLock? = null

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
        val files = DeviceFiles(File(AdhPaths.DEVICE_RPC_DIR), { file, mode -> Os.chmod(file.path, mode) }, { directory ->
            val fd = Os.open(directory.path, android.system.OsConstants.O_RDONLY, 0)
            try { Os.fsync(fd) } finally { Os.close(fd) }
        })
        files.initialize()
        val lockChannel = java.io.RandomAccessFile(File(files.directory, "daemon.lock"), "rw").channel
        domainLock = checkNotNull(lockChannel.tryLock()) { "another device domain instance owns this installation" }
        val identity = DeviceIdentity(files, File("/proc/sys/kernel/random/boot_id").readText().trim())
        val operations = DeviceOperations(identity, files, AndroidDeviceBackend(context, files))
        val service = RootScopeBinder(ManagerCallerVerifier(context), operations)
        // RPC availability never tears down the pre-existing authenticated Binder service.
        runCatching { rpc = LocalDeviceRpcServer(operations) }.onFailure { Log.e(TAG, "USB RPC unavailable; Binder remains available", it) }
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
