package com.adh.manager.ipc

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.os.Process
import android.util.Base64
import com.adh.daemon.IAdhScopeService
import com.adh.manager.data.DaemonClient
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class DaemonBinderProvider : ContentProvider() {
    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        if (method == METHOD_PUBLISH) {
            if (Binder.getCallingUid() != Process.ROOT_UID) {
                throw SecurityException("only the root ADH Device Daemon may publish a binder")
            }
            val binder = extras?.getBinder(EXTRA_BINDER)
                ?: throw IllegalArgumentException("daemon binder is missing")
            check(binder.interfaceDescriptor == IAdhScopeService.DESCRIPTOR) {
                "unexpected daemon binder descriptor"
            }
            install(binder)
            return Bundle().apply { putBoolean("accepted", true) }
        }
        if (method == METHOD_APP_CATALOG || method == METHOD_APP_ICON) {
            val caller = Binder.getCallingUid()
            if (caller != Process.ROOT_UID && caller != Process.SHELL_UID) {
                throw SecurityException("only the PC ADB shell may read the app catalog")
            }
            val client = awaitClient(CONNECT_TIMEOUT_MS)
                ?: return Bundle().apply { putString("error", "ADH Device Daemon is unavailable") }
            return when (method) {
                METHOD_APP_CATALOG -> {
                    val json = client.listApplicationsJson
                    Bundle().apply { putString("base64", Base64.encodeToString(json.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)) }
                }
                else -> {
                    val bytes = client.applicationIconPng(arg ?: "")
                    if (bytes.isEmpty()) return Bundle().apply { putString("error", "no icon") }
                    Bundle().apply { putString("base64", Base64.encodeToString(bytes, Base64.NO_WRAP)) }
                }
            }
        }
        return super.call(method, arg, extras)
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0

    companion object {
        private const val METHOD_PUBLISH = "publishDaemonBinder"
        private const val METHOD_APP_CATALOG = "appCatalog"
        private const val METHOD_APP_ICON = "appIcon"
        private const val EXTRA_BINDER = "daemonBinder"
        private const val CONNECT_TIMEOUT_MS = 3_000L
        private val client = AtomicReference<DaemonClient?>()
        @Volatile private var ready = CountDownLatch(1)

        fun awaitClient(timeoutMs: Long): DaemonClient? {
            client.get()?.let { return it }
            ready.await(timeoutMs, TimeUnit.MILLISECONDS)
            return client.get()
        }

        private fun install(binder: IBinder) {
            val service = IAdhScopeService.Stub.asInterface(binder)
            val adapter = object : DaemonClient {
                override val protocolVersion: Int get() = service.protocolVersion
                override val scopeJson: String get() = service.scopeJson
                override val scopeSnapshotJson:String get()=service.scopeSnapshotJson
                override fun patchScopePackages(packagesJson:String,scopeRevision:String,stateRevision:Long):String=service.patchScopePackagesJson(packagesJson,scopeRevision,stateRevision)
                override fun hookPlanState(packageName:String):String=service.getHookPlanStateJson(packageName)
                override fun revokeHookPlan(packageName:String,deploymentId:String,cacheRevision:Long,stateRevision:Long):String=service.revokeHookPlanJson(packageName,deploymentId,cacheRevision,stateRevision)
                override fun setScopeJson(json: String): Boolean = service.setScopeJson(json)
                override val listApplicationsJson: String get() = service.listApplications()
                override fun applicationIconPng(packageName: String): ByteArray =
                    service.getApplicationIconPng(packageName) ?: ByteArray(0)
                override fun controlPackage(packageName: String, action: String): String =
                    service.controlPackage(packageName, action).orEmpty()
                override fun getHostEndpoint(): String = service.hostEndpoint.orEmpty()
                override fun setHostEndpoint(endpoint: String): Boolean = service.setHostEndpoint(endpoint)
                override fun listCaCertsJson(): String = service.listCaCerts().orEmpty()
                override fun putCaCert(encoded: ByteArray): Int = service.putCaCert(encoded)
                override fun deleteCaCert(fileName: String): Boolean = service.deleteCaCert(fileName)
                override fun rebootDevice(): Boolean = service.rebootDevice()
                override val modulePresent: Boolean get() = service.isModulePresent
                override val loaderActive: Boolean get() = service.isLoaderActive
                override val moduleVersion: String get() = service.moduleVersion.orEmpty()
            }
            runCatching {
                binder.linkToDeath({
                    client.compareAndSet(adapter, null)
                    ready = CountDownLatch(1)
                }, 0)
            }
            client.set(adapter)
            ready.countDown()
        }
    }
}
