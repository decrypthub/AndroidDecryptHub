package com.adh.manager.ipc

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.os.Process
import com.adh.daemon.IAdhScopeService
import com.adh.manager.data.DaemonClient
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class DaemonBinderProvider : ContentProvider() {
    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        if (method != METHOD_PUBLISH) return super.call(method, arg, extras)
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
        private const val EXTRA_BINDER = "daemonBinder"
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
                override fun setScopeJson(json: String): Boolean = service.setScopeJson(json)
                override val listApplicationsJson: String get() = service.listApplications()
                override fun applicationIconPng(packageName: String): ByteArray =
                    service.getApplicationIconPng(packageName) ?: ByteArray(0)
                override fun controlPackage(packageName: String, action: String): String =
                    service.controlPackage(packageName, action).orEmpty()
                override val modulePresent: Boolean get() = service.isModulePresent
                override val loaderActive: Boolean get() = service.isLoaderActive
                override val moduleVersion: String get() = service.moduleVersion.orEmpty()
                override val xposedStatusJson: String get() = service.xposedStatus.orEmpty()
                override fun setXposedEnabled(enabled: Boolean): Boolean =
                    service.setXposedEnabled(enabled)
                override fun setXposedScope(packages: List<String>): Boolean =
                    service.setXposedScope(packages)
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
