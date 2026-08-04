package com.adh.daemon

import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.os.Process
import android.util.Log

internal object ExternalProviderPublisher {
    private const val TAG = "AdhDeviceDaemon"
    private const val AUTHORITY = "com.adh.manager.daemon-bridge"
    private const val METHOD_PUBLISH = "publishDaemonBinder"
    private const val EXTRA_BINDER = "daemonBinder"

    fun publish(binder: IBinder): Boolean = runCatching {
        val activityManagerClass = Class.forName("android.app.ActivityManager")
        val activityManager = activityManagerClass.getDeclaredMethod("getService").apply {
            isAccessible = true
        }.invoke(null)
        val getProvider = activityManager.javaClass.methods.first {
            it.name == "getContentProviderExternal" && it.parameterCount == 4
        }.apply { isAccessible = true }
        val holder = getProvider.invoke(activityManager, AUTHORITY, 0, null, AUTHORITY)
            ?: return@runCatching false
        val provider = holder.javaClass.getDeclaredField("provider").apply {
            isAccessible = true
        }.get(holder) ?: return@runCatching false

        try {
            val expectedArity = when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> 5
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.R -> 6
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q -> 5
                else -> 4
            }
            val call = provider.javaClass.methods.first {
                it.name == "call" && it.parameterCount == expectedArity
            }.apply {
                isAccessible = true
            }
            val extras = Bundle().apply { putBinder(EXTRA_BINDER, binder) }
            val reply = call.invoke(provider, *callArguments(call.parameterCount, extras)) as? Bundle
            reply?.getBoolean("accepted") == true
        } finally {
            removeExternalProvider(activityManager)
        }
    }.onFailure { Log.w(TAG, "binder publish failed", it) }.getOrDefault(false)

    private fun callArguments(parameterCount: Int, extras: Bundle): Array<Any?> = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && parameterCount == 5 -> arrayOf(
            newAttributionSource(),
            AUTHORITY,
            METHOD_PUBLISH,
            null,
            extras,
        )
        parameterCount == 6 -> arrayOf(null, null, AUTHORITY, METHOD_PUBLISH, null, extras)
        parameterCount == 5 -> arrayOf(null, AUTHORITY, METHOD_PUBLISH, null, extras)
        parameterCount == 4 -> arrayOf(null, METHOD_PUBLISH, null, extras)
        else -> error("unsupported IContentProvider.call arity=$parameterCount")
    }

    private fun newAttributionSource(): Any {
        val builderClass = Class.forName("android.content.AttributionSource\$Builder")
        val builder = builderClass.getConstructor(Int::class.javaPrimitiveType).newInstance(Process.myUid())
        return builderClass.getMethod("build").invoke(builder)
    }

    private fun removeExternalProvider(activityManager: Any) {
        runCatching {
            val remove = activityManager.javaClass.methods.first {
                it.name == "removeContentProviderExternal"
            }.apply { isAccessible = true }
            val args = when (remove.parameterCount) {
                2 -> arrayOf(AUTHORITY, null)
                3 -> arrayOf(AUTHORITY, null, 0)
                else -> return
            }
            remove.invoke(activityManager, *args)
        }.onFailure { Log.w(TAG, "remove external provider failed", it) }
    }
}
