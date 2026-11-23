package com.adh.sandbox

import android.content.Context
import android.os.Debug
import android.util.Log
import java.io.File
import java.util.concurrent.TimeUnit

// Java-layer detection triggers — the fixtures for the detect_java hook families
// (debug / root / signature / file). Those hooks are armed on demand; the auto-probe
// loop and this object exist so an armed hook always has something to observe.
object JavaDetect {
    private const val TAG = "ADH_SANDBOX"

    @JvmStatic
    fun run(ctx: Context): String {
        val dbg = Debug.isDebuggerConnected()
        val waiting = Debug.waitingForDebugger()
        val info = ctx.packageManager.getPackageInfo(ctx.packageName, 0)
        val filesDir = File("/data/data/${ctx.packageName}/files").exists()
        val exec = try {
            Runtime.getRuntime().exec("/system/bin/echo adh").waitFor(3, TimeUnit.SECONDS)
        } catch (t: Throwable) {
            Log.w(TAG, "JavaDetect exec failed: ${t.message}")
            "fail"
        }
        val summary = "dbg=$dbg waiting=$waiting ver=${info.versionName} files=$filesDir exec=$exec"
        Log.i(TAG, "JavaDetect: $summary")
        return summary
    }
}
