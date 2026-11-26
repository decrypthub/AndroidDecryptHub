package com.adh.sandbox

import android.content.Context
import android.util.Log

// Auto driver for the system + network fixtures: fires each probe on a slow loop right
// after launch so the panel's 系统/网络 tabs fill without anyone tapping a button —
// same role as JavaCrypto.startLiveDriver for the 加解密 tab. Toggle lives on the
// 网络·文件 page.
object AutoProbes {
    private const val TAG = "ADH_SANDBOX"
    @Volatile private var thread: Thread? = null

    @JvmStatic fun running(): Boolean = thread?.isAlive == true
    @JvmStatic fun stop() { thread?.interrupt(); thread = null }

    @JvmStatic
    fun start(ctx: Context) {
        if (running()) return
        val app = ctx.applicationContext
        val t = Thread {
            // The agent still has to dial out and take its arm — rounds fired earlier are lost.
            try { Thread.sleep(4000) } catch (e: InterruptedException) { return@Thread }
            while (!Thread.currentThread().isInterrupted) {
                for ((name, probe) in PROBES) {
                    try {
                        Log.i(TAG, "auto[$name] ${probe(app)}")
                    } catch (t: Throwable) {
                        Log.w(TAG, "auto[$name] fail: ${t.message}")
                    }
                }
                try { Thread.sleep(8000) } catch (e: InterruptedException) { break }
            }
        }.apply { isDaemon = true; name = "adh-auto-probes" }
        thread = t
        t.start()
    }

    private val PROBES: List<Pair<String, (Context) -> String>> = listOf(
        "file" to { FileIO.run() },
        "detect" to { "rc=${Detection.run()}" },
        "java-detect" to { JavaDetect.run(it) },
        "fingerprint" to { Fingerprint.run(it) },
        "net" to { Network.run() },
        "correlated" to { CorrelatedFlow.run() },
    )
}
