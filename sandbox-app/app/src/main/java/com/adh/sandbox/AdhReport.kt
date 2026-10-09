package com.adh.sandbox

import android.util.Log

// Java-layer crypto capture sink. The interposing JCE provider (AdhSecurity) reports every
// Cipher/Mac/MessageDigest operation here with the FULL context — algorithm, operation,
// key, IV, input, output — which the native agent picks up (Java_..._AdhReport_nReport is
// implemented in libadh_agent) and streams to the console. If the agent isn't loaded the
// native call is absent, so we swallow UnsatisfiedLinkError and keep the app running.
object AdhReport {
    private const val TAG = "ADH_SANDBOX"
    @Volatile private var nativeOk = true

    @JvmStatic
    external fun nReport(algo: String, op: String, key: ByteArray?, iv: ByteArray?, input: ByteArray?, output: ByteArray?)

    @JvmStatic
    fun report(algo: String, op: String, key: ByteArray?, iv: ByteArray?, input: ByteArray?, output: ByteArray?) {
        if (!nativeOk) return
        try { nReport(algo, op, key, iv, input, output) }
        catch (e: UnsatisfiedLinkError) { nativeOk = false; Log.i(TAG, "AdhReport native absent (agent not loaded)") }
        catch (t: Throwable) { /* never let capture break the app */ }
    }
}
