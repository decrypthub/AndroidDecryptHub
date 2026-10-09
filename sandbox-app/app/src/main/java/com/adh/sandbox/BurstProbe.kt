package com.adh.sandbox

import android.util.Log
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// WS-C high-rate capture driver. Invoked from OUTSIDE the agent — adhd's trigger passes the
// class name as a parameter; the agent has ZERO knowledge of this class (no hardcoded symbol).
// run() spawns a background daemon thread that performs BURST AES/CBC encryptions as fast as
// possible; each routes through Conscrypt → BoringSSL EVP_CipherUpdate, flooding the agent's
// capture ring far faster than the 1.5s drain can keep up. That lets the ring's honest
// accounting (seq / dropped / backlog, and the invariant emitted+backlog+dropped==seq) be
// verified — where the old fixed g_caps[64] would have silently dropped ~everything.
object BurstProbe {
    private const val TAG = "ADH_BURST"
    const val BURST = 20000
    @Volatile private var running = false
    @Volatile var lastN = 0

    @JvmStatic
    fun run(): String {
        if (running) return "ADH_BURST_BUSY"
        running = true
        Thread {
            var n = 0
            try {
                val key = SecretKeySpec("0123456789abcdef".toByteArray(), "AES")
                val iv = IvParameterSpec("abcdef0123456789".toByteArray())
                val pt = "ADH_BURST_PLAINTEXT_订单".toByteArray()
                val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
                while (n < BURST) {
                    c.init(Cipher.ENCRYPT_MODE, key, iv)
                    c.doFinal(pt)
                    n++
                }
                lastN = n
                Log.i(TAG, "burst done n=$n")
            } catch (t: Throwable) {
                Log.w(TAG, "burst error after $n: ${t.message}")
            } finally { running = false }
        }.apply { isDaemon = true; name = "adh-burst" }.start()
        return "ADH_BURST_STARTED_$BURST"
    }
}
