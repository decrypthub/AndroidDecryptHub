package com.idh.sandbox

import android.util.Base64
import android.util.Log
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// Deterministic crypto with known key/iv/plaintext. Two roles:
//  1) static channel (v0.4): its references to javax.crypto.* + algorithm strings
//     land in classes.dex, so the idhd dex crypto-scan can find them.
//  2) dynamic channel (later): a real runtime AES/HMAC to capture at the plaintext
//     boundary once the hook engine lands. Expected outputs are logged for asserts.
object JavaCrypto {
    private const val TAG = "IDH_SANDBOX"
    val KEY = "0123456789abcdef".toByteArray(Charsets.US_ASCII)   // AES-128 / HMAC key
    val IV = "abcdef9876543210".toByteArray(Charsets.US_ASCII)
    const val PLAINTEXT = "IDH_CRYPTO_PLAINTEXT_v1"
    const val AES_TRANSFORM = "AES/CBC/PKCS5Padding"
    const val HMAC_ALG = "HmacSHA256"

    @JvmStatic
    fun run() = runWith(PLAINTEXT)

    // AES-CBC encrypt + HMAC of an arbitrary plaintext. Used both for the fixed-vector
    // self-test (run) and the live driver (rotating plaintext), so the agent's persistent
    // EVP hook captures a steady stream of distinct plaintexts into the panel.
    @JvmStatic
    fun runWith(plaintext: String) {
        try {
            val cipher = Cipher.getInstance(AES_TRANSFORM)
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(KEY, "AES"), IvParameterSpec(IV))
            val ct = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
            Log.i(TAG, "AES ct(b64)=" + Base64.encodeToString(ct, Base64.NO_WRAP))

            val mac = Mac.getInstance(HMAC_ALG)
            mac.init(SecretKeySpec(KEY, HMAC_ALG))
            val m = mac.doFinal(plaintext.toByteArray(Charsets.UTF_8))
            Log.i(TAG, "HMAC(b64)=" + Base64.encodeToString(m, Base64.NO_WRAP))
        } catch (t: Throwable) {
            Log.w(TAG, "crypto failed: ${t.message}")
        }
    }

    // Background driver: every ~2.5s encrypt a rotating plaintext so the console shows a
    // live, growing 加解密 stream (the agent installs a persistent EVP hook on connect).
    @JvmStatic
    fun startLiveDriver() {
        Thread {
            var i = 0
            while (true) {
                runWith("IDH_LIVE_%04d_订单金额=%d.00元".format(i, 100 + i * 7))
                i++
                try { Thread.sleep(2500) } catch (e: InterruptedException) { break }
            }
        }.apply { isDaemon = true; name = "idh-live-crypto" }.start()
    }
}
