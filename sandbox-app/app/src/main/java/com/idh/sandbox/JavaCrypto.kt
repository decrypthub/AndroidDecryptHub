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

    fun run() {
        try {
            val cipher = Cipher.getInstance(AES_TRANSFORM)
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(KEY, "AES"), IvParameterSpec(IV))
            val ct = cipher.doFinal(PLAINTEXT.toByteArray(Charsets.UTF_8))
            Log.i(TAG, "AES ct(b64)=" + Base64.encodeToString(ct, Base64.NO_WRAP))

            val mac = Mac.getInstance(HMAC_ALG)
            mac.init(SecretKeySpec(KEY, HMAC_ALG))
            val m = mac.doFinal(PLAINTEXT.toByteArray(Charsets.UTF_8))
            Log.i(TAG, "HMAC(b64)=" + Base64.encodeToString(m, Base64.NO_WRAP))
        } catch (t: Throwable) {
            Log.w(TAG, "crypto failed: ${t.message}")
        }
    }
}
