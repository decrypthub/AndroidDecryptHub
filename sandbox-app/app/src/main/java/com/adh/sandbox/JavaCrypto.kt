package com.adh.sandbox

import android.util.Base64
import android.util.Log
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Provider
import java.security.PublicKey
import java.security.Security
import java.security.Signature
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// Deterministic crypto with known key/iv/plaintext. Two roles:
//  1) static channel (v0.4): its references to javax.crypto.* + algorithm strings
//     land in classes.dex, so the adhd dex crypto-scan can find them.
//  2) dynamic channel (later): a real runtime AES/HMAC to capture at the plaintext
//     boundary once the hook engine lands. Expected outputs are logged for asserts.
object JavaCrypto {
    private const val TAG = "ADH_SANDBOX"
    val KEY = "0123456789abcdef".toByteArray(Charsets.US_ASCII)   // AES-128 / HMAC key
    val IV = "abcdef9876543210".toByteArray(Charsets.US_ASCII)
    const val PLAINTEXT = "ADH_CRYPTO_PLAINTEXT_v1"
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

    // A rotating menu of real crypto ops so the panel shows the FULL surface, not just
    // AES: symmetric (AES-CBC/CTR/GCM, DESede), digests (MD5/SHA-1/SHA-256/SHA-512), HMAC.
    private val AES_KEY16 = "0123456789abcdef".toByteArray()
    private val AES_KEY32 = "0123456789abcdef0123456789abcdef".toByteArray()
    private val DES3_KEY24 = "0123456789abcdefADH-2026".toByteArray()   // 24 bytes for DESede

    private fun sym(transform: String, key: ByteArray, ivLen: Int, pt: ByteArray) {
        val c = Cipher.getInstance(transform)
        val ks = SecretKeySpec(key, transform.substringBefore('/'))
        when {
            transform.contains("GCM") -> c.init(Cipher.ENCRYPT_MODE, ks, GCMParameterSpec(128, IV.copyOf(ivLen)))
            ivLen > 0 -> c.init(Cipher.ENCRYPT_MODE, ks, IvParameterSpec(IV.copyOf(ivLen)))
            else -> c.init(Cipher.ENCRYPT_MODE, ks)
        }
        c.doFinal(pt)
    }
    private fun digest(alg: String, data: ByteArray) { MessageDigest.getInstance(alg).digest(data) }
    private fun hmac(alg: String, data: ByteArray) { val m = Mac.getInstance(alg); m.init(SecretKeySpec(KEY, alg)); m.doFinal(data) }
    private val rsaPub: PublicKey by lazy { KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair().public }
    private fun rsa(data: ByteArray) {
        val c = Cipher.getInstance("RSA/ECB/PKCS1Padding"); c.init(Cipher.ENCRYPT_MODE, rsaPub); c.doFinal(data.copyOf(minOf(data.size, 200)))
    }

    // The full rotating menu (name → op). Shared by the live driver and the "全部算法" button.
    private val MENU: List<Pair<String, (ByteArray) -> Unit>> = listOf(
        "AES-128-CBC" to { pt -> sym("AES/CBC/PKCS5Padding", AES_KEY16, 16, pt) },
        "AES-256-CTR" to { pt -> sym("AES/CTR/NoPadding", AES_KEY32, 16, pt) },
        "AES-128-GCM" to { pt -> sym("AES/GCM/NoPadding", AES_KEY16, 12, pt) },
        "DESede-CBC"  to { pt -> sym("DESede/CBC/PKCS5Padding", DES3_KEY24, 8, pt) },
        "MD5"         to { pt -> digest("MD5", pt) },
        "SHA-1"       to { pt -> digest("SHA-1", pt) },
        "SHA-256"     to { pt -> digest("SHA-256", pt) },
        "SHA-512"     to { pt -> digest("SHA-512", pt) },
        "HmacSHA256"  to { pt -> hmac("HmacSHA256", pt) },
        "HmacSHA1"    to { pt -> hmac("HmacSHA1", pt) },
        "RSA-2048"    to { pt -> rsa(pt) },
    )

    @JvmStatic @Volatile private var liveThread: Thread? = null

    @JvmStatic fun liveRunning(): Boolean = liveThread?.isAlive == true

    @JvmStatic
    fun stopLive() { liveThread?.interrupt(); liveThread = null }

    // Background driver: every ~2s run ONE op from the rotating menu so the console fills
    // with a varied, live crypto stream (the agent's persistent hooks capture each).
    // Idempotent — a second call while running is a no-op.
    @JvmStatic
    fun startLiveDriver() {
        if (liveRunning()) return
        val t = Thread {
            var i = 0
            while (!Thread.currentThread().isInterrupted) {
                val (name, op) = MENU[i % MENU.size]
                val pt = "ADH_LIVE_%04d_%s_订单金额=%d.00元".format(i, name, 100 + i * 7).toByteArray(Charsets.UTF_8)
                try { op(pt); Log.i(TAG, "live[$name] ${pt.size}B") } catch (t: Throwable) { Log.w(TAG, "live[$name] fail: ${t.message}") }
                i++
                try { Thread.sleep(2000) } catch (e: InterruptedException) { break }
            }
        }.apply { isDaemon = true; name = "adh-live-crypto" }
        liveThread = t
        t.start()
    }

    // ---- one-shot manual triggers (each returns a short summary for the on-device log) ----

    @JvmStatic fun oneAes(pt: ByteArray): String { sym("AES/CBC/PKCS5Padding", AES_KEY16, 16, pt); return "AES-128-CBC 明文 ${pt.size}B" }
    @JvmStatic fun oneRsa(pt: ByteArray): String { rsa(pt); return "RSA-2048 明文 ${minOf(pt.size, 200)}B" }
    @JvmStatic fun oneSha256(pt: ByteArray): String { digest("SHA-256", pt); return "SHA-256 明文 ${pt.size}B" }
    @JvmStatic fun oneHmac(pt: ByteArray): String { hmac("HmacSHA256", pt); return "HmacSHA256 明文 ${pt.size}B" }

    // Fire ONE round of every algorithm in the menu.
    @JvmStatic
    fun runAllOnce(pt: ByteArray): String {
        var ok = 0
        for ((name, op) in MENU) {
            try { op(pt); ok++ } catch (t: Throwable) { Log.w(TAG, "once[$name] fail: ${t.message}") }
        }
        return "全部算法 $ok/${MENU.size} 已触发"
    }

    // ---- v2.1: RSA/ECDSA Signature + AEAD(GCM/ChaCha20-Poly1305) demos ----
    // These hit native EVP_PKEY_sign/verify and EVP_AEAD_CTX_seal/open (see agent_main.c).

    private val ecKeyPair by lazy { KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair() }
    const val SIGN_TBS = "ADH_SIGN_TBS_v1"

    @JvmStatic
    fun sigDemo(): String {
        val msg = SIGN_TBS.toByteArray(Charsets.UTF_8)
        val s = Signature.getInstance("SHA256withECDSA"); s.initSign(ecKeyPair.private); s.update(msg)
        val sig = s.sign()
        val v = Signature.getInstance("SHA256withECDSA"); v.initVerify(ecKeyPair.public); v.update(msg)
        val ok = v.verify(sig)
        Log.i(TAG, "ECDSA sig(b64)=" + Base64.encodeToString(sig, Base64.NO_WRAP) + " verify=$ok")
        return "ECDSA sign+verify ok=$ok"
    }

    const val AEAD_PLAINTEXT = "ADH_AEAD_PLAINTEXT_v1"

    @JvmStatic
    fun aeadDemo(): String {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(AES_KEY16, "AES"), GCMParameterSpec(128, IV.copyOf(12)))
        c.doFinal(AEAD_PLAINTEXT.toByteArray(Charsets.UTF_8))
        var chacha = false
        try {
            val cc = Cipher.getInstance("ChaCha20-Poly1305")
            cc.init(Cipher.ENCRYPT_MODE, SecretKeySpec(AES_KEY32, "ChaCha20"), IvParameterSpec(IV.copyOf(12)))
            cc.doFinal(AEAD_PLAINTEXT.toByteArray(Charsets.UTF_8)); chacha = true
        } catch (t: Throwable) { Log.w(TAG, "ChaCha20-Poly1305 unavailable: ${t.message}") }
        return "AEAD ops fired chacha=$chacha"
    }

    // Fixed vectors for the agent Java hooks (Cipher / Mac / MessageDigest / Signature).
    // An explicit platform provider skips ADH-Intercept, so a java-source capture of these
    // markers can only come from the plugin hook, not from this app's own reporter.
    const val JHOOK_AES = "ADH_JHOOK_AES_v1"
    const val JHOOK_GCM = "ADH_JHOOK_GCM_v1"
    const val JHOOK_HMAC = "ADH_JHOOK_HMAC_v1"
    const val JHOOK_DIGEST = "ADH_JHOOK_DIGEST_v1"
    const val JHOOK_RSA = "ADH_JHOOK_RSA_v1"
    const val JHOOK_SIGN = "ADH_JHOOK_SIGN_v1"

    private val hookRsa: KeyPair by lazy {
        KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    }

    private fun platform(type: String, algorithm: String): Provider {
        for (provider in Security.getProviders()) {
            if (provider.name == "ADH-Intercept") continue
            if (provider.getService(type, algorithm) != null) return provider
        }
        throw IllegalStateException("no platform $type $algorithm")
    }

    @JvmStatic
    fun javaHookProbe(): String {
        return try {
            val aesPt = JHOOK_AES.toByteArray(Charsets.UTF_8)
            val aes = Cipher.getInstance(AES_TRANSFORM, platform("Cipher", AES_TRANSFORM))
            aes.init(Cipher.ENCRYPT_MODE, SecretKeySpec(AES_KEY16, "AES"), IvParameterSpec(IV))
            val ct = aes.doFinal(aesPt)
            val dec = Cipher.getInstance(AES_TRANSFORM, platform("Cipher", AES_TRANSFORM))
            dec.init(Cipher.DECRYPT_MODE, SecretKeySpec(AES_KEY16, "AES"), IvParameterSpec(IV))
            if (!dec.doFinal(ct).contentEquals(aesPt)) return "fail aes-roundtrip"

            val gcmPt = JHOOK_GCM.toByteArray(Charsets.UTF_8)
            val gcm = Cipher.getInstance("AES/GCM/NoPadding", platform("Cipher", "AES/GCM/NoPadding"))
            gcm.init(Cipher.ENCRYPT_MODE, SecretKeySpec(AES_KEY16, "AES"), GCMParameterSpec(128, IV.copyOf(12)))
            val gcmCt = gcm.doFinal(gcmPt)

            val mac = Mac.getInstance(HMAC_ALG, platform("Mac", HMAC_ALG))
            mac.init(SecretKeySpec(KEY, HMAC_ALG))
            val macOut = mac.doFinal(JHOOK_HMAC.toByteArray(Charsets.UTF_8))

            val dig = MessageDigest.getInstance("SHA-256", platform("MessageDigest", "SHA-256"))
            val digOut = dig.digest(JHOOK_DIGEST.toByteArray(Charsets.UTF_8))

            val rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding", platform("Cipher", "RSA/ECB/PKCS1Padding"))
            rsa.init(Cipher.ENCRYPT_MODE, hookRsa.public)
            val rsaCt = rsa.doFinal(JHOOK_RSA.toByteArray(Charsets.UTF_8))

            val msg = JHOOK_SIGN.toByteArray(Charsets.UTF_8)
            val signer = Signature.getInstance("SHA256withRSA", platform("Signature", "SHA256withRSA"))
            signer.initSign(hookRsa.private)
            signer.update(msg)
            val sig = signer.sign()
            val verifier = Signature.getInstance("SHA256withRSA", platform("Signature", "SHA256withRSA"))
            verifier.initVerify(hookRsa.public)
            verifier.update(msg)
            if (!verifier.verify(sig)) return "fail sign-verify"

            "ok aes=${ct.size} gcm=${gcmCt.size} hmac=${macOut.size} digest=${digOut.size} rsa=${rsaCt.size} sign=${sig.size}"
        } catch (t: Throwable) {
            val why = "${t.javaClass.simpleName}: ${t.message ?: ""}"
            if (why.length <= 140) "fail $why" else "fail ${why.substring(0, 140)}"
        }
    }
}
