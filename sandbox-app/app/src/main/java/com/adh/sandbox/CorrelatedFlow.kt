package com.adh.sandbox

import android.util.Base64
import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSession
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

// The real forensic scenario: encrypt data, then send the CIPHERTEXT over TLS —
// all on one thread. The agent hooks EVP_CipherUpdate (sees the plaintext) and
// SSL_write (sees the request carrying the ciphertext); adhd correlates them by
// thread+time to prove "this plaintext was encrypted and sent in this request".
object CorrelatedFlow {
    private const val TAG = "ADH_SANDBOX"
    const val PLAINTEXT = "ADH_CORRELATE_v1"
    private const val PORT = 8762

    @JvmStatic
    fun run(): String {
        return try {
            val key = "0123456789abcdef".toByteArray()
            val iv = "abcdef9876543210".toByteArray()
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            val ct = cipher.doFinal(PLAINTEXT.toByteArray())
            val ctB64 = Base64.encodeToString(ct, Base64.NO_WRAP)

            val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
                override fun checkClientTrusted(c: Array<X509Certificate>?, a: String?) {}
                override fun checkServerTrusted(c: Array<X509Certificate>?, a: String?) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            })
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, trustAll, SecureRandom())
            val conn = URL("https://127.0.0.1:$PORT/upload").openConnection() as HttpsURLConnection
            conn.sslSocketFactory = ctx.socketFactory
            conn.hostnameVerifier = HostnameVerifier { _: String?, _: SSLSession? -> true }
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.outputStream.use { it.write("ct=$ctB64".toByteArray()) }   // send the ciphertext
            val code = conn.responseCode
            val body = BufferedReader(InputStreamReader(conn.inputStream)).readText()
            Log.i(TAG, "CorrelatedFlow: encrypted+sent, code=$code")
            "$code:$body"
        } catch (t: Throwable) {
            Log.w(TAG, "CorrelatedFlow failed: ${t.message}")
            "error:${t.message}"
        }
    }
}
