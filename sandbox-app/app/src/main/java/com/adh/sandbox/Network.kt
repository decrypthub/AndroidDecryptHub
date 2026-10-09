package com.adh.sandbox

import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSession
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

// Makes a real HTTPS request (via Conscrypt/BoringSSL) to the local test server
// over `adb reverse`. Uses an all-trusting SSLContext so no CA is needed — the
// point is to exercise SSL_write/SSL_read, which the agent hooks to read plaintext.
object Network {
    private const val TAG = "ADH_SANDBOX"
    const val MARKER = "ADH_NET_MARKER_v1"
    private const val PORT = 8762

    @JvmStatic
    fun run(): String {
        Log.i(TAG, "Network.run: starting HTTPS to 127.0.0.1:$PORT")
        return try {
            val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
                override fun checkClientTrusted(c: Array<X509Certificate>?, a: String?) {}
                override fun checkServerTrusted(c: Array<X509Certificate>?, a: String?) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            })
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, trustAll, SecureRandom())
            val conn = URL("https://127.0.0.1:$PORT/api").openConnection() as HttpsURLConnection
            conn.sslSocketFactory = ctx.socketFactory
            conn.hostnameVerifier = HostnameVerifier { _: String?, _: SSLSession? -> true }
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.requestMethod = "POST"
            conn.setRequestProperty("X-Adh-Marker", MARKER)
            conn.doOutput = true
            conn.outputStream.use { it.write(MARKER.toByteArray()) }
            val code = conn.responseCode
            val body = BufferedReader(InputStreamReader(conn.inputStream)).readText()
            Log.i(TAG, "Network.run: code=$code body=$body")
            "$code:$body"
        } catch (t: Throwable) {
            Log.w(TAG, "Network.run failed: ${t.message}")
            "error:${t.message}"
        }
    }
}
