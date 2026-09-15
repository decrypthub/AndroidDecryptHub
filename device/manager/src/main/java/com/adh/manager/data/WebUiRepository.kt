package com.adh.manager.data

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

data class WebUiStatus(
    val reachable: Boolean,
    val primaryUrl: String,
    val lanUrl: String? = null,
    val localUrl: String = HostWebUiRepository.LOCAL_URL,
)

interface WebUiRepository {
    fun probe(): WebUiStatus
}

class HostWebUiRepository : WebUiRepository {
    override fun probe(): WebUiStatus {
        return runCatching {
            val connection = (URL("$LOCAL_URL/health").openConnection() as HttpURLConnection).apply {
                connectTimeout = 1_200
                readTimeout = 1_200
                requestMethod = "GET"
            }
            try {
                if (connection.responseCode != HttpURLConnection.HTTP_OK) {
                    WebUiStatus(reachable = false, primaryUrl = LOCAL_URL)
                } else {
                    val body = connection.inputStream.bufferedReader().use { it.readText() }
                    parseWebUiStatus(body)
                }
            } finally {
                connection.disconnect()
            }
        }.getOrElse {
            WebUiStatus(reachable = false, primaryUrl = LOCAL_URL)
        }
    }

    companion object {
        const val LOCAL_URL = "http://127.0.0.1:8088"
    }
}

internal fun parseWebUiStatus(body: String): WebUiStatus {
    val health = JSONObject(body)
    val web = health.optJSONObject("web")
    val lan = web?.optJSONArray("lan")
        ?.let { urls ->
            (0 until urls.length())
                .asSequence()
                .map(urls::optString)
                .firstOrNull(String::isNotBlank)
        }
    val local = web?.optString("local").orEmpty().ifBlank { HostWebUiRepository.LOCAL_URL }
    return WebUiStatus(
        reachable = health.optBoolean("ok", true),
        primaryUrl = lan ?: local,
        lanUrl = lan,
        localUrl = local,
    )
}
