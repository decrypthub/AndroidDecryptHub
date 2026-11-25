package com.adh.sandbox

import android.app.Activity
import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.pm.ApplicationInfo
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle
import android.util.Base64
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.CRC32

/** Opt-in call-site recording in the Demo. This neither changes nor replaces the two APIs. */
private object DemoApiObservation {
    private data class Api(val id: String, val className: String, val method: String)
    private val digest = Api("digest", "java.security.MessageDigest", "digest(byte[])")
    private val crc = Api("crc32", "java.util.zip.CRC32", "update(byte[])")
    private val apis = listOf(digest, crc)
    private val initialRevision = UUID.randomUUID().toString()
    private fun prefs(ctx: Context) = ctx.getSharedPreferences("own-api-observations", Context.MODE_PRIVATE)

    @Synchronized fun state(ctx: Context): JSONObject {
        val prefs = prefs(ctx)
        return JSONObject().put("revision", prefs.getString("revision", initialRevision))
            .put("apis", JSONArray(apis.map {
                JSONObject().put("id", it.id).put("className", it.className).put("method", it.method)
                    .put("enabled", prefs.getBoolean(it.id, false))
            }))
    }

    @Synchronized fun configure(ctx: Context, request: JSONObject): JSONObject {
        val prefs = prefs(ctx)
        val id = request.optString("id")
        val enabled = request.opt("enabled")
        if (request.length() != 3 || apis.none { it.id == id } || enabled !is Boolean ||
            request.opt("revision") !is String) throw ApiError(400)
        if (request.optString("revision") != prefs.getString("revision", initialRevision)) throw ApiError(409)
        if (prefs.getBoolean(id, false) != enabled &&
            !prefs.edit().putBoolean(id, enabled).putString("revision", UUID.randomUUID().toString()).commit()) {
            throw ApiError(503)
        }
        return state(ctx)
    }

    @Synchronized fun exercise(ctx: Context): JSONObject {
        val prefs = prefs(ctx)
        val sample = "ADH Demo API observation".toByteArray(Charsets.UTF_8)
        val captured = JSONArray()
        fun <T> recorded(api: Api, action: () -> T): T {
            val result = action()
            if (prefs.getBoolean(api.id, false)) captured.put(api.id)
            return result
        }
        val size = recorded(digest) { MessageDigest.getInstance("SHA-256").digest(sample).size }
        val checksum = CRC32()
        recorded(crc) { checksum.update(sample) }
        return JSONObject().put("executed", JSONArray(apis.map { it.id })).put("captured", captured)
            .put("digestSize", size).put("checksum", checksum.value)
    }
}

private class ApiError(val status: Int) : Exception()

class DemoApiActivity : Activity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        val view = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val space = (24 * resources.displayMetrics.density).toInt()
            setPadding(space, space, space, space)
        }
        val heading = TextView(this).apply { text = "API 采集验收"; textSize = 24f }
        val hint = TextView(this).apply { text = "在电脑面板选择需要采集的 API，再回到这里运行。两个 API 每次都会执行，开关只控制是否记录。"; textSize = 16f }
        val result = TextView(this).apply { text = "尚未运行"; textSize = 16f }
        val action = Button(this).apply {
            text = "运行本次 Demo"
            setOnClickListener {
                val data = DemoApiObservation.exercise(this@DemoApiActivity)
                val captured = data.getJSONArray("captured")
                val methods = (0 until captured.length()).map {
                    if (captured.getString(it) == "digest") "MessageDigest.digest(byte[])" else "CRC32.update(byte[])"
                }
                result.text = "两种 API 均已执行。\n本次记录：" + (methods.takeIf { it.isNotEmpty() }?.joinToString("\n") ?: "无")
            }
        }
        view.addView(heading); view.addView(hint); view.addView(action); view.addView(result)
        setContentView(view)
    }
}

class DemoApiProvider : ContentProvider() {
    override fun onCreate() = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        val app = context ?: return reply(503)
        if (Binder.getCallingUid() != 2000 || app.packageName != "com.adh.sandbox.apilab" ||
            (app.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) == 0) {
            throw SecurityException("Requires the USB debugging shell and the isolated Demo APK")
        }
        val identity = Binder.clearCallingIdentity()
        try {
            return when (method) {
                "catalog" -> if (!arg.isNullOrEmpty()) reply(400) else reply(200, DemoApiObservation.state(app))
                "set" -> {
                    if (arg == null || arg.length > 1024 || !arg.matches(Regex("[A-Za-z0-9_-]+"))) return reply(400)
                    val flags = Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                    val request = JSONObject(String(Base64.decode(arg, flags), Charsets.UTF_8))
                    reply(200, DemoApiObservation.configure(app, request))
                }
                // USB acceptance invokes the same fixed scenario as the visible Demo button.
                "exercise" -> if (!arg.isNullOrEmpty()) reply(400) else reply(200, DemoApiObservation.exercise(app))
                else -> reply(400)
            }
        } catch (err: ApiError) {
            return reply(err.status)
        } catch (_: org.json.JSONException) {
            return reply(400)
        } catch (_: IllegalArgumentException) {
            return reply(400)
        } catch (_: Exception) {
            return reply(503)
        } finally {
            Binder.restoreCallingIdentity(identity)
        }
    }

    private fun reply(status: Int, value: JSONObject? = null) = Bundle().apply {
        val text = value?.toString()?.toByteArray(Charsets.UTF_8) ?: byteArrayOf()
        val encoded = Base64.encodeToString(text, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        putString("adhApi", "$status.$encoded")
    }

    override fun getType(uri: Uri): String? = null
    override fun query(uri: Uri, projection: Array<out String>?, selection: String?,
                       selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = throw UnsupportedOperationException()
    override fun insert(uri: Uri, values: ContentValues?): Uri? = throw UnsupportedOperationException()
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = throw UnsupportedOperationException()
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int =
        throw UnsupportedOperationException()
}
