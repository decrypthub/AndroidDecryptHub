package com.adh.manager.notify

import android.app.Notification
import android.content.Context
import android.provider.Settings
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.util.ArrayDeque

/**
 * Opt-in notification surface for the AI.
 *
 * Why a real listener and not the accessibility connection: Android 15 strips the body out of
 * TYPE_NOTIFICATION_STATE_CHANGED — verified on-device (the event arrives with empty text and a
 * reduced Notification whose extras only carry appInfo/reduced.images). Only a
 * NotificationListenerService, granted by the user in system settings, can read titles and text.
 *
 * Nothing here runs before that grant. The ring is in-memory, bounded and never persisted, and the
 * host still gates AI reads behind settings.automation.notifications (default off).
 */
class AdhNotificationListener : NotificationListenerService() {
    override fun onListenerConnected() {
        connected = true
        Log.i(TAG, "notification listener connected")
    }

    override fun onListenerDisconnected() {
        connected = false
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        val posted = sbn ?: return
        runCatching { record(posted) }.onFailure { Log.w(TAG, "record failed: ${it.message}") }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        sbn ?: return
        synchronized(lock) {
            removedCount++
        }
    }

    private fun record(sbn: StatusBarNotification) {
        val extras = sbn.notification?.extras
        val title = extras?.getCharSequence(Notification.EXTRA_TITLE)?.toString()?.trim().orEmpty()
        val text = extras?.getCharSequence(Notification.EXTRA_TEXT)?.toString()?.trim().orEmpty()
        val bigText = extras?.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()?.trim().orEmpty()
        val lines = (extras?.getCharSequenceArray(Notification.EXTRA_TEXT_LINES) ?: emptyArray())
            .mapNotNull { it?.toString()?.trim()?.takeIf { line -> line.isNotEmpty() } }
        val body = listOf(bigText, text).firstOrNull { it.isNotEmpty() }.orEmpty()
        if (title.isEmpty() && body.isEmpty() && lines.isEmpty()) return

        val entry = JSONObject()
            .put("ts", sbn.postTime)
            .put("package", sbn.packageName ?: "")
            .put("title", title)
            .put("text", body)
            .put("key", sbn.key ?: "")
            .put("ongoing", sbn.isOngoing)
            .put("clearable", sbn.isClearable)
        if (lines.isNotEmpty()) entry.put("lines", JSONArray(lines.take(8)))
        synchronized(lock) {
            recent.addFirst(entry)
            while (recent.size > MAX_ENTRIES) recent.removeLast()
        }
    }

    companion object {
        private const val TAG = "AdhNotificationListener"
        private const val MAX_ENTRIES = 30
        private val lock = Any()
        private val recent = ArrayDeque<JSONObject>()

        @Volatile private var connected = false
        private var removedCount = 0

        fun isConnected(): Boolean = connected

        fun snapshot(limit: Int, sinceMs: Long): JSONObject {
            val out = JSONArray()
            synchronized(lock) {
                for (entry in recent) {
                    if (sinceMs > 0 && entry.optLong("ts") < sinceMs) continue
                    out.put(entry)
                    if (out.length() >= limit) break
                }
            }
            return JSONObject().put("count", out.length()).put("notifications", out)
        }

        fun clear(): Int {
            synchronized(lock) {
                val n = recent.size
                recent.clear()
                return n
            }
        }

        fun stats(): JSONObject = synchronized(lock) {
            JSONObject().put("connected", connected).put("buffered", recent.size).put("removed", removedCount)
        }

        /** Whether the user has granted notification access to this app. */
        fun isGranted(context: Context): Boolean {
            val enabled = Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners") ?: return false
            return enabled.split(':').any { it.startsWith(context.packageName) }
        }
    }
}
