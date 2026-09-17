package com.adh.daemon

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context

/**
 * Clipboard read/write for the automation surface: "copy this out", "paste this in" are basic
 * assistant moves that the UI tools cannot do, and the framework refuses background clipboard
 * access to ordinary apps on Android 10+. The root daemon has no such restriction.
 *
 * Bounded on purpose: 8 KiB in or out, no metadata, no HTML - plain text only.
 */
internal object DeviceClipboardControl {
    private const val MAX_CHARS = 8 * 1024

    fun read(context: Context): String {
        val manager = context.getSystemService(ClipboardManager::class.java) ?: return ""
        val clip = runCatching { manager.primaryClip }.getOrNull() ?: return ""
        if (clip.itemCount <= 0) return ""
        val text = runCatching { clip.getItemAt(0).coerceToText(context).toString() }.getOrNull() ?: return ""
        return text.take(MAX_CHARS)
    }

    fun write(context: Context, text: String?): Boolean {
        val value = text ?: return false
        if (value.isEmpty() || value.length > MAX_CHARS) return false
        val manager = context.getSystemService(ClipboardManager::class.java) ?: return false
        return runCatching {
            manager.setPrimaryClip(ClipData.newPlainText("ADH", value))
            true
        }.getOrDefault(false)
    }
}
