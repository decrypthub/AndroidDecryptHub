package com.adh.daemon

import android.content.Context
import android.media.AudioManager
import org.json.JSONObject

/**
 * Volume read/write for the automation surface. The agent already handles notification/quick
 * settings panels; volume was the missing "device-level" control an assistant needs (mute before a
 * recording, raise the alarm, quiet the ringtone). Kept deliberately small: fixed stream names and
 * an index that is clamped to the stream's own range, nothing else reaches AudioManager.
 */
internal object DeviceAudioControl {
    private const val STREAM_MUSIC = "music"
    private const val STREAM_RING = "ring"
    private const val STREAM_ALARM = "alarm"
    private const val STREAM_VOICE = "voice"

    fun statusJson(context: Context): String {
        val audio = context.getSystemService(AudioManager::class.java)
            ?: return JSONObject().toString()
        return JSONObject()
            .put("music", audio.getStreamVolume(AudioManager.STREAM_MUSIC))
            .put("musicMax", audio.getStreamMaxVolume(AudioManager.STREAM_MUSIC))
            .put("ring", audio.getStreamVolume(AudioManager.STREAM_RING))
            .put("ringMax", audio.getStreamMaxVolume(AudioManager.STREAM_RING))
            .put("alarm", audio.getStreamVolume(AudioManager.STREAM_ALARM))
            .put("alarmMax", audio.getStreamMaxVolume(AudioManager.STREAM_ALARM))
            .put("voice", audio.getStreamVolume(AudioManager.STREAM_VOICE_CALL))
            .put("voiceMax", audio.getStreamMaxVolume(AudioManager.STREAM_VOICE_CALL))
            .toString()
    }

    fun setVolume(context: Context, stream: String?, index: Int): Boolean {
        val audio = context.getSystemService(AudioManager::class.java) ?: return false
        val streamId = when (stream?.trim()?.lowercase()) {
            STREAM_MUSIC -> AudioManager.STREAM_MUSIC
            STREAM_RING -> AudioManager.STREAM_RING
            STREAM_ALARM -> AudioManager.STREAM_ALARM
            STREAM_VOICE -> AudioManager.STREAM_VOICE_CALL
            else -> return false
        }
        val max = audio.getStreamMaxVolume(streamId)
        val clamped = index.coerceIn(0, max)
        return runCatching {
            audio.setStreamVolume(streamId, clamped, 0)
            true
        }.getOrDefault(false)
    }
}
