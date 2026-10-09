package com.adh.sandbox

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Explicit test trigger: `adb shell am broadcast -a com.adh.sandbox.HOOK_PROBE
 * --es value <payload> -n com.adh.sandbox/.HookProbeReceiver`.
 */
class HookProbeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val value = intent.getStringExtra(EXTRA_VALUE) ?: "ADH_HOOK_EMPTY"
        val result = HookProbe.recordPing(value)
        Log.i(TAG, "result=$result")
    }

    companion object {
        const val ACTION = "com.adh.sandbox.HOOK_PROBE"
        const val EXTRA_VALUE = "value"
        private const val TAG = "ADH_HOOK_PROBE"
    }
}