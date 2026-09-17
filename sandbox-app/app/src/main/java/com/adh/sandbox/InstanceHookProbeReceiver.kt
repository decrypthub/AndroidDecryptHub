package com.adh.sandbox

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/** Trigger for the instance-method Java hook path (receiver is HookProbe.INSTANCE). */
class InstanceHookProbeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val value = intent.getStringExtra("value") ?: "ADH_INSTANCE_EMPTY"
        Log.i(TAG, "result=${HookProbe.instancePing(value)}")
    }

    companion object {
        const val ACTION = "com.adh.sandbox.INSTANCE_HOOK_PROBE"
        private const val TAG = "ADH_INSTANCE_HOOK"
    }
}