package com.adh.sandbox

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/** Explicit trigger for the native-hook acceptance: calls adh_trace_target() through JNI. */
class NativeHookProbeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        Log.i(TAG, "nativeHookProbe=${Detection.nativeHookProbe()}")
    }

    companion object {
        const val ACTION = "com.adh.sandbox.NATIVE_HOOK_PROBE"
        private const val TAG = "ADH_NATIVE_HOOK"
    }
}