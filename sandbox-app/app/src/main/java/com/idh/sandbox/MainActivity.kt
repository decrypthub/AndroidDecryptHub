package com.idh.sandbox

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.view.Gravity
import android.widget.TextView

class MainActivity : Activity() {

    companion object {
        private const val TAG = "IDH_SANDBOX"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val pid = android.os.Process.myPid()
        Log.i(TAG, "MainActivity onCreate, pid=$pid")

        val loadStatus: String = try {
            System.loadLibrary("idh_agent")
            Log.i(TAG, "idh_agent loaded")
            "idh_agent loaded"
        } catch (t: Throwable) {
            Log.w(TAG, "idh_agent not loaded: ${t.message}")
            "idh_agent not loaded: ${t.message}"
        }

        val text = "IDH Sandbox\npid=$pid\n$loadStatus"
        Log.i(TAG, "status: $text")

        val tv = TextView(this).apply {
            textSize = 18f
            gravity = Gravity.CENTER
            setPadding(32, 32, 32, 32)
            setText(text)
        }
        setContentView(tv)
    }
}
