package com.idh.sandbox

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.view.Gravity
import android.widget.TextView
import java.nio.ByteBuffer

class MainActivity : Activity() {

    companion object {
        private const val TAG = "IDH_SANDBOX"
        const val MOCK_MARKER = "IDH_MOCK_DEX_v1"
        const val MOCK_SIZE = 4096

        // Strong reference so the direct (native) buffer stays mapped & readable,
        // giving the agent a deterministic dex-magic target in /proc/self/maps.
        @JvmStatic private var mockDex: ByteBuffer? = null

        // Deterministic contents: byte[i] = i & 0xff, with a dex\n035 magic header
        // and marker at the front. verify_v02 recomputes this to match a dump's sha256.
        fun buildMockDexBytes(): ByteArray {
            val b = ByteArray(MOCK_SIZE) { (it and 0xff).toByte() }
            val magic = byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00) // "dex\n035\0"
            System.arraycopy(magic, 0, b, 0, magic.size)
            val mk = MOCK_MARKER.toByteArray(Charsets.US_ASCII)
            System.arraycopy(mk, 0, b, magic.size, mk.size)
            return b
        }

        private fun seedMockDex() {
            val bytes = buildMockDexBytes()
            val buf = ByteBuffer.allocateDirect(MOCK_SIZE)
            buf.put(bytes)
            buf.rewind()
            mockDex = buf
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val pid = android.os.Process.myPid()
        Log.i(TAG, "MainActivity onCreate, pid=$pid")

        // Seed the mock dex buffer BEFORE the agent loads so it can find it.
        seedMockDex()
        Log.i(TAG, "mock dex seeded: $MOCK_SIZE bytes direct, magic=dex\\n035 marker=$MOCK_MARKER")

        // Load a known dex via InMemoryDexClassLoader (ground truth for v0.3 ART capture).
        DynamicDex.load()

        // Run deterministic crypto (static-scan refs + future dynamic-hook target).
        JavaCrypto.run()

        val loadStatus: String = try {
            System.loadLibrary("idh_agent")
            Log.i(TAG, "idh_agent loaded")
            "idh_agent loaded"
        } catch (t: Throwable) {
            Log.w(TAG, "idh_agent not loaded: ${t.message}")
            "idh_agent not loaded: ${t.message}"
        }

        val text = "IDH Sandbox\npid=$pid\n$loadStatus\nmock dex: $MOCK_SIZE bytes"
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
