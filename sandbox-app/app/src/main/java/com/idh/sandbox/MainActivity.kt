package com.idh.sandbox

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.net.HttpURLConnection
import java.net.URL
import java.nio.ByteBuffer
import org.json.JSONObject

class MainActivity : Activity() {

    companion object {
        private const val TAG = "IDH_SANDBOX"
        const val MOCK_MARKER = "IDH_MOCK_DEX_v1"
        const val MOCK_SIZE = 4096

        // Web console (idhd) port. idhd runs on the HOST; the phone reaches it either via
        // `adb reverse tcp:8760` (127.0.0.1) or directly over Wi-Fi at the host's LAN IP.
        const val WEB_PORT = 8760
        const val LOCAL_URL = "http://127.0.0.1:$WEB_PORT"

        @JvmStatic private var mockDex: ByteBuffer? = null

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
            buf.put(bytes); buf.rewind()
            mockDex = buf
        }
    }

    @Volatile private var polling = true
    private var lanUrl: String = ""            // host LAN URL, discovered from idhd /health
    private lateinit var urlLan: TextView
    private lateinit var reach: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val pid = android.os.Process.myPid()
        Log.i(TAG, "MainActivity onCreate, pid=$pid")

        seedMockDex()
        DynamicDex.load()
        JavaCrypto.run()
        Detection.load()
        HeapProbe.init()
        TriggerProbe.reset()

        val loadStatus: String = try {
            System.loadLibrary("idh_agent"); "agent: libidh_agent 已加载（模拟注入）"
        } catch (t: Throwable) {
            Log.w(TAG, "idh_agent not loaded: ${t.message}"); "agent: 未加载 — ${t.message}"
        }

        // Java-layer crypto interception: interposing JCE provider captures algorithm/key/
        // IV/plaintext/ciphertext at the Cipher/Mac/MessageDigest API boundary (richer than
        // the native EVP hook). Install AFTER the agent so IdhReport's native is bound.
        IdhSecurity.install()

        // Drive a live crypto stream so the console's 加解密 panel fills itself.
        JavaCrypto.startLiveDriver()

        setContentView(buildUi(pid, loadStatus))
        startHealthPolling()
    }

    override fun onDestroy() { polling = false; super.onDestroy() }

    // ---- UI ---------------------------------------------------------------

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun label(text: String, size: Float, color: Int, bold: Boolean = false): TextView =
        TextView(this).apply {
            this.text = text; textSize = size; setTextColor(color)
            if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD)
            setPadding(0, dp(2), 0, dp(2))
        }

    private fun urlView(text: String, color: Int, onTap: () -> Unit): TextView =
        TextView(this).apply {
            this.text = text; textSize = 17f; setTextColor(color)
            setTypeface(android.graphics.Typeface.MONOSPACE, android.graphics.Typeface.BOLD)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            setBackgroundColor(Color.parseColor("#11151f"))
            isClickable = true
            setOnClickListener { onTap() }
        }

    private fun spacer(h: Int) = View(this).apply {
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(h))
    }

    private fun actbutton(text: String, onTap: () -> Unit) = Button(this).apply {
        this.text = text; isAllCaps = false
        setOnClickListener { onTap() }
        layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            .apply { marginEnd = dp(8) }
    }

    private fun buildUi(pid: Int, loadStatus: String): View {
        val muted = Color.parseColor("#6c7086")
        val fg = Color.parseColor("#cdd6f4")
        val blue = Color.parseColor("#89b4fa")
        val green = Color.parseColor("#a6e3a1")

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#0b0e14"))
            setPadding(dp(20), dp(28), dp(20), dp(28))
        }
        root.addView(label("ADH · Android DecryptHub", 22f, fg, bold = true))
        root.addView(label("运行时逆向分析 · 沙盒宿主（模拟注入）", 13f, muted))
        root.addView(spacer(18))
        root.addView(label("pid=$pid   ·   $loadStatus", 12f, muted))
        root.addView(spacer(22))

        root.addView(label("🔎 在浏览器打开观测控制台", 16f, blue, bold = true))
        root.addView(spacer(10))

        root.addView(label("局域网地址（电脑 / 手机 / 同网任意设备）— 点击复制", 12f, muted))
        urlLan = urlView("检测中…", green) { copy(if (lanUrl.isNotEmpty()) lanUrl else LOCAL_URL) }
        root.addView(urlLan)
        root.addView(spacer(12))

        root.addView(label("本机浏览器（经 adb reverse）— 点击复制", 12f, muted))
        root.addView(urlView(LOCAL_URL, fg) { copy(LOCAL_URL) })
        root.addView(spacer(18))

        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        row.addView(actbutton("复制局域网地址") { copy(if (lanUrl.isNotEmpty()) lanUrl else LOCAL_URL) })
        row.addView(actbutton("在手机浏览器打开") { openBrowser(LOCAL_URL) })
        root.addView(row)
        root.addView(spacer(18))

        reach = label("● 正在检测控制台…", 13f, muted)
        root.addView(reach)
        root.addView(spacer(16))

        root.addView(label(
            "用法：电脑上先跑  bash tools/dev_up.sh  启动 idhd 并建立 adb reverse，\n" +
            "然后浏览器打开上面的地址即可实时观测（脱壳 / 明文捕获 / hook / trace）。\n" +
            "局域网地址由控制台自动上报；手机与电脑需在同一 Wi-Fi。",
            12f, muted))

        return ScrollView(this).apply {
            setBackgroundColor(Color.parseColor("#0b0e14"))
            addView(root)
        }
    }

    // ---- actions ----------------------------------------------------------

    private fun copy(text: String) {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("adh-web", text))
        Toast.makeText(this, "已复制：$text", Toast.LENGTH_SHORT).show()
    }

    private fun openBrowser(url: String) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        } catch (e: Exception) {
            Toast.makeText(this, "无法打开浏览器：$e", Toast.LENGTH_LONG).show()
        }
    }

    // ---- live reachability: poll idhd /health via the reverse tunnel ------

    private fun startHealthPolling() {
        Thread {
            while (polling) {
                val r = probeHealth()
                runOnUiThread { applyHealth(r) }
                try { Thread.sleep(3000) } catch (e: InterruptedException) { break }
            }
        }.apply { isDaemon = true }.start()
    }

    private data class Health(val ok: Boolean, val agents: Int, val lan: String, val local: String)

    private fun probeHealth(): Health {
        return try {
            val c = (URL("$LOCAL_URL/health").openConnection() as HttpURLConnection).apply {
                connectTimeout = 1200; readTimeout = 1200
            }
            val code = c.responseCode
            val body = if (code == 200) c.inputStream.bufferedReader().use { it.readText() } else ""
            c.disconnect()
            if (code != 200) return Health(false, -1, "", "")
            val j = JSONObject(body)
            val agents = j.optInt("agents", -1)
            val web = j.optJSONObject("web")
            val lanArr = web?.optJSONArray("lan")
            val lan = if (lanArr != null && lanArr.length() > 0) lanArr.getString(0) else ""
            val local = web?.optString("local") ?: LOCAL_URL
            Health(true, agents, lan, local)
        } catch (e: Exception) {
            Health(false, -1, "", "")
        }
    }

    private fun applyHealth(h: Health) {
        Log.i(TAG, "health: ok=${h.ok} agents=${h.agents} lan='${h.lan}' local='${h.local}'")
        if (h.ok) {
            if (h.lan.isNotEmpty()) { lanUrl = h.lan; urlLan.text = h.lan }
            else { urlLan.text = "$LOCAL_URL  （控制台未上报局域网 IP，仅本地可访问）" }
            reach.setTextColor(Color.parseColor("#a6e3a1"))
            reach.text = "● 控制台在线" + (if (h.agents >= 0) "  ·  已连接 agents = ${h.agents}" else "")
        } else {
            urlLan.text = if (lanUrl.isNotEmpty()) lanUrl else "（等待控制台…）"
            reach.setTextColor(Color.parseColor("#f38ba8"))
            reach.text = "● 未连接 —— 在电脑运行  bash tools/dev_up.sh  启动 idhd（并 adb reverse tcp:$WEB_PORT）"
        }
    }
}
