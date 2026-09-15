package com.adh.sandbox

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.util.TypedValue
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.tabs.TabLayout
import java.net.HttpURLConnection
import java.net.URL
import java.nio.ByteBuffer
import org.json.JSONObject

class MainActivity : Activity() {

    companion object {
        private const val TAG = "ADH_SANDBOX"
        const val MOCK_MARKER = "ADH_MOCK_DEX_v1"
        const val MOCK_SIZE = 4096

        // Web console port. Host ADH Daemon runs on the PC; the phone reaches it either via
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
    private var lanUrl: String = ""            // host LAN URL, discovered from Host ADH Daemon /health
    private lateinit var urlLan: TextView
    private lateinit var reach: TextView
    private lateinit var logView: TextView
    private lateinit var liveBtn: MaterialButton
    private val logLines = ArrayDeque<String>()
    private val seq = java.util.concurrent.atomic.AtomicInteger(1)

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
            // Publish our Java rich-capture reporter class so the agent (which knows no sandbox
            // class name) can bind AdhReport.nReport via RegisterNatives at JNI_OnLoad — before
            // we install the JCE provider below, so no report can race the binding.
            System.setProperty("adh.reporter.class", "com.adh.sandbox.AdhReport")
            // Dobby (LSPlant's inline-hook backend) is statically linked into libidh_agent.so —
            // no separate .so to load.
            System.loadLibrary("idh_agent"); "agent: libidh_agent 已加载（模拟注入）"
        } catch (t: Throwable) {
            Log.w(TAG, "idh_agent not loaded: ${t.message}"); "agent: 未加载 — ${t.message}"
        }

        // Java-layer crypto interception: interposing JCE provider captures algorithm/key/
        // IV/plaintext/ciphertext at the Cipher/Mac/MessageDigest API boundary (richer than
        // the native EVP hook). Install AFTER the agent so AdhReport's native is bound.
        AdhSecurity.install()

        // Drive a live crypto stream so the console's 加解密 panel fills itself.
        JavaCrypto.startLiveDriver()

        setContentView(buildRoot(pid, loadStatus))
        startHealthPolling()
    }

    override fun onDestroy() { polling = false; super.onDestroy() }

    // ---- UI building blocks (stock Material 3; the theme supplies all colors) ----------

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    // Resolve a theme color role (colorPrimary / colorError / colorSurfaceVariant …) so we
    // never hand-pick hex — the palette is whatever Material 3 / the system provides.
    private fun themeColor(attr: Int): Int {
        val tv = TypedValue(); theme.resolveAttribute(attr, tv, true); return tv.data
    }

    private fun sectionTitle(text: String): TextView = TextView(this).apply {
        this.text = text
        setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_TitleMedium)
        setPadding(0, dp(2), 0, dp(8))
    }

    private fun body(text: String, muted: Boolean = false): TextView = TextView(this).apply {
        this.text = text
        setTextAppearance(
            if (muted) com.google.android.material.R.style.TextAppearance_Material3_BodySmall
            else com.google.android.material.R.style.TextAppearance_Material3_BodyMedium
        )
        if (muted) alpha = 0.7f
        setPadding(0, dp(2), 0, dp(2))
    }

    // A monospace, tappable address/log box tinted with the theme's surface-variant role.
    private fun monoBox(text: String, onTap: (() -> Unit)? = null): TextView = TextView(this).apply {
        this.text = text
        setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyLarge)
        typeface = android.graphics.Typeface.MONOSPACE
        setPadding(dp(12), dp(10), dp(12), dp(10))
        setBackgroundColor(themeColor(com.google.android.material.R.attr.colorSurfaceVariant))
        if (onTap != null) { isClickable = true; setOnClickListener { onTap() } }
    }

    private fun space(h: Int) = View(this).apply {
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(h))
    }

    // Default (filled) Material button, equal-width within its row.
    private fun mbutton(text: String, onTap: () -> Unit) = MaterialButton(this).apply {
        this.text = text; isAllCaps = false
        setOnClickListener { onTap() }
        layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            .apply { marginEnd = dp(8) }
    }

    private fun btnRow(vararg b: MaterialButton) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        setPadding(0, dp(4), 0, dp(4))
        b.forEach { addView(it) }
    }

    // A default Material card wrapping a vertical section (no custom bg/stroke — stock).
    private fun card(build: LinearLayout.() -> Unit): MaterialCardView {
        val inner = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
        }
        inner.build()
        return MaterialCardView(this).apply {
            radius = dp(16).toFloat()
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
                .apply { bottomMargin = dp(12) }
            addView(inner)
        }
    }

    // A scrollable tab page (vertical column of cards).
    private fun page(build: LinearLayout.() -> Unit): View {
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(24))
        }
        col.build()
        return ScrollView(this).apply {
            addView(col)
            layoutParams = FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
        }
    }

    // ---- tab pages ---------------------------------------------------------------------

    private fun consolePage(pid: Int, loadStatus: String): View = page {
        addView(card {
            addView(sectionTitle("观测控制台（浏览器打开）— 点击地址复制"))
            urlLan = monoBox("检测中…") { copy(bestUrl()) }
            addView(urlLan)
            addView(space(4))
            reach = body("● 正在检测控制台…")
            addView(reach)
            addView(space(8))
            addView(btnRow(
                mbutton("复制地址") { copy(bestUrl()) },
                mbutton("手机浏览器打开") { openBrowser(bestUrl()) },
            ))
            addView(body("本机 adb reverse：$LOCAL_URL", muted = true))
        })
        addView(card {
            addView(sectionTitle("Agent 状态"))
            addView(body("pid = $pid"))
            addView(body(loadStatus, muted = true))
        })
    }

    private fun cryptoPage(): View = page {
        addView(card {
            addView(sectionTitle("加解密测试"))
            liveBtn = mbutton(liveLabel()) { toggleLive() }
            addView(btnRow(
                mbutton("全部加密算法") { trigger("全部算法") { JavaCrypto.runAllOnce(pt("ALL")) } },
                liveBtn,
            ))
            addView(btnRow(
                mbutton("AES-CBC") { trigger("AES-CBC") { JavaCrypto.oneAes(pt("AES")) } },
                mbutton("RSA-2048") { trigger("RSA-2048") { JavaCrypto.oneRsa(pt("RSA")) } },
            ))
            addView(btnRow(
                mbutton("SHA-256") { trigger("SHA-256") { JavaCrypto.oneSha256(pt("SHA")) } },
                mbutton("HmacSHA256") { trigger("HMAC") { JavaCrypto.oneHmac(pt("HMAC")) } },
            ))
        })
    }

    private fun netFilePage(): View = page {
        addView(card {
            addView(sectionTitle("网络 / 文件 I/O 测试（Agent Hook）"))
            addView(btnRow(
                mbutton("HTTPS 明文边界") { trigger("HTTPS") { Network.run() } },
                mbutton("加密+上送(关联)") { trigger("关联流") { CorrelatedFlow.run() } },
            ))
            addView(btnRow(
                mbutton("文件读写(Hook)") { trigger("文件读写") { FileIO.run() } },
            ))
        })
    }

    private fun unpackPage(): View = page {
        addView(card {
            addView(sectionTitle("脱壳 / 触发"))
            addView(btnRow(
                mbutton("加载内存 DEX") { trigger("加载DEX") { DynamicDex.load(); "已触发内存 DEX 加载（脱壳面板可见）" } },
                mbutton("触发脱壳类") { trigger("脱壳触发") { TriggerProbe.reset(); TriggerProbe.safeCompute() } },
            ))
        })
    }

    private fun logPage(): View = page {
        addView(card {
            addView(sectionTitle("测试日志"))
            logView = TextView(this@MainActivity).apply {
                text = "（在其他标签页点击按钮开始测试）"
                setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
                typeface = android.graphics.Typeface.MONOSPACE
                setPadding(dp(12), dp(10), dp(12), dp(10))
                setBackgroundColor(themeColor(com.google.android.material.R.attr.colorSurfaceVariant))
            }
            addView(logView)
        })
    }

    private fun buildRoot(pid: Int, loadStatus: String): View {
        val toolbar = MaterialToolbar(this).apply {
            title = "ADH · Android DecryptHub"
            subtitle = "运行时逆向分析 · 沙盒宿主 · pid=$pid"
        }
        val tabs = TabLayout(this).apply { tabMode = TabLayout.MODE_SCROLLABLE }
        val content = FrameLayout(this)

        val pages = listOf(
            "控制台" to consolePage(pid, loadStatus),
            "加解密" to cryptoPage(),
            "网络·文件" to netFilePage(),
            "脱壳" to unpackPage(),
            "日志" to logPage(),
        )
        pages.forEach { tabs.addTab(tabs.newTab().setText(it.first)) }
        fun show(i: Int) { content.removeAllViews(); content.addView(pages[i].second) }
        tabs.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab) { show(tab.position) }
            override fun onTabUnselected(tab: TabLayout.Tab) {}
            override fun onTabReselected(tab: TabLayout.Tab) {}
        })
        show(0)

        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            fitsSystemWindows = true
            addView(toolbar, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
            addView(tabs, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
            addView(content, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        }
    }

    private fun bestUrl(): String = if (lanUrl.isNotEmpty()) lanUrl else LOCAL_URL

    private fun pt(tag: String): ByteArray =
        "ADH手动_${tag}_#${seq.getAndIncrement()}_订单金额=99.00元".toByteArray(Charsets.UTF_8)

    private fun liveLabel(): String = if (JavaCrypto.liveRunning()) "停止自动流" else "开启自动流"

    private fun toggleLive() {
        if (JavaCrypto.liveRunning()) { JavaCrypto.stopLive(); logLine("自动加密流已停止") }
        else { JavaCrypto.startLiveDriver(); logLine("自动加密流已启动（每2秒一种算法）") }
        liveBtn.text = liveLabel()
    }

    // Run a trigger off the UI thread; append start + result to the on-device log.
    private fun trigger(name: String, block: () -> String) {
        logLine("运行 $name …")
        Thread {
            val r = try { block() } catch (t: Throwable) { "失败 ${t.message}" }
            runOnUiThread { logLine("  $name = $r") }
        }.apply { isDaemon = true }.start()
    }

    private fun logLine(s: String) {
        logLines.addLast(s)
        while (logLines.size > 12) logLines.removeFirst()
        if (::logView.isInitialized) logView.text = logLines.joinToString("\n")
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

    // ---- live reachability: poll Host ADH Daemon /health via the reverse tunnel ------

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
        if (!::urlLan.isInitialized || !::reach.isInitialized) return
        Log.i(TAG, "health: ok=${h.ok} agents=${h.agents} lan='${h.lan}' local='${h.local}'")
        if (h.ok) {
            if (h.lan.isNotEmpty()) { lanUrl = h.lan; urlLan.text = h.lan }
            else { urlLan.text = "$LOCAL_URL  （控制台未上报局域网 IP，仅本地可访问）" }
            reach.setTextColor(themeColor(com.google.android.material.R.attr.colorPrimary))
            reach.text = "● 控制台在线" + (if (h.agents >= 0) "  ·  已连接 agents = ${h.agents}" else "")
        } else {
            urlLan.text = if (lanUrl.isNotEmpty()) lanUrl else "（等待控制台…）"
            reach.setTextColor(themeColor(com.google.android.material.R.attr.colorError))
            reach.text = "● 未连接 —— 在电脑运行  bash tools/dev_up.sh  启动 Host ADH Daemon（并 adb reverse tcp:$WEB_PORT）"
        }
    }
}
