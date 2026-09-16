package com.adh.sandbox

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.util.TypedValue
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.tabs.TabLayout
import java.nio.ByteBuffer

class MainActivity : Activity() {

    companion object {
        private const val TAG = "ADH_SANDBOX"
        const val MOCK_MARKER = "ADH_MOCK_DEX_v1"
        const val MOCK_SIZE = 4096


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
            // Dobby (the native inline-hook backend) is statically linked into libadh_agent.so —
            // no separate .so to load.
            System.loadLibrary("adh_agent"); "agent: libadh_agent 已加载（模拟注入）"
        } catch (t: Throwable) {
            Log.w(TAG, "idh_agent not loaded: ${t.message}"); "agent: 未加载 — ${t.message}"
        }

        // Java-layer crypto interception: interposing JCE provider captures algorithm/key/
        // IV/plaintext/ciphertext at the Cipher/Mac/MessageDigest API boundary (richer than
        // the native EVP hook). Install AFTER the agent so AdhReport's native is bound.
        AdhSecurity.install()

        // 低频加解密流：让 hook/捕获始终有东西可看；需要安静目标时可在「加解密」页停掉。
        JavaCrypto.startLiveDriver()

        setContentView(buildRoot(pid, loadStatus))
    }

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

    // 这个 App 只做"被插件观测/触发"的测试宿主：控制台在浏览器 Web UI 与手机侧 ADH Manager，
    // 这里不重复实现；本页只显示宿主自身状态，其余标签页是可以手动点击的能力触发点。
    private fun statusPage(pid: Int, loadStatus: String): View = page {
        addView(card {
            addView(sectionTitle("测试宿主状态"))
            addView(body("pid = $pid"))
            addView(body(loadStatus, muted = true))
            addView(space(4))
            addView(body("手动点击各标签页即可触发对应能力；控制台请看 Web UI / ADH Manager。", muted = true))
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
            subtitle = "插件功能测试宿主 · pid=$pid"
        }
        val tabs = TabLayout(this).apply { tabMode = TabLayout.MODE_SCROLLABLE }
        val content = FrameLayout(this)

        val pages = listOf(
            "状态" to statusPage(pid, loadStatus),
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

}
