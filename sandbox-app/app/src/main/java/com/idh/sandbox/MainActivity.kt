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
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
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

    // ---- Material dark palette (kept in code, mirrors res/values/colors.xml) ----
    private val cBg = Color.parseColor("#0F1116")
    private val cSurface = Color.parseColor("#1A1D26")
    private val cSurfaceAlt = Color.parseColor("#20242F")
    private val cPrimary = Color.parseColor("#8AB4FF")
    private val cSecondary = Color.parseColor("#8AE6B0")
    private val cFg = Color.parseColor("#E6E9F2")
    private val cMuted = Color.parseColor("#8890A6")
    private val cDanger = Color.parseColor("#FF8FA3")

    @Volatile private var polling = true
    private var lanUrl: String = ""            // host LAN URL, discovered from idhd /health
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

    // ---- UI building blocks (Material Components, built programmatically) -------------

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun label(text: String, size: Float, color: Int, bold: Boolean = false): TextView =
        TextView(this).apply {
            this.text = text; textSize = size; setTextColor(color)
            if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD)
            setPadding(0, dp(2), 0, dp(2))
        }

    private fun sectionTitle(text: String): TextView = label(text, 13f, cPrimary, bold = true)

    private fun urlView(text: String, color: Int, onTap: () -> Unit): TextView =
        TextView(this).apply {
            this.text = text; textSize = 16f; setTextColor(color)
            setTypeface(android.graphics.Typeface.MONOSPACE, android.graphics.Typeface.BOLD)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            setBackgroundColor(cSurfaceAlt)
            isClickable = true
            setOnClickListener { onTap() }
        }

    private fun spacer(h: Int) = View(this).apply {
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(h))
    }

    // Material filled button, equal-width within its row, rounded + ripple out of the box.
    private fun mbutton(text: String, danger: Boolean = false, onTap: () -> Unit) = MaterialButton(this).apply {
        this.text = text; isAllCaps = false; textSize = 13f
        cornerRadius = dp(10)
        insetTop = 0; insetBottom = 0
        setPadding(dp(4), dp(8), dp(4), dp(8))
        backgroundTintList = android.content.res.ColorStateList.valueOf(if (danger) cDanger else cPrimary)
        setTextColor(if (danger) Color.parseColor("#2A0A12") else Color.parseColor("#0B1220"))
        setOnClickListener { onTap() }
        layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            .apply { marginEnd = dp(8) }
    }

    // A row of equal-width buttons.
    private fun btnRow(vararg b: MaterialButton) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        setPadding(0, dp(4), 0, dp(4))
        b.forEach { addView(it) }
    }

    // A Material card wrapping a vertical section — the base unit of the new layout.
    private fun card(build: LinearLayout.() -> Unit): MaterialCardView {
        val inner = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), dp(14), dp(14), dp(14))
        }
        inner.build()
        return MaterialCardView(this).apply {
            radius = dp(16).toFloat()
            cardElevation = dp(2).toFloat()
            setCardBackgroundColor(cSurface)
            strokeColor = Color.parseColor("#2A2F3D")
            strokeWidth = dp(1)
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
                .apply { bottomMargin = dp(14) }
            addView(inner)
        }
    }

    private fun buildUi(pid: Int, loadStatus: String): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(cBg)
            setPadding(dp(16), dp(22), dp(16), dp(24))
        }

        // --- header ---
        root.addView(label("ADH · Android DecryptHub", 22f, cFg, bold = true))
        root.addView(label("运行时逆向分析 · 沙盒宿主（模拟注入）  ·  pid=$pid", 12f, cMuted))
        root.addView(spacer(16))

        // --- console access card ---
        root.addView(card {
            addView(sectionTitle("观测控制台（浏览器打开）— 点击地址复制"))
            urlLan = urlView("检测中…", cSecondary) { copy(bestUrl()) }
            addView(urlLan)
            reach = label("● 正在检测控制台…", 12f, cMuted)
            addView(reach)
            addView(spacer(6))
            addView(btnRow(
                mbutton("复制地址") { copy(bestUrl()) },
                mbutton("手机浏览器打开") { openBrowser(bestUrl()) },
            ))
            addView(label("本机 adb reverse：$LOCAL_URL", 11f, cMuted))
        })

        // --- crypto triggers card ---
        root.addView(card {
            addView(sectionTitle("加解密测试"))
            addView(spacer(4))
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

        // --- network + file I/O card (agent hook surface) ---
        root.addView(card {
            addView(sectionTitle("网络 / 文件 I/O 测试（Agent Hook）"))
            addView(spacer(4))
            addView(btnRow(
                mbutton("HTTPS 明文边界") { trigger("HTTPS") { Network.run() } },
                mbutton("加密+上送(关联)") { trigger("关联流") { CorrelatedFlow.run() } },
            ))
            addView(btnRow(
                mbutton("文件读写(Hook)") { trigger("文件读写") { FileIO.run() } },
            ))
        })

        // --- dex / trigger card ---
        root.addView(card {
            addView(sectionTitle("脱壳 / 触发"))
            addView(spacer(4))
            addView(btnRow(
                mbutton("加载内存 DEX") { trigger("加载DEX") { DynamicDex.load(); "已触发内存 DEX 加载（脱壳面板可见）" } },
                mbutton("触发脱壳类") { trigger("脱壳触发") { TriggerProbe.reset(); TriggerProbe.safeCompute() } },
            ))
        })

        // --- on-device result log card ---
        root.addView(card {
            addView(sectionTitle("测试日志"))
            addView(spacer(4))
            logView = TextView(this@MainActivity).apply {
                text = "（点击上面的按钮开始测试）"
                textSize = 12f; setTextColor(cFg)
                setTypeface(android.graphics.Typeface.MONOSPACE)
                setPadding(dp(12), dp(10), dp(12), dp(10))
                setBackgroundColor(cSurfaceAlt)
            }
            addView(logView)
        })

        return ScrollView(this).apply {
            setBackgroundColor(cBg)
            addView(root)
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
        while (logLines.size > 10) logLines.removeFirst()
        logView.text = logLines.joinToString("\n")
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
            reach.setTextColor(cSecondary)
            reach.text = "● 控制台在线" + (if (h.agents >= 0) "  ·  已连接 agents = ${h.agents}" else "")
        } else {
            urlLan.text = if (lanUrl.isNotEmpty()) lanUrl else "（等待控制台…）"
            reach.setTextColor(cDanger)
            reach.text = "● 未连接 —— 在电脑运行  bash tools/dev_up.sh  启动 idhd（并 adb reverse tcp:$WEB_PORT）"
        }
    }
}
