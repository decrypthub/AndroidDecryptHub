package com.adh.sandbox

import android.util.Log
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream

// Real file read/write against an app-private path — the JNI-reflection target for
// cmd_file_hook_test. Java FileOutputStream.write()/FileInputStream.read() route through
// libcore's native layer into libc open/openat/read/write/close, which is exactly where
// the agent's GOT hook (see cmd_file_probe / cmd_file_hook_test) intercepts them.
object FileIO {
    private const val TAG = "ADH_SANDBOX"
    private const val FILE_NAME = "adh_file_test.txt"
    const val MARKER = "ADH_FILE_MARKER_v1"

    @JvmStatic
    fun run(): String = runWith("$MARKER 订单号=A20260714 金额=199.00元")

    @JvmStatic
    fun runWith(content: String): String {
        return try {
            val path = filePath()
            val bytes = content.toByteArray(Charsets.UTF_8)
            FileOutputStream(path).use { it.write(bytes) }

            val readBack = ByteArray(bytes.size)
            FileInputStream(path).use { fis ->
                var off = 0
                while (off < readBack.size) {
                    val n = fis.read(readBack, off, readBack.size - off)
                    if (n < 0) break
                    off += n
                }
            }
            val ok = readBack.contentEquals(bytes)
            val summary = "写入${bytes.size}B 读回${readBack.size}B 校验${if (ok) "OK" else "FAIL"} path=$path"
            Log.i(TAG, "FileIO: $summary")
            summary
        } catch (t: Throwable) {
            Log.w(TAG, "FileIO failed: ${t.message}")
            "error:${t.message}"
        }
    }

    private fun filePath(): String {
        val dir = File("/data/data/com.adh.sandbox/files")
        if (!dir.exists()) dir.mkdirs()
        return File(dir, FILE_NAME).absolutePath
    }
}
