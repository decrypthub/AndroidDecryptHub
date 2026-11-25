package com.adh.sandbox

import android.content.ContentProvider
import android.content.ContentValues
import android.content.pm.ApplicationInfo
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Build
import android.os.Bundle
import android.system.Os
import android.system.OsConstants
import android.util.Base64
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.file.Files
import java.security.MessageDigest

/** Files owned by this Demo, using the app's real storage access. Included only in fileLab. */
class DemoFilesProvider : ContentProvider() {
    private class Denied(val status: Int) : Exception()

    companion object {
        private const val APP = "com.adh.sandbox.filelab"
        private const val SHELL_UID = 2000
        private const val NOTE = "adh-demo-external.txt"
        private const val PREVIEW = 32 * 1024
        private const val EDIT = 8 * 1024
        private const val MAX_ENTRIES = 320
        private const val BASE64_FLAGS = Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
        private val TOKEN = Regex("[A-Za-z0-9_-]*")
        private val REVISION = Regex("[0-9a-f]{64}")
        private val TEXT = Regex("""\.(txt|log|md|json|jsonl|csv|tsv|xml|yaml|yml|ini|properties)$""", RegexOption.IGNORE_CASE)
    }

    override fun onCreate() = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        val app = context ?: return reply(503)
        if (Binder.getCallingUid() != SHELL_UID || app.packageName != APP ||
            (app.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) == 0) {
            throw SecurityException("The isolated Demo only accepts the USB debugging shell")
        }
        if (method != "list" && method != "preview" && method != "save" && method != "prepare") return reply(400)
        val identity = Binder.clearCallingIdentity()
        try {
            return synchronized(this) {
                val root = app.getExternalFilesDir(null)?.canonicalFile ?: throw Denied(503)
                if (!root.isDirectory) throw Denied(503)
                when (method) {
                    "list" -> reply(200, list(root, pathArg(arg)))
                    "preview" -> {
                        val path = pathArg(arg)
                        if (!TEXT.containsMatchIn(path)) throw Denied(415)
                        reply(200, read(resolve(root, path), PREVIEW + 1))
                    }
                    "save" -> reply(200, save(root, arg).toByteArray(Charsets.US_ASCII))
                    else -> {
                        if (!arg.isNullOrEmpty()) throw Denied(400)
                        prepare(root)
                        reply(200)
                    }
                }
            }
        } catch (e: Denied) {
            return reply(e.status)
        } catch (_: Exception) {
            // Don't expose system paths or raw Android errors to the browser.
            return reply(503)
        } finally {
            Binder.restoreCallingIdentity(identity)
        }
    }

    private fun resolve(root: File, path: String): File {
        if (!validPath(path)) throw Denied(400)
        val file = if (path.isEmpty()) root else File(root, path)
        if (file.canonicalFile != file) throw Denied(404)
        return file
    }

    private fun validPath(path: String): Boolean =
        path.isEmpty() || (path.toByteArray().size <= 2048 &&
            path.none { it <= '\u001f' || it == '\u007f' || it == '\\' || it == '\ufffd' } &&
            path.split('/').let { parts ->
                parts.size <= 24 && parts.all { it.isNotEmpty() && !it.startsWith('.') && it.toByteArray().size <= 240 }
            })

    private fun list(root: File, path: String): ByteArray {
        val dir = resolve(root, path)
        if (!dir.isDirectory) throw Denied(404)
        val result = ByteArrayOutputStream()
        var count = 0
        Files.newDirectoryStream(dir.toPath()).use { stream ->
            for (item in stream) {
                val name = item.fileName.toString()
                if (!validPath(name)) continue
                val entry = item.toFile()
                if (entry.canonicalFile != entry) continue
                val kind = when {
                    entry.isDirectory -> "directory"
                    entry.isFile -> "file"
                    else -> continue
                }
                for (word in listOf(name, kind, entry.length().toString(), (entry.lastModified() / 1000L).toString())) {
                    result.write(word.toByteArray(Charsets.UTF_8))
                    result.write(0)
                }
                if (++count > MAX_ENTRIES) break
            }
        }
        return result.toByteArray()
    }

    private fun read(file: File, limit: Int): ByteArray {
        if (!file.isFile) throw Denied(404)
        val fd = Os.open(file.path, OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW or OsConstants.O_NONBLOCK, 0)
        try {
            if (!OsConstants.S_ISREG(Os.fstat(fd).st_mode)) throw Denied(404)
            val buffer = ByteArray(limit)
            var size = 0
            while (size < limit) {
                val n = Os.read(fd, buffer, size, limit - size)
                if (n == 0) break
                size += n
            }
            return buffer.copyOf(size)
        } finally {
            Os.close(fd)
        }
    }

    private fun save(root: File, arg: String?): String {
        val fields = arg?.split('.', limit = 2) ?: throw Denied(400)
        if (fields.size != 2 || !REVISION.matches(fields[0])) throw Denied(400)
        val expected = fields[0]
        val bytes = decode(fields[1], EDIT)
        requireEditText(bytes)
        val file = resolve(root, NOTE)
        fun confirmSource() {
            val before = read(file, EDIT + 1)
            if (before.size > EDIT || digest(before) != expected) throw Denied(409)
            requireEditText(before)
        }
        confirmSource()
        val temp = File.createTempFile(".adh-", ".pending", root)
        try {
            FileOutputStream(temp).use {
                it.write(bytes)
                it.fd.sync()
            }
            confirmSource()
            Os.rename(temp.path, file.path)
            val next = digest(bytes)
            if (digest(read(file, EDIT + 1)) != next) throw Denied(409)
            return next
        } finally {
            temp.delete()
        }
    }

    private fun prepare(root: File) {
        fun create(path: String, text: String) {
            val file = resolve(root, path)
            if (file.createNewFile()) file.writeText(text, Charsets.UTF_8)
        }
        val dir = resolve(root, "记录")
        if (!dir.isDirectory && !dir.mkdir()) throw Denied(503)
        create("记录/说明.txt", "由 ADH Demo 写入应用专属外部目录。\n设备：" + Build.MODEL + "\n")
        create(NOTE, "这是 Demo 的外部目录记事本，可以在 ADH 保存到原文件。\n")
    }

    private fun pathArg(arg: String?): String = utf8(decode(arg.orEmpty(), 2048))

    private fun utf8(bytes: ByteArray): String = try {
        Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString()
    } catch (_: Exception) {
        throw Denied(415)
    }

    private fun requireEditText(bytes: ByteArray) {
        if (utf8(bytes).any { it == '\u0000' || it == '\r' || it == '\uFEFF' }) throw Denied(415)
    }

    private fun decode(input: String, limit: Int): ByteArray {
        if (input.length > (limit * 4 + 2) / 3) throw Denied(413)
        if (!TOKEN.matches(input)) throw Denied(400)
        val result = try { Base64.decode(input, BASE64_FLAGS) } catch (_: IllegalArgumentException) { throw Denied(400) }
        if (result.size > limit || Base64.encodeToString(result, BASE64_FLAGS) != input) throw Denied(400)
        return result
    }

    private fun digest(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun reply(status: Int, payload: ByteArray = byteArrayOf()) = Bundle().apply {
        val encoded = Base64.encodeToString(payload, BASE64_FLAGS)
        putString("adhFile", "$status.$encoded")
    }

    override fun getType(uri: Uri): String? = null
    override fun query(uri: Uri, projection: Array<out String>?, selection: String?,
                       selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = throw UnsupportedOperationException()
    override fun insert(uri: Uri, values: ContentValues?): Uri? = throw UnsupportedOperationException()
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = throw UnsupportedOperationException()
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int =
        throw UnsupportedOperationException()
}
