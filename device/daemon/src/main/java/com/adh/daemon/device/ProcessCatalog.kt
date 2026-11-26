package com.adh.daemon.device

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileNotFoundException
import java.nio.file.NoSuchFileException

/**
 * True only when the pid entry really left /proc. Android's FileInputStream throws the same
 * FileNotFoundException for EACCES, so the message decides: a denied read is an unknown
 * process, not an exited one.
 */
internal fun processVanished(error: Exception): Boolean {
    if (error is NoSuchFileException) return true
    if (error !is FileNotFoundException) return false
    val message = error.message?.lowercase().orEmpty()
    return !(message.contains("permission denied") || message.contains("eacces") || message.contains("denied"))
}

internal class ProcessCatalog(private val proc: File = File("/proc")) {
    fun list(packageName: String, offset: Int = 0, limit: Int = 200): JSONObject {
        val rows = mutableListOf<JSONObject>()
        var inaccessible = 0
        val directories = proc.listFiles() ?: throw DeviceFault("PROC_UNAVAILABLE", "process directory unavailable")
        for (dir in directories.filter { it.name.toIntOrNull() != null }.take(8192)) {
            val command = try { File(dir, "cmdline").inputStream().use { val bytes = ByteArray(4096); val count = it.read(bytes); if (count < 0) "" else String(bytes, 0, count).substringBefore('\u0000') } }
                catch (error: Exception) { if (vanished(error)) continue; inaccessible++; continue }
            if (command.isBlank() || packageName.isNotEmpty() && command != packageName && !command.startsWith("$packageName:")) continue
            val row = try {
                val stat = File(dir, "stat").readText()
                val fields = stat.substring(stat.lastIndexOf(')') + 2).trim().split(Regex("\\s+"))
                val start = fields[19]; require(Regex("[0-9]+").matches(start))
                val uid = File(dir, "status").useLines { lines -> lines.first { it.startsWith("Uid:") }.substringAfter(':').trim().split(Regex("\\s+"))[0].toInt() }
                JSONObject().put("pid", dir.name.toInt()).put("uid", uid).put("starttimeTicks", start).put("process", command).put("package", command.substringBefore(':'))
            } catch (error: Exception) { if (vanished(error)) continue; inaccessible++; continue }
            rows.add(row)
        }
        rows.sortBy { it.getInt("pid") }
        return JSONObject().put("processes", JSONArray(rows.drop(offset).take(limit))).put("total", rows.size).put("nextOffset", if (offset + limit < rows.size) offset + limit else JSONObject.NULL)
            .put("complete", inaccessible == 0 && directories.size <= 8192).put("inaccessible", inaccessible)
    }

    /**
     * A process exiting between listFiles() and the per-pid reads is normal, not an unknown:
     * counting it made `complete` flip at random and every write then failed its precondition
     * (IDENTITY_UNVERIFIED) even though nothing had changed for the target package.
     *
     * Android reports EACCES through the same FileNotFoundException type, so the type alone is
     * not enough: treating a denied read as "gone" would hide a process the fence never saw.
     */
    private fun vanished(error: Exception): Boolean = processVanished(error)

    fun verify(packageName: String, expected: JSONArray) {
        require(expected.length() <= 128)
        // One rescan: an incomplete first pass is usually a process that just exited. A second
        // incomplete pass is reported as such instead of being retried forever.
        var actual = list(packageName, 0, 128)
        if (!actual.getBoolean("complete") || actual.getInt("total") > 128) actual = list(packageName, 0, 128)
        if (!actual.getBoolean("complete") || actual.getInt("total") > 128) throw DeviceFault("IDENTITY_UNVERIFIED", "cannot verify all current package processes")
        fun identities(array: JSONArray): String = (0 until array.length()).map { array.getJSONObject(it) }.map {
            "${it.getInt("pid")}:${it.getInt("uid")}:${it.getString("starttimeTicks")}" }.sorted().joinToString(",")
        if (identities(actual.getJSONArray("processes")) != identities(expected)) throw DeviceFault("TARGET_CHANGED", "package process generations changed before dispatch")
    }
}
