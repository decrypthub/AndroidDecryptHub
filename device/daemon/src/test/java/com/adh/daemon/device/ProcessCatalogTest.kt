package com.adh.daemon.device

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class ProcessCatalogTest {
    @get:Rule val temp = TemporaryFolder()

    private val pkg = "com.adh.sandbox.apilab"

    /** /proc/<pid>/stat: starttime is field 22, i.e. index 19 after "(comm) ". */
    private fun stat(pid: Int, comm: String, start: Long) =
        "$pid ($comm) S 1 $pid $pid 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 $start 0 0\n"

    private fun status(uid: Int?) =
        "Name:\t$pkg\n" + (uid?.let { "Uid:\t$it\t$it\t$it\t$it\n" } ?: "Gid:\t10210\t10210\t10210\t10210\n")

    private fun proc(): File = temp.newFolder("proc")

    private fun liveProcess(root: File, pid: Int, comm: String = pkg, start: Long = 9001, uid: Int? = 10210): File {
        val dir = File(root, pid.toString()).apply { mkdirs() }
        File(dir, "cmdline").writeText("$comm\u0000")
        File(dir, "stat").writeText(stat(pid, comm, start))
        File(dir, "status").writeText(status(uid))
        return dir
    }

    @Test
    fun `a process that exits during the scan is skipped, not counted as unknown`() {
        val root = proc()
        liveProcess(root, 100)
        // cmdline already gone: the pid vanished between listFiles() and the read.
        File(root, "101").mkdirs()
        // stat gone but cmdline still readable: exits between the two reads.
        File(root, "102").apply { mkdirs() }.let { File(it, "cmdline").writeText("$pkg\u0000") }

        val snapshot = ProcessCatalog(root).list(pkg)
        assertEquals(1, snapshot.getJSONArray("processes").length())
        assertEquals(0, snapshot.getInt("inaccessible"))
        assertTrue("a vanished pid must not poison completeness", snapshot.getBoolean("complete"))
    }

    @Test
    fun `a readable but unattributable process still makes the scan incomplete`() {
        val root = proc()
        liveProcess(root, 100)
        // Files exist and read fine, but there is no Uid line: this is not a race, it is unknown.
        File(root, "103").apply { mkdirs() }.let { dir ->
            File(dir, "cmdline").writeText("$pkg\u0000")
            File(dir, "stat").writeText(stat(103, pkg, 9002))
            File(dir, "status").writeText(status(null))
        }

        val snapshot = ProcessCatalog(root).list(pkg)
        assertEquals(1, snapshot.getInt("inaccessible"))
        assertFalse(snapshot.getBoolean("complete"))
    }

    @Test
    fun `starting a stopped package is allowed - empty expected set against an empty view`() {
        val root = proc()
        liveProcess(root, 200, comm = "com.other.app", uid = 10300)
        // Nothing of `pkg` is running; the host is about to open it.
        ProcessCatalog(root).verify(pkg, JSONArray())
    }

    @Test
    fun `an exact identity set passes the fence`() {
        val root = proc()
        liveProcess(root, 100, start = 9001)
        liveProcess(root, 101, comm = "$pkg:worker", start = 9002)
        ProcessCatalog(root).verify(pkg, JSONArray()
            .put(JSONObject().put("pid", 100).put("uid", 10210).put("starttimeTicks", "9001"))
            .put(JSONObject().put("pid", 101).put("uid", 10210).put("starttimeTicks", "9002")))
    }

    @Test
    fun `a restarted process generation is refused`() {
        val root = proc()
        liveProcess(root, 100, start = 9002)
        val error = runCatching {
            ProcessCatalog(root).verify(pkg, JSONArray().put(JSONObject().put("pid", 100).put("uid", 10210).put("starttimeTicks", "9001")))
        }.exceptionOrNull()
        assertTrue(error is DeviceFault)
        assertEquals("TARGET_CHANGED", (error as DeviceFault).code)
    }

    @Test
    fun `a missing proc tree is reported instead of looking empty`() {
        val error = runCatching { ProcessCatalog(File(temp.root, "absent")).list(pkg) }.exceptionOrNull()
        assertTrue(error is DeviceFault)
        assertEquals("PROC_UNAVAILABLE", (error as DeviceFault).code)
    }
}
