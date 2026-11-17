package com.adh.daemon.device

import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.UUID

/** Explicit initialization/writes only; callers never rebuild corrupt authoritative files. */
internal class DeviceFiles(val directory: File, private val secure: (File, Int) -> Unit = { _, _ -> }, private val syncDirectory: (File) -> Unit = {}) {
    fun initialize() { check(directory.mkdirs() || directory.isDirectory); secure(directory, 448) /* 0700 */ }
    fun write(file: File, text: String, mode: Int = 384) {
        val parent = checkNotNull(file.parentFile)
        check(parent.mkdirs() || parent.isDirectory)
        val temp = File(parent, ".${file.name}.${UUID.randomUUID()}.tmp")
        try {
            check(temp.createNewFile()); secure(temp, mode)
            FileOutputStream(temp).use { it.write(text.toByteArray(Charsets.UTF_8)); it.fd.sync() }
            Files.move(temp.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            secure(file, mode)
            syncDirectory(parent)
        } finally { temp.delete() }
    }
}
