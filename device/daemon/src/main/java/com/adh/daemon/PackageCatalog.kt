package com.adh.daemon

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.os.Build
import android.util.Log
import com.adh.core.AdhPaths
import com.adh.core.HardExcludes
import com.adh.core.InstalledApp
import com.adh.core.InstalledAppsJson
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Enumerate installed packages from the uid=0 system context.
 * Manager must not call PackageManager itself — Android 11+ / ColorOS hides
 * sideloaded packages from QUERY_ALL_PACKAGES and can TransactionTooLarge.
 */
internal object PackageCatalog {
    private const val TAG = "AdhPackageCatalog"
    private const val ICON_PX = 96

    fun listJson(context: Context): String = InstalledAppsJson.encode(list(context))

    fun iconPng(context: Context, packageName: String?): ByteArray {
        val pkg = packageName?.trim().orEmpty()
        if (pkg.isEmpty() || HardExcludes.isExcluded(pkg) || pkg == AdhPaths.DAEMON_PKG) return ByteArray(0)
        val pm = context.packageManager
        val drawable = runCatching { pm.getApplicationIcon(pkg) }.getOrNull() ?: return ByteArray(0)
        return runCatching { drawableToPng(drawable) }.getOrDefault(ByteArray(0))
    }

    fun list(context: Context): List<InstalledApp> {
        val fromPm = runCatching { listFromPackageManager(context) }.getOrElse {
            Log.w(TAG, "PackageManager catalog failed", it)
            emptyList()
        }
        val apps = if (fromPm.size >= 2) fromPm else {
            Log.w(TAG, "PackageManager returned ${fromPm.size} apps; falling back to cmd package")
            listFromCmd(context.packageManager)
        }
        return apps
            .filterNot { HardExcludes.isExcluded(it.packageName) || it.packageName == AdhPaths.DAEMON_PKG }
            .sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.label })
    }

    private fun listFromPackageManager(context: Context): List<InstalledApp> {
        val pm = context.packageManager
        val infos = if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledApplications(0)
        }
        return infos.map { info -> toApp(pm, info) }
    }

    private fun listFromCmd(pm: PackageManager): List<InstalledApp> {
        val thirdParty = packagesFromCmd("-3")
        val system = packagesFromCmd("-s")
        val merged = LinkedHashMap<String, Boolean>()
        for (pkg in thirdParty) merged[pkg] = false
        for (pkg in system) merged.putIfAbsent(pkg, true)
        if (merged.isEmpty()) {
            for (pkg in packagesFromCmd()) merged.putIfAbsent(pkg, false)
        }
        return merged.map { (pkg, system) ->
            val info = runCatching { pm.getApplicationInfo(pkg, 0) }.getOrNull()
            if (info != null) toApp(pm, info) else InstalledApp(pkg, pkg, system)
        }
    }

    private fun toApp(pm: PackageManager, info: ApplicationInfo): InstalledApp {
        val label = runCatching { pm.getApplicationLabel(info).toString() }
            .getOrDefault(info.packageName)
        val system = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        return InstalledApp(info.packageName, label, system)
    }

    private fun packagesFromCmd(flag: String? = null): List<String> {
        val args = mutableListOf("/system/bin/cmd", "package", "list", "packages")
        if (!flag.isNullOrBlank()) args.add(flag)
        val proc = runCatching {
            ProcessBuilder(args)
                .directory(File("/"))
                .redirectErrorStream(true)
                .start()
        }.getOrElse {
            Log.w(TAG, "cmd package failed to start", it)
            return emptyList()
        }
        val lines = runCatching {
            proc.inputStream.bufferedReader().use { it.readLines() }
        }.getOrDefault(emptyList())
        val finished = runCatching { proc.waitFor(5, TimeUnit.SECONDS) }.getOrDefault(false)
        if (!finished) {
            proc.destroyForcibly()
            Log.w(TAG, "cmd package timed out")
        }
        return lines.mapNotNull { line ->
            val pkg = line.trim().removePrefix("package:").substringBefore('=').trim()
            pkg.takeIf { it.isNotEmpty() && it.contains('.') }
        }
    }

    private fun drawableToPng(drawable: Drawable): ByteArray {
        val bitmap = when {
            drawable is BitmapDrawable && drawable.bitmap != null &&
                drawable.bitmap.width == ICON_PX && drawable.bitmap.height == ICON_PX ->
                drawable.bitmap
            else -> {
                val bmp = Bitmap.createBitmap(ICON_PX, ICON_PX, Bitmap.Config.ARGB_8888)
                val canvas = Canvas(bmp)
                drawable.setBounds(0, 0, ICON_PX, ICON_PX)
                drawable.draw(canvas)
                bmp
            }
        }
        val out = ByteArrayOutputStream()
        bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
        if (bitmap !== (drawable as? BitmapDrawable)?.bitmap) bitmap.recycle()
        return out.toByteArray()
    }
}
