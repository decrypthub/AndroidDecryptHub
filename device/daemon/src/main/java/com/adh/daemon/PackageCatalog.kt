package com.adh.daemon

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
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
    private var catalogCache: Pair<Long, String>? = null
    private val iconCache = LinkedHashMap<String, Pair<Long, ByteArray>>(256, 0.75f, true)
    private val iconCacheLock = Any()

    private fun nowMs(): Long = System.nanoTime() / 1_000_000

    @Synchronized fun listJson(context: Context): String {
        val now = nowMs()
        catalogCache?.let { if (now - it.first < 10_000) return it.second }
        val encoded = InstalledAppsJson.encode(list(context))
        catalogCache = now to encoded
        return encoded
    }

    fun iconPng(context: Context, packageName: String?): ByteArray {
        val pkg = packageName?.trim().orEmpty()
        if (pkg.isEmpty() || HardExcludes.isExcluded(pkg) || pkg == AdhPaths.DAEMON_PKG) return ByteArray(0)
        val pm = context.packageManager
        val packageInfo = runCatching {
            if (Build.VERSION.SDK_INT >= 33) pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(0))
            else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(pkg, 0)
            }
        }.getOrNull() ?: return ByteArray(0)
        val version = if (Build.VERSION.SDK_INT >= 28) packageInfo.longVersionCode else {
            @Suppress("DEPRECATION")
            packageInfo.versionCode.toLong()
        }
        val key = pkg + '@' + version + ':' + packageInfo.lastUpdateTime
        val now = nowMs()
        synchronized(iconCacheLock) { iconCache[key] }?.let {
            if (now - it.first < 600_000) return it.second
        }
        val rendered = renderIcon(context, pkg)
        synchronized(iconCacheLock) {
            iconCache[key] = now to rendered
            while (iconCache.size > 256) iconCache.remove(iconCache.keys.first())
        }
        return rendered
    }

    private fun renderIcon(context: Context, pkg: String): ByteArray {
        val pm = context.packageManager
        // getApplicationIcon() never returns null: on any resource miss it hands back the
        // system default icon, which would paint the same Android robot on every row.
        // Resolve the drawable through the app's Resources directly so failures stay empty.
        val info = runCatching { pm.getApplicationInfo(pkg, PackageManager.GET_META_DATA) }.getOrNull()
            ?: return ByteArray(0)
        if (info.icon == 0) return ByteArray(0)
        val res = runCatching { pm.getResourcesForApplication(info) }.getOrNull() ?: return ByteArray(0)
        val drawable = runCatching { res.getDrawable(info.icon, null) }.getOrNull() ?: return ByteArray(0)
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
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(0)
        }
        return infos.mapNotNull { info -> info.applicationInfo?.let { appInfo -> toApp(pm, appInfo, info) } }
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
            if (info != null) toApp(pm, info, null) else InstalledApp(pkg, pkg, system)
        }
    }

    private fun toApp(pm: PackageManager, info: ApplicationInfo, packageInfo: PackageInfo?): InstalledApp {
        val label = runCatching { pm.getApplicationLabel(info).toString() }
            .getOrDefault(info.packageName)
        val system = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val version = packageInfo?.let {
            if (Build.VERSION.SDK_INT >= 28) it.longVersionCode else {
                @Suppress("DEPRECATION")
                it.versionCode.toLong()
            }
        } ?: 0
        return InstalledApp(info.packageName, label, system, version, packageInfo?.lastUpdateTime ?: 0, info.icon != 0)
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
