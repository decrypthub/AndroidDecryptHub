package com.adh.daemon

import android.content.Context
import android.content.pm.PackageManager
import android.os.Binder
import android.os.Build
import com.adh.core.AdhPaths
import java.security.MessageDigest

internal class ManagerCallerVerifier(private val context: Context) {
    fun enforce() {
        val uid = Binder.getCallingUid()
        val packages = context.packageManager.getPackagesForUid(uid)?.toSet().orEmpty()
        val digests = managerSignerDigests()
        if (!CallerAuthorizer.isAuthorized(
                callingUid = uid,
                packagesForUid = packages,
                signerDigests = digests,
                expectedPackage = AdhPaths.MANAGER_PKG,
                expectedSignerDigest = BuildConfig.MANAGER_CERT_SHA256,
            )
        ) {
            throw SecurityException("unauthorized ADH Device Daemon caller uid=$uid")
        }
    }

    @Suppress("DEPRECATION")
    private fun managerSignerDigests(): Set<String> {
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            PackageManager.GET_SIGNATURES
        }
        val info = context.packageManager.getPackageInfo(AdhPaths.MANAGER_PKG, flags)
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signingInfo = info.signingInfo ?: return emptySet()
            if (signingInfo.hasMultipleSigners()) signingInfo.apkContentsSigners.toList()
            else signingInfo.signingCertificateHistory.toList()
        } else {
            info.signatures?.toList().orEmpty()
        }
        return signatures.mapTo(linkedSetOf()) { signature ->
            MessageDigest.getInstance("SHA-256")
                .digest(signature.toByteArray())
                .joinToString("") { "%02X".format(it) }
        }
    }
}
