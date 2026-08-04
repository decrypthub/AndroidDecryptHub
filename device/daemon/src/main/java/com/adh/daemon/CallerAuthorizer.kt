package com.adh.daemon

internal object CallerAuthorizer {
    fun isAuthorized(
        callingUid: Int,
        packagesForUid: Set<String>,
        signerDigests: Set<String>,
        expectedPackage: String,
        expectedSignerDigest: String,
    ): Boolean {
        if (callingUid < 10_000) return false
        if (expectedSignerDigest.isBlank()) return false
        if (expectedPackage !in packagesForUid) return false
        val expected = normalizeDigest(expectedSignerDigest)
        return signerDigests.any { normalizeDigest(it) == expected }
    }

    fun normalizeDigest(value: String): String =
        value.filter { it.isLetterOrDigit() }.uppercase()
}
