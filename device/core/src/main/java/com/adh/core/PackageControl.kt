package com.adh.core

/**
 * Guardrail for Device Daemon process control (force-stop / restart).
 * Manager must not call `am`/`su`; the daemon still refuses critical packages.
 */
object PackageControl {
    const val ACTION_OPEN = "open"
    const val ACTION_STOP = "stop"
    const val ACTION_RESTART = "restart"

    const val RESULT_OK = "ok"
    const val RESULT_DENIED = "denied"
    const val RESULT_NO_LAUNCHER = "no_launcher"
    const val RESULT_FAILED = "failed"

    private val PACKAGE_NAME =
        Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")

    private val BLOCKED: Set<String> = setOf(
        AdhPaths.DAEMON_PKG,
        "android",
        "com.android.systemui",
    )

    fun isAction(action: String?): Boolean =
        action == ACTION_OPEN || action == ACTION_STOP || action == ACTION_RESTART

    fun mayControl(packageName: String?): Boolean {
        val pkg = packageName?.trim().orEmpty()
        if (pkg.isEmpty() || !PACKAGE_NAME.matches(pkg)) return false
        if (HardExcludes.isExcluded(pkg) || BLOCKED.contains(pkg)) return false
        return true
    }
}
