package com.adh.manager.ui

import android.net.Uri

object Routes {
    const val HOME = "home"
    const val SCOPE = "scope"
    const val CERTS = "certs"
    const val HOOK = "hook/{packageName}"

    fun hook(packageName: String) = "hook/${Uri.encode(packageName)}"
}
