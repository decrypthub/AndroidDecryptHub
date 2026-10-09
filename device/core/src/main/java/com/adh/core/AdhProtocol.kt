package com.adh.core

/** Binder protocol between Manager and the root Device Daemon. */
object AdhProtocol {
    /** v1-v6: scope, app catalog/icons/process control, Xposed control, and app open. v13 removes phone automation surfaces. */
    const val VERSION = 13
    const val MIN_SCOPE_VERSION = 1
    const val MIN_CATALOG_VERSION = 2
    const val MIN_ICON_VERSION = 3
    const val MIN_PROCESS_VERSION = 4
    const val MIN_XPOSED_VERSION = 5
    const val MIN_APP_OPEN_VERSION = 6
}
