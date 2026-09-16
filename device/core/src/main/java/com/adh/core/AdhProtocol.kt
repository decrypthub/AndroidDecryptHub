package com.adh.core

/** Binder protocol between Manager and the root Device Daemon. */
object AdhProtocol {
    /** v1: scope + module status. v2: + catalog. v3: + icons. v4: + stop/restart. v5: + optional Xposed backend. v6: + app open. */
    const val VERSION = 6
    const val MIN_SCOPE_VERSION = 1
    const val MIN_CATALOG_VERSION = 2
    const val MIN_ICON_VERSION = 3
    const val MIN_PROCESS_VERSION = 4
    const val MIN_XPOSED_VERSION = 5
    const val MIN_APP_OPEN_VERSION = 6
}
