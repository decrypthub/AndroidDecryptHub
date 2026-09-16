package com.adh.core

/** Binder protocol between Manager and the root Device Daemon. */
object AdhProtocol {
    /** v1: scope + module status. v2: + catalog. v3: + icons. v4: + stop/restart. v5: + optional Xposed backend. v6: + app open. v7: + automation service control. v8: + device power state. v9: + raw input injection. */
    const val VERSION = 9
    const val MIN_SCOPE_VERSION = 1
    const val MIN_CATALOG_VERSION = 2
    const val MIN_ICON_VERSION = 3
    const val MIN_PROCESS_VERSION = 4
    const val MIN_XPOSED_VERSION = 5
    const val MIN_APP_OPEN_VERSION = 6
    const val MIN_AUTOMATION_CONTROL_VERSION = 7
    const val MIN_DEVICE_POWER_VERSION = 8
    /** Raw input injection through the root daemon (fallback for rejected accessibility gestures). */
    const val MIN_INPUT_INJECTION_VERSION = 9
}
