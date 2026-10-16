package com.adh.core

/** Binder protocol between Manager and the root Device Daemon. */
object AdhProtocol {
    /** v1-v6: scope, app catalog/icons/process control, and app open. v13 removes phone automation
     *  surfaces; v14 removes an optional injection backend; v15 adds per-package capture policy.
     *  v16 briefly carried an SSL-bypass section; that section was removed and a leftover `b` key
     *  is ignored. The number stays 16 so an already-installed peer is not told it is older. */
    const val VERSION = 16
    const val MIN_SCOPE_VERSION = 1
    const val MIN_CATALOG_VERSION = 2
    const val MIN_ICON_VERSION = 3
    const val MIN_PROCESS_VERSION = 4
    const val MIN_APP_OPEN_VERSION = 6
    /** Floors track the protocol version a feature APPEARED at: v15 introduced per-package policy. */
    const val MIN_POLICY_VERSION = 15
}
