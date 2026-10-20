package com.adh.core

/** Binder protocol between Manager and the root Device Daemon. */
object AdhProtocol {
    /** v1-v6: scope, app catalog/icons/process control, and app open. v13 removes phone automation
     *  surfaces; v14 removes an optional injection backend; v15 adds per-package capture policy.
     *  v16 briefly carried an SSL-bypass section; that section was removed and a leftover `b` key
     *  is ignored. v17 stores the host address an injected process dials when adb reverse is absent.
     *  v18 stores user CA certificates that post-fs-data mounts into the system trust store. */
    const val VERSION = 18
    const val MIN_SCOPE_VERSION = 1
    const val MIN_CATALOG_VERSION = 2
    const val MIN_ICON_VERSION = 3
    const val MIN_PROCESS_VERSION = 4
    const val MIN_APP_OPEN_VERSION = 6
    /** Floors track the protocol version a feature APPEARED at: v15 introduced per-package policy. */
    const val MIN_POLICY_VERSION = 15
    /** v17 introduced the remembered host agent address (`/data/adb/adh/host.endpoint`). */
    const val MIN_HOST_ENDPOINT_VERSION = 17
    /** v18 introduced user CA import (`/data/adb/adh/cacerts`). */
    const val MIN_CA_CERT_VERSION = 18
}
