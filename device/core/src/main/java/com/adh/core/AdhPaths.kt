package com.adh.core

/**
 * Device-side path + package constants — single source of truth for Manager / Device Daemon.
 * Zygisk C++ mirrors [SCOPE_PATH] / [MANAGER_PKG] / [MODULE_DIR] by hand
 * (see injector/zygisk/jni/main.cpp); keep in sync when changing.
 */
object AdhPaths {
    const val SCOPE_PATH = "/data/adb/adh/scope.json"
    const val SCOPE_DIR = "/data/adb/adh"
    const val LOADER_MARKER = "/data/adb/adh/zygisk_loaded"
    const val DAEMON_READY_MARKER = "/data/adb/adh/device_daemon_ready"
    const val DAEMON_PID_PATH = "/data/adb/adh/device_daemon.pid"
    const val MODULE_DIR = "/data/adb/modules/adh"
    const val MODULE_PROP = "/data/adb/modules/adh/module.prop"
    const val MANAGER_PKG = "com.adh.manager"
    const val DAEMON_PKG = "com.adh.daemon"
    const val AGENT_SO_NAME = "libadh_agent.so"
}
