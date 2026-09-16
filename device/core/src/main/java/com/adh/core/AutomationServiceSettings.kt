package com.adh.core

/**
 * Pure parsing/update helpers for Android's `enabled_accessibility_services` secure setting.
 * The daemon performs the privileged write; this object only owns the stable format rules.
 */
object AutomationServiceSettings {
    const val COMPONENT = "com.adh.manager/com.adh.manager.automation.AdhAutomationAccessibilityService"

    fun contains(serialized: String?, component: String = COMPONENT): Boolean =
        entries(serialized).contains(component)

    fun update(serialized: String?, enabled: Boolean, component: String = COMPONENT): String {
        val current = entries(serialized)
        val next = if (enabled) (current + component).distinct() else current.filterNot { it == component }
        return next.joinToString(":")
    }

    private fun entries(serialized: String?): List<String> =
        serialized.orEmpty()
            .split(':')
            .map(String::trim)
            .filter(String::isNotEmpty)
}
