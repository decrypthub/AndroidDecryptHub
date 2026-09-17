package com.adh.manager.data

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.view.accessibility.AccessibilityManager
import com.adh.manager.automation.AdhAutomationAccessibilityService

object AutomationStatus {
    /**
     * Live bridge state as last reported by the AccessibilityService:
     * "disabled" | "connecting:<endpoint>" | "connected:<endpoint>" | "error:<failure>".
     * The Manager UI shows it so an operator can tell "the AI cannot reach the host" from
     * "the AI is connected but this app is not allowlisted".
     */
    @Volatile
    var bridgeState: String = "disabled"

    fun bridgeSummary(): String = when {
        bridgeState == "disabled" -> "未启用"
        bridgeState.startsWith("connected:") -> "已连接 " + bridgeState.removePrefix("connected:")
        bridgeState.startsWith("connecting:") -> "正在连接 " + bridgeState.removePrefix("connecting:")
        bridgeState.startsWith("error:") -> "未连接（" + bridgeState.removePrefix("error:") + "）"
        else -> bridgeState
    }

    fun isServiceEnabled(context: Context): Boolean {
        val manager = context.getSystemService(AccessibilityManager::class.java) ?: return false
        val expectedPackage = context.packageName
        val expectedClass = AdhAutomationAccessibilityService::class.java.name
        return manager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK).any { service ->
            val info = service.resolveInfo?.serviceInfo ?: return@any false
            info.packageName == expectedPackage && info.name == expectedClass
        }
    }
}
