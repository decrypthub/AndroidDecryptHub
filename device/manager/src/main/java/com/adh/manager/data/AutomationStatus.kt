package com.adh.manager.data

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.view.accessibility.AccessibilityManager
import com.adh.manager.automation.AdhAutomationAccessibilityService

object AutomationStatus {
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
