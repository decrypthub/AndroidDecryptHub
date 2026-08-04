package com.adh.daemon

import android.content.Context

internal object SystemContext {
    fun create(): Context {
        exemptHiddenApis()
        val activityThreadClass = Class.forName("android.app.ActivityThread")
        val thread = activityThreadClass.getDeclaredMethod("systemMain").invoke(null)
        return activityThreadClass.getDeclaredMethod("getSystemContext").invoke(thread) as Context
    }

    private fun exemptHiddenApis() {
        runCatching {
            val vmRuntime = Class.forName("dalvik.system.VMRuntime")
            val runtime = vmRuntime.getDeclaredMethod("getRuntime").invoke(null)
            vmRuntime.getDeclaredMethod("setHiddenApiExemptions", Array<String>::class.java)
                .invoke(
                    runtime,
                    arrayOf(
                        "Landroid/app/ActivityManager;",
                        "Landroid/app/ActivityThread;",
                        "Landroid/app/ContentProviderHolder;",
                        "Landroid/app/IActivityManager;",
                        "Landroid/content/IContentProvider;",
                    ),
                )
        }
    }
}
