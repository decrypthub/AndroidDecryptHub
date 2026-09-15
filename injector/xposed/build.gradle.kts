// Optional LSPosed/Xposed backend (module W). Pure Java + AGP only — the module carries no
// AndroidX, no Kotlin and no analysis code: it exists to bring the ADH agent into a scoped
// target process and nothing else.
plugins {
    id("com.android.application") version "8.7.3" apply false
}