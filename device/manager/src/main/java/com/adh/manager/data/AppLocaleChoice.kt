package com.adh.manager.data

/** Which of the two shipped locales the UI should show. Empty stored tags follow the system language. */
object AppLocaleChoice {
    const val ZH = "zh"
    const val EN = "en"

    fun selected(storedTags: String, systemLanguage: String): String {
        return when (head(storedTags)) {
            EN -> EN
            ZH -> ZH
            else -> if (systemLanguage.lowercase().startsWith(EN)) EN else ZH
        }
    }

    fun matches(storedTags: String, tag: String): Boolean = head(storedTags) == tag

    private fun head(tags: String): String =
        tags.substringBefore(',').substringBefore('-').trim().lowercase()
}
