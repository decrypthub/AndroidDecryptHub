package com.adh.manager

import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import com.adh.manager.data.AppLocaleChoice
import java.util.Locale

object AppLocale {
    fun selectedTag(): String = AppLocaleChoice.selected(
        AppCompatDelegate.getApplicationLocales().toLanguageTags(),
        Locale.getDefault().language,
    )

    fun apply(tag: String) {
        val stored = AppCompatDelegate.getApplicationLocales().toLanguageTags()
        if (AppLocaleChoice.matches(stored, tag)) return
        AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(tag))
    }
}
