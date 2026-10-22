package com.adh.manager.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppLocaleChoiceTest {
    @Test
    fun storedTagWinsOverTheSystemLanguage() {
        assertEquals(AppLocaleChoice.EN, AppLocaleChoice.selected("en-US", "zh"))
        assertEquals(AppLocaleChoice.ZH, AppLocaleChoice.selected("zh-CN", "en"))
    }

    @Test
    fun emptyStoredTagFollowsTheSystemLanguage() {
        assertEquals(AppLocaleChoice.EN, AppLocaleChoice.selected("", "en"))
        assertEquals(AppLocaleChoice.ZH, AppLocaleChoice.selected("", "zh"))
        assertEquals(AppLocaleChoice.ZH, AppLocaleChoice.selected("", "ja"))
    }

    @Test
    fun matchesOnlyAnExplicitStoredTag() {
        assertTrue(AppLocaleChoice.matches("zh-Hans-CN", AppLocaleChoice.ZH))
        assertFalse(AppLocaleChoice.matches("", AppLocaleChoice.ZH))
        assertFalse(AppLocaleChoice.matches("en", AppLocaleChoice.ZH))
    }
}
