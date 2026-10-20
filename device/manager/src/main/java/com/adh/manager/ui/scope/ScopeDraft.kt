package com.adh.manager.ui.scope

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.adh.core.CaptureFamilies

/**
 * Injection-scope edits shared by the app list and the hook screen.
 * The list is disposed while the hook screen is open, so the draft has to live above both routes.
 */
class ScopeDraft {
    var selected by mutableStateOf<Set<String>>(emptySet())
    var families by mutableStateOf<Map<String, CaptureFamilies>>(emptyMap())
    var dirty by mutableStateOf(false)
}
