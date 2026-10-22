package com.adh.manager.ui.scope

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.annotation.StringRes
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.adh.core.CaptureFamilies
import com.adh.manager.R

private enum class HookTab {
    Crypto,
    Capture,
    System,
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HookConfigScreen(
    packageName: String,
    draft: ScopeDraft,
    onBack: () -> Unit,
    onPersist: () -> Unit,
) {
    val context = LocalContext.current
    val label = remember(packageName) {
        runCatching {
            val info = context.packageManager.getApplicationInfo(packageName, 0)
            context.packageManager.getApplicationLabel(info).toString()
        }.getOrDefault(packageName)
    }
    val families = draft.families[packageName] ?: CaptureFamilies.DEFAULT
    var tab by remember { mutableStateOf(HookTab.Crypto) }

    fun update(next: CaptureFamilies) {
        draft.families = if (next.isDefault) draft.families - packageName else draft.families + (packageName to next)
        onPersist()
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = stringResource(R.string.hook_config_title),
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Rounded.ArrowBack,
                            contentDescription = stringResource(R.string.back),
                        )
                    }
                },
                actions = {
                    Column(
                        modifier = Modifier
                            .widthIn(max = 168.dp)
                            .clip(RoundedCornerShape(8.dp))
                            .clickable(onClickLabel = stringResource(R.string.hook_copy_package)) {
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                clipboard.setPrimaryClip(ClipData.newPlainText(label, packageName))
                            }
                            .padding(horizontal = 12.dp, vertical = 4.dp),
                        horizontalAlignment = Alignment.End,
                    ) {
                        if (label != packageName) {
                            Text(
                                text = label,
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.Medium,
                                textAlign = TextAlign.End,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                        Text(
                            text = packageName,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            textAlign = TextAlign.End,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            if (draft.persistFailed) {
                Text(
                    text = stringResource(R.string.scope_save_failed),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp),
                )
            }
            HookTabBar(
                tab = tab,
                onTab = { tab = it },
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
            )
            LazyColumn(modifier = Modifier.weight(1f)) {
                when (tab) {
                    HookTab.Crypto -> {
                        item { FamilyRow(R.string.hook_family_digest, families.digest) { update(families.copy(digest = it)) } }
                        item { FamilyRow(R.string.hook_family_hmac, families.hmac) { update(families.copy(hmac = it)) } }
                        item { FamilyRow(R.string.hook_family_symmetric, families.symmetric) { update(families.copy(symmetric = it)) } }
                        item { FamilyRow(R.string.hook_family_asymmetric, families.asymmetric) { update(families.copy(asymmetric = it)) } }
                        item { FamilyRow(R.string.hook_family_aead, families.aead) { update(families.copy(aead = it)) } }
                    }
                    HookTab.Capture -> {
                        item { FamilyRow(R.string.hook_family_tls, families.tls) { update(families.copy(tls = it)) } }
                    }
                    HookTab.System -> {
                        item { FamilyRow(R.string.hook_family_system, families.system) { update(families.copy(system = it)) } }
                    }
                }
            }
        }
    }
}

@Composable
private fun HookTabBar(
    tab: HookTab,
    onTab: (HookTab) -> Unit,
    modifier: Modifier = Modifier,
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        shape = RoundedCornerShape(28.dp),
        modifier = modifier.fillMaxWidth(),
    ) {
        Row(modifier = Modifier.padding(4.dp)) {
            HookTabSegment(R.string.hook_tab_crypto, tab == HookTab.Crypto, { onTab(HookTab.Crypto) }, Modifier.weight(1f))
            HookTabSegment(R.string.hook_tab_capture, tab == HookTab.Capture, { onTab(HookTab.Capture) }, Modifier.weight(1f))
            HookTabSegment(R.string.hook_tab_system, tab == HookTab.System, { onTab(HookTab.System) }, Modifier.weight(1f))
        }
    }
}

@Composable
private fun HookTabSegment(
    @StringRes labelRes: Int,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Box(
        modifier = modifier
            .height(40.dp)
            .clip(RoundedCornerShape(24.dp))
            .background(if (selected) MaterialTheme.colorScheme.primary else Color.Transparent)
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = stringResource(labelRes),
            style = MaterialTheme.typography.labelLarge,
            fontWeight = FontWeight.SemiBold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            color = if (selected) MaterialTheme.colorScheme.onPrimary
            else MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 6.dp),
        )
    }
}

@Composable
private fun FamilyRow(@StringRes labelRes: Int, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = stringResource(labelRes),
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.weight(1f),
        )
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}
