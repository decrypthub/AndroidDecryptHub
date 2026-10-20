package com.adh.manager.ui.scope

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.adh.core.CaptureFamilies
import com.adh.manager.R

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HookConfigScreen(
    packageName: String,
    draft: ScopeDraft,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val label = remember(packageName) {
        runCatching {
            val info = context.packageManager.getApplicationInfo(packageName, 0)
            context.packageManager.getApplicationLabel(info).toString()
        }.getOrDefault(packageName)
    }
    val families = draft.families[packageName] ?: CaptureFamilies.DEFAULT

    fun update(next: CaptureFamilies) {
        draft.families = if (next.isDefault) draft.families - packageName else draft.families + (packageName to next)
        draft.dirty = true
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            text = stringResource(R.string.hook_config_title),
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            text = label,
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
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
                    TextButton(onClick = { update(CaptureFamilies.DEFAULT) }) {
                        Text(stringResource(R.string.hook_config_reset))
                    }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            item {
                Text(
                    text = packageName,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp),
                )
            }
            item { FamilyRow(R.string.hook_family_digest, families.digest) { update(families.copy(digest = it)) } }
            item { FamilyRow(R.string.hook_family_hmac, families.hmac) { update(families.copy(hmac = it)) } }
            item { FamilyRow(R.string.hook_family_symmetric, families.symmetric) { update(families.copy(symmetric = it)) } }
            item { FamilyRow(R.string.hook_family_asymmetric, families.asymmetric) { update(families.copy(asymmetric = it)) } }
            item { FamilyRow(R.string.hook_family_tls, families.tls) { update(families.copy(tls = it)) } }
            item { FamilyRow(R.string.hook_family_aead, families.aead) { update(families.copy(aead = it)) } }
        }
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
