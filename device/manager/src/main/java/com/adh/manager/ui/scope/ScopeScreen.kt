package com.adh.manager.ui.scope

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.widget.ImageView
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.FilterList
import androidx.compose.material.icons.rounded.Save
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.adh.core.AdhPaths
import com.adh.core.ScopeConfig
import com.adh.manager.R
import com.adh.manager.data.ScopeRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class AppRow(
    val packageName: String,
    val label: String,
    val isSystem: Boolean,
    val icon: Drawable?,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScopeScreen(
    repository: ScopeRepository,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val snackbar = remember { SnackbarHostState() }
    val coroutineScope = rememberCoroutineScope()
    val savedMessage = stringResource(R.string.scope_saved)
    val saveFailedMessage = stringResource(R.string.scope_save_failed)

    var query by remember { mutableStateOf("") }
    var showSystem by remember { mutableStateOf(false) }
    var rows by remember { mutableStateOf<List<AppRow>>(emptyList()) }
    var selected by remember { mutableStateOf<Set<String>>(emptySet()) }
    var loading by remember { mutableStateOf(true) }
    var loadFailed by remember { mutableStateOf(false) }
    var daemonUnavailable by remember { mutableStateOf(false) }
    var saving by remember { mutableStateOf(false) }
    var refreshVersion by remember { mutableStateOf(0) }

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { refreshVersion++ }

    LaunchedEffect(repository, refreshVersion) {
        loading = true
        loadFailed = false
        daemonUnavailable = false
        val status = withContext(Dispatchers.IO) { repository.moduleStatus() }
        if (status.daemonAvailable == false) {
            daemonUnavailable = true
            loading = false
            return@LaunchedEffect
        }
        runCatching {
            val loaded = withContext(Dispatchers.IO) { repository.load() }
            selected = loaded.packages
            val pm = context.packageManager
            rows = withContext(Dispatchers.IO) {
                pm.getInstalledApplications(PackageManager.GET_META_DATA)
                    .asSequence()
                    .filter { it.packageName != AdhPaths.MANAGER_PKG }
                    .map { info ->
                        val label = runCatching { pm.getApplicationLabel(info).toString() }
                            .getOrDefault(info.packageName)
                        val system = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                        AppRow(info.packageName, label, system, runCatching { info.loadIcon(pm) }.getOrNull())
                    }
                    .sortedWith(
                        compareByDescending<AppRow> { loaded.packages.contains(it.packageName) }
                            .thenBy { it.label.lowercase() }
                    )
                    .toList()
            }
        }.onFailure { loadFailed = true }
        loading = false
    }

    val filtered = remember(rows, query, showSystem) {
        val normalized = query.trim().lowercase()
        rows.filter { row ->
            (showSystem || !row.isSystem) &&
                (normalized.isEmpty() ||
                    row.label.lowercase().contains(normalized) ||
                    row.packageName.lowercase().contains(normalized))
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            text = stringResource(R.string.scope_title),
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            text = stringResource(R.string.scope_selected, selected.size),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
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
            )
        },
        bottomBar = {
            Surface(color = MaterialTheme.colorScheme.surfaceContainer) {
                Button(
                    enabled = !saving && !loading && !loadFailed && !daemonUnavailable,
                    onClick = {
                        coroutineScope.launch {
                            saving = true
                            val result = withContext(Dispatchers.IO) {
                                repository.save(ScopeConfig(packages = selected))
                            }
                            saving = false
                            snackbar.showSnackbar(if (result.isSuccess) savedMessage else saveFailedMessage)
                        }
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                ) {
                    Icon(Icons.Rounded.Save, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(if (saving) R.string.saving else R.string.save))
                }
            }
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            SearchField(
                query = query,
                onQueryChange = { query = it },
                showSystem = showSystem,
                onToggleSystem = { showSystem = !showSystem },
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
            )

            when {
                loading -> LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                daemonUnavailable -> EmptyState(
                    title = stringResource(R.string.status_daemon_unavailable),
                    body = stringResource(R.string.status_daemon_unavailable_detail),
                )
                loadFailed -> EmptyState(
                    title = stringResource(R.string.apps_load_failed),
                    body = stringResource(R.string.apps_load_failed_detail),
                )
                filtered.isEmpty() -> EmptyState(
                    title = stringResource(R.string.apps_empty),
                    body = stringResource(R.string.apps_empty_detail),
                )
                else -> LazyColumn(
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    items(filtered, key = { it.packageName }) { row ->
                        AppRowItem(
                            row = row,
                            checked = selected.contains(row.packageName),
                            onCheckedChange = { checked ->
                                selected = if (checked) selected + row.packageName
                                else selected - row.packageName
                            },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun SearchField(
    query: String,
    onQueryChange: (String) -> Unit,
    showSystem: Boolean,
    onToggleSystem: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        shape = RoundedCornerShape(28.dp),
        modifier = modifier.fillMaxWidth(),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Spacer(Modifier.width(16.dp))
            Icon(
                Icons.Rounded.Search,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.width(12.dp))
            BasicTextField(
                value = query,
                onValueChange = onQueryChange,
                singleLine = true,
                textStyle = MaterialTheme.typography.bodyLarge.copy(
                    color = MaterialTheme.colorScheme.onSurface,
                ),
                cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                modifier = Modifier
                    .weight(1f)
                    .padding(vertical = 16.dp),
                decorationBox = { inner ->
                    if (query.isEmpty()) {
                        Text(
                            text = stringResource(R.string.search_apps),
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    inner()
                },
            )
            if (query.isNotEmpty()) {
                IconButton(onClick = { onQueryChange("") }) {
                    Icon(
                        Icons.Rounded.Close,
                        contentDescription = stringResource(R.string.clear_search),
                    )
                }
            }
            IconButton(onClick = onToggleSystem) {
                Icon(
                    Icons.Rounded.FilterList,
                    contentDescription = stringResource(
                        if (showSystem) R.string.hide_system_apps else R.string.show_system_apps
                    ),
                    tint = if (showSystem) MaterialTheme.colorScheme.primary
                    else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.width(4.dp))
        }
    }
}

@Composable
private fun EmptyState(title: String, body: String) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            Icons.Rounded.Apps,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(42.dp),
        )
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(top = 14.dp),
        )
        Text(
            text = body,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 6.dp),
        )
    }
}

@Composable
private fun AppRowItem(
    row: AppRow,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                color = if (checked) MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.48f)
                else MaterialTheme.colorScheme.background,
                shape = RoundedCornerShape(8.dp),
            )
            .clickable { onCheckedChange(!checked) }
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (row.icon != null) {
            AndroidView(
                factory = { context -> ImageView(context).apply { setImageDrawable(row.icon) } },
                update = { it.setImageDrawable(row.icon) },
                modifier = Modifier.size(42.dp),
            )
        } else {
            Box(
                modifier = Modifier
                    .size(42.dp)
                    .background(
                        MaterialTheme.colorScheme.surfaceContainerHighest,
                        RoundedCornerShape(8.dp),
                    ),
                contentAlignment = Alignment.Center,
            ) {
                Icon(Icons.Rounded.Apps, contentDescription = null, modifier = Modifier.size(22.dp))
            }
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = row.label,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = row.packageName,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Checkbox(checked = checked, onCheckedChange = onCheckedChange)
    }
}
