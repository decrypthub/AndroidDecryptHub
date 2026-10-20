package com.adh.manager.ui.scope

import android.graphics.drawable.Drawable
import android.util.Log
import androidx.compose.foundation.Image
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
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material.icons.rounded.RestartAlt
import androidx.compose.material.icons.rounded.Save
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Stop
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.adh.core.CaptureFamilies
import com.adh.core.PackageControl
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
)

private enum class AppListFilter {
    Enabled,
    All,
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScopeScreen(
    repository: ScopeRepository,
    draft: ScopeDraft,
    onBack: () -> Unit,
    onOpenHook: (String) -> Unit,
) {
    val context = LocalContext.current
    val snackbar = remember { SnackbarHostState() }
    val coroutineScope = rememberCoroutineScope()
    val savedMessage = stringResource(R.string.scope_saved)
    val saveFailedMessage = stringResource(R.string.scope_save_failed)
    val controlDeniedMessage = stringResource(R.string.app_control_denied)

    var query by remember { mutableStateOf("") }
    var searching by remember { mutableStateOf(false) }
    var listFilter by remember { mutableStateOf(AppListFilter.Enabled) }
    var filterReady by remember { mutableStateOf(false) }
    var showSystem by remember { mutableStateOf(false) }
    val searchFocus = remember { FocusRequester() }
    val keyboard = LocalSoftwareKeyboardController.current
    var rows by remember { mutableStateOf<List<AppRow>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var loadFailed by remember { mutableStateOf(false) }
    var catalogIncomplete by remember { mutableStateOf(false) }
    var daemonUnavailable by remember { mutableStateOf(false) }
    var canControlPackages by remember { mutableStateOf(false) }
    var saving by remember { mutableStateOf(false) }
    var refreshVersion by remember { mutableStateOf(0) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { refreshVersion++ }

    LaunchedEffect(repository, refreshVersion) {
        loading = true
        loadFailed = false
        catalogIncomplete = false
        daemonUnavailable = false
        val status = withContext(Dispatchers.IO) { repository.moduleStatus() }
        if (status.daemonAvailable == false) {
            daemonUnavailable = true
            canControlPackages = false
            loading = false
            return@LaunchedEffect
        }
        canControlPackages = withContext(Dispatchers.IO) { repository.supportsPackageControl() }
        val loaded = runCatching {
            withContext(Dispatchers.IO) { repository.load() }
        }.onFailure {
            Log.e(TAG, "scope read failed", it)
        }.getOrElse {
            loadFailed = true
            loading = false
            return@LaunchedEffect
        }
        if (!draft.dirty) {
            draft.selected = loaded.packages
            draft.families = loaded.policy
        }
        if (!filterReady) {
            listFilter = if (draft.selected.isEmpty()) AppListFilter.All else AppListFilter.Enabled
            filterReady = true
        }

        val catalog = runCatching {
            withContext(Dispatchers.IO) { repository.listApplications() }
        }.onFailure {
            Log.e(TAG, "installed application catalog failed", it)
        }.getOrDefault(emptyList())
        catalogIncomplete = catalog.isEmpty()

        val merged = LinkedHashMap<String, AppRow>()
        for (app in catalog) {
            merged[app.packageName] = AppRow(
                packageName = app.packageName,
                label = app.label,
                isSystem = app.system,
            )
        }
        for (pkg in loaded.packages) {
            if (merged.containsKey(pkg)) continue
            merged[pkg] = AppRow(
                packageName = pkg,
                label = pkg,
                isSystem = false,
            )
        }
        rows = merged.values.sortedWith(
            compareByDescending<AppRow> { loaded.packages.contains(it.packageName) }
                .thenBy { it.label.lowercase() },
        )
        loading = false
    }

    val selected = draft.selected
    val filtered = remember(rows, query, showSystem, listFilter, selected) {
        val normalized = query.trim().lowercase()
        rows.filter { row ->
            val enabled = selected.contains(row.packageName)
            val inTab = when (listFilter) {
                AppListFilter.Enabled -> enabled
                AppListFilter.All -> showSystem || !row.isSystem
            }
            inTab && (normalized.isEmpty() ||
                row.label.lowercase().contains(normalized) ||
                row.packageName.lowercase().contains(normalized))
        }
    }

    fun closeSearch() {
        searching = false
        query = ""
        keyboard?.hide()
    }

    fun controlApp(row: AppRow, restart: Boolean) {
        coroutineScope.launch {
            val result = withContext(Dispatchers.IO) {
                repository.controlPackage(row.packageName, restart)
            }
            val message = when (result) {
                PackageControl.RESULT_OK ->
                    if (restart) context.getString(R.string.app_restarted, row.label)
                    else context.getString(R.string.app_stopped, row.label)
                PackageControl.RESULT_NO_LAUNCHER ->
                    context.getString(R.string.app_no_launcher, row.label)
                PackageControl.RESULT_DENIED -> controlDeniedMessage
                else -> context.getString(R.string.app_control_failed, row.label)
            }
            snackbar.showSnackbar(message)
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = {
                    if (searching) {
                        BasicTextField(
                            value = query,
                            onValueChange = { query = it },
                            singleLine = true,
                            textStyle = MaterialTheme.typography.titleMedium.copy(
                                color = MaterialTheme.colorScheme.onSurface,
                            ),
                            cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                            modifier = Modifier
                                .fillMaxWidth()
                                .focusRequester(searchFocus),
                            decorationBox = { inner ->
                                Box(contentAlignment = Alignment.CenterStart) {
                                    if (query.isEmpty()) {
                                        Text(
                                            text = stringResource(R.string.search_apps),
                                            style = MaterialTheme.typography.titleMedium,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis,
                                        )
                                    }
                                    inner()
                                }
                            },
                        )
                    } else {
                        Column {
                            Text(
                                text = stringResource(R.string.scope_title),
                                style = MaterialTheme.typography.titleLarge,
                                fontWeight = FontWeight.SemiBold,
                            )
                            Text(
                                text = stringResource(R.string.scope_selected, draft.selected.size),
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                },
                navigationIcon = {
                    IconButton(onClick = { if (searching) closeSearch() else onBack() }) {
                        Icon(
                            Icons.AutoMirrored.Rounded.ArrowBack,
                            contentDescription = stringResource(R.string.back),
                        )
                    }
                },
                actions = {
                    if (searching) {
                        if (query.isNotEmpty()) {
                            IconButton(onClick = { query = "" }) {
                                Icon(
                                    Icons.Rounded.Close,
                                    contentDescription = stringResource(R.string.clear_search),
                                )
                            }
                        }
                    } else {
                        if (listFilter == AppListFilter.All) {
                            IconButton(onClick = { showSystem = !showSystem }) {
                                Icon(
                                    Icons.Rounded.FilterList,
                                    contentDescription = stringResource(
                                        if (showSystem) R.string.hide_system_apps else R.string.show_system_apps,
                                    ),
                                    tint = if (showSystem) MaterialTheme.colorScheme.primary
                                    else MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                        IconButton(onClick = { searching = true }) {
                            Icon(
                                Icons.Rounded.Search,
                                contentDescription = stringResource(R.string.search_apps),
                            )
                        }
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
                                // Carry the whole config: sending `selected` alone silently drops
                                // version/mode/policy on every save.
                                repository.save(
                                    ScopeConfig(
                                        packages = draft.selected,
                                        policy = draft.families.filterKeys { draft.selected.contains(it) },
                                    ),
                                )
                            }
                            saving = false
                            if (result.isSuccess) draft.dirty = false
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
            LaunchedEffect(searching) {
                if (searching) {
                    searchFocus.requestFocus()
                    keyboard?.show()
                }
            }
            ScopeFilterBar(
                showEnabled = listFilter == AppListFilter.Enabled,
                onShowEnabled = { listFilter = AppListFilter.Enabled },
                onShowAll = { listFilter = AppListFilter.All },
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
                filtered.isEmpty() -> {
                    val enabledEmpty = listFilter == AppListFilter.Enabled && query.isBlank()
                    val catalogEmpty = catalogIncomplete && query.isBlank() && listFilter == AppListFilter.All
                    EmptyState(
                        title = stringResource(
                            when {
                                catalogEmpty -> R.string.apps_catalog_empty
                                enabledEmpty -> R.string.apps_enabled_empty
                                else -> R.string.apps_empty
                            },
                        ),
                        body = if (enabledEmpty) "" else stringResource(
                            if (catalogEmpty) R.string.apps_catalog_empty_detail
                            else R.string.apps_empty_detail,
                        ),
                    )
                }
                else -> Column(modifier = Modifier.weight(1f)) {
                    if (catalogIncomplete) {
                        Text(
                            text = stringResource(R.string.apps_catalog_unavailable),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                        )
                    }
                    LazyColumn(
                        modifier = Modifier.weight(1f),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        items(filtered, key = { it.packageName }) { row ->
                            AppRowItem(
                                row = row,
                                checked = draft.selected.contains(row.packageName),
                                onCheckedChange = { checked ->
                                    draft.selected = if (checked) draft.selected + row.packageName
                                    else draft.selected - row.packageName
                                    draft.dirty = true
                                },
                                canControl = canControlPackages,
                                families = draft.families[row.packageName] ?: CaptureFamilies.DEFAULT,
                                onConfigure = { onOpenHook(row.packageName) },
                                onForceStop = { controlApp(row, restart = false) },
                                onRestart = { controlApp(row, restart = true) },
                                loadIcon = { pkg ->
                                    withContext(Dispatchers.IO) {
                                        runCatching { context.packageManager.getApplicationIcon(pkg) }.getOrNull()
                                            ?: repository.applicationIcon(pkg)?.let { bytes ->
                                                android.graphics.BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                                                    ?.let { android.graphics.drawable.BitmapDrawable(context.resources, it) }
                                            }
                                    }
                                },
                            )
                        }
                    }
                }
            }
        }
    }
}

private const val TAG = "AdhScopeScreen"

@Composable
private fun ScopeFilterBar(
    showEnabled: Boolean,
    onShowEnabled: () -> Unit,
    onShowAll: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        shape = RoundedCornerShape(28.dp),
        modifier = modifier.fillMaxWidth(),
    ) {
        Row(modifier = Modifier.padding(4.dp)) {
            ScopeFilterSegment(
                text = stringResource(R.string.scope_filter_enabled),
                selected = showEnabled,
                onClick = onShowEnabled,
                modifier = Modifier.weight(1f),
            )
            ScopeFilterSegment(
                text = stringResource(R.string.scope_filter_all),
                selected = !showEnabled,
                onClick = onShowAll,
                modifier = Modifier.weight(1f),
            )
        }
    }
}

@Composable
private fun ScopeFilterSegment(
    text: String,
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
            text = text,
            style = MaterialTheme.typography.labelLarge,
            fontWeight = FontWeight.SemiBold,
            color = if (selected) MaterialTheme.colorScheme.onPrimary
            else MaterialTheme.colorScheme.onSurfaceVariant,
        )
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
        if (body.isNotEmpty()) {
            Text(
                text = body,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 6.dp),
            )
        }
    }
}

@Composable
private fun AppRowItem(
    row: AppRow,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    canControl: Boolean,
    families: CaptureFamilies,
    onConfigure: () -> Unit,
    onForceStop: () -> Unit,
    onRestart: () -> Unit,
    loadIcon: suspend (String) -> Drawable?,
) {
    var icon by remember(row.packageName) { mutableStateOf<Drawable?>(null) }
    var menuOpen by remember { mutableStateOf(false) }
    LaunchedEffect(row.packageName) { icon = loadIcon(row.packageName) }
    val bitmap = remember(icon) {
        runCatching { icon?.toBitmap(width = 96, height = 96)?.asImageBitmap() }.getOrNull()
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                color = if (checked) MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.48f)
                else MaterialTheme.colorScheme.background,
                shape = RoundedCornerShape(8.dp),
            )
            .clickable { onCheckedChange(!checked) }
            .padding(start = 12.dp, end = 4.dp, top = 10.dp, bottom = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (bitmap != null) {
            Image(
                bitmap = bitmap,
                contentDescription = null,
                modifier = Modifier
                    .size(42.dp)
                    .clip(RoundedCornerShape(8.dp)),
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
            // One glance is enough to tell a trimmed app from a default one.
            if (checked && !families.isDefault) {
                Text(
                    text = stringResource(R.string.app_hooks_trimmed),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
        }
        Checkbox(checked = checked, onCheckedChange = onCheckedChange)
        if (canControl) {
            Box {
                IconButton(onClick = { menuOpen = true }) {
                    Icon(
                        Icons.Rounded.MoreVert,
                        contentDescription = stringResource(R.string.app_actions),
                    )
                }
                DropdownMenu(
                    expanded = menuOpen,
                    onDismissRequest = { menuOpen = false },
                ) {
                    // Only a scoped app can have a hook policy (an unscoped one is never injected).
                    if (checked) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.app_hook_config)) },
                            onClick = {
                                menuOpen = false
                                onConfigure()
                            },
                            leadingIcon = { Icon(Icons.Rounded.Tune, contentDescription = null) },
                        )
                    }
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.app_force_stop)) },
                        onClick = {
                            menuOpen = false
                            onForceStop()
                        },
                        leadingIcon = { Icon(Icons.Rounded.Stop, contentDescription = null) },
                    )
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.app_restart)) },
                        onClick = {
                            menuOpen = false
                            onRestart()
                        },
                        leadingIcon = { Icon(Icons.Rounded.RestartAlt, contentDescription = null) },
                    )
                }
            }
        }
    }
}
