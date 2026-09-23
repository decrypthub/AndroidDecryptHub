package com.adh.manager.ui.home

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowForward
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.OpenInBrowser
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.adh.manager.BuildConfig
import com.adh.manager.R
import com.adh.manager.data.ModuleStatus
import com.adh.manager.data.HostWebUiRepository
import com.adh.manager.data.ScopeRepository
import com.adh.manager.data.WebUiRepository
import com.adh.manager.data.WebUiStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
fun HomeScreen(
    repository: ScopeRepository,
    webUiRepository: WebUiRepository,
    onOpenScope: () -> Unit,
) {
    var status by remember { mutableStateOf(ModuleStatus()) }
    var webStatus by remember { mutableStateOf<WebUiStatus?>(null) }
    var count by remember { mutableIntStateOf(0) }
    var refreshVersion by remember { mutableIntStateOf(0) }
    val context = LocalContext.current

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { refreshVersion++ }

    LaunchedEffect(repository, refreshVersion) {
        val result = withContext(Dispatchers.IO) {
            val moduleStatus = repository.moduleStatus()
            val selectedCount = if (moduleStatus.daemonAvailable == false) {
                0
            } else {
                runCatching { repository.load().packages.size }.getOrDefault(0)
            }
            moduleStatus to selectedCount
        }
        status = result.first
        count = result.second
    }

    LaunchedEffect(webUiRepository, refreshVersion) {
        webStatus = withContext(Dispatchers.IO) { webUiRepository.probe() }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
    ) {
        StatusHeader(status = status, onRefresh = { refreshVersion++ })
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 20.dp),
            verticalArrangement = Arrangement.spacedBy(18.dp),
        ) {
            WebUiSection(status = webStatus)
            SectionLabel(text = stringResource(R.string.section_configuration))
            Surface(
                color = MaterialTheme.colorScheme.surfaceContainer,
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(onClick = onOpenScope),
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 18.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(14.dp),
                ) {
                    Icon(
                        Icons.Rounded.Apps,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                    )
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = stringResource(R.string.scope_title),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            text = stringResource(R.string.scope_count, count),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Icon(
                        Icons.AutoMirrored.Rounded.ArrowForward,
                        contentDescription = stringResource(R.string.open_scope),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            SectionLabel(text = stringResource(R.string.section_versions))
            Surface(
                color = MaterialTheme.colorScheme.surfaceContainerLow,
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                    DetailRow(
                        label = stringResource(R.string.module_version),
                        value = status.version ?: stringResource(R.string.unknown),
                    )
                    DetailRow(
                        label = stringResource(R.string.manager_version),
                        value = BuildConfig.VERSION_NAME,
                    )
                }
            }
        }
    }
}

@Composable
private fun WebUiSection(status: WebUiStatus?) {
    val context = LocalContext.current
    val url = status?.primaryUrl ?: HostWebUiRepository.LOCAL_URL
    val stateText = when {
        status == null -> stringResource(R.string.web_ui_checking)
        status.reachable -> stringResource(R.string.web_ui_online)
        else -> stringResource(R.string.web_ui_offline)
    }
    val detailText = when {
        status == null -> stringResource(R.string.web_ui_checking_detail)
        !status.reachable -> stringResource(R.string.web_ui_unavailable_detail)
        status.lanUrl != null -> stringResource(R.string.web_ui_lan_detail)
        status.reachable -> stringResource(R.string.web_ui_local_detail)
        else -> stringResource(R.string.web_ui_unavailable_detail)
    }

    SectionLabel(text = stringResource(R.string.section_web_ui))
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainer,
        shape = RoundedCornerShape(8.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(start = 16.dp, top = 12.dp, end = 8.dp, bottom = 12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stateText,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        text = url,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
                IconButton(onClick = {
                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    clipboard.setPrimaryClip(ClipData.newPlainText("ADH Web UI", url))
                }) {
                    Icon(Icons.Rounded.ContentCopy, contentDescription = stringResource(R.string.copy_web_ui_url))
                }
                IconButton(onClick = {
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                }) {
                    Icon(Icons.Rounded.OpenInBrowser, contentDescription = stringResource(R.string.open_web_ui))
                }
            }
            Text(
                text = detailText,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (status?.reachable == true && status.lanUrl != null && status.localUrl != status.lanUrl) {
                Text(
                    text = stringResource(R.string.web_ui_local_address, status.localUrl),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun StatusHeader(status: ModuleStatus, onRefresh: () -> Unit) {
    val checking = status.daemonAvailable == null
    val daemonUnavailable = status.daemonAvailable == false
    val active = status.daemonAvailable == true && status.installed && status.loaderActive
    val containerTarget = when {
        checking -> MaterialTheme.colorScheme.surfaceContainerHighest
        daemonUnavailable -> MaterialTheme.colorScheme.errorContainer
        active -> MaterialTheme.colorScheme.primaryContainer
        status.installed -> MaterialTheme.colorScheme.tertiaryContainer
        else -> MaterialTheme.colorScheme.errorContainer
    }
    val contentTarget = when {
        checking -> MaterialTheme.colorScheme.onSurface
        daemonUnavailable -> MaterialTheme.colorScheme.onErrorContainer
        active -> MaterialTheme.colorScheme.onPrimaryContainer
        status.installed -> MaterialTheme.colorScheme.onTertiaryContainer
        else -> MaterialTheme.colorScheme.onErrorContainer
    }
    val container by animateColorAsState(containerTarget, label = "statusContainer")
    val content by animateColorAsState(contentTarget, label = "statusContent")
    val stateText = when {
        checking -> stringResource(R.string.status_checking)
        daemonUnavailable -> stringResource(R.string.status_daemon_unavailable)
        active -> stringResource(R.string.status_running)
        status.installed -> stringResource(R.string.status_not_loaded)
        else -> stringResource(R.string.status_not_installed)
    }
    val detailText = when {
        checking -> stringResource(R.string.status_checking_detail)
        daemonUnavailable -> stringResource(R.string.status_daemon_unavailable_detail)
        active -> stringResource(R.string.status_running_detail)
        status.installed -> stringResource(R.string.status_not_loaded_detail)
        else -> stringResource(R.string.status_not_installed_detail)
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(bottomStart = 28.dp, bottomEnd = 28.dp))
            .background(container)
            .windowInsetsPadding(WindowInsets.statusBars),
    ) {
        Column(modifier = Modifier.padding(start = 20.dp, end = 20.dp, top = 30.dp, bottom = 24.dp)) {
            Spacer(Modifier.height(32.dp))
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(52.dp)
                        .clip(RoundedCornerShape(if (active) 18.dp else 26.dp))
                        .background(content.copy(alpha = 0.14f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = when {
                            active -> Icons.Rounded.Check
                            status.installed || checking || daemonUnavailable -> Icons.Rounded.Info
                            else -> Icons.Rounded.Close
                        },
                        contentDescription = null,
                        tint = content,
                        modifier = Modifier.size(28.dp),
                    )
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.app_name),
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.SemiBold,
                        color = content,
                    )
                    Text(
                        text = stateText,
                        style = MaterialTheme.typography.titleMedium,
                        color = content.copy(alpha = 0.92f),
                        modifier = Modifier.padding(top = 2.dp),
                    )
                    Text(
                        text = detailText,
                        style = MaterialTheme.typography.bodyMedium,
                        color = content.copy(alpha = 0.78f),
                        modifier = Modifier.padding(top = 4.dp),
                    )
                }
                IconButton(onClick = onRefresh) {
                    Icon(
                        Icons.Rounded.Refresh,
                        contentDescription = stringResource(R.string.refresh_status),
                        tint = content,
                    )
                }
            }
        }
    }
}

@Composable
private fun SectionLabel(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(horizontal = 4.dp),
    )
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .height(52.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(text = label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
