package com.adh.manager.ui.home

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.adh.manager.AppLocale
import com.adh.manager.data.AppLocaleChoice
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.adh.manager.BuildConfig
import com.adh.manager.R
import com.adh.manager.data.HostWebUiRepository
import com.adh.manager.data.ModuleStatus
import com.adh.manager.data.RemoteUpdate
import com.adh.manager.data.ScopeRepository
import com.adh.manager.data.UpdateJson
import com.adh.manager.data.WebUiRepository
import com.adh.manager.data.WebUiStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
fun HomeScreen(
    repository: ScopeRepository,
    webUiRepository: WebUiRepository,
) {
    var status by remember { mutableStateOf(ModuleStatus()) }
    var webStatus by remember { mutableStateOf<WebUiStatus?>(null) }
    var remoteUpdate by remember { mutableStateOf<RemoteUpdate?>(null) }
    var updateChecked by remember { mutableStateOf(false) }
    var refreshVersion by remember { mutableIntStateOf(0) }

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { refreshVersion++ }

    LaunchedEffect(repository, refreshVersion) {
        status = withContext(Dispatchers.IO) { repository.moduleStatus() }
    }

    LaunchedEffect(webUiRepository, repository, refreshVersion) {
        val probed = withContext(Dispatchers.IO) { webUiRepository.probe() }
        webStatus = probed
        val host = probed?.callbackHost
        if (probed?.reachable == true && !host.isNullOrBlank()) {
            withContext(Dispatchers.IO) { repository.rememberHostEndpoint(host, probed.callbackPort) }
        }
    }

    LaunchedEffect(refreshVersion) {
        updateChecked = false
        remoteUpdate = withContext(Dispatchers.IO) { UpdateJson.fetch() }
        updateChecked = true
    }

    val unknown = stringResource(R.string.unknown)
    val published = remoteUpdate
    val updateLabel = when {
        !updateChecked -> stringResource(R.string.update_checking)
        published == null -> stringResource(R.string.update_failed)
        UpdateJson.isNewer(BuildConfig.VERSION_CODE, published) ->
            stringResource(R.string.update_available, published.version)
        else -> stringResource(R.string.update_current)
    }
    val changelog = if (
        updateChecked && published != null &&
        UpdateJson.isNewer(BuildConfig.VERSION_CODE, published) &&
        published.changelog.startsWith("http")
    ) {
        published.changelog
    } else {
        null
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
            FactCard(
                rows = listOf(
                    stringResource(R.string.fact_module) to (status.version ?: unknown),
                    stringResource(R.string.fact_app) to BuildConfig.VERSION_NAME,
                    stringResource(R.string.fact_model) to Build.MODEL,
                    stringResource(R.string.fact_system) to stringResource(
                        R.string.system_line,
                        Build.VERSION.RELEASE,
                        Build.VERSION.SDK_INT,
                    ),
                    stringResource(R.string.fact_abi) to (Build.SUPPORTED_ABIS.firstOrNull() ?: unknown),
                    stringResource(R.string.fact_update) to updateLabel,
                ),
                linkLast = changelog,
            )
            WebUiSection(status = webStatus)
        }
    }
}

@Composable
private fun FactCard(rows: List<Pair<String, String>>, linkLast: String?) {
    val context = LocalContext.current
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainer,
        shape = RoundedCornerShape(HomeCorner),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(vertical = 6.dp)) {
            rows.forEachIndexed { index, (label, value) ->
                val open = if (index == rows.lastIndex) linkLast else null
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .then(if (open != null) Modifier.clickable {
                            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(open)))
                        } else Modifier)
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    Text(
                        text = label,
                        style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.weight(0.42f),
                    )
                    Text(
                        text = value,
                        style = MaterialTheme.typography.bodyLarge,
                        color = if (open != null) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.weight(0.58f),
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
    SectionLabel(text = stringResource(R.string.section_web_ui))
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainer,
        shape = RoundedCornerShape(HomeCorner),
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
    val title = stringResource(
        when {
            checking -> R.string.status_title_checking
            active -> R.string.status_title_running
            else -> R.string.status_title_abnormal
        },
    )
    val detail = when {
        checking -> stringResource(R.string.status_detail_checking)
        daemonUnavailable -> stringResource(R.string.status_daemon_unavailable)
        active -> stringResource(
            R.string.version_module,
            status.version ?: stringResource(R.string.unknown),
        )
        status.installed -> stringResource(R.string.status_detail_loader_inactive)
        else -> stringResource(R.string.status_detail_not_installed)
    }

    var entered by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { entered = true }
    val reveal by animateFloatAsState(
        targetValue = if (entered) 1f else 0f,
        animationSpec = tween(durationMillis = 420, easing = FastOutSlowInEasing),
        label = "statusEnter",
    )
    val density = LocalDensity.current
    val icon = when {
        active -> Icons.Rounded.Check
        status.installed || checking || daemonUnavailable -> Icons.Rounded.Info
        else -> Icons.Rounded.Close
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(bottomStart = HomeCorner, bottomEnd = HomeCorner))
            .background(container)
            .windowInsetsPadding(WindowInsets.statusBars),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .graphicsLayer {
                    alpha = reveal
                    translationY = with(density) { (10.dp * (1f - reveal)).toPx() }
                }
                .padding(start = 16.dp, end = 4.dp, top = 10.dp, bottom = 14.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(32.dp)
                        .clip(CircleShape)
                        .background(content.copy(alpha = 0.16f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = icon,
                        contentDescription = null,
                        tint = content,
                        modifier = Modifier.size(16.dp),
                    )
                }
                Text(
                    text = title,
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = content,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(CircleShape)
                        .clickable(onClick = onRefresh),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        Icons.Rounded.Refresh,
                        contentDescription = stringResource(R.string.refresh_status),
                        tint = content,
                    )
                }
            }
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 40.dp, end = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    text = detail,
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodyMedium,
                    color = content.copy(alpha = 0.72f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                LanguageSwitch()
            }
        }
    }
}

@Composable
private fun LanguageSwitch(modifier: Modifier = Modifier) {
    val selected = AppLocale.selectedTag()
    val ink = MaterialTheme.colorScheme.onSurface
    Surface(
        color = MaterialTheme.colorScheme.surface.copy(alpha = 0.88f),
        shape = CircleShape,
        modifier = modifier,
    ) {
        Row(
            modifier = Modifier.padding(3.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            LanguageChip(
                AppLocaleChoice.ZH,
                "中文",
                selected == AppLocaleChoice.ZH,
                ink,
                Modifier.size(width = 56.dp, height = 30.dp),
            )
            LanguageChip(
                AppLocaleChoice.EN,
                "EN",
                selected == AppLocaleChoice.EN,
                ink,
                Modifier.size(width = 56.dp, height = 30.dp),
            )
        }
    }
}

@Composable
private fun LanguageChip(
    tag: String,
    label: String,
    selected: Boolean,
    ink: Color,
    modifier: Modifier = Modifier,
) {
    Box(
        modifier = modifier
            .clip(CircleShape)
            .background(if (selected) ink else Color.Transparent)
            .clickable { AppLocale.apply(tag) },
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelLarge,
            fontWeight = FontWeight.SemiBold,
            color = if (selected) MaterialTheme.colorScheme.surface else ink,
        )
    }
}

private val HomeCorner = 16.dp

@Composable
private fun SectionLabel(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(horizontal = 4.dp),
    )
}

