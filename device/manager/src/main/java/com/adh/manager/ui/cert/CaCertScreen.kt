package com.adh.manager.ui.cert

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
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
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.adh.core.CaCert
import com.adh.core.CaCertStore
import com.adh.manager.R
import com.adh.manager.data.ScopeRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant
import java.time.ZoneId

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CaCertScreen(
    repository: ScopeRepository,
) {
    val context = LocalContext.current
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    var loading by remember { mutableStateOf(true) }
    var daemonDown by remember { mutableStateOf(false) }
    var unsupported by remember { mutableStateOf(false) }
    var certs by remember { mutableStateOf<List<CaCert>>(emptyList()) }
    var busy by remember { mutableStateOf(false) }
    var refreshVersion by remember { mutableStateOf(0) }
    var pendingDelete by remember { mutableStateOf<CaCert?>(null) }
    var rebootPrompt by remember { mutableStateOf<RebootPrompt?>(null) }
    val noCa = stringResource(R.string.cert_no_ca)
    val writeFailed = stringResource(R.string.cert_write_failed)
    val readFailed = stringResource(R.string.cert_read_failed)
    val tooLarge = stringResource(R.string.cert_too_large)
    val deleteFailed = stringResource(R.string.cert_delete_failed)
    val rebootFailed = stringResource(R.string.cert_reboot_failed)

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { refreshVersion++ }

    LaunchedEffect(repository, refreshVersion) {
        loading = true
        val status = withContext(Dispatchers.IO) { repository.moduleStatus() }
        if (status.daemonAvailable == false) {
            daemonDown = true
            unsupported = false
            certs = emptyList()
            loading = false
            return@LaunchedEffect
        }
        daemonDown = false
        val supported = withContext(Dispatchers.IO) { repository.supportsCaCerts() }
        unsupported = !supported
        certs = if (supported) {
            withContext(Dispatchers.IO) { runCatching { repository.listCaCerts() }.getOrDefault(emptyList()) }
        } else {
            emptyList()
        }
        loading = false
    }

    val picker = rememberLauncherForActivityResult(OpenCertificateFile()) { uri ->
        if (uri == null || busy) return@rememberLauncherForActivityResult
        scope.launch {
            busy = true
            val bytes = withContext(Dispatchers.IO) {
                runCatching {
                    context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                }.getOrNull()
            }
            val message = when {
                bytes == null -> readFailed
                bytes.size > CaCertStore.MAX_BUNDLE_BYTES -> tooLarge
                else -> {
                    val stored = withContext(Dispatchers.IO) { repository.putCaCert(bytes) }
                    when {
                        stored > 0 -> {
                            rebootPrompt = RebootPrompt.Stored
                            refreshVersion++
                            null
                        }
                        stored == 0 -> noCa
                        else -> writeFailed
                    }
                }
            }
            busy = false
            if (message != null) snackbar.showSnackbar(message)
        }
    }

    rebootPrompt?.let { prompt ->
        val body = when (prompt) {
            RebootPrompt.Stored -> R.string.cert_reboot_body
            RebootPrompt.Removed -> R.string.cert_reboot_removed
            RebootPrompt.Pending -> R.string.cert_reboot_pending
        }
        AlertDialog(
            onDismissRequest = { rebootPrompt = null },
            title = { Text(stringResource(R.string.cert_reboot_title)) },
            text = { Text(stringResource(body)) },
            confirmButton = {
                TextButton(onClick = {
                    rebootPrompt = null
                    scope.launch {
                        val ok = withContext(Dispatchers.IO) { runCatching { repository.rebootDevice() }.getOrDefault(false) }
                        if (!ok) snackbar.showSnackbar(rebootFailed)
                    }
                }) { Text(stringResource(R.string.cert_reboot_now)) }
            },
            dismissButton = {
                TextButton(onClick = { rebootPrompt = null }) { Text(stringResource(R.string.cert_reboot_later)) }
            },
        )
    }

    pendingDelete?.let { cert ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text(stringResource(R.string.cert_delete_title)) },
            text = { Text(stringResource(R.string.cert_delete_body)) },
            confirmButton = {
                TextButton(onClick = {
                    pendingDelete = null
                    scope.launch {
                        busy = true
                        val ok = withContext(Dispatchers.IO) { repository.deleteCaCert(cert.fileName) }
                        busy = false
                        if (ok) {
                            rebootPrompt = RebootPrompt.Removed
                            refreshVersion++
                        } else {
                            snackbar.showSnackbar(deleteFailed)
                        }
                    }
                }) { Text(stringResource(R.string.cert_delete)) }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) { Text(stringResource(R.string.cancel)) }
            },
        )
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.cert_title), fontWeight = FontWeight.SemiBold) },
                actions = {
                    IconButton(
                        onClick = { picker.launch(Unit) },
                        enabled = !busy && !daemonDown && !unsupported,
                    ) {
                        Icon(Icons.Rounded.Add, contentDescription = stringResource(R.string.cert_import))
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
            if (loading || busy) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            when {
                daemonDown -> Message(
                    title = stringResource(R.string.status_daemon_unavailable),
                    detail = stringResource(R.string.status_daemon_unavailable_detail),
                )
                unsupported -> Message(
                    title = stringResource(R.string.cert_title),
                    detail = stringResource(R.string.cert_unsupported),
                )
                certs.isEmpty() && !loading -> Message(
                    title = stringResource(R.string.cert_empty),
                    detail = stringResource(R.string.cert_empty_detail),
                )
                else -> LazyColumn(
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(certs, key = { it.fileName }) { cert ->
                        CertRow(cert = cert, onDelete = { pendingDelete = cert })
                    }
                    if (certs.any { !it.active }) {
                        item {
                            Button(
                                onClick = { rebootPrompt = RebootPrompt.Pending },
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Text(stringResource(R.string.cert_reboot_action))
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun CertRow(cert: CaCert, onDelete: () -> Unit) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainer,
        shape = RoundedCornerShape(8.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.padding(start = 16.dp, top = 12.dp, end = 4.dp, bottom = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = cert.subject.ifBlank { cert.fileName },
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = cert.fileName,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = stringResource(R.string.cert_valid, day(cert.notBeforeMs), day(cert.notAfterMs)),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = stringResource(if (cert.active) R.string.cert_active else R.string.cert_waiting),
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (cert.active) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.tertiary
                    },
                )
            }
            IconButton(onClick = onDelete) {
                Icon(Icons.Rounded.Delete, contentDescription = stringResource(R.string.cert_delete))
            }
        }
    }
}

@Composable
private fun Message(title: String, detail: String) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 24.dp, vertical = 32.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(text = title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(
            text = detail,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

private enum class RebootPrompt { Stored, Removed, Pending }

private fun day(ms: Long): String = runCatching {
    Instant.ofEpochMilli(ms).atZone(ZoneId.systemDefault()).toLocalDate().toString()
}.getOrDefault("")
