package com.nexusfireman.gomap

import android.app.Application
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import go.Seq
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val LOCAL_NETWORK_PERMISSION = "android.permission.ACCESS_LOCAL_NETWORK"

class GoMapApplication : Application() {
    var nativeReady = false
        private set
    override fun onCreate() {
        super.onCreate()
        try { Seq.setContext(this); nativeReady = true }
        catch (_: LinkageError) { nativeReady = false }
        catch (_: Exception) { nativeReady = false }
    }
}

class MainActivity : ComponentActivity() {
    private val scan: ScanViewModel by viewModels {
        object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                require(modelClass == ScanViewModel::class.java)
                @Suppress("UNCHECKED_CAST")
                return ScanViewModel(GoScanBackend((application as GoMapApplication).nativeReady)) as T
            }
        }
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent { GoMapTheme { ScanScreen(scan) } }
    }
    override fun onStop() { scan.stop(); super.onStop() }
}

@Composable
fun GoMapTheme(content: @Composable () -> Unit) {
    val colors = if (isSystemInDarkTheme()) darkColorScheme(
        primary = Color(0xFF68D4CC), secondary = Color(0xFFD8BCD3),
        surface = Color(0xFF101716), background = Color(0xFF101716),
    ) else lightColorScheme(
        primary = Color(0xFF006D77), secondary = Color(0xFF71556B),
        surface = Color(0xFFF7FAFA), background = Color(0xFFF7FAFA),
    )
    val base = Typography()
    MaterialTheme(colorScheme = colors,
        typography = base.copy(
            titleLarge = base.titleLarge.copy(letterSpacing = 0.sp),
            titleMedium = base.titleMedium.copy(letterSpacing = 0.sp),
            bodyLarge = base.bodyLarge.copy(letterSpacing = 0.sp),
            bodyMedium = base.bodyMedium.copy(letterSpacing = 0.sp),
            bodySmall = base.bodySmall.copy(letterSpacing = 0.sp),
            labelLarge = base.labelLarge.copy(letterSpacing = 0.sp),
        ), content = content)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(scan: ScanViewModel) {
    val state by scan.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    var onlyOpen by remember { mutableStateOf(false) }
    var hostView by remember { mutableStateOf(false) }
    var respondingOnly by remember { mutableStateOf(true) }
    var about by remember { mutableStateOf(false) }
    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        val snapshot = scan.takeExport()
        if (uri != null) scope.launch {
            val success = withContext(Dispatchers.IO) {
                runCatching {
                    requireNotNull(snapshot) { "Report no longer available" }
                    val stream = requireNotNull(context.contentResolver.openOutputStream(uri))
                    stream.bufferedWriter(Charsets.UTF_8).use { it.write(snapshot.reportJson()) }
                }.isSuccess
            }
            snackbar.showSnackbar(context.getString(if (success) R.string.exported else R.string.export_failed))
        }
    }
    val permissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        // Permission grants never start scans; a new explicit Start action is required.
        scope.launch { snackbar.showSnackbar(context.getString(if (granted) R.string.permission_granted else R.string.permission_denied)) }
    }
    val shown = remember(state.observations, onlyOpen) { if (onlyOpen) state.observations.filter { it.state == "open" } else state.observations }
    val showHosts = state.scannedDiscoveryOnly == true || hostView
    val shownHosts = remember(state.hosts, respondingOnly) { if (respondingOnly) state.hosts.filter { it.state == "responding" } else state.hosts }
    Scaffold(
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(title = { Text("GoMap") }, actions = {
                if (state.running) ActionIcon(R.string.stop, enabled = state.phase == ScanPhase.RUNNING, icon = { Icon(Icons.Default.Close, null) }) { scan.stop() }
                else ActionIcon(R.string.export, enabled = state.summary != null || state.observations.isNotEmpty() || state.hosts.isNotEmpty(), icon = { Icon(Icons.Default.Share, null) }) {
                    if (scan.prepareExport()) exportLauncher.launch("gomap-scan.json")
                }
                ActionIcon(R.string.clear, enabled = !state.running, icon = { Icon(Icons.Default.Delete, null) }) { scan.clear() }
                ActionIcon(R.string.about, enabled = true, icon = { Icon(Icons.Default.Info, null) }) { about = true }
            })
        },
    ) { padding ->
        LazyColumn(modifier = Modifier.fillMaxSize().padding(padding).imePadding().testTag("scan-content"), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min)) {
                        listOf(R.string.port_scan, R.string.host_discovery).forEachIndexed { index, label ->
                            SegmentedButton(selected = state.discoveryOnly == (index == 1), enabled = !state.running,
                                onClick = { scan.setDiscoveryOnly(index == 1) }, shape = SegmentedButtonDefaults.itemShape(index, 2),
                                modifier = Modifier.fillMaxHeight().testTag("scan-mode-$index")) { Text(stringResource(label)) }
                        }
                    }
                    OutlinedTextField(value = state.host, onValueChange = scan::setHost, enabled = !state.running,
                        label = { Text(stringResource(R.string.target)) }, placeholder = { Text("10.0.11.0/24") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false),
                        singleLine = true, modifier = Modifier.fillMaxWidth())
                    if (!state.discoveryOnly) OutlinedTextField(value = state.ports, onValueChange = scan::setPorts, enabled = !state.running,
                        label = { Text(stringResource(R.string.ports)) },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii, autoCorrectEnabled = false),
                        singleLine = true, modifier = Modifier.fillMaxWidth())
                    if (!state.discoveryOnly) Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Text(stringResource(R.string.services), modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                        Switch(checked = state.services, enabled = !state.running, onCheckedChange = scan::setServices,
                            modifier = Modifier.semantics { contentDescription = context.getString(R.string.services) })
                    }
                    Row(modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("authorization").toggleable(
                        value = state.authorized, enabled = !state.running, role = Role.Checkbox, onValueChange = scan::setAuthorized,
                    ), verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = state.authorized, onCheckedChange = null, enabled = !state.running)
                        Text(stringResource(R.string.authorization), modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                    }
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(enabled = !state.running && state.authorized && state.host.isNotBlank() && (state.discoveryOnly || state.ports.isNotBlank()), onClick = {
                            if (needsLocalNetworkPermission(Build.VERSION.SDK_INT, context.checkSelfPermission(LOCAL_NETWORK_PERMISSION) == PackageManager.PERMISSION_GRANTED)) permissionLauncher.launch(LOCAL_NETWORK_PERMISSION)
                            else scan.start()
                        }) { Icon(Icons.Default.PlayArrow, null); Spacer(Modifier.width(8.dp)); Text(stringResource(R.string.start)) }
                        OutlinedButton(enabled = state.phase == ScanPhase.RUNNING, onClick = scan::stop) {
                            Icon(Icons.Default.Close, null); Spacer(Modifier.width(8.dp)); Text(stringResource(R.string.stop))
                        }
                    }
                }
            }
            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(phaseLabel(state.phase)), style = MaterialTheme.typography.titleMedium)
                    state.scannedHost?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
                    if (!(state.scannedDiscoveryOnly ?: state.discoveryOnly)) Text(pluralStringResource(R.plurals.observed, state.observations.size, state.observations.size), style = MaterialTheme.typography.bodySmall)
                    if (state.hosts.isNotEmpty()) Text(stringResource(R.string.hosts_observed, state.hosts.count { it.state == "responding" }, state.hosts.size), style = MaterialTheme.typography.bodySmall)
                    if (state.running) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    state.error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium) }
                }
            }
            state.summary?.takeIf { it.requested > 0 }?.let { summary ->
                item {
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(stringResource(R.string.coverage), style = MaterialTheme.typography.titleMedium)
                        Text(stringResource(R.string.completed_count, summary.completed, summary.requested))
                        FlowRow(horizontalArrangement = Arrangement.spacedBy(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(stringResource(R.string.open_count, summary.open))
                            Text(stringResource(R.string.closed_count, summary.closed))
                            Text(stringResource(R.string.filtered_count, summary.filtered))
                            Text(stringResource(R.string.unknown_count, summary.unknown))
                            Text(stringResource(R.string.unreported_count, summary.unreported))
                        }
                    }
                }
            }
            state.discovery?.let { discovery ->
                item {
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(stringResource(R.string.discovery_coverage), style = MaterialTheme.typography.titleMedium)
                        Text(stringResource(R.string.host_coverage_counts, discovery.completed, discovery.requested, discovery.responding, discovery.noResponse, discovery.unknown, discovery.unreported))
                    }
                }
            }
            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    HorizontalDivider()
                    Text(stringResource(R.string.results), style = MaterialTheme.typography.titleMedium)
                    if (state.hosts.isNotEmpty() && state.scannedDiscoveryOnly != true) SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                        listOf(R.string.ports_view, R.string.hosts_view).forEachIndexed { index, label ->
                            SegmentedButton(selected = hostView == (index == 1), onClick = { hostView = index == 1 }, shape = SegmentedButtonDefaults.itemShape(index, 2)) { Text(stringResource(label)) }
                        }
                    }
                    SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                        val labels = if (showHosts) listOf(R.string.all_hosts, R.string.responding_hosts) else listOf(R.string.all_results, R.string.open_results)
                        labels.forEachIndexed { index, label ->
                            SegmentedButton(selected = (if (showHosts) respondingOnly else onlyOpen) == (index == 1),
                                onClick = { if (showHosts) respondingOnly = index == 1 else onlyOpen = index == 1 }, shape = SegmentedButtonDefaults.itemShape(index, 2)) { Text(stringResource(label)) }
                        }
                    }
                }
            }
            if (showHosts) {
                if (shownHosts.isEmpty()) item { Text(stringResource(R.string.empty_results)) }
                items(shownHosts, key = { "host/${it.address}" }) { host ->
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(host.address, fontFamily = FontFamily.Monospace)
                        Text(stringResource(when (host.state) { "responding" -> R.string.host_responding; "no_response" -> R.string.host_no_response; else -> R.string.state_unknown }))
                        Text(host.evidence, style = MaterialTheme.typography.bodySmall)
                        HorizontalDivider(modifier = Modifier.padding(top = 8.dp))
                    }
                }
            } else {
                if (shown.isEmpty()) item { Text(stringResource(R.string.empty_results), style = MaterialTheme.typography.bodyMedium) }
                items(shown, key = { "${it.host}/${it.port}" }) { row ->
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.fillMaxWidth()) {
                        if (row.host.isNotEmpty()) Text(row.host, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                            Text(row.port.toString(), fontFamily = FontFamily.Monospace, modifier = Modifier.widthIn(min = 64.dp))
                            Text(stringResource(when (row.state) { "open" -> R.string.state_open; "closed" -> R.string.state_closed; "filtered" -> R.string.state_filtered; else -> R.string.state_unknown }),
                                modifier = Modifier.weight(1f), color = if (row.state == "open") MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface)
                        }
                        if (row.service.isNotEmpty()) Text(if (row.confidence == "low" && row.evidence.startsWith("port map")) stringResource(R.string.probable_service, row.service) else row.service, style = MaterialTheme.typography.bodySmall)
                        if (row.version.isNotEmpty()) Text(row.version, style = MaterialTheme.typography.bodyMedium)
                        if (row.confidence.isNotEmpty()) Text(stringResource(R.string.confidence, row.confidence), style = MaterialTheme.typography.bodySmall)
                        if (row.evidence.isNotEmpty()) Text(row.evidence, style = MaterialTheme.typography.bodySmall)
                        HorizontalDivider(modifier = Modifier.padding(top = 8.dp))
                    }
                }
            }
        }
    }
    if (about) AlertDialog(onDismissRequest = { about = false }, title = { Text("GoMap") },
        text = { Text(stringResource(R.string.development_version, BuildConfig.VERSION_NAME) + "\nNexusFireMan") },
        confirmButton = { TextButton(onClick = { about = false }) { Text(stringResource(R.string.close)) } })
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ActionIcon(label: Int, enabled: Boolean, icon: @Composable () -> Unit, onClick: () -> Unit) {
    val text = stringResource(label)
    TooltipBox(positionProvider = TooltipDefaults.rememberTooltipPositionProvider(TooltipAnchorPosition.Above), tooltip = { PlainTooltip { Text(text) } }, state = rememberTooltipState()) {
        IconButton(enabled = enabled, onClick = onClick, modifier = Modifier.size(48.dp).semantics { contentDescription = text }) {
            icon()
        }
    }
}

internal fun needsLocalNetworkPermission(sdk: Int, granted: Boolean): Boolean = sdk >= 37 && !granted

private fun phaseLabel(phase: ScanPhase): Int = when (phase) {
    ScanPhase.IDLE -> R.string.idle
    ScanPhase.RUNNING -> R.string.running
    ScanPhase.STOPPING -> R.string.stopping
    ScanPhase.COMPLETED -> R.string.completed
    ScanPhase.CANCELLED -> R.string.cancelled
    ScanPhase.FAILED -> R.string.failed
}
