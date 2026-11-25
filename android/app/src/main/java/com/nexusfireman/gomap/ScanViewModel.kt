package com.nexusfireman.gomap

import androidx.lifecycle.ViewModel
import com.nexusfireman.gomap.mobile.Mobile
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicBoolean

enum class ScanPhase { IDLE, RUNNING, STOPPING, COMPLETED, CANCELLED, FAILED }

data class ScanState(
    val host: String = "",
    val ports: String = "22,80,443",
    val portPreset: PortPreset = PortPreset.CUSTOM,
    val scannedPortPreset: PortPreset? = null,
    val authorized: Boolean = false,
    val services: Boolean = true,
    val discoveryOnly: Boolean = false,
    val scannedServices: Boolean? = null,
    val scannedDiscoveryOnly: Boolean? = null,
    val scannedHost: String? = null,
    val scannedPorts: String? = null,
    val phase: ScanPhase = ScanPhase.IDLE,
    val observations: List<Observation> = emptyList(),
    val hosts: List<HostObservation> = emptyList(),
    val discovery: DiscoverySummary? = null,
    val summary: CoverageSummary? = null,
    val error: String? = null,
) {
    val running: Boolean get() = phase == ScanPhase.RUNNING || phase == ScanPhase.STOPPING
    val effectivePorts: String get() = portPreset.specification(ports)
}

interface ScanSession {
    fun nextEvent(): String
    fun cancel()
    fun awaitSummary(): String
}

fun interface ScanBackend {
    fun start(host: String, ports: String): ScanSession
    fun survey(host: String, ports: String, services: Boolean, discoveryOnly: Boolean): ScanSession = start(host, ports)
}

class GoScanBackend(private val ready: Boolean = true) : ScanBackend {
    override fun start(host: String, ports: String): ScanSession {
        check(ready) { "Native library unavailable" }
        val session = Mobile.startConnect(host, ports)
        return object : ScanSession {
            override fun nextEvent(): String = session.nextEvent()
            override fun cancel() = session.cancel()
            override fun awaitSummary(): String = session.awaitSummary()
        }
    }
    override fun survey(host: String, ports: String, services: Boolean, discoveryOnly: Boolean): ScanSession {
        check(ready) { "Native library unavailable" }
        val session = Mobile.startSurvey(host, ports, services, discoveryOnly)
        return object : ScanSession {
            override fun nextEvent(): String = session.nextEvent()
            override fun cancel() = session.cancel()
            override fun awaitSummary(): String = session.awaitSummary()
        }
    }
}

private class RunControl {
    val cancelled = AtomicBoolean()
    @Volatile var session: ScanSession? = null
    fun cancel() { cancelled.set(true); session?.cancel() }
    fun attach(value: ScanSession) { session = value; if (cancelled.get()) value.cancel() }
}

class ScanViewModel(
    private val backend: ScanBackend = GoScanBackend(),
    private val executor: ExecutorService = Executors.newSingleThreadExecutor(),
) : ViewModel() {
    private val gate = Any()
    private var active: RunControl? = null
    private var disposed = false
    private var initialAddressHandled = false
    private var hostEdited = false
    private var pendingExport: ScanState? = null
    private val mutableState = MutableStateFlow(ScanState())
    val state: StateFlow<ScanState> = mutableState.asStateFlow()

    fun setHost(value: String) = edit { hostEdited = true; it.copy(host = value, authorized = it.authorized && value == it.host) }
    fun initializeHost(value: String?) = synchronized(gate) {
        if (initialAddressHandled || disposed) return@synchronized
        initialAddressHandled = true
        if (!hostEdited && active == null && mutableState.value.host.isEmpty() && value != null) {
            mutableState.update { it.copy(host = value, authorized = false) }
        }
    }
    fun setPorts(value: String) = edit { it.copy(ports = value, authorized = it.authorized && value == it.ports) }
    fun setPortPreset(value: PortPreset) = edit { it.copy(portPreset = value, authorized = it.authorized && value == it.portPreset) }
    fun setAuthorized(value: Boolean) = edit { it.copy(authorized = value) }
    fun setServices(value: Boolean) = edit { it.copy(services = value, authorized = it.authorized && value == it.services) }
    fun setDiscoveryOnly(value: Boolean) = edit { it.copy(discoveryOnly = value, authorized = it.authorized && value == it.discoveryOnly) }
    private fun edit(transform: (ScanState) -> ScanState) = synchronized(gate) {
        if (active == null && !disposed) mutableState.update(transform)
    }

    fun clear() = edit { pendingExport = null; it.copy(phase = ScanPhase.IDLE, scannedHost = null, scannedPorts = null, scannedPortPreset = null, scannedServices = null, scannedDiscoveryOnly = null, observations = emptyList(), hosts = emptyList(), discovery = null, summary = null, error = null) }

    fun prepareExport(): Boolean = synchronized(gate) {
        val snapshot = mutableState.value
        if (disposed || active != null || (snapshot.summary == null && snapshot.observations.isEmpty() && snapshot.hosts.isEmpty())) return@synchronized false
        pendingExport = snapshot
        true
    }
    fun takeExport(): ScanState? = synchronized(gate) { pendingExport.also { pendingExport = null } }

    fun start() = synchronized(gate) {
        val input = mutableState.value
        if (disposed || active != null || !input.authorized || input.host.isBlank() || (!input.discoveryOnly && input.effectivePorts.isBlank())) return@synchronized
        val run = RunControl()
        active = run
        mutableState.value = input.copy(phase = ScanPhase.RUNNING, scannedHost = input.host.trim(), scannedPorts = if (input.discoveryOnly) "" else input.effectivePorts, scannedPortPreset = input.portPreset, scannedServices = input.services && !input.discoveryOnly, scannedDiscoveryOnly = input.discoveryOnly, observations = emptyList(), hosts = emptyList(), discovery = null, summary = null, error = null)
        try { executor.execute { execute(run, input.host.trim(), input.effectivePorts, input.services, input.discoveryOnly) } }
        catch (_: RejectedExecutionException) {
            run.cancel()
            active = null
            mutableState.update { it.copy(phase = ScanPhase.FAILED, error = "Scan worker unavailable") }
        }
    }

    fun stop() = synchronized(gate) {
        active?.let { run ->
            mutableState.update { it.copy(phase = ScanPhase.STOPPING) }
            run.cancel()
        }
    }

    private fun execute(run: RunControl, host: String, ports: String, services: Boolean, discoveryOnly: Boolean) {
        val rows = sortedMapOf<EndpointKey, Observation>()
        val canonicalHosts = mutableMapOf<String, String>()
        val hosts = linkedMapOf<String, HostObservation>()
        var summary: CoverageSummary? = null
        var discovery: DiscoverySummary? = null
        var error: String? = null
        var lastPublish = 0L
        var pending = 0
        try {
            if (!run.cancelled.get()) {
                val session = backend.survey(host, ports, services, discoveryOnly)
                run.attach(session)
                while (true) {
                    val text = session.nextEvent()
                    if (text.isEmpty()) break
                    when (nativeEventType(text)) {
                        "result" -> {
                            val row = parseObservation(text)
                            val hostIdentity = canonicalHosts.getOrPut(row.host) { row.host }
                            val key = EndpointKey(hostIdentity, row.port)
                            require(rows.size < 65535 && !rows.containsKey(key)) { "Duplicate or oversized native result set" }
                            rows[key] = row.copy(host = hostIdentity)
                        }
                        "host" -> {
                            val observed = parseHost(text)
                            require(hosts.size < 256 && !hosts.containsKey(observed.address)) { "Duplicate or oversized host set" }
                            hosts[observed.address] = observed
                        }
                        else -> throw IllegalArgumentException("Unsupported native event")
                    }
                    pending++
                    val now = System.nanoTime()
                    if (pending >= maxOf(32, rows.size / 20) || now - lastPublish >= 250_000_000L) {
                        val snapshot = rows.values.toList()
                        val hostSnapshot = hosts.values.sortedBy { it.address }
                        mutableState.update { it.copy(observations = snapshot, hosts = hostSnapshot) }
                        pending = 0
                        lastPublish = now
                    }
                }
                val text = session.awaitSummary()
                val (nativeSummary, nativeError) = parseSummary(text, rows.values)
                discovery = parseDiscovery(text, hosts.values)
                summary = nativeSummary
                if (nativeError == "cancelled") run.cancelled.set(true)
                if (nativeError.isNotEmpty() && nativeError != "cancelled") error = if (nativeError == "result_limit") "Open-result safety limit reached; scan incomplete" else "Native scan failed"
            }
        } catch (e: Exception) {
            error = safeError(e.message)
        } catch (_: LinkageError) {
            error = "Native library unavailable"
        } finally {
            run.session?.let { session ->
                try { session.cancel(); session.awaitSummary() }
                catch (_: Exception) { if (error == null) error = "Native cleanup failed" }
                catch (_: LinkageError) { if (error == null) error = "Native cleanup failed" }
            }
            synchronized(gate) {
                if (active === run) {
                    val phase = when {
                        error != null -> ScanPhase.FAILED
                        run.cancelled.get() || summary?.cancelled == true -> ScanPhase.CANCELLED
                        summary != null -> ScanPhase.COMPLETED
                        else -> ScanPhase.FAILED
                    }
                    mutableState.update { it.copy(phase = phase, observations = rows.values.toList(), hosts = hosts.values.sortedBy { it.address }, discovery = discovery, summary = summary, error = error) }
                    active = null
                }
            }
        }
    }

    internal fun dispose() {
        synchronized(gate) { disposed = true; pendingExport = null; active?.cancel() }
        executor.shutdown()
    }
    override fun onCleared() = dispose()
}

private data class EndpointKey(val host: String, val port: Int) : Comparable<EndpointKey> {
    override fun compareTo(other: EndpointKey): Int = host.compareTo(other.host).takeIf { it != 0 } ?: port.compareTo(other.port)
}

private fun safeError(text: String?): String = text.orEmpty().filter {
    !it.isISOControl() && Character.getType(it) != Character.FORMAT.toInt()
}.take(240).ifEmpty { "Scan failed" }
