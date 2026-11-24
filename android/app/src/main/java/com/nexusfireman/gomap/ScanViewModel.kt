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
    val authorized: Boolean = false,
    val scannedHost: String? = null,
    val scannedPorts: String? = null,
    val phase: ScanPhase = ScanPhase.IDLE,
    val observations: List<Observation> = emptyList(),
    val summary: CoverageSummary? = null,
    val error: String? = null,
) {
    val running: Boolean get() = phase == ScanPhase.RUNNING || phase == ScanPhase.STOPPING
}

interface ScanSession {
    fun nextEvent(): String
    fun cancel()
    fun awaitSummary(): String
}

fun interface ScanBackend { fun start(host: String, ports: String): ScanSession }

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
    private var pendingExport: ScanState? = null
    private val mutableState = MutableStateFlow(ScanState())
    val state: StateFlow<ScanState> = mutableState.asStateFlow()

    fun setHost(value: String) = edit { it.copy(host = value, authorized = it.authorized && value == it.host) }
    fun setPorts(value: String) = edit { it.copy(ports = value, authorized = it.authorized && value == it.ports) }
    fun setAuthorized(value: Boolean) = edit { it.copy(authorized = value) }
    private fun edit(transform: (ScanState) -> ScanState) = synchronized(gate) {
        if (active == null && !disposed) mutableState.update(transform)
    }

    fun clear() = edit { pendingExport = null; it.copy(phase = ScanPhase.IDLE, scannedHost = null, scannedPorts = null, observations = emptyList(), summary = null, error = null) }

    fun prepareExport(): Boolean = synchronized(gate) {
        val snapshot = mutableState.value
        if (disposed || active != null || (snapshot.summary == null && snapshot.observations.isEmpty())) return@synchronized false
        pendingExport = snapshot
        true
    }
    fun takeExport(): ScanState? = synchronized(gate) { pendingExport.also { pendingExport = null } }

    fun start() = synchronized(gate) {
        val input = mutableState.value
        if (disposed || active != null || !input.authorized || input.host.isBlank() || input.ports.isBlank()) return@synchronized
        val run = RunControl()
        active = run
        mutableState.value = input.copy(phase = ScanPhase.RUNNING, scannedHost = input.host.trim(), scannedPorts = input.ports.trim(), observations = emptyList(), summary = null, error = null)
        try { executor.execute { execute(run, input.host.trim(), input.ports.trim()) } }
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

    private fun execute(run: RunControl, host: String, ports: String) {
        val rows = linkedMapOf<Int, Observation>()
        var summary: CoverageSummary? = null
        var error: String? = null
        var lastPublish = 0L
        var pending = 0
        try {
            if (!run.cancelled.get()) {
                val session = backend.start(host, ports)
                run.attach(session)
                while (true) {
                    val text = session.nextEvent()
                    if (text.isEmpty()) break
                    val row = parseObservation(text)
                    require(rows.size < 4096 && !rows.containsKey(row.port)) { "Duplicate or oversized native result set" }
                    rows[row.port] = row
                    pending++
                    val now = System.nanoTime()
                    if (pending >= 16 || now - lastPublish >= 100_000_000L) {
                        val snapshot = rows.values.sortedBy { it.port }
                        mutableState.update { it.copy(observations = snapshot) }
                        pending = 0
                        lastPublish = now
                    }
                }
                val (nativeSummary, nativeError) = parseSummary(session.awaitSummary(), rows.values)
                summary = nativeSummary
                if (nativeError == "cancelled") run.cancelled.set(true)
                if (nativeError.isNotEmpty() && nativeError != "cancelled") error = "Native scan failed"
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
                    mutableState.update { it.copy(phase = phase, observations = rows.values.sortedBy { row -> row.port }, summary = summary, error = error) }
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

private fun safeError(text: String?): String = text.orEmpty().filter {
    !it.isISOControl() && Character.getType(it) != Character.FORMAT.toInt()
}.take(240).ifEmpty { "Scan failed" }
