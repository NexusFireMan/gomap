package com.nexusfireman.gomap

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

internal fun resultEvent(row: Observation): String = buildJsonObject {
    put("schema_version", 1); put("type", "result"); put("host", "127.0.0.1")
    put("result", wireJson.encodeToJsonElement(row))
}.toString()

internal fun summaryEvent(summary: CoverageSummary, error: String = ""): String = buildJsonObject {
    put("schema_version", 1); put("type", "summary"); put("host", "127.0.0.1")
    put("summary", wireJson.encodeToJsonElement(summary)); put("error", error)
}.toString()

internal class FixtureSession(private val events: List<String>, private val summary: String) : ScanSession {
    private var index = 0
    val cancels = AtomicInteger()
    val joins = AtomicInteger()
    override fun nextEvent(): String = if (index < events.size) events[index++] else ""
    override fun cancel() { cancels.incrementAndGet() }
    override fun awaitSummary(): String { joins.incrementAndGet(); return summary }
}

internal fun finishedFixture(): FixtureSession = FixtureSession(
    listOf(resultEvent(Observation(443, "open", true, service = "https")), resultEvent(Observation(22, "closed", false))),
    summaryEvent(CoverageSummary(2, 2, 1, 1, 0, 0, 0, false, 1)),
)

class ScanViewModelTest {
    private val owned = mutableListOf<ScanViewModel>()
    @After fun cleanup() { owned.forEach { it.dispose() } }
    private fun model(backend: ScanBackend): ScanViewModel = ScanViewModel(backend).also { owned += it }
    private fun ready(vm: ScanViewModel) { vm.setHost("127.0.0.1"); vm.setPorts("22,443"); vm.setAuthorized(true) }
    private fun finished(vm: ScanViewModel): ScanState = runBlocking { withTimeout(5000) { vm.state.first { !it.running && it.phase != ScanPhase.IDLE } } }

    @Test fun authorizationAndExplicitStartAreRequired() {
        val calls = AtomicInteger()
        val session = finishedFixture()
        val vm = model { _, _ -> calls.incrementAndGet(); session }
        vm.setHost("127.0.0.1"); vm.setPorts("22,443"); vm.start()
        assertEquals(ScanPhase.IDLE, vm.state.value.phase)
        assertEquals(0, calls.get())
        vm.setAuthorized(true)
        assertEquals(0, calls.get())
        vm.start()
        val state = finished(vm)
        assertEquals(ScanPhase.COMPLETED, state.phase)
        assertEquals(listOf(22, 443), state.observations.map { it.port })
        assertEquals(1, calls.get())
        assertTrue(session.cancels.get() > 0)
        assertTrue(session.joins.get() >= 2)
    }

    @Test fun reportsKeepOriginalScopeAfterEditingAndExportIsExplicit() {
        val vm = model { _, _ -> finishedFixture() }; ready(vm); vm.start(); finished(vm)
        vm.setHost("127.0.0.2"); vm.setPorts("80")
        assertFalse(vm.state.value.authorized)
        assertTrue(vm.prepareExport())
        val report = Json.parseToJsonElement(requireNotNull(vm.takeExport()).reportJson()).jsonObject
        assertEquals("127.0.0.1", report.getValue("target").jsonPrimitive.content)
        assertEquals("22,443", report.getValue("ports").jsonPrimitive.content)
        assertEquals(2, report.getValue("results").jsonArray.size)
        assertNull(vm.takeExport())
        vm.clear()
        assertFalse(vm.prepareExport())
        assertNull(vm.state.value.scannedHost)
    }

    @Test fun cancellationDuringConstructionIsNotLostAndStartCannotOverlap() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val cancelled = CountDownLatch(1)
        val calls = AtomicInteger()
        val vm = model { _, _ ->
            calls.incrementAndGet(); entered.countDown(); check(release.await(5, TimeUnit.SECONDS))
            object : ScanSession {
                override fun cancel() { cancelled.countDown() }
                override fun nextEvent(): String { check(cancelled.await(5, TimeUnit.SECONDS)); return "" }
                override fun awaitSummary(): String = summaryEvent(CoverageSummary(2, 0, 0, 0, 0, 0, 2, true, 0), "cancelled")
            }
        }
        try {
            ready(vm); vm.start(); assertTrue(entered.await(5, TimeUnit.SECONDS))
            vm.stop(); vm.start(); assertEquals(ScanPhase.STOPPING, vm.state.value.phase)
            release.countDown()
            val state = finished(vm)
            assertEquals(ScanPhase.CANCELLED, state.phase)
            assertEquals(2, state.summary?.unreported)
            assertEquals(1, calls.get())
        } finally { release.countDown(); vm.stop() }
    }

    @Test fun disposedOwnerCancelsBlockedReaderAndCannotRestart() {
        val reading = CountDownLatch(1)
        val cancelled = CountDownLatch(1)
        val vm = model { _, _ -> object : ScanSession {
            override fun nextEvent(): String { reading.countDown(); check(cancelled.await(5, TimeUnit.SECONDS)); return "" }
            override fun cancel() { cancelled.countDown() }
            override fun awaitSummary(): String = summaryEvent(CoverageSummary(2, 0, 0, 0, 0, 0, 2, true, 0), "cancelled")
        } }
        ready(vm); vm.start(); assertTrue(reading.await(5, TimeUnit.SECONDS)); vm.dispose()
        assertEquals(ScanPhase.CANCELLED, finished(vm).phase)
        vm.start(); assertFalse(vm.state.value.running)
    }

    @Test fun duplicateOrMalformedResultsFailAndCleanupStillJoins() {
        val event = resultEvent(Observation(22, "open", true))
        for (events in listOf(listOf(event, event), listOf("invalid JSON"))) {
            val session = FixtureSession(events, summaryEvent(CoverageSummary(2, 2, 2, 0, 0, 0, 0, false, 0)))
            val vm = model { _, _ -> session }; ready(vm); vm.start()
            assertEquals(ScanPhase.FAILED, finished(vm).phase)
            assertTrue(session.cancels.get() > 0); assertTrue(session.joins.get() > 0)
        }
    }

    @Test fun backendErrorsAreBoundedAndDoNotLeakControlCharacters() {
        val vm = model { _, _ -> error("failure\n\u202e" + "x".repeat(400)) }
        ready(vm); vm.start()
        val state = finished(vm)
        assertEquals(ScanPhase.FAILED, state.phase)
        assertTrue(requireNotNull(state.error).length <= 240)
        assertFalse(state.error.contains('\n')); assertFalse(state.error.contains('\u202e'))
    }
}
