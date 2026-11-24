package com.nexusfireman.gomap

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

internal fun surveyResult(host: String, row: Observation): String = buildJsonObject {
    put("schema_version", 2); put("type", "result"); put("host", host)
    put("result", wireJson.encodeToJsonElement(Observation.serializer(), row))
}.toString()

internal fun hostEvent(host: HostObservation): String = buildJsonObject {
    put("schema_version", 2); put("type", "host"); put("host", host.address)
    put("host_result", wireJson.encodeToJsonElement(HostObservation.serializer(), host))
}.toString()

internal fun surveySummary(summary: CoverageSummary, discovery: DiscoverySummary? = null): String = buildJsonObject {
    put("schema_version", 2); put("type", "summary"); put("host", "10.0.11.0/30")
    put("summary", wireJson.encodeToJsonElement(CoverageSummary.serializer(), summary))
    discovery?.let { put("discovery", wireJson.encodeToJsonElement(DiscoverySummary.serializer(), it)) }
}.toString()

internal fun hostFixture(): FixtureSession = FixtureSession(
    listOf(hostEvent(HostObservation("10.0.11.1", "responding", "tcp/443: TCP connection refused")),
        hostEvent(HostObservation("10.0.11.2", "no_response", "No TCP response; not confirmed down"))),
    surveySummary(CoverageSummary(0, 0, 0, 0, 0, 0, 0, false, 1), DiscoverySummary(2, 2, 1, 1, 0, 0)),
)

class SurveyTest {
    private fun finished(vm: ScanViewModel): ScanState = runBlocking { withTimeout(5000) { vm.state.first { !it.running && it.phase != ScanPhase.IDLE } } }

    @Test fun versionTwoRetainsHostIdentityAndRejectsContradictions() {
        val row = Observation(80, "open", true, service = "http", version = "nginx 1.26.0", confidence = "high", evidence = "Server: nginx/1.26.0")
        assertEquals("10.0.11.1", parseObservation(surveyResult("10.0.11.1", row)).host)
        assertThrows(Exception::class.java) { parseObservation(surveyResult("10.0.11.1", row.copy(host = "10.0.11.2"))) }
        assertThrows(Exception::class.java) { parseHost(hostEvent(HostObservation("10.0.11.1", "offline", "silence"))) }
    }

    @Test fun hostCoverageRequiresDeliveredStatesAndCounts() {
        val host = HostObservation("10.0.11.1", "no_response", "silence")
        val coverage = CoverageSummary(0, 0, 0, 0, 0, 0, 0, false, 1)
        val discovery = DiscoverySummary(2, 1, 0, 1, 0, 1)
        assertEquals(discovery, parseDiscovery(surveySummary(coverage, discovery), listOf(host)))
        assertThrows(Exception::class.java) { parseDiscovery(surveySummary(coverage, discovery.copy(responding = 1, noResponse = 0)), listOf(host)) }
        assertThrows(Exception::class.java) { parseDiscovery(surveySummary(coverage), listOf(host)) }
    }

    @Test fun samePortAcrossTwoHostsIsNotDeduplicatedAndExportsKeepOptions() {
        val observed = listOf("10.0.11.1", "10.0.11.2").map { HostObservation(it, "responding", "TCP connection established") }
        val session = FixtureSession(observed.map(::hostEvent) + observed.map {
            surveyResult(it.address, Observation(80, "open", true, service = "http", version = "nginx 1.26.0", confidence = "high"))
        }, surveySummary(CoverageSummary(2, 2, 2, 0, 0, 0, 0, false, 1), DiscoverySummary(2, 2, 2, 0, 0, 0)))
        var flags: Pair<Boolean, Boolean>? = null
        val vm = ScanViewModel(object : ScanBackend {
            override fun start(host: String, ports: String): ScanSession = error("legacy entry point used")
            override fun survey(host: String, ports: String, services: Boolean, discoveryOnly: Boolean): ScanSession { flags = services to discoveryOnly; return session }
        })
        try {
            vm.setHost("10.0.11.0/30"); vm.setPorts("80"); vm.setAuthorized(true); vm.start()
            val state = finished(vm)
            assertEquals(ScanPhase.COMPLETED, state.phase)
            assertEquals(2, state.observations.size)
            assertEquals(observed.map { it.address }, state.observations.map { it.host })
            assertEquals(true to false, flags)
            vm.setServices(false); vm.setDiscoveryOnly(true)
            assertFalse(vm.state.value.authorized)
            val report = Json.parseToJsonElement(vm.state.value.reportJson()).jsonObject
            assertTrue(report.getValue("services").jsonPrimitive.boolean)
            assertFalse(report.getValue("discovery_only").jsonPrimitive.boolean)
            assertEquals(2, report.getValue("hosts").jsonArray.size)
        } finally { vm.dispose() }
    }

    @Test fun discoveryOnlyAcceptsBlankPortInputAndExportsHosts() {
        val vm = ScanViewModel(ScanBackend { _, _ -> hostFixture() })
        try {
            vm.setHost("10.0.11.0/30"); vm.setPorts(""); vm.setDiscoveryOnly(true); vm.setAuthorized(true); vm.start()
            val state = finished(vm)
            assertEquals(ScanPhase.COMPLETED, state.phase)
            assertEquals(2, state.hosts.size)
            assertTrue(state.observations.isEmpty())
            assertEquals(1, state.discovery?.noResponse)
            assertEquals(false, state.scannedServices)
            assertTrue(Json.parseToJsonElement(state.reportJson()).jsonObject.getValue("discovery_only").jsonPrimitive.boolean)
        } finally { vm.dispose() }
    }

    @Test fun duplicateHostObservationsFailAndJoin() {
        val host = hostEvent(HostObservation("10.0.11.1", "responding", "TCP refused"))
        val session = FixtureSession(listOf(host, host), "unused")
        val vm = ScanViewModel(ScanBackend { _, _ -> session })
        try {
            vm.setHost("10.0.11.0/30"); vm.setAuthorized(true); vm.start()
            assertEquals(ScanPhase.FAILED, finished(vm).phase)
            assertTrue(session.cancels.get() > 0 && session.joins.get() > 0)
        } finally { vm.dispose() }
    }
}
