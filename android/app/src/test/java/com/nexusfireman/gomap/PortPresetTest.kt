package com.nexusfireman.gomap

import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

class PortPresetTest {
    private fun finished(vm: ScanViewModel): ScanState = runBlocking { withTimeout(5000) { vm.state.first { !it.running && it.phase != ScanPhase.IDLE } } }
    private fun ip(vararg bytes: Int): InetAddress = InetAddress.getByAddress(bytes.map { it.toByte() }.toByteArray())

    @Test fun phoneAddressPrefersUsableIPv4AndFallsBackToGlobalIPv6() {
        val ipv6 = InetAddress.getByAddress(ByteArray(16).apply { this[0] = 0xfd.toByte(); this[15] = 1 })
        assertEquals("10.0.11.5", selectPhoneAddress(listOf(ip(127, 0, 0, 1), ipv6, ip(10, 0, 11, 5))))
        assertEquals(ipv6.hostAddress, selectPhoneAddress(listOf(ipv6)))
        assertNull(selectPhoneAddress(listOf(ip(0, 0, 0, 0), ip(127, 0, 0, 1), ip(169, 254, 1, 2), ip(224, 0, 0, 1))))
        assertNull(selectPhoneAddress(emptyList()))
    }

    @Test fun initialAddressNeverScansOrOverwritesManualInputOrRotation() {
        val calls = AtomicInteger()
        val vm = ScanViewModel(ScanBackend { _, _ -> calls.incrementAndGet(); finishedFixture() })
        try {
            vm.initializeHost("10.0.11.5")
            assertEquals("10.0.11.5", vm.state.value.host)
            assertFalse(vm.state.value.authorized)
            vm.initializeHost("10.0.11.7")
            assertEquals("10.0.11.5", vm.state.value.host)
            vm.setHost("10.0.11.9"); vm.initializeHost("10.0.11.8")
            assertEquals("10.0.11.9", vm.state.value.host)
            assertEquals(0, calls.get())
        } finally { vm.dispose() }
        val edited = ScanViewModel(ScanBackend { _, _ -> error("unexpected scan") })
        try {
            edited.setHost("10.0.11.9"); edited.setHost(""); edited.initializeHost("10.0.11.5")
            assertEquals("", edited.state.value.host)
        } finally { edited.dispose() }
    }

    @Test fun profilesPreserveCustomInputConsentAndFrozenExport() {
        var selected = ""
        val vm = ScanViewModel(ScanBackend { _, ports -> selected = ports; finishedFixture() })
        try {
            vm.setHost("127.0.0.1"); vm.setPorts("2222,8080"); vm.setAuthorized(true)
            vm.setPortPreset(PortPreset.ALL)
            assertFalse(vm.state.value.authorized)
            assertEquals("1-65535", vm.state.value.effectivePorts)
            vm.setPortPreset(PortPreset.COMMON); vm.setAuthorized(true); vm.start()
            assertEquals(ScanPhase.COMPLETED, finished(vm).phase)
            assertEquals("@common1000", selected)
            vm.setPortPreset(PortPreset.CUSTOM)
            assertEquals("2222,8080", vm.state.value.ports)
            val report = Json.parseToJsonElement(vm.state.value.reportJson()).jsonObject
            assertEquals("common", report.getValue("port_profile").jsonPrimitive.content)
            assertEquals("@common1000", report.getValue("ports").jsonPrimitive.content)
            val bytes = ByteArrayOutputStream()
            vm.state.value.writeReport(bytes)
            assertEquals(report, Json.parseToJsonElement(bytes.toString(Charsets.UTF_8.name())))
        } finally { vm.dispose() }
    }

    @Test fun fullRangeRetainsEveryResultAndStreamsJsonWithoutNetwork() {
        val vm = ScanViewModel(ScanBackend { _, _ -> object : ScanSession {
            var port = 0
            override fun nextEvent(): String = if (port < 65535) resultEvent(Observation(++port, "closed", false)) else ""
            override fun cancel() = Unit
            override fun awaitSummary(): String = summaryEvent(CoverageSummary(65535, 65535, 0, 65535, 0, 0, 0, false, 1))
        } })
        try {
            vm.setHost("127.0.0.1"); vm.setPortPreset(PortPreset.ALL); vm.setAuthorized(true); vm.start()
            val state = runBlocking { withTimeout(30000) { vm.state.first { it.phase == ScanPhase.COMPLETED || it.phase == ScanPhase.FAILED } } }
            assertEquals(ScanPhase.COMPLETED, state.phase)
            assertEquals(65535, state.observations.size)
            assertEquals(1, state.observations.first().port)
            assertEquals(65535, state.observations.last().port)
            var written = 0L
            state.writeReport(object : java.io.OutputStream() {
                override fun write(b: Int) { written++ }
                override fun write(b: ByteArray, off: Int, len: Int) { written += len }
            })
            assertTrue(written > 65535)
        } finally { vm.dispose() }
    }
}
