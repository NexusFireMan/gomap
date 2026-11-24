package com.nexusfireman.gomap

import org.junit.Assert.*
import org.junit.Test

class ScanProtocolTest {
    @Test fun explicitStatesRemainDistinct() {
        for (state in listOf("open", "closed", "filtered", "unknown")) {
            val row = Observation(22, state, state == "open")
            assertEquals(row, parseObservation(resultEvent(row)))
        }
    }
    @Test fun unsupportedOrContradictoryEventsAreRejected() {
        for (text in listOf(resultEvent(Observation(0, "open", true)), resultEvent(Observation(22, "closed", true)),
            resultEvent(Observation(22, "open", true)).replace("\"schema_version\":1", "\"schema_version\":3"))) {
            assertThrows(Exception::class.java) { parseObservation(text) }
        }
    }
    @Test fun coverageMustReconcileIncludingCancelledWork() {
        val partial = CoverageSummary(3, 1, 1, 0, 0, 0, 2, true, 0)
        val rows = listOf(Observation(22, "open", true))
        assertEquals(partial, parseSummary(summaryEvent(partial, "cancelled"), rows).first)
        assertThrows(Exception::class.java) { parseSummary(summaryEvent(partial), emptyList()) }
        assertThrows(Exception::class.java) { parseSummary(summaryEvent(partial.copy(closed = 3)), rows) }
        assertThrows(Exception::class.java) { parseSummary(summaryEvent(partial.copy(open = 0, closed = 1)), rows) }
    }
    @Test fun permissionGuardDoesNotAskForFuturePermissionOnOlderAndroid() {
        assertFalse(needsLocalNetworkPermission(31, false))
        assertFalse(needsLocalNetworkPermission(36, false))
        assertTrue(needsLocalNetworkPermission(37, false))
        assertTrue(needsLocalNetworkPermission(38, false))
        assertFalse(needsLocalNetworkPermission(37, true))
    }
}
