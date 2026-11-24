package com.nexusfireman.gomap

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.nexusfireman.gomap.mobile.Mobile
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.net.ServerSocket

@RunWith(AndroidJUnit4::class)
class NativeLoopbackTest {
    @Test fun nativeConnectAndCleanupOnDevice() {
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { server ->
            val session = Mobile.startConnect("127.0.0.1", server.localPort.toString())
            try {
                val row = parseObservation(session.nextEvent())
                assertEquals(server.localPort, row.port)
                assertEquals("open", row.state)
                assertEquals("", session.nextEvent())
                val (summary, error) = parseSummary(session.awaitSummary(), listOf(row))
                assertEquals(1, summary.open)
                assertEquals(0, summary.unreported)
                assertEquals("", error)
            } finally { session.cancel(); session.awaitSummary() }
        }
    }
}
