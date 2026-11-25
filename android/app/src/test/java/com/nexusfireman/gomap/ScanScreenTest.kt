package com.nexusfireman.gomap

import android.app.Application
import android.graphics.Bitmap
import android.graphics.Canvas
import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.unit.Density
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [31], application = Application::class, qualifiers = "en-rUS-w360dp-h800dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class ScanScreenTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private val calls = AtomicInteger()
    private val vm = ScanViewModel(ScanBackend { _, _ -> calls.incrementAndGet(); finishedFixture() })
    @After fun cleanup() { vm.dispose() }

    @Test fun authorizationGatesStartAndResultsAreUsableAtPhoneWidth() {
        compose.setContent { GoMapTheme { ScanScreen(vm) } }
        compose.onNodeWithText("Start").assertIsNotEnabled()
        compose.onNodeWithText("Target IP / CIDR").performTextInput("127.0.0.1")
        compose.onNodeWithText("Ports").performTextClearance()
        compose.onNodeWithText("Ports").performTextInput("22,443")
        assertEquals(0, calls.get())
        compose.onNodeWithTag("authorization").performClick()
        compose.onNodeWithText("Start").assertIsEnabled()
        screenshot("phone-ready.png")
        compose.onNodeWithText("Start").performClick()
        compose.waitUntil(5000) { vm.state.value.phase == ScanPhase.COMPLETED }
        compose.onNodeWithText("Completed").assertIsDisplayed()
        compose.onNodeWithText("Results").performScrollTo()
        compose.onNode(hasText("Open") and hasClickAction()).performScrollTo().assertIsDisplayed().performClick().assertIsSelected()
        compose.onNodeWithTag("scan-content").performScrollToNode(hasText("443"))
        compose.onNodeWithText("443").assertIsDisplayed()
        compose.onNodeWithText("22").assertDoesNotExist()
        screenshot("phone-results.png")
        assertEquals(1, calls.get())
    }

    @Test fun largeFontControlsRemainReachable() {
        compose.setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(density.density, 2f)) { GoMapTheme { ScanScreen(vm) } }
        }
        compose.onNodeWithText("Target IP / CIDR").performTextInput("127.0.0.1")
        compose.onNodeWithTag("authorization").performScrollTo().performClick()
        compose.onNodeWithText("Start").performScrollTo().assertIsDisplayed().assertIsEnabled()
        compose.onNodeWithContentDescription("About GoMap").assertIsDisplayed()
        compose.onNodeWithContentDescription("Clear results").assertIsDisplayed()
        val portMode = compose.onNodeWithTag("scan-mode-0").fetchSemanticsNode().boundsInRoot
        val hostMode = compose.onNodeWithTag("scan-mode-1").fetchSemanticsNode().boundsInRoot
        assertEquals(portMode.height, hostMode.height, 1f)
        screenshot("phone-large-font.png")
    }

    @Test fun hostDiscoveryKeepsSilentHostsSeparateAndVisibleOnRequest() {
        val hostModel = ScanViewModel(ScanBackend { _, _ -> hostFixture() })
        try {
            compose.setContent { GoMapTheme { ScanScreen(hostModel) } }
            compose.onNodeWithText("Host discovery").performClick()
            compose.onNodeWithText("Target IP / CIDR").performTextInput("10.0.11.0/30")
            compose.onNodeWithTag("authorization").performClick()
            compose.onNodeWithText("Start").performClick()
            compose.waitUntil(5000) { hostModel.state.value.phase == ScanPhase.COMPLETED }
            compose.onNodeWithText("All hosts").performScrollTo().performClick()
            compose.onNodeWithTag("scan-content").performScrollToNode(hasText("10.0.11.2"))
            compose.onNodeWithText("10.0.11.2").assertIsDisplayed()
            compose.onNodeWithTag("scan-content").performScrollToNode(hasText("No TCP response · not confirmed down"))
            compose.onNodeWithText("No TCP response · not confirmed down").assertIsDisplayed()
            screenshot("phone-network-hosts.png")
        } finally { hostModel.dispose() }
    }

    @Test fun nativeServiceVersionAndEvidenceRemainReadable() {
        val bannerModel = ScanViewModel(ScanBackend { _, _ -> FixtureSession(
            listOf(surveyResult("127.0.0.1", Observation(22222, "open", true, service = "ssh", version = "OpenSSH 9.9", confidence = "high", evidence = "SSH-2.0-OpenSSH_9.9"))),
            surveySummary(CoverageSummary(1, 1, 1, 0, 0, 0, 0, false, 1)),
        ) })
        try {
            compose.setContent { GoMapTheme { ScanScreen(bannerModel) } }
            compose.onNodeWithText("Target IP / CIDR").performTextInput("127.0.0.1")
            compose.onNodeWithText("Ports").performTextClearance()
            compose.onNodeWithText("Ports").performTextInput("22222")
            compose.onNodeWithTag("authorization").performClick()
            compose.onNodeWithText("Start").performClick()
            compose.waitUntil(5000) { bannerModel.state.value.phase == ScanPhase.COMPLETED }
            compose.onNodeWithTag("scan-content").performScrollToNode(hasText("OpenSSH 9.9"))
            compose.onNodeWithText("OpenSSH 9.9").assertIsDisplayed()
            compose.onNodeWithTag("scan-content").performScrollToNode(hasText("SSH-2.0-OpenSSH_9.9"))
            compose.onNodeWithText("SSH-2.0-OpenSSH_9.9").assertIsDisplayed()
            screenshot("phone-services.png")
        } finally { bannerModel.dispose() }
    }

    @Test fun portDropdownPreservesManualPortsAndOffersBothProfiles() {
        vm.initializeHost("10.0.11.5")
        compose.setContent { GoMapTheme { ScanScreen(vm) } }
        compose.onNodeWithText("Ports").performTextClearance()
        compose.onNodeWithText("Ports").performTextInput("2222,8080")
        compose.onNodeWithTag("port-preset").performClick()
        compose.onNodeWithText("All (65535)").performClick()
        assertEquals(PortPreset.ALL, vm.state.value.portPreset)
        compose.onNodeWithText("Ports").assertDoesNotExist()
        compose.onNodeWithTag("port-preset").performClick()
        compose.onNodeWithText("Common (1000)").performClick()
        assertEquals("@common1000", vm.state.value.effectivePorts)
        screenshot("phone-port-profiles.png")
        compose.onNodeWithTag("port-preset").performClick()
        compose.onNodeWithText("Custom").performClick()
        compose.onNodeWithText("Ports").assertTextContains("2222,8080")
        assertEquals(0, calls.get())
    }

    @Test fun toolbarStopRemainsReachableWhileBrowsingStreamedPorts() {
        val stopped = CountDownLatch(1)
        val streamModel = ScanViewModel(ScanBackend { _, _ -> object : ScanSession {
            var delivered = 0
            override fun nextEvent(): String {
                if (delivered < 40) return resultEvent(Observation(++delivered, "open", true))
                check(stopped.await(30, TimeUnit.SECONDS)); return ""
            }
            override fun cancel() { stopped.countDown() }
            override fun awaitSummary(): String = summaryEvent(CoverageSummary(100, delivered, delivered, 0, 0, 0, 100 - delivered, true, 1), "cancelled")
        } })
        try {
            compose.setContent { GoMapTheme { ScanScreen(streamModel) } }
            compose.onNodeWithText("Target IP / CIDR").performTextInput("127.0.0.1")
            compose.onNodeWithText("Ports").performTextClearance()
            compose.onNodeWithText("Ports").performTextInput("1-100")
            compose.onNodeWithTag("authorization").performClick()
            compose.onNodeWithText("Start").performClick()
            compose.waitUntil(5000) { streamModel.state.value.observations.size >= 32 }
            compose.onNodeWithTag("scan-content").performScrollToNode(hasText("32"))
            compose.onNodeWithContentDescription("Stop").assertIsDisplayed().performClick()
            compose.waitUntil(5000) { streamModel.state.value.phase == ScanPhase.CANCELLED }
            assertEquals(60, streamModel.state.value.summary?.unreported)
        } finally { stopped.countDown(); streamModel.dispose() }
    }

    private fun screenshot(name: String) {
        compose.waitForIdle()
        // Draw the Robolectric view explicitly; there is no real display Surface
        // for PixelCopy/captureToImage on this host-only test runtime.
        lateinit var image: Bitmap
        compose.runOnIdle {
            val view = compose.activity.window.decorView
            image = Bitmap.createBitmap(view.width, view.height, Bitmap.Config.ARGB_8888)
            view.draw(Canvas(image))
        }
        val file = File("build/reports/ui/$name")
        requireNotNull(file.parentFile).mkdirs()
        file.outputStream().use { image.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }
}
