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
        compose.onNodeWithText("Target IP").performTextInput("127.0.0.1")
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
        compose.onNode(hasText("Open") and hasClickAction()).performClick()
        compose.onNodeWithText("443").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("22").assertDoesNotExist()
        screenshot("phone-results.png")
        assertEquals(1, calls.get())
    }

    @Test fun largeFontControlsRemainReachable() {
        compose.setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(density.density, 2f)) { GoMapTheme { ScanScreen(vm) } }
        }
        compose.onNodeWithText("Target IP").performTextInput("127.0.0.1")
        compose.onNodeWithTag("authorization").performScrollTo().performClick()
        compose.onNodeWithText("Start").performScrollTo().assertIsDisplayed().assertIsEnabled()
        screenshot("phone-large-font.png")
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
