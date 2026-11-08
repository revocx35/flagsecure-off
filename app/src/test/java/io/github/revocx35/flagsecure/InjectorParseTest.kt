package io.github.revocx35.flagsecure

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Unit tests for the agent-output parser (no device needed). */
class InjectorParseTest {

    @Test
    fun parsesAppliedAndSkippedHooks() {
        val out = """
            fso:hooked com.android.server.wm.WindowState.isSecureLocked
            fso:hooked com.android.server.wm.WmScreenshotController.canBeScreenshotTarget
            fso:skipped android.window.ScreenCapture${'$'}ScreenshotHardwareBuffer.containsSecureLayers
            fso:ready
        """.trimIndent()

        val r = Injector.parseAgentOutput(out)

        assertTrue(r.success)
        assertEquals(3, r.hooks.size)
        assertEquals(2, r.hooks.count { it.applied })
        assertTrue(r.summary.contains("2 hook"))
    }

    @Test
    fun agentErrorIsNotSuccess() {
        val r = Injector.parseAgentOutput("fso:error services classloader not found")
        assertFalse(r.success)
        assertTrue(r.summary.contains("Agent error"))
    }

    @Test
    fun readyButNoHooksIsNotSuccess() {
        val r = Injector.parseAgentOutput("fso:ready")
        assertFalse(r.success)
        assertTrue(r.summary.contains("no hooks"))
    }

    @Test
    fun emptyOutputIsNotSuccess() {
        val r = Injector.parseAgentOutput("")
        assertFalse(r.success)
        assertTrue(r.hooks.isEmpty())
    }

    @Test
    fun ignoresNonFsoNoise() {
        val out = """
            Spawned system_server
            fso:hooked com.android.server.wm.WindowState.isSecureLocked
            some unrelated log line
            fso:ready
        """.trimIndent()
        val r = Injector.parseAgentOutput(out)
        assertTrue(r.success)
        assertEquals(1, r.hooks.size)
    }
}
