package io.github.revocx35.flagsecure

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Drives the root-side work: copy the compiled Frida agent out of the APK and inject it into
 * system_server, then report which window-manager hooks landed.
 *
 * The agent (assets/agent.js) and the native frida-inject binary (jniLibs/<abi>/libfridainject.so)
 * are both bundled in the APK. Everything that needs root goes through `su -c`, so this only works
 * on a device where the user has granted this app root (Magisk / KernelSU / APatch).
 */
object Injector {

    private const val AGENT_ASSET = "agent.js"
    private const val BINARY_NAME = "libfridainject.so"

    data class Hook(val target: String, val applied: Boolean)

    data class Result(
        val success: Boolean,
        val summary: String,
        val hooks: List<Hook>,
        val log: String,
    )

    /** One parsed `fso:` line from the agent, used by [parseAgentOutput]. */
    private val HOOKED = Regex("""^fso:hooked (.+)$""")
    private val SKIPPED = Regex("""^fso:skipped (.+)$""")

    /**
     * Turn the agent's stdout into a [Result]. Pure function so it can be unit-tested without a
     * device. `ready` is emitted once the hooks are installed; `error` means the agent bailed out
     * (e.g. it could not find the system_server class loader).
     */
    fun parseAgentOutput(output: String, injectorFailed: Boolean = false): Result {
        val hooks = mutableListOf<Hook>()
        var ready = false
        var agentError: String? = null
        for (raw in output.lineSequence()) {
            val line = raw.trim()
            when {
                line == "fso:ready" -> ready = true
                line.startsWith("fso:error") -> agentError = line.removePrefix("fso:error").trim()
                else -> {
                    HOOKED.matchEntire(line)?.let { hooks += Hook(it.groupValues[1], true) }
                    SKIPPED.matchEntire(line)?.let { hooks += Hook(it.groupValues[1], false) }
                }
            }
        }
        val appliedCount = hooks.count { it.applied }
        val summary = when {
            agentError != null -> "Agent error: $agentError"
            injectorFailed && !ready -> "Injection failed before the agent ran (see log)."
            !ready && hooks.isEmpty() -> "No output from the agent — injection did not reach system_server."
            appliedCount == 0 -> "Injected, but no hooks applied — Android version may differ."
            else -> "FLAG_SECURE disabled: $appliedCount hook(s) active until reboot."
        }
        return Result(
            success = agentError == null && ready && appliedCount > 0,
            summary = summary,
            hooks = hooks,
            log = output.trim(),
        )
    }

    /** True if `su` grants a uid-0 shell to this app. */
    suspend fun hasRoot(): Boolean = withContext(Dispatchers.IO) {
        runCatching {
            val out = runSu("id -u")
            out.trim().lineSequence().any { it.trim() == "0" }
        }.getOrDefault(false)
    }

    /** Copy the agent, locate the binary, inject into system_server and parse the result. */
    suspend fun apply(context: Context): Result = withContext(Dispatchers.IO) {
        val agent = File(context.filesDir, AGENT_ASSET)
        context.assets.open(AGENT_ASSET).use { input ->
            agent.outputStream().use { input.copyTo(it) }
        }
        val binary = File(context.applicationInfo.nativeLibraryDir, BINARY_NAME)
        if (!binary.exists()) {
            return@withContext Result(
                success = false,
                summary = "frida-inject binary missing for this ABI (${binary.path}).",
                hooks = emptyList(),
                log = "",
            )
        }
        // -e eternalizes the script so the hooks survive after frida-inject detaches and exits.
        // ${'$'} emits a literal shell '$' (Kotlin would otherwise read it as a string template).
        val d = "${'$'}"
        val cmd = buildString {
            append("PID=${d}(pidof system_server); ")
            append("if [ -z \"${d}PID\" ]; then echo 'fso:error system_server not found'; exit 3; fi; ")
            append("'${binary.path}' -p \"${d}PID\" -s '${agent.path}' -e 2>&1")
        }
        val out = runCatching { runSu(cmd) }
        out.fold(
            onSuccess = { parseAgentOutput(it, injectorFailed = false) },
            onFailure = {
                Result(
                    success = false,
                    summary = "Could not run su — is root granted to this app? (${it.message})",
                    hooks = emptyList(),
                    log = it.stackTraceToString(),
                )
            },
        )
    }

    /** Run one command in a root shell and return its combined output. */
    private fun runSu(command: String): String {
        val process = ProcessBuilder("su", "-c", command)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        process.waitFor()
        return output
    }
}
