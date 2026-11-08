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

    // The bypass is "on" exactly while our frida-inject stays attached to system_server. Its PID is
    // kept here; turning off SIGTERMs it, which makes frida unload the agent and restore the
    // original methods (no residual overhead). The .out file holds the injector's log for parsing.
    private const val PID_FILE = "/data/local/tmp/fso.pid"
    private const val OUT_FILE = "/data/local/tmp/fso.out"

    // Shell snippet: succeeds only if PID_FILE names a live process that is really our injector
    // (guards against PID reuse after a reboot). Depends on $d expanding to a literal '$'.
    private fun ours(d: String) =
        "P=${d}(cat '$PID_FILE' 2>/dev/null); [ -n \"${d}P\" ] && " +
            "grep -qa fridainject /proc/${d}P/cmdline 2>/dev/null"

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
        var selinuxBefore: String? = null
        var selinuxAfter: String? = null
        for (raw in output.lineSequence()) {
            val line = raw.trim()
            when {
                line == "fso:ready" -> ready = true
                line.startsWith("fso:error") -> agentError = line.removePrefix("fso:error").trim()
                line.startsWith("fso:selinux-before") ->
                    selinuxBefore = line.removePrefix("fso:selinux-before").trim()
                line.startsWith("fso:selinux-after") ->
                    selinuxAfter = line.removePrefix("fso:selinux-after").trim()
                else -> {
                    HOOKED.matchEntire(line)?.let { hooks += Hook(it.groupValues[1], true) }
                    SKIPPED.matchEntire(line)?.let { hooks += Hook(it.groupValues[1], false) }
                }
            }
        }
        val reused = output.lineSequence().any { it.trim() == "fso:reused" }
        val appliedCount = hooks.count { it.applied }
        // When injection didn't reach the agent, the likeliest cause on Samsung/Knox is SELinux:
        // either setenforce 0 was blocked by RKP (still Enforcing) or something else killed the
        // agent even while Permissive.
        val selinuxHint = when {
            !ready && selinuxAfter.equals("Enforcing", ignoreCase = true) ->
                " SELinux is still Enforcing (setenforce 0 was blocked — Knox/RKP). Frida cannot " +
                    "inject into system_server. A kernel-level SELinux rule is needed."
            !ready && selinuxAfter.equals("Permissive", ignoreCase = true) ->
                " SELinux is Permissive but the agent still died — likely a Knox/seccomp block " +
                    "(see log)."
            else -> ""
        }
        val summary = when {
            agentError != null -> "Agent error: $agentError"
            reused ->
                "FLAG_SECURE disabled — reused this boot's injection (screenshots allowed again)."
            injectorFailed && !ready -> "Injection failed before the agent ran (see log).$selinuxHint"
            !ready && hooks.isEmpty() ->
                "No output from the agent — injection did not reach system_server.$selinuxHint"
            appliedCount == 0 -> "Injected, but no hooks applied — Android version may differ."
            else -> "FLAG_SECURE disabled: $appliedCount hook(s) active. " +
                "Toggle it with the buttons — no reboot needed."
        }
        return Result(
            success = agentError == null && ready && (appliedCount > 0 || reused),
            summary = summary,
            hooks = hooks,
            log = output.trim(),
        )
    }

    /**
     * True when the bypass is live right now: our frida-inject is still attached to system_server.
     * Used by the quick-settings tile and buttons to show on/off.
     */
    suspend fun isActive(): Boolean = withContext(Dispatchers.IO) {
        val d = "${'$'}"
        runCatching {
            val out = runSu("if ${ours(d)}; then echo ACTIVE; else echo INACTIVE; fi")
            out.lineSequence().any { it.trim() == "ACTIVE" }
        }.getOrDefault(false)
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
        // Frida must load its agent into the system_server SELinux domain. On stock/Knox Android
        // that is denied while enforcing, so we drop SELinux to permissive first (reverts on
        // reboot) and report whether it actually took — on Knox/RKP setenforce 0 can be ignored.
        // On failure we also dump recent AVC denials so the real block is visible.
        // ${'$'} emits a literal shell '$' (Kotlin would otherwise read it as a string template).
        // Inject once and keep frida-inject attached in the background (NOT eternalized), so turning
        // off can SIGTERM it and cleanly revert. If it is already attached this boot, report reused.
        val d = "${'$'}"
        val cmd = buildString {
            append("if ${ours(d)}; then echo fso:reused; echo fso:ready; exit 0; fi; ")
            append("echo \"fso:selinux-before ${d}(getenforce 2>/dev/null)\"; ")
            append("setenforce 0 2>/dev/null; ")
            append("echo \"fso:selinux-after ${d}(getenforce 2>/dev/null)\"; ")
            append("SS=${d}(pidof system_server); ")
            append("if [ -z \"${d}SS\" ]; then echo 'fso:error system_server not found'; exit 3; fi; ")
            append(": > '$OUT_FILE'; ")
            // detached, stdin from /dev/null so frida-inject does not read it and stays running
            append("nohup '${binary.path}' -p \"${d}SS\" -s '${agent.path}' >> '$OUT_FILE' 2>&1 </dev/null & ")
            append("echo ${d}! > '$PID_FILE'; ")
            append("for i in ${d}(seq 1 60); do ")
            append("grep -q fso:ready '$OUT_FILE' && break; ")
            append("grep -qiE 'closed unexpectedly|unable to|error|denied' '$OUT_FILE' && break; ")
            append("kill -0 ${d}(cat '$PID_FILE') 2>/dev/null || break; ")
            append("sleep 0.25; done; ")
            append("cat '$OUT_FILE'; ")
            append("if ! grep -q fso:ready '$OUT_FILE'; then ")
            append("echo '--- recent SELinux denials ---'; ")
            append("{ logcat -d -b all -t 500 2>/dev/null; dmesg 2>/dev/null; } ")
            append("| grep -iE 'avc: *denied|frida|system_server' | tail -25; ")
            append("kill -TERM ${d}(cat '$PID_FILE') 2>/dev/null; rm -f '$PID_FILE'; fi")
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

    /**
     * Re-enable FLAG_SECURE instantly and cleanly: SIGTERM our frida-inject so frida unloads the
     * agent and restores the original methods. Nothing stays hooked, so there is no residual
     * slowdown. Harmless if nothing is attached. No reboot.
     */
    suspend fun reEnable(): Result = withContext(Dispatchers.IO) {
        val d = "${'$'}"
        val cmd = "if ${ours(d)}; then kill -TERM \"${d}P\" 2>/dev/null; fi; rm -f '$PID_FILE'; echo ok"
        runCatching { runSu(cmd) }.fold(
            onSuccess = {
                if (it.contains("ok")) {
                    Result(
                        success = true,
                        summary = "FLAG_SECURE re-enabled and the hooks removed — no leftover " +
                            "slowdown. No reboot needed; tap Disable to allow screenshots again.",
                        hooks = emptyList(),
                        log = "",
                    )
                } else {
                    Result(false, "Could not revert (see log).", emptyList(), it.trim())
                }
            },
            onFailure = {
                Result(false, "Could not run su — is root granted? (${it.message})", emptyList(), "")
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
