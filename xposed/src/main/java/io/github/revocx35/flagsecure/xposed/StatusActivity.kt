package io.github.revocx35.flagsecure.xposed

import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.text.method.ScrollingMovementMethod
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Minimal status screen. The real work is the Xposed hook; this just tells the user how to enable
 * the module and whether the hook is currently loaded. `isModuleActive` is rewritten by the Xposed
 * hook at runtime, so if it still reads false here, the module is not active yet.
 */
class StatusActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val active = isModuleActive()
        val pad = (16 * resources.displayMetrics.density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }

        root.addView(TextView(this).apply {
            text = "FLAG_SECURE off (Xposed)"
            textSize = 22f
            setTextColor(Color.BLACK)
        })
        root.addView(TextView(this).apply {
            text = "Version ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})"
            textSize = 13f
            setTextColor(Color.GRAY)
            setPadding(0, pad / 3, 0, pad)
        })

        val status = TextView(this).apply {
            text = if (active) "● Module ACTIVE — FLAG_SECURE is being ignored."
            else "○ Module NOT active yet."
            textSize = 16f
            setTextColor(if (active) Color.parseColor("#1B7F3B") else Color.parseColor("#B00020"))
            setPadding(pad / 2, pad / 2, pad / 2, pad / 2)
            gravity = Gravity.CENTER_VERTICAL
        }
        root.addView(status)

        root.addView(TextView(this).apply {
            text = buildString {
                appendLine("Setup:")
                appendLine("1. Open your Xposed manager (LSPosed).")
                appendLine("2. Enable \"FLAG_SECURE off (Xposed)\".")
                appendLine("3. Scope: tick System Framework.")
                appendLine("4. Reboot.")
                appendLine()
                appendLine("Then screenshots and screen recording work in apps that block them. ")
                appendLine("No lag (Xposed hooks don't deoptimize the framework). It does NOT defeat ")
                appendLine("hardware DRM (Widevine L1), so paid-video apps stay black. Your own device only.")
            }
            textSize = 14f
            setTextColor(Color.DKGRAY)
            setPadding(0, pad, 0, 0)
            movementMethod = ScrollingMovementMethod()
        })

        setContentView(root)
    }

    /**
     * Returns false normally; the Xposed module replaces this method's return value with true when
     * it is loaded, which is how the screen detects that the framework picked up the module.
     */
    private fun isModuleActive(): Boolean = false
}
