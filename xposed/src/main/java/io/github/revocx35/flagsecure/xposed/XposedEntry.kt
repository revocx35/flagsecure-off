package io.github.revocx35.flagsecure.xposed

import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodReplacement
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam

/**
 * Xposed/LSPosed module: makes the window manager treat every window as non-secure so FLAG_SECURE
 * is ignored (screenshots and screen recording work everywhere).
 *
 * Unlike the Frida build, Xposed installs these hooks through the framework's own hooking engine,
 * which does not force ART to permanently deoptimize the methods — so there is no runtime lag.
 *
 * Hooks run in the system framework process ("android" / system_server). Targets mirror
 * LSPosed/DisableFlagSecure; classes absent on a given Android version are skipped.
 */
class XposedEntry : IXposedHookLoadPackage {

    override fun handleLoadPackage(lpparam: LoadPackageParam) {
        // Self-detection: when our own app is loaded with the module active, make StatusActivity's
        // isModuleActive() return true so the UI can show "active".
        if (lpparam.packageName.startsWith("io.github.revocx35.flagsecure.xposed")) {
            try {
                XposedHelpers.findAndHookMethod(
                    "io.github.revocx35.flagsecure.xposed.StatusActivity",
                    lpparam.classLoader,
                    "isModuleActive",
                    XC_MethodReplacement.returnConstant(true),
                )
            } catch (_: Throwable) {
            }
            return
        }

        // The system framework / system_server loads as package "android".
        if (lpparam.packageName != "android") return
        val cl = lpparam.classLoader

        hookConst(cl, "com.android.server.wm.WindowState", "isSecureLocked", false)
        hookConst(cl, "com.android.server.wm.WmScreenshotController", "canBeScreenshotTarget", true)
        hookConst(cl, "android.window.ScreenCaptureInternal\$ScreenshotHardwareBuffer", "containsSecureLayers", false)
        hookConst(cl, "android.window.ScreenCapture\$ScreenshotHardwareBuffer", "containsSecureLayers", false)
    }

    /** Replace every overload of [method] on [className] with one that returns [value]. */
    private fun hookConst(cl: ClassLoader, className: String, method: String, value: Any) {
        try {
            val clazz = XposedHelpers.findClass(className, cl)
            val count = XposedBridge.hookAllMethods(clazz, method, XC_MethodReplacement.returnConstant(value)).size
            XposedBridge.log("flagsecure: hooked $className.$method ($count)")
        } catch (t: Throwable) {
            XposedBridge.log("flagsecure: skipped $className.$method (${t.message})")
        }
    }
}
