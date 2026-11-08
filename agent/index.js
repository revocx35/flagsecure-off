// Injected into system_server. Replaces the window-manager methods that enforce FLAG_SECURE so
// every window is treated as non-secure; screenshots and screen recording then work.
//
// The replacements are plain constant returns (the cheapest possible), and the agent is NOT
// eternalized: the app keeps frida-inject attached while the bypass is on, and turning it off sends
// SIGTERM, which makes frida unload this script and RESTORE the original methods. That means there
// is zero residual overhead when off — nothing stays hooked. Hook targets mirror
// LSPosed/DisableFlagSecure; classes absent on this Android version are skipped. Lines starting
// with "fso:" are parsed by the app.
import Java from "frida-java-bridge";

Java.perform(() => {
  const loader = Java.enumerateClassLoadersSync().find((l) => {
    try {
      l.loadClass("com.android.server.wm.WindowState");
      return true;
    } catch (e) {
      return false;
    }
  });
  if (!loader) {
    console.log("fso:error services classloader not found");
    return;
  }
  const factory = Java.ClassFactory.get(loader);

  const force = (cls, method, value) => {
    try {
      factory.use(cls)[method].overloads.forEach((o) => {
        o.implementation = function () {
          return value;
        };
      });
      console.log("fso:hooked " + cls + "." + method);
    } catch (e) {
      console.log("fso:skipped " + cls + "." + method);
    }
  };

  force("com.android.server.wm.WindowState", "isSecureLocked", false);
  force("com.android.server.wm.WmScreenshotController", "canBeScreenshotTarget", true); // One UI
  force("android.window.ScreenCaptureInternal$ScreenshotHardwareBuffer", "containsSecureLayers", false); // Android 16+
  force("android.window.ScreenCapture$ScreenshotHardwareBuffer", "containsSecureLayers", false); // Android 14-15
  console.log("fso:ready");
});
