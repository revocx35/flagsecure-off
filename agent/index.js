// Injected into system_server. Makes the window manager treat every window as non-secure.
// Hook targets come from LSPosed/DisableFlagSecure; missing classes are skipped because they vary by Android version
// and vendor. Lines starting with "fso:" are parsed by the app.
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
