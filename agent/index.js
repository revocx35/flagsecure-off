// Injected into system_server. Hooks the window-manager methods that enforce FLAG_SECURE, but
// makes the bypass TOGGLEABLE at runtime via a flag file, so FLAG_SECURE can be re-enabled without
// restarting the framework.
//
//   flag file /data/local/tmp/fso_paused present  -> bypass PAUSED: call the original method, i.e.
//                                                     real FLAG_SECURE behavior (screenshots blocked
//                                                     in secure windows, allowed elsewhere).
//   flag file absent                              -> bypass ACTIVE: screenshots work everywhere.
//
// The agent polls the flag every 500 ms, so creating/removing the file flips the state near-instantly
// (no system_server restart). Hook targets come from LSPosed/DisableFlagSecure; missing classes are
// skipped (they vary by Android version/vendor). Lines starting with "fso:" are parsed by the app.
import Java from "frida-java-bridge";

const PAUSE_FILE = "/data/local/tmp/fso_paused";

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

  // Shared, polled bypass state. Starts ACTIVE; a background timer keeps it in sync with the flag.
  const JFile = Java.use("java.io.File");
  const flagPresent = () => {
    try {
      return JFile.$new(PAUSE_FILE).exists();
    } catch (e) {
      return false;
    }
  };
  let paused = flagPresent();
  setInterval(() => {
    paused = flagPresent();
  }, 500);

  // Replace `method` so it returns `bypassValue` while active, or defers to the ORIGINAL method
  // while paused (restoring true FLAG_SECURE behavior rather than a blanket block).
  const force = (cls, method, bypassValue) => {
    try {
      factory.use(cls)[method].overloads.forEach((o) => {
        o.implementation = function () {
          if (paused) {
            return this[method].apply(this, arguments);
          }
          return bypassValue;
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
