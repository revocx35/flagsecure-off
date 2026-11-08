// Injected into system_server (eternalized). Hooks the window-manager methods that enforce
// FLAG_SECURE so every window is treated as non-secure. The hooks are TOGGLEABLE in place:
//
//   flag file /data/local/tmp/fso_paused absent  -> hooks installed (bypass on, screenshots work)
//   flag file present                            -> hooks REMOVED (implementation = null), i.e. the
//                                                   original methods run with zero Frida overhead.
//
// A persistent timer polls the flag every 500 ms, so toggling needs no re-injection and leaves no
// residual slowdown when off (the hot isSecureLocked hook is actually removed, not just bypassed).
// The eternalized script keeps running after frida-inject exits (verified). Hook targets mirror
// LSPosed/DisableFlagSecure; classes absent on this Android version are skipped. Lines starting with
// "fso:" are parsed by the app.
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
  const JFile = Java.use("java.io.File");
  const flagPresent = () => {
    try {
      return JFile.$new(PAUSE_FILE).exists();
    } catch (e) {
      return false;
    }
  };

  // Collect the overloads we control plus the value to force; actual (un)hooking is done in setHooks.
  const targets = [];
  const prepare = (cls, method, value) => {
    try {
      targets.push({ value, overloads: factory.use(cls)[method].overloads });
      console.log("fso:hooked " + cls + "." + method);
    } catch (e) {
      console.log("fso:skipped " + cls + "." + method);
    }
  };
  prepare("com.android.server.wm.WindowState", "isSecureLocked", false);
  prepare("com.android.server.wm.WmScreenshotController", "canBeScreenshotTarget", true); // One UI
  prepare("android.window.ScreenCaptureInternal$ScreenshotHardwareBuffer", "containsSecureLayers", false); // 16+
  prepare("android.window.ScreenCapture$ScreenshotHardwareBuffer", "containsSecureLayers", false); // 14-15

  let installed = null;
  const setHooks = (on) => {
    if (on === installed) return;
    targets.forEach((t) => {
      t.overloads.forEach((o) => {
        // Installing returns the forced value; removing (null) restores the original method, so
        // there is no Frida overhead on the hot path while off.
        o.implementation = on ? () => t.value : null;
      });
    });
    installed = on;
  };

  setHooks(!flagPresent());
  setInterval(() => setHooks(!flagPresent()), 500);
  console.log("fso:ready");
});
