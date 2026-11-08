# ARCHITECTURE.md

## Purpose

Disable `FLAG_SECURE` globally on a rooted Android device so screenshots and screen recording work
everywhere, **without** Zygisk/LSPosed. This is the no-Zygisk alternative to the `DisableFlagSecure`
LSPosed module, for devices (e.g. Galaxy Z Fold7 on One UI 8) where Zygisk does not work.

## Two variants

This repo ships two independent ways to disable FLAG_SECURE, as separate APKs:

- **Xposed module** (`:xposed`, package `io.github.revocx35.flagsecure.xposed`) — a standard
  Xposed/LSPosed module. `XposedEntry` implements `IXposedHookLoadPackage`, and when the system
  framework (`android`) loads it replaces the same window-manager methods with constant returns via
  `XposedBridge.hookAllMethods` / `XC_MethodReplacement.returnConstant`. The Xposed hooking engine
  (LSPlant) does **not** force ART to deoptimize the methods, so there is **no runtime lag** — this
  is the recommended variant when an Xposed framework is available. Needs LSPosed (i.e. a working
  Zygisk/ Zygisk-alternative); no root shell at runtime. The Xposed API is a `compileOnly`
  dependency (provided by the framework), never packaged.
- **Frida app** (`:app`) — the no-Zygisk fallback described below. Reliable injection, but hooking
  the framework live makes ART deoptimize the hooked methods, which is laggy on some devices until
  reboot. v1.3.x hooks only capture-path methods to limit this, with the trade-off noted above.

The rest of this document describes the Frida app.

## Components

1. **Frida agent** (`agent/index.js` → compiled to `app/src/main/assets/agent.js`)
   A JavaScript Frida script. When loaded into a process it:
   - finds the class loader that owns `com.android.server.wm.WindowState` (the `system_server`
     framework loader);
   - is **eternalized** (frida-inject injects it and exits; the script stays resident in
     system_server — verified that its timer keeps running). It hooks a set of window-manager
     methods with constant returns, and polls a pause flag every 500 ms: when the flag appears it
     sets each hook's `implementation = null`, which **removes** the hook and restores the original
     method (zero Frida overhead on the hot `isSecureLocked` path while off); when it is removed the
     hooks go back on. Only one target is hooked:
     - `WindowState.isSecureLocked` → `false`
   - **Why only this one (the least-laggy config).** Every Frida hook forces ART to deoptimize that
     method, which lingers until reboot — so the goal is to hook as few, and as un-hot, methods as
     possible. Field testing on One UI showed the capture-path hooks
     (`WmScreenshotController.canBeScreenshotTarget`, `ScreenshotHardwareBuffer.containsSecureLayers`)
     cause *more* lag than `isSecureLocked` (Samsung calls them constantly), so they were dropped.
     `isSecureLocked` alone is enough to make windows screenshot-able and is the lighter hook. There
     is no lag-free Frida option — that requires Xposed (persistent root) or a framework patch.
   - Classes that do not exist on the running Android version are skipped, not fatal.
   - Emits machine-readable progress on stdout: `fso:hooked <t>`, `fso:skipped <t>`, `fso:ready`,
     `fso:error <msg>`.

2. **Native injector** (`frida-inject`, bundled as `jniLibs/<abi>/libfridainject.so`)
   The upstream Frida command-line injector, statically linked. Run as root it attaches to a PID,
   loads the agent, `--eternalize`s it (so the hooks outlive the injector), and exits.

3. **App** (`MainActivity.kt`, `Injector.kt`)
   - `MainActivity` — Compose UI (Material 3, dynamic color). Shows a warning, a root-status line,
     an Apply button, a "Re-enable FLAG_SECURE (restart UI)" button (behind a confirm dialog), and
     the parsed hook results.
   - `Injector` — the only code that touches root:
     - `hasRoot()` runs `su -c id -u` and checks for uid 0.
     - `apply()` eternalizes the agent (`frida-inject -e`) and removes the pause flag; a boot_id
       marker (`/data/local/tmp/fso_boot`) means it injects at most once per boot (a later tap just
       flips the flag). `fso:reused` on a repeat tap this boot.
     - `reEnable()` turns it off by creating the pause flag; the resident agent removes its hooks
       within ~0.5s. No restart, no residual overhead.
     - `isActive()` reports on when the boot marker matches this boot and the pause flag is absent.
     - `apply()` copies `agent.js` from assets into `filesDir`, locates
       `nativeLibraryDir/libfridainject.so`, then runs, via `su -c`:
       `PID=$(pidof system_server); libfridainject.so -p "$PID" -s agent.js -e`
       and parses the combined output with `parseAgentOutput()` (pure, unit-tested).

## Data flow

```
 user taps "Disable FLAG_SECURE now"
        │
 Injector.apply(context)
        │  copy assets/agent.js ─► filesDir/agent.js
        │  locate nativeLibraryDir/libfridainject.so
        ▼
 su -c "frida-inject -p $(pidof system_server) -s agent.js -e"   ── root ──►  system_server
        │                                                                         │
        │                                                      agent hooks WindowState etc.
        │  ◄── stdout: fso:hooked… / fso:ready ────────────────────────────────────┘
        ▼
 parseAgentOutput() ─► Result{success, summary, hooks[]} ─► Compose result card
```

After this, every window's secure flag reads as clear until `system_server` restarts (reboot).

## Key design decisions

- **Frida injection, not an LSPosed/Xposed module.** The target devices cannot run Zygisk, so
  Xposed-family modules are out. `frida-inject --eternalize` gives the same framework hooks from a
  plain root shell.
- **Agent shipped precompiled in assets.** `frida-compile` bundles `frida-java-bridge` into one JS
  file at build time; the device needs no Node/Frida toolchain.
- **Binary shipped in `jniLibs` with legacy packaging (`extractNativeLibs=true`).** Android's W^X
  policy only lets an app execute from `nativeLibraryDir`. Legacy packaging extracts the binary
  there on install. (Modern packaging keeps it inside the APK, unexecutable — do not use it here.)
- **One APK per ABI.** frida-inject is tens-to-hundreds of MB per architecture; ABI splits keep each
  APK to a single copy.
- **Binaries/agent are not committed.** They are downloaded (`scripts/fetch-frida.sh`) / generated
  (`npm run build`) at build time, keeping the git repo small and free of large blobs.

## Platform constraints

- **Root required**, granted to this app by Magisk / KernelSU / APatch. No root → the UI disables
  the button and says so.
- **Non-persistent root** (e.g. exploit-based) means the hooks vanish on reboot *and* so does the
  ability to re-apply until root is re-established. Re-tap after each boot.
- **Hardware DRM (Widevine L1)** is enforced in the display pipeline / TEE, independent of
  `FLAG_SECURE`. Protected video (Netflix, etc.) stays black. Out of scope by design.
- **Android-version coupling.** The hooked class/method names track AOSP + vendor internals; a new
  Android or One UI release can move them. Unknown targets are skipped, and the UI reports how many
  hooks actually applied so a regression is visible.
- **SELinux / vendor hardening** can block `frida-inject` from attaching on some firmwares; failure
  is reported, not silent.

## Security / threat model

This app is a local power-user tool for the device owner, not a networked service.

- **No network.** No INTERNET permission, no servers, no telemetry, nothing outbound. Removes the
  usual auth/transport/token attack surface entirely.
- **Trust boundary is root.** It already runs with the user's granted root; it adds no new remotely
  reachable surface. The only inputs are the bundled agent and binary (shipped in the APK) — no
  user- or network-controlled data reaches the root command.
- **Integrity of shipped artifacts.** The agent is compiled from `agent/index.js` in this repo; the
  binary is a pinned `frida-inject` release fetched by `scripts/fetch-frida.sh` (pin by
  `FRIDA_VERSION`; verify checksums when bumping).
- **Abuse consideration.** Disabling `FLAG_SECURE` defeats an app-side anti-capture signal on the
  owner's own screen; it does not bypass DRM, exfiltrate data, or affect other devices/users.
- **Secrets.** None in the repo or APK. Release signing keys live only in CI secrets /
  `keystore.properties` (never committed).
