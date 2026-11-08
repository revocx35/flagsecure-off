# AGENTS.md — notes for AI agents working on this repo

Self-contained orientation. Read this before touching anything; deeper rationale is in
[ARCHITECTURE.md](ARCHITECTURE.md).

## What this is

A one-screen Android app that, on a **rooted** device, injects a Frida agent into `system_server`
so the window manager ignores `FLAG_SECURE`. Screenshots and screen recording then work in apps
that normally block them. The effect lasts until the next reboot. Built for the owner's own rooted
Galaxy Z Fold7 (One UI 8 / Android 16) where Zygisk — and therefore LSPosed — is unavailable, so
the usual `DisableFlagSecure` LSPosed module cannot be used.

## Layout

```
app/                     Android app module (Kotlin + Jetpack Compose)
  src/main/
    java/io/github/revocx35/flagsecure/
      MainActivity.kt      Compose UI: root check, Apply button, result view
      Injector.kt          Root-side logic: copy agent, exec frida-inject, parse output
    assets/agent.js        Compiled Frida agent (GENERATED from agent/ — not committed)
    jniLibs/<abi>/libfridainject.so   frida-inject binary (DOWNLOADED — not committed)
  src/test/.../InjectorParseTest.kt   JVM unit tests for the output parser
agent/                   Frida agent source (frida-compile project)
  index.js               The hooks; compiled to app/src/main/assets/agent.js
  package.json           `npm run build` -> frida-compile
scripts/
  fetch-frida.sh         Download frida-inject into jniLibs (run before building)
  emulator.sh            Headless API-37 emulator for install/launch smoke tests
third_party/frida/       Local cache of frida-inject downloads (not committed)
```

## Build & test commands

Prereqs: JDK 17, Android SDK at `/opt/android-sdk` (set `local.properties` `sdk.dir`), Node for the
agent. On this host, wrap Gradle/emulator in `/usr/local/bin/heavy` (CPU/RAM caps — see the root
CLAUDE.md) and run only one emulator at a time.

```bash
# 1. Build the Frida agent (regenerates app/src/main/assets/agent.js)
cd agent && npm install && npm run build && cd ..

# 2. Fetch the native frida-inject binaries into app/src/main/jniLibs/
scripts/fetch-frida.sh            # or set FRIDA_VERSION=...

# 3. Build
heavy ./gradlew :app:testDebugUnitTest   # JVM unit tests (parser)
heavy ./gradlew :app:assembleDebug       # per-ABI debug APKs
heavy ./gradlew :app:assembleRelease     # per-ABI release APKs (signed if keystore.properties)

# 4. Smoke test on an emulator (install + launch only; see "never do")
scripts/emulator.sh setup         # once
scripts/emulator.sh start
/opt/android-sdk/platform-tools/adb install -r app/build/outputs/apk/debug/app-x86_64-debug.apk
scripts/emulator.sh stop
```

APKs land in `app/build/outputs/apk/{debug,release}/app-<abi>-<type>.apk`. There is **one APK per
ABI** (arm64-v8a for phones, x86_64 for emulators); no universal APK, because frida-inject is large.

## Conventions

- Keep the agent's hook list in sync with upstream `LSPosed/DisableFlagSecure`; each hook target is
  a `force(class, method, value)` call in `agent/index.js`. After editing, re-run `npm run build`.
- The agent prints machine-readable lines prefixed `fso:` (`hooked`, `skipped`, `ready`, `error`).
  `Injector.parseAgentOutput` is the single parser and is unit-tested — keep them in step.
- Package / applicationId: `io.github.revocx35.flagsecure`. compileSdk/targetSdk 37, minSdk 26.
- Versions come from `gradle/libs.versions.toml` (AGP 9.4.1, Kotlin 2.4.20, Gradle 9.8.0).

## Never do

- **Never commit** `app/src/main/assets/agent.js`, anything under `app/src/main/jniLibs/`,
  `third_party/`, `keystore.properties`, `*.jks`, `local.properties`, or build output. They are in
  `.gitignore`; they are generated or downloaded. (The repo must stay small and secret-free.)
- **Never set** `jniLibs.useLegacyPackaging = false`. frida-inject is *executed*, not linked, so it
  must be extracted to `nativeLibraryDir` on install; the modern default leaves it inside the APK
  with no exec path. This was a real bug caught on the emulator.
- **Never run the live `system_server` injection as part of automated testing here.** The stock
  emulator has no `su`, and that path has tripped safety tooling. Verify build + install + launch +
  that the bundled binary executes (`libfridainject.so --help`); leave the end-to-end FLAG_SECURE
  bypass to the owner on their own rooted device.
- Don't add a universal APK or Play "dependency metadata" (`dependenciesInfo` is off).

## Gotchas

- Shell `$` inside Kotlin strings must be written `${'$'}` (see `Injector.kt`), or Kotlin reads it
  as a string template and the build fails with "Unresolved reference 'PID'".
- The emulator boots slowly under `heavy`; poll `adb shell getprop sys.boot_completed` rather than
  trusting a fixed timeout.
- The bypass is on exactly while frida-inject stays attached (NOT eternalized). Turning off
  SIGTERMs it so frida reverts the hooks — that clean revert is what removes the residual lag of
  hooking a hot method (`isSecureLocked`). Do not add `-e`; it would leave hooks installed.
- A quick-settings tile (`FlagSecureTileService`) toggles the same state from the shade.
- DRM video (Widevine L1) is a separate hardware path; this app does not and cannot capture it.
