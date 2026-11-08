<img src="assets/icon.svg" width="64" height="64" alt="">

# Disable FLAG_SECURE (no Zygisk)

A one-tap Android app that turns off `FLAG_SECURE` **system-wide** on a rooted device, so
screenshots and screen recording work in apps that block them — **without Zygisk or LSPosed**.

There are **two variants** in this repo:

| | Mechanism | Needs | Lag | Install |
|---|---|---|---|---|
| **Xposed module** (recommended) | Xposed/LSPosed hooks in the system framework | an Xposed framework (LSPosed) | none | `flagsecure-off-xposed.apk` → enable in LSPosed, scope *System Framework*, reboot |
| **Frida app** | Injects a Frida agent into `system_server` from a root shell | root only (no Zygisk/LSPosed) | runtime overhead¹ | `app-arm64-v8a-release.apk` → install, grant root, tap |

¹ The Frida build hooks framework methods live, which makes ART deoptimize them — noticeable lag on
some devices (e.g. One UI) that lasts until reboot. If you have an Xposed framework, use the Xposed
module; its hooks don't deoptimize anything. Both are the no-store equivalent of
[DisableFlagSecure](https://github.com/LSPosed/DisableFlagSecure).

> **Root required.** Use only on a device you own. This does **not** defeat hardware DRM
> (Widevine L1), so paid-video apps (Netflix, etc.) stay black. Once injected, the two buttons
> toggle FLAG_SECURE off and on **instantly** (no reboot). The agent clears on reboot — open the
> app and tap Disable again afterwards.

## How it works

1. The app bundles the Frida command-line injector (`frida-inject`) and a precompiled agent script.
2. Tapping the button runs, as root: `frida-inject -p $(pidof system_server) -s agent.js -e`.
3. The agent hooks the window-manager methods that enforce `FLAG_SECURE` (same hook set as the
   upstream LSPosed module) and `--eternalize`s itself so the hooks persist until reboot.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and [AGENTS.md](AGENTS.md) for build/test.

## Install

Download the APK for your device's ABI (**arm64-v8a** for phones) from
[Releases](../../releases), install it, open it, and **grant it root** when your root manager
prompts. Then tap **Disable FLAG_SECURE now**. After that, the two buttons toggle it off/on
instantly; re-inject (tap Disable) once after each reboot.

## Build from source

```bash
cd agent && npm install && npm run build && cd ..   # compile the Frida agent
scripts/fetch-frida.sh                               # download frida-inject into jniLibs
./gradlew :app:assembleRelease                       # APKs in app/build/outputs/apk/release/
```

## Credits

Hook set derived from [LSPosed/DisableFlagSecure](https://github.com/LSPosed/DisableFlagSecure)
(GPL-3.0). Injection uses [Frida](https://frida.re). Licensed under GPL-3.0 — see [LICENSE](LICENSE).
