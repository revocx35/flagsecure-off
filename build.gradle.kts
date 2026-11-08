// Top-level build file. The single :app module is a Compose UI that, on a rooted device,
// injects a Frida agent (app/src/main/assets/agent.js, built from agent/) into system_server
// to make the window manager ignore FLAG_SECURE. See ARCHITECTURE.md.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.compose) apply false
}
