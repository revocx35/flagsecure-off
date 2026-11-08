pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // Xposed API (compileOnly) — provided by the Xposed/LSPosed framework at runtime.
        maven {
            url = uri("https://api.xposed.info/")
            content { includeGroup("de.robv.android.xposed") }
        }
    }
}

rootProject.name = "flagsecure"
include(":app")
include(":xposed")
