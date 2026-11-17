pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "ADH Device"
include(":core")
include(":daemon")
include(":manager")
// Verification-only package, excluded from normal release/bundle project graphs.
if (providers.gradleProperty("adhP5Sandbox").orNull == "true") include(":p5sandbox")
