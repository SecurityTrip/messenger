@file:Suppress("UnstableApiUsage")

rootProject.name = "messenger"

pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

include(":shared")
include(":server")
// Enabled in later phases:
// include(":composeApp")
