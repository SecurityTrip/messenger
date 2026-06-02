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
        // Compose Multiplatform's iOS artifacts pull transitive androidx (lifecycle/annotation/
        // collection) multiplatform libraries that are published only on Google's Maven.
        google()
        mavenCentral()
    }
}

include(":shared")
include(":server")
include(":composeApp")
