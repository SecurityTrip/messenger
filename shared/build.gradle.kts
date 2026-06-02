plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.kotlinSerialization)
    alias(libs.plugins.sqldelight)
}

kotlin {
    jvmToolchain(17)

    // expect/actual classes (DatabaseDriverFactory) are still flagged Beta; opt in to silence.
    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }

    // JVM target: used for fast unit testing of the crypto/protocol/domain layers
    // (fully buildable on Windows/Linux/macOS).
    jvm()

    // iOS targets: declared so macOS/CI can produce the framework consumed by the
    // Compose Multiplatform / SwiftUI app. They are skipped on non-macOS hosts
    // (see kotlin.native.ignoreDisabledTargets in gradle.properties).
    listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64(),
    ).forEach { iosTarget ->
        iosTarget.binaries.framework {
            baseName = "Shared"
            isStatic = true
        }
    }

    sourceSets {
        commonMain.dependencies {
            implementation(libs.kotlinx.coroutines.core)
            implementation(libs.kotlinx.serialization.json)
            implementation(libs.kotlinx.datetime)
            implementation(libs.libsodium.bindings)
            implementation(libs.sqldelight.runtime)
            implementation(libs.sqldelight.coroutines)
            implementation(libs.sqldelight.primitive.adapters)
            implementation(libs.ktor.client.core)
            implementation(libs.ktor.client.websockets)
            implementation(libs.ktor.client.content.negotiation)
            implementation(libs.ktor.serialization.json)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
            implementation(libs.ktor.client.mock)
        }
        jvmMain.dependencies {
            implementation(libs.sqldelight.driver.sqlite)
            implementation(libs.ktor.client.cio)
        }
        iosMain.dependencies {
            implementation(libs.sqldelight.driver.native)
            implementation(libs.ktor.client.darwin)
        }
    }
}

sqldelight {
    databases {
        create("MessengerDatabase") {
            packageName.set("com.messenger.db")
        }
    }
}
