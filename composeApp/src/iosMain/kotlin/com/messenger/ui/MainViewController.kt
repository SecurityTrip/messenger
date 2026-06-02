package com.messenger.ui

import androidx.compose.ui.window.ComposeUIViewController
import com.messenger.app.MessengerComponent
import com.messenger.db.DatabaseDriverFactory
import com.messenger.security.KeychainSecureKeyStore
import platform.Foundation.NSProcessInfo
import platform.UIKit.UIViewController

/**
 * iOS entry point consumed by the SwiftUI host (`ContentView`). Returns a [UIViewController] hosting
 * the Compose UI, wiring the **real** iOS implementations: the Keychain-backed secure key store and
 * the persistent native SQLite database.
 *
 * Reads optional launch env vars (set via `simctl launch` with `SIMCTL_CHILD_*`) for end-to-end
 * testing: `MESSENGER_SERVER` overrides the relay URL, and `MESSENGER_USER` + `MESSENGER_PEER` make
 * the app connect automatically on launch.
 */
fun MainViewController(): UIViewController {
    val env = NSProcessInfo.processInfo.environment
    val server = (env["MESSENGER_SERVER"] as? String) ?: "http://localhost:8080"
    val me = (env["MESSENGER_USER"] as? String)?.takeIf { it.isNotBlank() }
    val peer = (env["MESSENGER_PEER"] as? String)?.takeIf { it.isNotBlank() }
    val autoConnect = if (me != null && peer != null) AutoConnect(me, peer) else null

    return ComposeUIViewController {
        App(componentFactory = { createComponent(server) }, autoConnect = autoConnect)
    }
}

private suspend fun createComponent(serverBaseUrl: String): MessengerComponent =
    MessengerComponent.create(
        driverFactory = DatabaseDriverFactory(),
        secureKeyStore = KeychainSecureKeyStore(),
        serverBaseUrl = serverBaseUrl,
    )
