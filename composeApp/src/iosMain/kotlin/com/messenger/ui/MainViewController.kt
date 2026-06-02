package com.messenger.ui

import androidx.compose.ui.window.ComposeUIViewController
import com.messenger.app.MessengerComponent
import com.messenger.db.DatabaseDriverFactory
import com.messenger.security.KeychainSecureKeyStore
import platform.UIKit.UIViewController

/**
 * iOS entry point consumed by the SwiftUI host (`ContentView`). Returns a [UIViewController] hosting
 * the Compose UI. Wires the **real** iOS implementations: the Keychain-backed secure key store and
 * the persistent native SQLite database — so launching the app validates [KeychainSecureKeyStore] in
 * a genuine app context (where the keychain access group exists, unlike the bare test runner).
 */
fun MainViewController(): UIViewController = ComposeUIViewController {
    App(componentFactory = ::createComponent)
}

private suspend fun createComponent(): MessengerComponent =
    MessengerComponent.create(
        driverFactory = DatabaseDriverFactory(),
        secureKeyStore = KeychainSecureKeyStore(),
        // Local relay; unused by the local-only skeleton, but required by create().
        serverBaseUrl = "http://localhost:8080",
    )
