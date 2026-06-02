package com.messenger.db

import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.driver.native.NativeSqliteDriver
import app.cash.sqldelight.driver.native.inMemoryDriver

/**
 * iOS driver factory backed by the native SQLite driver. [inMemory] is used by tests for isolation;
 * the app uses the default persistent on-device database. (Compiled on macOS/CI.)
 */
actual class DatabaseDriverFactory actual constructor(private val inMemory: Boolean) {
    actual fun create(): SqlDriver =
        if (inMemory) {
            inMemoryDriver(MessengerDatabase.Schema)
        } else {
            NativeSqliteDriver(MessengerDatabase.Schema, "messenger.db")
        }
}
