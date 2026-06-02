package com.messenger.db

import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.driver.native.NativeSqliteDriver

/** iOS driver factory backed by the native SQLite driver. (Compiled on macOS/CI.) */
actual class DatabaseDriverFactory {
    actual fun create(): SqlDriver =
        NativeSqliteDriver(MessengerDatabase.Schema, "messenger.db")
}
