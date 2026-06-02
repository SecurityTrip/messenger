package com.messenger.db

import app.cash.sqldelight.db.SqlDriver

/** Creates a platform [SqlDriver] for the messenger database (JDBC on JVM, native SQLite on iOS). */
expect class DatabaseDriverFactory {
    fun create(): SqlDriver
}

/** Open the typed database on top of a [driver]. */
fun createMessengerDatabase(driver: SqlDriver): MessengerDatabase = MessengerDatabase(driver)
