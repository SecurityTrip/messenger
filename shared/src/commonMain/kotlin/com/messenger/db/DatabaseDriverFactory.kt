package com.messenger.db

import app.cash.sqldelight.db.SqlDriver

/**
 * Creates a platform [SqlDriver] for the messenger database (JDBC on JVM, native SQLite on iOS).
 * Set [inMemory] = true for tests so each instance gets an isolated, throwaway database; the app
 * uses the default (persistent on-device storage).
 */
expect class DatabaseDriverFactory(inMemory: Boolean = false) {
    fun create(): SqlDriver
}

/** Open the typed database on top of a [driver]. */
fun createMessengerDatabase(driver: SqlDriver): MessengerDatabase = MessengerDatabase(driver)
