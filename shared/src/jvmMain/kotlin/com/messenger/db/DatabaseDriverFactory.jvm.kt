package com.messenger.db

import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver

/**
 * JVM driver factory. Uses an in-memory SQLite database — the JVM target exists only for tests on
 * this (Windows) dev machine; the shipping app runs on iOS with the native driver.
 */
actual class DatabaseDriverFactory {
    actual fun create(): SqlDriver {
        val driver = JdbcSqliteDriver(JdbcSqliteDriver.IN_MEMORY)
        MessengerDatabase.Schema.create(driver)
        return driver
    }
}
