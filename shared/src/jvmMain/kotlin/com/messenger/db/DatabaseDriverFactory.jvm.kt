package com.messenger.db

import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver

/**
 * JVM driver factory. The JVM target exists for tests on this (Windows) dev machine, so it
 * defaults to (and effectively only uses) an in-memory database; the shipping app runs on iOS.
 */
actual class DatabaseDriverFactory actual constructor(private val inMemory: Boolean) {
    actual fun create(): SqlDriver {
        val url = if (inMemory) JdbcSqliteDriver.IN_MEMORY else "jdbc:sqlite:messenger.db"
        val driver = JdbcSqliteDriver(url)
        MessengerDatabase.Schema.create(driver)
        return driver
    }
}
