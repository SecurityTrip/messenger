package com.messenger.db

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class DatabaseTest {

    private fun openDatabase(): MessengerDatabase =
        createMessengerDatabase(DatabaseDriverFactory().create())

    @Test
    fun account_upsertAndSelect() {
        val db = openDatabase()
        assertNull(db.accountQueries.selectAccount().executeAsOneOrNull())

        db.accountQueries.upsertAccount(
            userId = "alice",
            identityPublicKey = byteArrayOf(1, 2, 3),
            identityPrivateKeyEnc = byteArrayOf(4, 5, 6),
            registrationId = 42L,
            createdAt = 1000L,
        )

        val account = db.accountQueries.selectAccount().executeAsOne()
        assertEquals("alice", account.userId)
        assertEquals(42L, account.registrationId)
    }

    @Test
    fun message_insertAndList() {
        val db = openDatabase()
        db.messageQueries.insertMessage(
            id = "m1",
            contactId = "bob",
            direction = 1L,
            bodyEnc = byteArrayOf(9),
            timestamp = 100L,
            status = 0L,
        )
        db.messageQueries.insertMessage(
            id = "m2",
            contactId = "bob",
            direction = 0L,
            bodyEnc = byteArrayOf(8),
            timestamp = 200L,
            status = 1L,
        )

        val messages = db.messageQueries.selectMessagesForContact("bob").executeAsList()
        assertEquals(2, messages.size)
        assertEquals("m1", messages.first().id) // ordered by timestamp ASC
    }
}
