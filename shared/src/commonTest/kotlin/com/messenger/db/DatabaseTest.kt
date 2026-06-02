package com.messenger.db

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class DatabaseTest {

    private fun openDatabase(): MessengerDatabase =
        createMessengerDatabase(DatabaseDriverFactory(inMemory = true).create())

    @Test
    fun account_upsertAndSelect() {
        val db = openDatabase()
        assertNull(db.accountQueries.selectAccount().executeAsOneOrNull())

        db.accountQueries.upsertAccount(
            userId = "alice",
            deviceId = "deviceA",
            identityPublicKey = byteArrayOf(1, 2, 3),
            identityPrivateKeyEnc = byteArrayOf(4, 5, 6),
            registrationId = 42L,
            createdAt = 1000L,
        )

        val account = db.accountQueries.selectAccount().executeAsOne()
        assertEquals("alice", account.userId)
        assertEquals("deviceA", account.deviceId)
        assertEquals(42L, account.registrationId)
    }

    @Test
    fun message_insertListAndLookup() {
        val db = openDatabase()
        db.messageQueries.insertMessage(
            id = "m1",
            contactId = "bob",
            peerDeviceId = null,
            direction = 1L,
            bodyEnc = byteArrayOf(9),
            timestamp = 100L,
            status = 0L,
            senderMessageId = null,
        )
        db.messageQueries.insertMessage(
            id = "m2",
            contactId = "bob",
            peerDeviceId = "bobDevice",
            direction = 0L,
            bodyEnc = byteArrayOf(8),
            timestamp = 200L,
            status = 1L,
            senderMessageId = "remote-7",
        )

        val messages = db.messageQueries.selectMessagesForContact("bob").executeAsList()
        assertEquals(2, messages.size)
        assertEquals("m1", messages.first().id) // ordered by timestamp ASC
        assertEquals("remote-7", db.messageQueries.selectMessageById("m2").executeAsOne().senderMessageId)
    }
}
