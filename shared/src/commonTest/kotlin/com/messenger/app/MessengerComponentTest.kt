package com.messenger.app

import com.messenger.db.DatabaseDriverFactory
import com.messenger.security.InMemorySecureKeyStore
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

class MessengerComponentTest {

    private suspend fun component() = MessengerComponent.create(
        driverFactory = DatabaseDriverFactory(inMemory = true),
        secureKeyStore = InMemorySecureKeyStore(),
        serverBaseUrl = "http://localhost:0",
    )

    @Test
    fun componentWiresFullStack_andDrivesAConversation() = runTest {
        val alice = component()
        val bob = component()

        alice.conversations.ensureProvisioned("alice")
        bob.conversations.ensureProvisioned("bob", oneTimePreKeyCount = 3)

        // Drive a conversation directly through the wired managers (no network needed here).
        val bundle = bob.conversations.publishBundle()
        val wire = alice.conversations.startConversation("bob", bundle, "wired hello")
        assertEquals("wired hello", bob.conversations.receive("alice", wire).body)

        val reply = bob.conversations.send("alice", "wired reply")
        assertEquals("wired reply", alice.conversations.receive("bob", reply).body)

        alice.close()
        bob.close()
    }
}
