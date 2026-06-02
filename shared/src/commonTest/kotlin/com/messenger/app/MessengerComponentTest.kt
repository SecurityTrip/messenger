package com.messenger.app

import com.messenger.app.ConversationManager.ReceiveResult
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

        alice.conversations.ensureProvisioned("alice", "aliceD")
        bob.conversations.ensureProvisioned("bob", "bobD", oneTimePreKeyCount = 3)

        val first = alice.conversations.startConversation("bob", deviceBundlesFor(bob.conversations), "wired hello").single()
        assertEquals("wired hello", (bob.conversations.receive(first) as ReceiveResult.MessageReceived).message.body)

        val reply = bob.conversations.send("alice", "wired reply").single()
        assertEquals("wired reply", (alice.conversations.receive(reply) as ReceiveResult.MessageReceived).message.body)

        alice.close()
        bob.close()
    }
}
