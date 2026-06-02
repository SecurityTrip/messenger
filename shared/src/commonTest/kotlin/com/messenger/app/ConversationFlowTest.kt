package com.messenger.app

import com.messenger.app.ConversationManager.ReceiveResult
import com.messenger.crypto.LibsodiumCryptoProvider
import com.messenger.crypto.initCrypto
import com.messenger.domain.MessageDirection
import com.messenger.domain.MessageStatus
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ConversationFlowTest {

    private val crypto = LibsodiumCryptoProvider()
    private var clock = 0L

    private fun device(userId: String, deviceId: String) = testDevice(crypto, userId, deviceId) { ++clock }

    @Test
    fun fullConversation_withReceipts_andPersistence() = runTest {
        initCrypto()
        val alice = device("alice", "aliceD")
        val bob = device("bob", "bobD")
        alice.provision()
        bob.provision()

        // Alice starts a conversation (one device → one envelope).
        val first = alice.manager.startConversation("bob", deviceBundlesFor(bob.manager), "hi Bob").single()
        val outgoingId = first.messageId

        // Bob receives, decrypts, and emits a DELIVERED receipt.
        val received = bob.manager.receive(first) as ReceiveResult.MessageReceived
        assertEquals("hi Bob", received.message.body)
        assertEquals(MessageDirection.INCOMING, received.message.direction)

        // Alice processes the delivery receipt → her message flips to DELIVERED.
        assertTrue(alice.manager.receive(received.deliveryReceipt) is ReceiveResult.ReceiptReceived)
        assertEquals(MessageStatus.DELIVERED, alice.messages.messageById(outgoingId)!!.status)

        // Bob reads the message → READ receipt → Alice's message flips to READ.
        val readReceipt = bob.manager.markRead(received.message.id)!!
        assertTrue(alice.manager.receive(readReceipt) is ReceiveResult.ReceiptReceived)
        assertEquals(MessageStatus.READ, alice.messages.messageById(outgoingId)!!.status)

        // Bob replies; Alice receives.
        val reply = bob.manager.send("alice", "hey Alice").single()
        assertEquals("hey Alice", (alice.manager.receive(reply) as ReceiveResult.MessageReceived).message.body)

        // Simulate Alice restarting: a fresh manager over the same stores keeps the session.
        val aliceRestarted = ConversationManager(
            crypto, alice.identities, alice.sessions, alice.messages, alice.contacts,
        ) { ++clock }
        val afterRestart = aliceRestarted.send("bob", "after restart").single()
        assertEquals("after restart", (bob.manager.receive(afterRestart) as ReceiveResult.MessageReceived).message.body)

        // History persisted on both sides, in order.
        assertEquals(listOf("hi Bob", "hey Alice", "after restart"), alice.messages.messagesForContact("bob").map { it.body })
        assertEquals(listOf("hi Bob", "hey Alice", "after restart"), bob.messages.messagesForContact("alice").map { it.body })
    }
}
