package com.messenger.app

import com.messenger.crypto.LibsodiumCryptoProvider
import com.messenger.crypto.initCrypto
import com.messenger.data.ContactStore
import com.messenger.data.IdentityStore
import com.messenger.data.MessageStore
import com.messenger.data.SessionStore
import com.messenger.db.DatabaseDriverFactory
import com.messenger.db.MessengerDatabase
import com.messenger.db.createMessengerDatabase
import com.messenger.domain.MessageDirection
import com.messenger.protocol.wire.WireMessage
import com.messenger.security.BlobCipher
import com.messenger.security.InMemorySecureKeyStore
import com.messenger.security.MasterKey
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class ConversationFlowTest {

    private val crypto = LibsodiumCryptoProvider()
    private var clock = 0L

    private class Device(
        val identities: IdentityStore,
        val sessions: SessionStore,
        val messages: MessageStore,
        val contacts: ContactStore,
        val manager: ConversationManager,
    )

    private fun device(): Device {
        val db: MessengerDatabase = createMessengerDatabase(DatabaseDriverFactory(inMemory = true).create())
        val cipher = BlobCipher(crypto, MasterKey.loadOrCreate(crypto, InMemorySecureKeyStore()))
        val identities = IdentityStore(db, cipher)
        val sessions = SessionStore(db, cipher, crypto)
        val messages = MessageStore(db, cipher)
        val contacts = ContactStore(db)
        val manager = ConversationManager(crypto, identities, sessions, messages, contacts) { ++clock }
        return Device(identities, sessions, messages, contacts, manager)
    }

    @Test
    fun twoParties_fullEncryptedFlow_withPersistence() = runTest {
        initCrypto()
        val alice = device()
        val bob = device()

        val aliceIdentity = alice.manager.ensureProvisioned("alice")
        bob.manager.ensureProvisioned("bob", oneTimePreKeyCount = 5)

        // Bob publishes a bundle; Alice initiates from it.
        val bobBundle = bob.manager.publishBundle()
        assertEquals(5, bob.identities.unusedOneTimePreKeyCount())

        // The first wire message goes through JSON to prove it is transport-ready.
        val wire1 = alice.manager.startConversation("bob", bobBundle, "hi Bob")
        val roundTripped = Json.decodeFromString(
            WireMessage.serializer(),
            Json.encodeToString(WireMessage.serializer(), wire1),
        )

        val received1 = bob.manager.receive("alice", roundTripped)
        assertEquals("hi Bob", received1.body)
        assertEquals(MessageDirection.INCOMING, received1.direction)
        assertEquals(4, bob.identities.unusedOneTimePreKeyCount(), "Bob must consume one one-time prekey")

        // Bob now knows Alice's identity key (for safety-number verification).
        assertContentEquals(aliceIdentity.publicKey, bob.contacts.get("alice")!!.identityPublicKey)

        // Alternating conversation.
        assertEquals("hey Alice", alice.manager.receive("bob", bob.manager.send("alice", "hey Alice")).body)
        assertEquals("how are you", bob.manager.receive("alice", alice.manager.send("bob", "how are you")).body)
        assertEquals("good!", alice.manager.receive("bob", bob.manager.send("alice", "good!")).body)

        // Simulate Alice restarting the app: a brand-new manager over the same (persisted) stores.
        val aliceRestarted = ConversationManager(
            crypto, alice.identities, alice.sessions, alice.messages, alice.contacts,
        ) { ++clock }
        val wireAfterRestart = aliceRestarted.send("bob", "after restart")
        assertEquals("after restart", bob.manager.receive("alice", wireAfterRestart).body)

        // Full history persisted and decryptable on both devices, in order.
        val expected = listOf("hi Bob", "hey Alice", "how are you", "good!", "after restart")
        assertEquals(expected, alice.messages.messagesForContact("bob").map { it.body })
        assertEquals(expected, bob.messages.messagesForContact("alice").map { it.body })
    }
}
