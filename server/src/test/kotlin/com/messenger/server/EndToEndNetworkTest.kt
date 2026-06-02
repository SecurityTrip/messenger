package com.messenger.server

import com.messenger.app.ConversationManager
import com.messenger.crypto.LibsodiumCryptoProvider
import com.messenger.crypto.initCrypto
import com.messenger.data.ContactStore
import com.messenger.data.IdentityStore
import com.messenger.data.MessageStore
import com.messenger.data.SessionStore
import com.messenger.db.DatabaseDriverFactory
import com.messenger.db.createMessengerDatabase
import com.messenger.net.MessengerApiClient
import com.messenger.protocol.wire.RelayEnvelope
import com.messenger.security.BlobCipher
import com.messenger.security.InMemorySecureKeyStore
import com.messenger.security.MasterKey
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/**
 * The whole system over a real network: two clients run the real crypto stack (X3DH + Double
 * Ratchet) and storage, talking to the real Ktor relay server over HTTP + WebSockets. Proves the
 * end-to-end pipeline — registration, prekey distribution, session setup and encrypted relay.
 */
class EndToEndNetworkTest {

    private val crypto = LibsodiumCryptoProvider()
    private var clock = 0L

    private class Device(val manager: ConversationManager, val api: MessengerApiClient, val userId: String) {
        suspend fun provisionRegisterAndPublish() {
            manager.ensureProvisioned(userId, oneTimePreKeyCount = 5)
            api.register(manager.registration())
            api.uploadKeys(userId, manager.keysForUpload())
        }
    }

    private fun device(baseUrl: String, userId: String): Device {
        val db = createMessengerDatabase(DatabaseDriverFactory().create())
        val cipher = BlobCipher(crypto, MasterKey.loadOrCreate(crypto, InMemorySecureKeyStore()))
        val manager = ConversationManager(
            crypto,
            IdentityStore(db, cipher),
            SessionStore(db, cipher, crypto),
            MessageStore(db, cipher),
            ContactStore(db),
        ) { ++clock }
        return Device(manager, MessengerApiClient(baseUrl), userId)
    }

    @Test
    fun twoClients_exchangeEncryptedMessages_overRealServer() = runBlocking {
        initCrypto()

        val server = embeddedServer(Netty, port = 0) { messengerModule() }
        server.start(wait = false)
        val port = server.engine.resolvedConnectors().first().port
        val baseUrl = "http://127.0.0.1:$port"

        val alice = device(baseUrl, "alice")
        val bob = device(baseUrl, "bob")
        try {
            alice.provisionRegisterAndPublish()
            bob.provisionRegisterAndPublish()

            // Bob comes online and listens; Alice fetches his bundle and opens a session.
            val bobConn = bob.api.openRelay("bob")
            val bundle = alice.api.fetchBundle("bob") ?: error("bundle not found")

            val firstWire = alice.manager.startConversation("bob", bundle, "hello over the network")
            val aliceConn = alice.api.openRelay("alice")
            val ack = aliceConn.send(RelayEnvelope(to = "bob", from = "alice", message = firstWire))
            assertFalse(ack.queued, "Bob is online, message should be delivered immediately")

            // Bob receives and decrypts.
            val delivered = bobConn.receiveNext()
            assertEquals("hello over the network", bob.manager.receive("alice", delivered.message).body)

            // Bob replies; Alice receives and decrypts.
            val replyWire = bob.manager.send("alice", "hi back over the network")
            bobConn.send(RelayEnvelope(to = "alice", from = "bob", message = replyWire))
            val replyDelivered = aliceConn.receiveNext()
            assertEquals("hi back over the network", alice.manager.receive("bob", replyDelivered.message).body)

            // One more round to exercise the ongoing ratchet over the wire.
            val w3 = alice.manager.send("bob", "third message")
            aliceConn.send(RelayEnvelope(to = "bob", from = "alice", message = w3))
            assertEquals("third message", bob.manager.receive("alice", bobConn.receiveNext().message).body)

            aliceConn.close()
            bobConn.close()
        } finally {
            alice.api.close()
            bob.api.close()
            server.stop(gracePeriodMillis = 0, timeoutMillis = 500)
        }
    }
}
