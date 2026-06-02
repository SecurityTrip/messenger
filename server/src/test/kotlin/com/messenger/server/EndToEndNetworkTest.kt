package com.messenger.server

import com.messenger.app.ConversationManager
import com.messenger.app.ConversationManager.ReceiveResult
import com.messenger.crypto.LibsodiumCryptoProvider
import com.messenger.crypto.initCrypto
import com.messenger.data.ContactStore
import com.messenger.data.IdentityStore
import com.messenger.data.MessageStore
import com.messenger.data.SessionStore
import com.messenger.db.DatabaseDriverFactory
import com.messenger.db.createMessengerDatabase
import com.messenger.net.MessengerApiClient
import com.messenger.security.BlobCipher
import com.messenger.security.InMemorySecureKeyStore
import com.messenger.security.MasterKey
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The whole system over a real network: real crypto (X3DH + Double Ratchet) + storage on two
 * clients, talking to the real Ktor relay over HTTP + WebSockets, including multi-device fan-out,
 * reliable delivery (ack) and read receipts.
 *
 * Opt-in (binds real sockets, hangs CI): set env RUN_NETWORK_TESTS=1 to run.
 */
class EndToEndNetworkTest {

    private val crypto = LibsodiumCryptoProvider()
    private var clock = 0L

    private class Device(val manager: ConversationManager, val api: MessengerApiClient, val userId: String, val deviceId: String) {
        suspend fun provisionRegisterAndPublish() {
            manager.ensureProvisioned(userId, deviceId, oneTimePreKeyCount = 5)
            api.register(manager.registration())
            api.uploadKeys(userId, deviceId, manager.keysForUpload())
        }
    }

    private fun device(baseUrl: String, userId: String, deviceId: String): Device {
        val db = createMessengerDatabase(DatabaseDriverFactory(inMemory = true).create())
        val cipher = BlobCipher(crypto, MasterKey.loadOrCreate(crypto, InMemorySecureKeyStore()))
        val manager = ConversationManager(
            crypto, IdentityStore(db, cipher), SessionStore(db, cipher, crypto),
            MessageStore(db, cipher), ContactStore(db),
        ) { ++clock }
        return Device(manager, MessengerApiClient(baseUrl), userId, deviceId)
    }

    @Test
    fun twoClients_exchangeEncryptedMessages_overRealServer() = runBlocking {
        if (System.getenv("RUN_NETWORK_TESTS").isNullOrBlank()) return@runBlocking

        initCrypto()
        val server = embeddedServer(Netty, port = 0) { messengerModule() }
        server.start(wait = false)
        val port = server.engine.resolvedConnectors().first().port
        val baseUrl = "http://127.0.0.1:$port"

        val alice = device(baseUrl, "alice", "aliceD")
        val bob = device(baseUrl, "bob", "bobD")
        try {
            alice.provisionRegisterAndPublish()
            bob.provisionRegisterAndPublish()

            val bobConn = bob.api.openRelay("bob", "bobD")
            val aliceConn = alice.api.openRelay("alice", "aliceD")

            val bundles = alice.api.fetchBundles("bob") ?: error("no bundles")
            val envelope = alice.manager.startConversation("bob", bundles, "hello over the network").single()
            aliceConn.send(envelope)

            // Bob receives, decrypts, acks to the server, and sends a delivery receipt.
            val delivered = bobConn.receiveNext()
            val received = bob.manager.receive(delivered) as ReceiveResult.MessageReceived
            assertEquals("hello over the network", received.message.body)
            bobConn.ackDelivery(delivered.messageId)
            bobConn.send(received.deliveryReceipt)

            // Alice gets the delivery receipt.
            val receipt = aliceConn.receiveNext()
            aliceConn.ackDelivery(receipt.messageId)
            alice.manager.receive(receipt)

            // Bob replies; Alice receives.
            val reply = bob.manager.send("alice", "hi back").single()
            bobConn.send(reply)
            val replyDelivered = aliceConn.receiveNext()
            assertEquals("hi back", (alice.manager.receive(replyDelivered) as ReceiveResult.MessageReceived).message.body)

            aliceConn.close()
            bobConn.close()
        } finally {
            alice.api.close()
            bob.api.close()
            server.stop(gracePeriodMillis = 0, timeoutMillis = 500)
        }
    }
}
