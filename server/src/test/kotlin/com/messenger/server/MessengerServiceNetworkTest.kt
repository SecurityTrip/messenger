package com.messenger.server

import com.messenger.app.ConversationManager
import com.messenger.app.MessengerService
import com.messenger.crypto.LibsodiumCryptoProvider
import com.messenger.crypto.initCrypto
import com.messenger.data.ContactStore
import com.messenger.data.IdentityStore
import com.messenger.data.MessageStore
import com.messenger.data.SessionStore
import com.messenger.db.DatabaseDriverFactory
import com.messenger.db.createMessengerDatabase
import com.messenger.domain.ChatMessage
import com.messenger.domain.MessageDirection
import com.messenger.domain.MessageStatus
import com.messenger.net.MessengerApiClient
import com.messenger.security.BlobCipher
import com.messenger.security.InMemorySecureKeyStore
import com.messenger.security.MasterKey
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExecutorCoroutineDispatcher
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.util.concurrent.Executors
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Exercises [MessengerService] (the relay coordinator) end-to-end over the real Ktor server: two
 * clients provision, connect, and exchange encrypted messages, and the sender's status upgrades to
 * DELIVERED once the receiver's delivery receipt comes back through the receive loop.
 *
 * Each device confines all of its work (service calls + its receive loop + DB reads) to one
 * single-thread dispatcher — the SQLDelight `JdbcSqliteDriver` connection is not thread-safe (the
 * real iOS app uses the thread-safe NativeSqliteDriver). The WebSocket readers run on Ktor's own
 * dispatcher, so relayed sends never deadlock.
 *
 * Opt-in (binds real sockets, hangs CI): set env RUN_NETWORK_TESTS=1 to run.
 */
class MessengerServiceNetworkTest {

    private val crypto = LibsodiumCryptoProvider()
    private var clock = 0L

    private class Device(
        val service: MessengerService,
        val messages: MessageStore,
        val api: MessengerApiClient,
        val ctx: ExecutorCoroutineDispatcher,
        val scope: CoroutineScope,
    ) {
        suspend fun <T> on(block: suspend () -> T): T = withContext(ctx) { block() }

        suspend fun shutdown() {
            service.stop()  // closes the relay WebSocket session
            scope.cancel()  // stops the receive loop
            api.close()     // closes the HTTP client engine
            ctx.close()     // shuts the (daemon) executor; non-blocking
        }
    }

    private fun device(baseUrl: String, name: String): Device {
        // Daemon single-thread dispatcher: confines this device's DB to one thread and never blocks
        // JVM shutdown even if a stray coroutine outlives the test.
        val ctx = Executors.newSingleThreadExecutor { r -> Thread(r, name).apply { isDaemon = true } }
            .asCoroutineDispatcher()
        val db = createMessengerDatabase(DatabaseDriverFactory(inMemory = true).create())
        val cipher = BlobCipher(crypto, MasterKey.loadOrCreate(crypto, InMemorySecureKeyStore()))
        val sessions = SessionStore(db, cipher, crypto)
        val messages = MessageStore(db, cipher)
        val manager = ConversationManager(
            crypto, IdentityStore(db, cipher), sessions, messages, ContactStore(db),
        ) { ++clock }
        val api = MessengerApiClient(baseUrl)
        val scope = CoroutineScope(SupervisorJob() + ctx)
        return Device(MessengerService(manager, sessions, api, scope), messages, api, ctx, scope)
    }

    @Test
    fun twoServices_exchangeMessages_andSenderStatusUpgrades() = runBlocking {
        if (System.getenv("RUN_NETWORK_TESTS").isNullOrBlank()) return@runBlocking

        initCrypto()
        val server = embeddedServer(Netty, port = 0) { messengerModule() }
        server.start(wait = false)
        val port = server.engine.resolvedConnectors().first().port
        val baseUrl = "http://127.0.0.1:$port"

        val alice = device(baseUrl, "alice")
        val bob = device(baseUrl, "bob")
        try {
            alice.on { alice.service.start("alice", "aliceD") }
            bob.on { bob.service.start("bob", "bobD") }

            alice.on { alice.service.sendMessage("bob", "hello service") }

            // Bob's receive loop decrypts and persists the message.
            val onBob = await { bob.on { bob.incoming("alice") } }
            assertEquals("hello service", onBob.body)

            // Bob's delivery receipt flows back → Alice's outgoing message upgrades past SENT.
            val onAlice = await { alice.on { alice.outgoingDelivered("bob") } }
            assertEquals(MessageStatus.DELIVERED, onAlice.status)

            // Bob replies on the now-established session; Alice receives it.
            bob.on { bob.service.sendMessage("alice", "hi back") }
            val reply = await { alice.on { alice.incoming("bob") } }
            assertEquals("hi back", reply.body)
        } finally {
            // Tear down the clients (receive loops + WebSockets) before the server, so in-flight
            // relay coroutines don't thrash against a stopped Netty executor.
            alice.shutdown()
            bob.shutdown()
            server.stop(gracePeriodMillis = 0, timeoutMillis = 500)
        }
    }

    private fun Device.incoming(peer: String): ChatMessage? =
        messages.messagesForContact(peer).firstOrNull { it.direction == MessageDirection.INCOMING }

    private fun Device.outgoingDelivered(peer: String): ChatMessage? =
        messages.messagesForContact(peer)
            .firstOrNull { it.direction == MessageDirection.OUTGOING && it.status == MessageStatus.DELIVERED }

    private suspend fun <T : Any> await(timeoutMs: Long = 5_000, block: suspend () -> T?): T =
        withTimeout(timeoutMs) {
            var result = block()
            while (result == null) {
                delay(25)
                result = block()
            }
            result
        }
}
