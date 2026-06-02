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
import com.messenger.net.MessengerApiClient
import com.messenger.security.BlobCipher
import com.messenger.security.InMemorySecureKeyStore
import com.messenger.security.MasterKey
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.util.concurrent.Executors

/**
 * A tiny command-line messenger client used to drive end-to-end tests against a running relay (e.g.
 * to send a message to the iOS app and watch the conversation). All DB access is confined to one
 * thread (the JVM JdbcSqliteDriver isn't thread-safe).
 *
 * Usage: peerTool <serverUrl> <me> <peer> <message>
 */
fun main(args: Array<String>) = runBlocking {
    val server = args.getOrElse(0) { "http://localhost:8080" }
    val me = args.getOrElse(1) { "bob" }
    val peer = args.getOrElse(2) { "alice" }
    val text = args.drop(3).joinToString(" ").ifBlank { "Hello from $me (JVM peer)" }

    initCrypto()
    val crypto = LibsodiumCryptoProvider()
    val db = createMessengerDatabase(DatabaseDriverFactory(inMemory = true).create())
    val cipher = BlobCipher(crypto, MasterKey.loadOrCreate(crypto, InMemorySecureKeyStore()))
    val sessions = SessionStore(db, cipher, crypto)
    val messages = MessageStore(db, cipher)
    val manager = ConversationManager(crypto, IdentityStore(db, cipher), sessions, messages, ContactStore(db))
    val api = MessengerApiClient(server)
    val ctx = Executors.newSingleThreadExecutor { r -> Thread(r, "peer").apply { isDaemon = true } }
        .asCoroutineDispatcher()
    val scope = CoroutineScope(SupervisorJob() + ctx)
    val service = MessengerService(manager, sessions, api, scope)

    try {
        withContext(ctx) { service.start(me, "${me}-cli") }
        println("[$me] connected to $server")
        delay(800) // let the peer publish keys / connect
        withContext(ctx) { service.sendMessage(peer, text) }
        println("[$me] sent to $peer: \"$text\"")

        // Stay online to receive any reply and process delivery receipts.
        delay(8000)
        withContext(ctx) {
            messages.messagesForContact(peer).forEach {
                println("[$me] ${it.direction} ${it.status}: ${it.body}")
            }
        }
    } finally {
        withContext(ctx) { service.stop() }
        scope.cancel()
        api.close()
        ctx.close()
    }
}
