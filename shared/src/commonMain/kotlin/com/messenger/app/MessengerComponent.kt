package com.messenger.app

import com.messenger.crypto.CryptoProvider
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
import com.messenger.security.MasterKey
import com.messenger.security.SecureKeyStore

/**
 * Composition root: wires the whole messenger stack together behind one object the UI layer holds.
 * Build it with [create] (which initializes libsodium first). Pass the platform [DatabaseDriverFactory]
 * (JVM/iOS), a [SecureKeyStore] (iOS Keychain in the app; in-memory in tests), and the server URL.
 */
class MessengerComponent private constructor(
    driverFactory: DatabaseDriverFactory,
    secureKeyStore: SecureKeyStore,
    serverBaseUrl: String,
    val crypto: CryptoProvider,
) {
    private val database = createMessengerDatabase(driverFactory.create())
    private val cipher = BlobCipher(crypto, MasterKey.loadOrCreate(crypto, secureKeyStore))

    val identities = IdentityStore(database, cipher)
    val sessions = SessionStore(database, cipher, crypto)
    val messages = MessageStore(database, cipher)
    val contacts = ContactStore(database)
    val conversations = ConversationManager(crypto, identities, sessions, messages, contacts)
    val api = MessengerApiClient(serverBaseUrl)

    fun close() = api.close()

    companion object {
        suspend fun create(
            driverFactory: DatabaseDriverFactory,
            secureKeyStore: SecureKeyStore,
            serverBaseUrl: String,
            crypto: CryptoProvider = LibsodiumCryptoProvider(),
        ): MessengerComponent {
            initCrypto()
            return MessengerComponent(driverFactory, secureKeyStore, serverBaseUrl, crypto)
        }
    }
}
