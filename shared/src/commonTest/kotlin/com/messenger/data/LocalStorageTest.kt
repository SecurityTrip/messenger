package com.messenger.data

import com.messenger.crypto.LibsodiumCryptoProvider
import com.messenger.crypto.initCrypto
import com.messenger.db.DatabaseDriverFactory
import com.messenger.db.MessengerDatabase
import com.messenger.db.createMessengerDatabase
import com.messenger.domain.ChatMessage
import com.messenger.domain.Contact
import com.messenger.domain.MessageDirection
import com.messenger.domain.MessageStatus
import com.messenger.protocol.ratchet.DoubleRatchet
import com.messenger.security.BlobCipher
import com.messenger.security.InMemorySecureKeyStore
import com.messenger.security.MasterKey
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class LocalStorageTest {

    private val crypto = LibsodiumCryptoProvider()

    private fun newDatabase(): MessengerDatabase = createMessengerDatabase(DatabaseDriverFactory(inMemory = true).create())

    private fun cipher(): BlobCipher = BlobCipher(crypto, MasterKey.loadOrCreate(crypto, InMemorySecureKeyStore()))

    @Test
    fun identity_savedAndLoaded_withEncryptedPrivateKey() = runTest {
        initCrypto()
        val db = newDatabase()
        val cipher = cipher()
        val store = IdentityStore(db, cipher)

        val identity = crypto.generateSigningKeyPair()
        store.saveAccount("alice", identity, registrationId = 7, now = 1000L)

        val loaded = store.loadIdentity()!!
        assertContentEquals(identity.publicKey, loaded.publicKey)
        assertContentEquals(identity.privateKey, loaded.privateKey)
        assertEquals("alice", store.accountUserId())

        // The private key must be stored encrypted, not in the clear.
        val rawPrivateEnc = db.accountQueries.selectAccount().executeAsOne().identityPrivateKeyEnc
        assertFalse(rawPrivateEnc.contentEquals(identity.privateKey), "private key must not be stored in plaintext")
    }

    @Test
    fun preKeys_savedLoadedAndConsumed() = runTest {
        initCrypto()
        val store = IdentityStore(newDatabase(), cipher())

        val spkPair = crypto.generateDhKeyPair()
        val spk = com.messenger.protocol.x3dh.SignedPreKey(
            id = 1,
            keyPair = spkPair,
            signature = crypto.randomBytes(64),
        )
        store.saveSignedPreKey(spk, now = 1L)
        val loadedSpk = store.loadSignedPreKey(1)!!
        assertContentEquals(spkPair.privateKey, loadedSpk.keyPair.privateKey)

        val otks = (10..12).map {
            com.messenger.protocol.x3dh.OneTimePreKey(it, crypto.generateDhKeyPair())
        }
        store.saveOneTimePreKeys(otks)
        assertEquals(3, store.unusedOneTimePreKeyCount())

        val loadedOtk = store.loadOneTimePreKey(11)!!
        assertContentEquals(otks[1].keyPair.privateKey, loadedOtk.keyPair.privateKey)

        store.markOneTimePreKeyUsed(11)
        assertEquals(2, store.unusedOneTimePreKeyCount())
    }

    @Test
    fun contacts_crudAndVerification() = runTest {
        initCrypto()
        val store = ContactStore(newDatabase())

        store.upsert(Contact("bob", byteArrayOf(1, 2, 3), "Bob", verified = false))
        store.upsert(Contact("carol", byteArrayOf(4, 5, 6), "Carol", verified = false))

        assertEquals("Bob", store.get("bob")!!.displayName)
        assertEquals(2, store.all().size)

        store.setVerified("bob", true)
        assertTrue(store.get("bob")!!.verified)
    }

    @Test
    fun session_survivesReloadAndContinuesConversation() = runTest {
        initCrypto()
        val cipher = cipher()
        val db = newDatabase()
        val sessions = SessionStore(db, cipher, crypto)

        // Establish a live ratchet pair and exchange a couple of messages.
        val sharedSecret = crypto.randomBytes(32)
        val associatedData = crypto.randomBytes(64)
        val bobSignedPreKey = crypto.generateDhKeyPair()
        val alice = DoubleRatchet.initAlice(crypto, sharedSecret, bobSignedPreKey.publicKey, associatedData)
        val bob = DoubleRatchet.initBob(crypto, sharedSecret, bobSignedPreKey, associatedData)
        bob.decrypt(alice.encrypt("hi".encodeToByteArray()))

        assertFalse(sessions.exists("bob"))
        sessions.save("bob", alice, now = 1L)
        assertTrue(sessions.exists("bob"))

        // The stored blob must be ciphertext (must not contain the shared secret in the clear).
        val blob = db.sessionQueries.selectSession("bob").executeAsOne()
        assertFalse(containsSubsequence(blob, sharedSecret), "session blob must be encrypted at rest")

        // Reload Alice's ratchet from storage and continue the conversation with the live Bob.
        val aliceReloaded = sessions.load("bob")!!
        assertEquals("hello again", bob.decrypt(aliceReloaded.encrypt("hello again".encodeToByteArray())).decodeToString())
    }

    @Test
    fun messages_insertedDecryptedAndObserved() = runTest {
        initCrypto()
        val cipher = cipher()
        val db = newDatabase()
        val store = MessageStore(db, cipher)

        store.insert(ChatMessage("m1", "bob", MessageDirection.OUTGOING, "hello bob", 100L, MessageStatus.SENDING))
        store.insert(ChatMessage("m2", "bob", MessageDirection.INCOMING, "hi alice", 200L, MessageStatus.DELIVERED))

        val list = store.messagesForContact("bob")
        assertEquals(listOf("hello bob", "hi alice"), list.map { it.body })

        // Body must be encrypted at rest.
        val rawBody = db.messageQueries.selectMessagesForContact("bob").executeAsList().first().bodyEnc
        assertFalse(rawBody.decodeToString().contains("hello bob"), "message body must be encrypted")

        store.updateStatus("m1", MessageStatus.SENT)
        assertEquals(MessageStatus.SENT, store.messagesForContact("bob").first { it.id == "m1" }.status)

        // Reactive stream reflects current state.
        val observed = store.observeMessages("bob", coroutineContext).first()
        assertEquals(2, observed.size)
    }

    private fun containsSubsequence(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > haystack.size) return false
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return true
        }
        return false
    }
}
