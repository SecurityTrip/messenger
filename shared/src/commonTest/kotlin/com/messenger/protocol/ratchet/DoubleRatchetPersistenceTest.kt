package com.messenger.protocol.ratchet

import com.messenger.crypto.CryptoProvider
import com.messenger.crypto.LibsodiumCryptoProvider
import com.messenger.crypto.initCrypto
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals

class DoubleRatchetPersistenceTest {

    private val crypto: CryptoProvider = LibsodiumCryptoProvider()

    private fun pair(): Pair<DoubleRatchet, DoubleRatchet> {
        val sharedSecret = crypto.randomBytes(32)
        val associatedData = crypto.randomBytes(64)
        val bobSignedPreKey = crypto.generateDhKeyPair()
        val alice = DoubleRatchet.initAlice(crypto, sharedSecret, bobSignedPreKey.publicKey, associatedData)
        val bob = DoubleRatchet.initBob(crypto, sharedSecret, bobSignedPreKey, associatedData)
        return alice to bob
    }

    @Test
    fun exportRestore_continuesConversation() = runTest {
        initCrypto()
        val (alice, bob) = pair()

        // Run a few rounds so both sides have non-trivial ratchet state.
        bob.decrypt(alice.encrypt("a1".encodeToByteArray()))
        alice.decrypt(bob.encrypt("b1".encodeToByteArray()))
        bob.decrypt(alice.encrypt("a2".encodeToByteArray()))

        // Simulate an app restart: persist both sides and rebuild from the snapshots.
        val aliceRestored = DoubleRatchet.restore(crypto, alice.export())
        val bobRestored = DoubleRatchet.restore(crypto, bob.export())

        // The conversation must continue seamlessly across the restart.
        assertEquals("b2", aliceRestored.decrypt(bobRestored.encrypt("b2".encodeToByteArray())).decodeToString())
        assertEquals("a3", bobRestored.decrypt(aliceRestored.encrypt("a3".encodeToByteArray())).decodeToString())
    }

    @Test
    fun restoredSession_preservesSkippedKeys() = runTest {
        initCrypto()
        val (alice, bob) = pair()

        val m0 = alice.encrypt("zero".encodeToByteArray())
        val m1 = alice.encrypt("one".encodeToByteArray())

        // Bob receives m1 first → m0's key is stored as skipped, then Bob "restarts".
        assertEquals("one", bob.decrypt(m1).decodeToString())
        val bobRestored = DoubleRatchet.restore(crypto, bob.export())

        // The stored skipped key must survive the round-trip so m0 still decrypts.
        assertEquals("zero", bobRestored.decrypt(m0).decodeToString())
    }

    @Test
    fun snapshot_jsonRoundTrip() = runTest {
        initCrypto()
        val (alice, bob) = pair()
        bob.decrypt(alice.encrypt("hello".encodeToByteArray()))

        val json = Json.encodeToString(RatchetStateSnapshot.serializer(), bob.export())
        val decoded = Json.decodeFromString(RatchetStateSnapshot.serializer(), json)
        val bobFromJson = DoubleRatchet.restore(crypto, decoded)

        // Reply path works after a full serialize → JSON → deserialize → restore cycle.
        assertEquals("world", alice.decrypt(bobFromJson.encrypt("world".encodeToByteArray())).decodeToString())
    }
}
