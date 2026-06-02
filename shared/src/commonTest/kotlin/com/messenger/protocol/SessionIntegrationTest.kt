package com.messenger.protocol

import com.messenger.crypto.LibsodiumCryptoProvider
import com.messenger.crypto.initCrypto
import com.messenger.protocol.ratchet.DoubleRatchet
import com.messenger.protocol.x3dh.X3dh
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * End-to-end protocol test: the full real flow of X3DH establishing the session, then the Double
 * Ratchet carrying the conversation. This proves the two phases compose — in particular that Bob's
 * signed prekey seeds the ratchet identically on both sides and the X3DH associated data lines up.
 */
class SessionIntegrationTest {

    private val crypto = LibsodiumCryptoProvider()
    private val x3dh = X3dh(crypto)

    @Test
    fun fullHandshakeThenConversation() = runTest {
        initCrypto()

        // --- Bob provisions and "uploads" a prekey bundle (he is offline thereafter) ---
        val bobIdentity = x3dh.generateIdentityKey()
        val bobSignedPreKey = x3dh.generateSignedPreKey(bobIdentity, id = 1)
        val bobOneTimePreKey = x3dh.generateOneTimePreKeys(startId = 500, count = 1).single()
        val bundle = x3dh.createBundle(bobIdentity, bobSignedPreKey, bobOneTimePreKey)

        // --- Alice fetches the bundle and initiates ---
        val aliceIdentity = x3dh.generateIdentityKey()
        val initiation = x3dh.initiate(aliceIdentity, bundle)
        val alice = DoubleRatchet.initAlice(
            crypto = crypto,
            sharedSecret = initiation.result.sharedSecret,
            remoteSignedPreKey = bundle.signedPreKey,
            associatedData = initiation.result.associatedData,
        )

        // Alice's very first message (sent together with the X3DH header).
        val firstCiphertext = alice.encrypt("hi Bob, this is Alice".encodeToByteArray())

        // --- Bob receives the X3DH header, completes the handshake, sets up his ratchet ---
        val bobResult = x3dh.respond(
            ourIdentity = bobIdentity,
            ourSignedPreKey = bobSignedPreKey,
            ourOneTimePreKey = bobOneTimePreKey, // consumed; would be deleted in real storage
            message = initiation.header,
        )
        // Sanity: X3DH agreed on both sides.
        assertContentEquals(initiation.result.sharedSecret, bobResult.sharedSecret)
        assertContentEquals(initiation.result.associatedData, bobResult.associatedData)

        val bob = DoubleRatchet.initBob(
            crypto = crypto,
            sharedSecret = bobResult.sharedSecret,
            signedPreKey = bobSignedPreKey.keyPair,
            associatedData = bobResult.associatedData,
        )

        // Bob decrypts Alice's first message.
        assertEquals("hi Bob, this is Alice", bob.decrypt(firstCiphertext).decodeToString())

        // --- A normal back-and-forth conversation continues over the ratchet ---
        assertEquals("hey Alice!", alice.decrypt(bob.encrypt("hey Alice!".encodeToByteArray())).decodeToString())
        assertEquals("how are you?", bob.decrypt(alice.encrypt("how are you?".encodeToByteArray())).decodeToString())
        assertEquals("great, you?", alice.decrypt(bob.encrypt("great, you?".encodeToByteArray())).decodeToString())

        // Bob sends a burst; Alice receives out of order.
        val b1 = bob.encrypt("burst-1".encodeToByteArray())
        val b2 = bob.encrypt("burst-2".encodeToByteArray())
        val b3 = bob.encrypt("burst-3".encodeToByteArray())
        assertEquals("burst-3", alice.decrypt(b3).decodeToString())
        assertEquals("burst-1", alice.decrypt(b1).decodeToString())
        assertEquals("burst-2", alice.decrypt(b2).decodeToString())
    }
}
