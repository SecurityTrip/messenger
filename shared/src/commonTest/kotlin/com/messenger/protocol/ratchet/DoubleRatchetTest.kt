package com.messenger.protocol.ratchet

import com.messenger.crypto.CryptoProvider
import com.messenger.crypto.LibsodiumCryptoProvider
import com.messenger.crypto.initCrypto
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DoubleRatchetTest {

    private val crypto: CryptoProvider = LibsodiumCryptoProvider()

    /** Establish a fresh Alice/Bob ratchet pair sharing an X3DH secret + AD and Bob's prekey. */
    private fun pair(): Pair<DoubleRatchet, DoubleRatchet> {
        val sharedSecret = crypto.randomBytes(32)
        val associatedData = crypto.randomBytes(64)
        val bobSignedPreKey = crypto.generateDhKeyPair()
        val alice = DoubleRatchet.initAlice(crypto, sharedSecret, bobSignedPreKey.publicKey, associatedData)
        val bob = DoubleRatchet.initBob(crypto, sharedSecret, bobSignedPreKey, associatedData)
        return alice to bob
    }

    @Test
    fun alternatingConversation_decryptsCorrectly() = runTest {
        initCrypto()
        val (alice, bob) = pair()

        assertEquals("a1", bob.decrypt(alice.encrypt("a1".encodeToByteArray())).decodeToString())
        assertEquals("b1", alice.decrypt(bob.encrypt("b1".encodeToByteArray())).decodeToString())
        assertEquals("a2", bob.decrypt(alice.encrypt("a2".encodeToByteArray())).decodeToString())
        assertEquals("b2", alice.decrypt(bob.encrypt("b2".encodeToByteArray())).decodeToString())
        assertEquals("a3", bob.decrypt(alice.encrypt("a3".encodeToByteArray())).decodeToString())
    }

    @Test
    fun consecutiveMessagesSameDirection_inOrder() = runTest {
        initCrypto()
        val (alice, bob) = pair()

        val m1 = alice.encrypt("one".encodeToByteArray())
        val m2 = alice.encrypt("two".encodeToByteArray())
        val m3 = alice.encrypt("three".encodeToByteArray())

        assertEquals("one", bob.decrypt(m1).decodeToString())
        assertEquals("two", bob.decrypt(m2).decodeToString())
        assertEquals("three", bob.decrypt(m3).decodeToString())
    }

    @Test
    fun outOfOrderDelivery_withinChain_usesSkippedKeys() = runTest {
        initCrypto()
        val (alice, bob) = pair()

        val m0 = alice.encrypt("zero".encodeToByteArray())
        val m1 = alice.encrypt("one".encodeToByteArray())
        val m2 = alice.encrypt("two".encodeToByteArray())

        // Bob receives them reordered: 2, 0, 1
        assertEquals("two", bob.decrypt(m2).decodeToString())
        assertEquals("zero", bob.decrypt(m0).decodeToString())
        assertEquals("one", bob.decrypt(m1).decodeToString())
    }

    @Test
    fun droppedMessage_thenContinue_acrossRatchet() = runTest {
        initCrypto()
        val (alice, bob) = pair()

        // Alice sends two, Bob only receives the first.
        val a0 = alice.encrypt("a0".encodeToByteArray())
        val a1 = alice.encrypt("a1-dropped".encodeToByteArray())
        assertEquals("a0", bob.decrypt(a0).decodeToString())

        // Conversation continues; a new DH ratchet happens when Bob replies and Alice answers.
        assertEquals("b0", alice.decrypt(bob.encrypt("b0".encodeToByteArray())).decodeToString())
        assertEquals("a2", bob.decrypt(alice.encrypt("a2".encodeToByteArray())).decodeToString())

        // The dropped message can still be decrypted later via the stored skipped key.
        assertEquals("a1-dropped", bob.decrypt(a1).decodeToString())
    }

    @Test
    fun tamperedCiphertext_isRejected() = runTest {
        initCrypto()
        val (alice, bob) = pair()

        val msg = alice.encrypt("secret".encodeToByteArray())
        val tampered = RatchetMessage(
            header = msg.header,
            ciphertext = msg.ciphertext.copyOf().also { it[0] = (it[0] + 1).toByte() },
        )
        assertFailsWith<DoubleRatchetException> { bob.decrypt(tampered) }
    }

    @Test
    fun tamperedHeader_breaksAssociatedData() = runTest {
        initCrypto()
        val (alice, bob) = pair()

        val msg = alice.encrypt("secret".encodeToByteArray())
        // Same ciphertext, but claim a different message number → AD mismatch → auth fails.
        val forgedHeader = DoubleRatchetHeader(
            ratchetPublicKey = msg.header.ratchetPublicKey,
            previousChainLength = msg.header.previousChainLength,
            messageNumber = msg.header.messageNumber + 1,
        )
        assertFailsWith<DoubleRatchetException> { bob.decrypt(RatchetMessage(forgedHeader, msg.ciphertext)) }
    }

    @Test
    fun bobCannotSendBeforeReceiving() = runTest {
        initCrypto()
        val (_, bob) = pair()
        assertFailsWith<DoubleRatchetException> { bob.encrypt("too early".encodeToByteArray()) }
    }

    @Test
    fun tooManySkippedMessages_isRejected() = runTest {
        initCrypto()
        val (alice, bob) = pair()

        // Establish the receiving chain with one real message.
        val a0 = alice.encrypt("a0".encodeToByteArray())
        bob.decrypt(a0)

        // A message far beyond MAX_SKIP in the same chain must be rejected before any decryption.
        val absurd = RatchetMessage(
            header = DoubleRatchetHeader(
                ratchetPublicKey = a0.header.ratchetPublicKey,
                previousChainLength = 0,
                messageNumber = DoubleRatchet.MAX_SKIP + 10,
            ),
            ciphertext = ByteArray(48),
        )
        assertFailsWith<DoubleRatchetException> { bob.decrypt(absurd) }
    }

    @Test
    fun eachMessageProducesDistinctCiphertext() = runTest {
        initCrypto()
        val (alice, _) = pair()
        val c1 = alice.encrypt("same".encodeToByteArray()).ciphertext
        val c2 = alice.encrypt("same".encodeToByteArray()).ciphertext
        assertFalse(c1.contentEquals(c2), "identical plaintext must yield different ciphertext (forward secrecy)")
        assertTrue(c1.isNotEmpty())
    }
}
