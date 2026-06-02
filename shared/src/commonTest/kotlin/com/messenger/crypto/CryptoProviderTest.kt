package com.messenger.crypto

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CryptoProviderTest {

    private val crypto: CryptoProvider = LibsodiumCryptoProvider()

    @Test
    fun randomBytes_hasRequestedSizeAndVaries() = runTest {
        initCrypto()
        val a = crypto.randomBytes(32)
        val b = crypto.randomBytes(32)
        assertEquals(32, a.size)
        assertFalse(a.contentEquals(b), "two random buffers should differ")
    }

    @Test
    fun dh_isCommutative() = runTest {
        initCrypto()
        val alice = crypto.generateDhKeyPair()
        val bob = crypto.generateDhKeyPair()

        val aliceShared = crypto.dh(alice.privateKey, bob.publicKey)
        val bobShared = crypto.dh(bob.privateKey, alice.publicKey)

        assertEquals(32, aliceShared.size)
        assertContentEquals(aliceShared, bobShared, "DH must be commutative")
    }

    @Test
    fun dhPublicKey_matchesGeneratedPublic() = runTest {
        initCrypto()
        val kp = crypto.generateDhKeyPair()
        assertContentEquals(kp.publicKey, crypto.dhPublicKey(kp.privateKey))
    }

    @Test
    fun sign_thenVerify_andRejectTamper() = runTest {
        initCrypto()
        val id = crypto.generateSigningKeyPair()
        val message = "hello, world".encodeToByteArray()

        val signature = crypto.sign(id.privateKey, message)
        assertEquals(CryptoProvider.SIGNATURE_SIZE, signature.size)
        assertTrue(crypto.verify(id.publicKey, message, signature))

        val tampered = message.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertFalse(crypto.verify(id.publicKey, tampered, signature), "tampered message must not verify")

        val wrongKey = crypto.generateSigningKeyPair()
        assertFalse(crypto.verify(wrongKey.publicKey, message, signature), "wrong key must not verify")
    }

    @Test
    fun ed25519ToCurve25519_enablesDh() = runTest {
        initCrypto()
        val aliceId = crypto.generateSigningKeyPair()
        val bobId = crypto.generateSigningKeyPair()

        val alicePriv = crypto.signingPrivateKeyToDh(aliceId.privateKey)
        val alicePub = crypto.signingPublicKeyToDh(aliceId.publicKey)
        val bobPriv = crypto.signingPrivateKeyToDh(bobId.privateKey)
        val bobPub = crypto.signingPublicKeyToDh(bobId.publicKey)

        // The converted public key must match the one derived from the converted private key.
        assertContentEquals(alicePub, crypto.dhPublicKey(alicePriv))
        // And a DH using the converted identity keys must agree on both sides.
        assertContentEquals(
            crypto.dh(alicePriv, bobPub),
            crypto.dh(bobPriv, alicePub),
            "identity-key DH must agree after Ed25519->X25519 conversion",
        )
    }

    @Test
    fun hkdf_isDeterministicAndContextSensitive() = runTest {
        initCrypto()
        val ikm = crypto.randomBytes(32)
        val salt = ByteArray(32)

        val out1 = crypto.hkdf(ikm, salt, "info-a".encodeToByteArray(), 64)
        val out2 = crypto.hkdf(ikm, salt, "info-a".encodeToByteArray(), 64)
        val out3 = crypto.hkdf(ikm, salt, "info-b".encodeToByteArray(), 64)

        assertEquals(64, out1.size)
        assertContentEquals(out1, out2, "HKDF must be deterministic")
        assertFalse(out1.contentEquals(out3), "different info must yield different output")
    }

    @Test
    fun hkdf_longerThanOneBlock() = runTest {
        initCrypto()
        // 100 bytes spans 4 HMAC blocks (32 each) — exercises the expand loop.
        val out = crypto.hkdf(crypto.randomBytes(32), ByteArray(32), "x".encodeToByteArray(), 100)
        assertEquals(100, out.size)
    }

    @Test
    fun aead_roundTrip_andTamperDetection() = runTest {
        initCrypto()
        val key = crypto.randomBytes(CryptoProvider.AEAD_KEY_SIZE)
        val nonce = crypto.randomBytes(CryptoProvider.AEAD_NONCE_SIZE)
        val ad = "associated-header".encodeToByteArray()
        val plaintext = "this is a secret message".encodeToByteArray()

        val ciphertext = crypto.aeadEncrypt(key, nonce, plaintext, ad)
        assertEquals(plaintext.size + CryptoProvider.AEAD_TAG_SIZE, ciphertext.size)
        assertContentEquals(plaintext, crypto.aeadDecrypt(key, nonce, ciphertext, ad))

        assertNull(
            crypto.aeadDecrypt(key, nonce, ciphertext, "other-header".encodeToByteArray()),
            "wrong associated data must fail authentication",
        )

        val tampered = ciphertext.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertNull(crypto.aeadDecrypt(key, nonce, tampered, ad), "tampered ciphertext must fail authentication")

        val wrongKey = crypto.randomBytes(CryptoProvider.AEAD_KEY_SIZE)
        assertNull(crypto.aeadDecrypt(wrongKey, nonce, ciphertext, ad), "wrong key must fail authentication")
    }
}
