package com.messenger.protocol.x3dh

import com.messenger.crypto.LibsodiumCryptoProvider
import com.messenger.crypto.initCrypto
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class X3dhTest {

    private val crypto = LibsodiumCryptoProvider()
    private val x3dh = X3dh(crypto)

    @Test
    fun handshake_withOneTimePreKey_agreesOnSecretAndAd() = runTest {
        initCrypto()

        // Bob publishes a bundle (offline).
        val bobIdentity = x3dh.generateIdentityKey()
        val bobSignedPreKey = x3dh.generateSignedPreKey(bobIdentity, id = 1)
        val bobOneTimePreKey = x3dh.generateOneTimePreKeys(startId = 100, count = 1).single()
        val bundle = x3dh.createBundle(bobIdentity, bobSignedPreKey, bobOneTimePreKey)

        // Alice initiates.
        val aliceIdentity = x3dh.generateIdentityKey()
        val initiation = x3dh.initiate(aliceIdentity, bundle)

        // Bob responds using the prekeys referenced in the header.
        val bobResult = x3dh.respond(
            ourIdentity = bobIdentity,
            ourSignedPreKey = bobSignedPreKey,
            ourOneTimePreKey = bobOneTimePreKey,
            message = initiation.header,
        )

        assertContentEquals(
            initiation.result.sharedSecret,
            bobResult.sharedSecret,
            "both parties must derive the same shared secret",
        )
        assertContentEquals(
            initiation.result.associatedData,
            bobResult.associatedData,
            "associated data must match on both sides",
        )
        assertEquals(32, initiation.result.sharedSecret.size)
        assertEquals(100, initiation.header.oneTimePreKeyId)
    }

    @Test
    fun handshake_withoutOneTimePreKey_stillAgrees() = runTest {
        initCrypto()

        val bobIdentity = x3dh.generateIdentityKey()
        val bobSignedPreKey = x3dh.generateSignedPreKey(bobIdentity, id = 7)
        val bundle = x3dh.createBundle(bobIdentity, bobSignedPreKey, oneTimePreKey = null)

        val aliceIdentity = x3dh.generateIdentityKey()
        val initiation = x3dh.initiate(aliceIdentity, bundle)
        val bobResult = x3dh.respond(bobIdentity, bobSignedPreKey, ourOneTimePreKey = null, message = initiation.header)

        assertContentEquals(initiation.result.sharedSecret, bobResult.sharedSecret)
        assertEquals(null, initiation.header.oneTimePreKeyId)
    }

    @Test
    fun initiate_rejectsTamperedSignedPreKeySignature() = runTest {
        initCrypto()

        val bobIdentity = x3dh.generateIdentityKey()
        val bobSignedPreKey = x3dh.generateSignedPreKey(bobIdentity, id = 1)
        val honest = x3dh.createBundle(bobIdentity, bobSignedPreKey)
        // Flip a byte in the signature.
        val forgedSignature = honest.signedPreKeySignature.copyOf().also { it[0] = (it[0] + 1).toByte() }
        val tampered = PreKeyBundle(
            identityKey = honest.identityKey,
            signedPreKeyId = honest.signedPreKeyId,
            signedPreKey = honest.signedPreKey,
            signedPreKeySignature = forgedSignature,
            oneTimePreKeyId = honest.oneTimePreKeyId,
            oneTimePreKey = honest.oneTimePreKey,
        )

        val alice = x3dh.generateIdentityKey()
        assertFailsWith<IllegalArgumentException> { x3dh.initiate(alice, tampered) }
    }

    @Test
    fun initiate_rejectsSignedPreKeyFromWrongIdentity() = runTest {
        initCrypto()

        val bobIdentity = x3dh.generateIdentityKey()
        // Signed prekey signed by an attacker's identity but advertised under Bob's identity.
        val attacker = x3dh.generateIdentityKey()
        val spk = x3dh.generateSignedPreKey(attacker, id = 1)
        val bundle = PreKeyBundle(
            identityKey = bobIdentity.publicKey,
            signedPreKeyId = spk.id,
            signedPreKey = spk.keyPair.publicKey,
            signedPreKeySignature = spk.signature,
            oneTimePreKeyId = null,
            oneTimePreKey = null,
        )

        val alice = x3dh.generateIdentityKey()
        assertFailsWith<IllegalArgumentException> { x3dh.initiate(alice, bundle) }
    }

    @Test
    fun differentParties_deriveDifferentSecrets() = runTest {
        initCrypto()

        val bobIdentity = x3dh.generateIdentityKey()
        val bobSignedPreKey = x3dh.generateSignedPreKey(bobIdentity, id = 1)
        val bundle = x3dh.createBundle(bobIdentity, bobSignedPreKey)

        val alice = x3dh.generateIdentityKey()
        val s1 = x3dh.initiate(alice, bundle).result.sharedSecret
        val s2 = x3dh.initiate(alice, bundle).result.sharedSecret // new ephemeral each time

        assertFalse(s1.contentEquals(s2), "each initiation uses a fresh ephemeral, so secrets differ")
    }

    @Test
    fun respond_rejectsPreKeyIdMismatch() = runTest {
        initCrypto()

        val bobIdentity = x3dh.generateIdentityKey()
        val bobSignedPreKey = x3dh.generateSignedPreKey(bobIdentity, id = 1)
        val bundle = x3dh.createBundle(bobIdentity, bobSignedPreKey)
        val alice = x3dh.generateIdentityKey()
        val header = x3dh.initiate(alice, bundle).header

        val wrongSpk = x3dh.generateSignedPreKey(bobIdentity, id = 999)
        assertFailsWith<IllegalArgumentException> {
            x3dh.respond(bobIdentity, wrongSpk, ourOneTimePreKey = null, message = header)
        }
    }
}
