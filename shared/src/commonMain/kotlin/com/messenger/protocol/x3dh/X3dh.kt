package com.messenger.protocol.x3dh

import com.messenger.crypto.CryptoProvider
import com.messenger.crypto.SigningKeyPair

/**
 * X3DH (Extended Triple Diffie-Hellman) key agreement.
 *
 * Establishes a shared secret between an initiator (Alice) and a responder (Bob) who may be
 * offline, using prekeys Bob published in advance. The resulting [X3dhResult.sharedSecret] seeds
 * the Double Ratchet.
 *
 * Identity keys are Ed25519 (so they can *sign* the signed prekey); for the DH steps they are
 * converted to their X25519 form. Signed prekeys, one-time prekeys and the ephemeral key are
 * native X25519 keys.
 *
 * Reference: https://signal.org/docs/specifications/x3dh/
 */
class X3dh(private val crypto: CryptoProvider) {

    fun generateIdentityKey(): SigningKeyPair = crypto.generateSigningKeyPair()

    /** Create a signed prekey: a fresh X25519 key pair whose public key is signed by [identity]. */
    fun generateSignedPreKey(identity: SigningKeyPair, id: Int): SignedPreKey {
        val keyPair = crypto.generateDhKeyPair()
        val signature = crypto.sign(identity.privateKey, keyPair.publicKey)
        return SignedPreKey(id, keyPair, signature)
    }

    /** Create [count] one-time prekeys with sequential ids starting at [startId]. */
    fun generateOneTimePreKeys(startId: Int, count: Int): List<OneTimePreKey> =
        (0 until count).map { OneTimePreKey(startId + it, crypto.generateDhKeyPair()) }

    /** Assemble the public bundle to publish for [identity]. [oneTimePreKey] may be omitted. */
    fun createBundle(
        identity: SigningKeyPair,
        signedPreKey: SignedPreKey,
        oneTimePreKey: OneTimePreKey? = null,
    ): PreKeyBundle = PreKeyBundle(
        identityKey = identity.publicKey,
        signedPreKeyId = signedPreKey.id,
        signedPreKey = signedPreKey.keyPair.publicKey,
        signedPreKeySignature = signedPreKey.signature,
        oneTimePreKeyId = oneTimePreKey?.id,
        oneTimePreKey = oneTimePreKey?.keyPair?.publicKey,
    )

    /**
     * Initiator (Alice). Verifies Bob's signed prekey, derives the shared secret and produces the
     * [X3dhInitialMessage] header to send alongside the first ciphertext.
     *
     * @throws IllegalArgumentException if the signed prekey signature is invalid.
     */
    fun initiate(ourIdentity: SigningKeyPair, bundle: PreKeyBundle): InitiationResult {
        require(
            crypto.verify(bundle.identityKey, bundle.signedPreKey, bundle.signedPreKeySignature),
        ) { "Invalid signed prekey signature — possible MITM, aborting" }

        val ephemeral = crypto.generateDhKeyPair()

        val ourIdentityDhPrivate = crypto.signingPrivateKeyToDh(ourIdentity.privateKey)
        val theirIdentityDhPublic = crypto.signingPublicKeyToDh(bundle.identityKey)

        val dh1 = crypto.dh(ourIdentityDhPrivate, bundle.signedPreKey) // IK_A <-> SPK_B
        val dh2 = crypto.dh(ephemeral.privateKey, theirIdentityDhPublic) // EK_A <-> IK_B
        val dh3 = crypto.dh(ephemeral.privateKey, bundle.signedPreKey) // EK_A <-> SPK_B
        val dh4 = bundle.oneTimePreKey?.let { crypto.dh(ephemeral.privateKey, it) } // EK_A <-> OPK_B

        val sharedSecret = deriveSecret(dh1, dh2, dh3, dh4)
        val associatedData = ourIdentity.publicKey + bundle.identityKey // IK_A || IK_B

        val header = X3dhInitialMessage(
            identityKey = ourIdentity.publicKey,
            ephemeralKey = ephemeral.publicKey,
            signedPreKeyId = bundle.signedPreKeyId,
            oneTimePreKeyId = bundle.oneTimePreKeyId,
        )
        return InitiationResult(X3dhResult(sharedSecret, associatedData), header)
    }

    /**
     * Responder (Bob). Recomputes the same shared secret from Alice's [message] and his private
     * prekeys. The caller must supply the prekeys whose ids the message references, and delete the
     * one-time prekey afterwards.
     */
    fun respond(
        ourIdentity: SigningKeyPair,
        ourSignedPreKey: SignedPreKey,
        ourOneTimePreKey: OneTimePreKey?,
        message: X3dhInitialMessage,
    ): X3dhResult {
        require(ourSignedPreKey.id == message.signedPreKeyId) {
            "Signed prekey id mismatch (have ${ourSignedPreKey.id}, message ${message.signedPreKeyId})"
        }
        require(ourOneTimePreKey?.id == message.oneTimePreKeyId) {
            "One-time prekey id mismatch (have ${ourOneTimePreKey?.id}, message ${message.oneTimePreKeyId})"
        }

        val ourIdentityDhPrivate = crypto.signingPrivateKeyToDh(ourIdentity.privateKey)
        val theirIdentityDhPublic = crypto.signingPublicKeyToDh(message.identityKey)

        val dh1 = crypto.dh(ourSignedPreKey.keyPair.privateKey, theirIdentityDhPublic) // SPK_B <-> IK_A
        val dh2 = crypto.dh(ourIdentityDhPrivate, message.ephemeralKey) // IK_B <-> EK_A
        val dh3 = crypto.dh(ourSignedPreKey.keyPair.privateKey, message.ephemeralKey) // SPK_B <-> EK_A
        val dh4 = ourOneTimePreKey?.let { crypto.dh(it.keyPair.privateKey, message.ephemeralKey) } // OPK_B <-> EK_A

        val sharedSecret = deriveSecret(dh1, dh2, dh3, dh4)
        val associatedData = message.identityKey + ourIdentity.publicKey // IK_A || IK_B
        return X3dhResult(sharedSecret, associatedData)
    }

    private fun deriveSecret(dh1: ByteArray, dh2: ByteArray, dh3: ByteArray, dh4: ByteArray?): ByteArray {
        // KM = DH1 || DH2 || DH3 [|| DH4]; IKM = F || KM (F domain-separates X25519 inputs).
        val ikm = KDF_PREFIX + dh1 + dh2 + dh3 + (dh4 ?: ByteArray(0))
        return crypto.hkdf(ikm, KDF_SALT, KDF_INFO, SHARED_SECRET_SIZE)
    }

    /** Bundles the initiator's [result] with the [header] that must be sent to the responder. */
    class InitiationResult(val result: X3dhResult, val header: X3dhInitialMessage)

    companion object {
        private val KDF_INFO = "Messenger_X3DH_25519_v1".encodeToByteArray()

        /** HKDF salt: per spec, a zero-filled byte sequence of hash length. */
        private val KDF_SALT = ByteArray(32)

        /** F: domain-separation prefix of 0xFF * 32 for Curve25519 (X3DH spec §2.2). */
        private val KDF_PREFIX = ByteArray(32) { 0xFF.toByte() }

        private const val SHARED_SECRET_SIZE = 32
    }
}
