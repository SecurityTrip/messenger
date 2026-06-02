package com.messenger.crypto

import com.ionspin.kotlin.crypto.LibsodiumInitializer
import com.ionspin.kotlin.crypto.aead.AuthenticatedEncryptionWithAssociatedData
import com.ionspin.kotlin.crypto.auth.Auth
import com.ionspin.kotlin.crypto.box.Box
import com.ionspin.kotlin.crypto.generichash.GenericHash
import com.ionspin.kotlin.crypto.scalarmult.ScalarMultiplication
import com.ionspin.kotlin.crypto.signature.Signature
import com.ionspin.kotlin.crypto.util.LibsodiumRandom

/**
 * Initialize the libsodium backend. Idempotent; must complete before any [CryptoProvider]
 * call. Call once during app startup (and in tests before exercising crypto).
 */
suspend fun initCrypto() {
    if (!LibsodiumInitializer.isInitialized()) {
        LibsodiumInitializer.initialize()
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
class LibsodiumCryptoProvider : CryptoProvider {

    override fun randomBytes(size: Int): ByteArray =
        LibsodiumRandom.buf(size).toByteArray()

    override fun generateDhKeyPair(): DhKeyPair {
        val kp = Box.keypair()
        return DhKeyPair(publicKey = kp.publicKey.toByteArray(), privateKey = kp.secretKey.toByteArray())
    }

    override fun dhPublicKey(privateKey: ByteArray): ByteArray =
        ScalarMultiplication.scalarMultiplicationBase(privateKey.toUByteArray()).toByteArray()

    override fun dh(privateKey: ByteArray, publicKey: ByteArray): ByteArray =
        ScalarMultiplication.scalarMultiplication(privateKey.toUByteArray(), publicKey.toUByteArray()).toByteArray()

    override fun generateSigningKeyPair(): SigningKeyPair {
        val kp = Signature.keypair()
        return SigningKeyPair(publicKey = kp.publicKey.toByteArray(), privateKey = kp.secretKey.toByteArray())
    }

    override fun sign(privateKey: ByteArray, message: ByteArray): ByteArray =
        Signature.detached(message.toUByteArray(), privateKey.toUByteArray()).toByteArray()

    override fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
        try {
            Signature.verifyDetached(
                signature.toUByteArray(),
                message.toUByteArray(),
                publicKey.toUByteArray(),
            )
            true
        } catch (e: Exception) {
            false
        }

    override fun signingPublicKeyToDh(edPublicKey: ByteArray): ByteArray =
        Signature.ed25519PkToCurve25519(edPublicKey.toUByteArray()).toByteArray()

    override fun signingPrivateKeyToDh(edPrivateKey: ByteArray): ByteArray =
        Signature.ed25519SkToCurve25519(edPrivateKey.toUByteArray()).toByteArray()

    override fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray =
        Auth.authHmacSha256(message.toUByteArray(), key.toUByteArray()).toByteArray()

    override fun hash(data: ByteArray, size: Int): ByteArray =
        GenericHash.genericHash(data.toUByteArray(), size).toByteArray()

    override fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray =
        Hkdf.derive(::hmacSha256, ikm, salt, info, length)

    override fun aeadEncrypt(
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        associatedData: ByteArray,
    ): ByteArray =
        AuthenticatedEncryptionWithAssociatedData.xChaCha20Poly1305IetfEncrypt(
            plaintext.toUByteArray(),
            associatedData.toUByteArray(),
            nonce.toUByteArray(),
            key.toUByteArray(),
        ).toByteArray()

    override fun aeadDecrypt(
        key: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray,
        associatedData: ByteArray,
    ): ByteArray? =
        try {
            AuthenticatedEncryptionWithAssociatedData.xChaCha20Poly1305IetfDecrypt(
                ciphertext.toUByteArray(),
                associatedData.toUByteArray(),
                nonce.toUByteArray(),
                key.toUByteArray(),
            ).toByteArray()
        } catch (e: Exception) {
            null
        }
}
