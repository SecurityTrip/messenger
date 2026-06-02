package com.messenger.security

import com.messenger.crypto.CryptoProvider

/**
 * Encrypts/decrypts blobs **at rest** (private keys, ratchet snapshots, message bodies) with a
 * 32-byte master key using XChaCha20-Poly1305.
 *
 * Output layout: `nonce(24) || ciphertext(+16-byte tag)`. A fresh random nonce is used per call —
 * safe because XChaCha20's 24-byte nonce space makes random-nonce collisions negligible.
 */
class BlobCipher(
    private val crypto: CryptoProvider,
    private val masterKey: ByteArray,
) {
    init {
        require(masterKey.size == CryptoProvider.AEAD_KEY_SIZE) {
            "master key must be ${CryptoProvider.AEAD_KEY_SIZE} bytes (got ${masterKey.size})"
        }
    }

    fun encrypt(plaintext: ByteArray, associatedData: ByteArray = EMPTY): ByteArray {
        val nonce = crypto.randomBytes(CryptoProvider.AEAD_NONCE_SIZE)
        return nonce + crypto.aeadEncrypt(masterKey, nonce, plaintext, associatedData)
    }

    /** Returns null if the blob is malformed or fails authentication. */
    fun decrypt(blob: ByteArray, associatedData: ByteArray = EMPTY): ByteArray? {
        if (blob.size < CryptoProvider.AEAD_NONCE_SIZE + CryptoProvider.AEAD_TAG_SIZE) return null
        val nonce = blob.copyOf(CryptoProvider.AEAD_NONCE_SIZE)
        val ciphertext = blob.copyOfRange(CryptoProvider.AEAD_NONCE_SIZE, blob.size)
        return crypto.aeadDecrypt(masterKey, nonce, ciphertext, associatedData)
    }

    companion object {
        private val EMPTY = ByteArray(0)
    }
}
