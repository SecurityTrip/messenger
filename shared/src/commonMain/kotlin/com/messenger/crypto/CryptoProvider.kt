package com.messenger.crypto

/**
 * Low-level cryptographic primitives the messaging protocols (X3DH, Double Ratchet)
 * are built on. Implemented once in commonMain on top of libsodium, so the exact same
 * code runs on the JVM (for tests) and on iOS.
 *
 * All keys/byte material are plain [ByteArray]. Curve choices:
 *  - DH / key agreement: X25519 (Curve25519)
 *  - signatures / identity: Ed25519
 *  - AEAD: XChaCha20-Poly1305-IETF (24-byte nonce, so random nonces are safe)
 *  - KDF: HKDF-SHA256
 */
interface CryptoProvider {

    /** Cryptographically secure random bytes. */
    fun randomBytes(size: Int): ByteArray

    // --- X25519 Diffie-Hellman ---

    /** Generate a fresh X25519 key pair. */
    fun generateDhKeyPair(): DhKeyPair

    /** Derive the X25519 public key for a given private key. */
    fun dhPublicKey(privateKey: ByteArray): ByteArray

    /** Compute the X25519 shared secret between our private key and their public key. */
    fun dh(privateKey: ByteArray, publicKey: ByteArray): ByteArray

    // --- Ed25519 signatures (identity key) ---

    /** Generate a fresh Ed25519 signing key pair. */
    fun generateSigningKeyPair(): SigningKeyPair

    /** Produce a detached Ed25519 signature over [message]. */
    fun sign(privateKey: ByteArray, message: ByteArray): ByteArray

    /** Verify a detached Ed25519 [signature]. Returns false on any failure. */
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean

    // --- Ed25519 <-> X25519 conversion ---
    // X3DH needs the identity key both for signing (Ed25519) and for DH (X25519).
    // libsodium lets us convert the same key between the two representations.

    /** Convert an Ed25519 public key to its X25519 equivalent. */
    fun signingPublicKeyToDh(edPublicKey: ByteArray): ByteArray

    /** Convert an Ed25519 secret key to its X25519 equivalent. */
    fun signingPrivateKeyToDh(edPrivateKey: ByteArray): ByteArray

    // --- KDF & AEAD ---

    /** HMAC-SHA256. [key] must be exactly 32 bytes. Used for the Double Ratchet chain-key KDF. */
    fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray

    /** BLAKE2b hash of [data] producing [size] bytes (16..64). Used for safety-number fingerprints. */
    fun hash(data: ByteArray, size: Int = HASH_SIZE): ByteArray

    /** HKDF-SHA256. [salt] must be exactly 32 bytes (use 32 zero bytes when unsalted). */
    fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray

    /** XChaCha20-Poly1305-IETF encryption. Returns ciphertext with the 16-byte tag appended. */
    fun aeadEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, associatedData: ByteArray): ByteArray

    /** XChaCha20-Poly1305-IETF decryption. Returns null if authentication fails. */
    fun aeadDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, associatedData: ByteArray): ByteArray?

    companion object {
        const val DH_PUBLIC_KEY_SIZE = 32
        const val DH_PRIVATE_KEY_SIZE = 32
        const val AEAD_KEY_SIZE = 32
        const val AEAD_NONCE_SIZE = 24
        const val AEAD_TAG_SIZE = 16
        const val SIGNATURE_SIZE = 64
        const val HASH_SIZE = 32
    }
}
