package com.messenger.crypto

/**
 * A Curve25519 (X25519) key pair used for Diffie-Hellman agreement.
 * Used for ephemeral keys, signed/one-time prekeys and the Double Ratchet ratchet keys.
 */
class DhKeyPair(val publicKey: ByteArray, val privateKey: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DhKeyPair) return false
        return publicKey.contentEquals(other.publicKey) && privateKey.contentEquals(other.privateKey)
    }

    override fun hashCode(): Int = 31 * publicKey.contentHashCode() + privateKey.contentHashCode()

    // Private key intentionally never rendered, to avoid leaking secrets into logs.
    override fun toString(): String = "DhKeyPair(publicKey=${publicKey.toHex()}, privateKey=***)"
}

/**
 * An Ed25519 key pair used for signatures (the long-term identity key).
 * The private key is the 64-byte libsodium secret key (seed + public key).
 */
class SigningKeyPair(val publicKey: ByteArray, val privateKey: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SigningKeyPair) return false
        return publicKey.contentEquals(other.publicKey) && privateKey.contentEquals(other.privateKey)
    }

    override fun hashCode(): Int = 31 * publicKey.contentHashCode() + privateKey.contentHashCode()

    override fun toString(): String = "SigningKeyPair(publicKey=${publicKey.toHex()}, privateKey=***)"
}
