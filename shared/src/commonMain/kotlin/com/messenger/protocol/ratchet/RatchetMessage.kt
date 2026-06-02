package com.messenger.protocol.ratchet

/**
 * Per-message Double Ratchet header sent in the clear alongside the ciphertext. It is also bound
 * into the AEAD as associated data, so any tampering is detected on decryption.
 */
class DoubleRatchetHeader(
    /** The sender's current ratchet public key (X25519). */
    val ratchetPublicKey: ByteArray,
    /** Number of messages in the sender's previous sending chain (PN). */
    val previousChainLength: Int,
    /** This message's index within the current sending chain (N). */
    val messageNumber: Int,
) {
    /** Canonical byte encoding: ratchetPublicKey(32) || PN(4, big-endian) || N(4, big-endian). */
    fun encode(): ByteArray = ratchetPublicKey + previousChainLength.toBytesBE() + messageNumber.toBytesBE()
}

/** A Double Ratchet message: the cleartext [header] plus the AEAD [ciphertext] (incl. 16-byte tag). */
class RatchetMessage(
    val header: DoubleRatchetHeader,
    val ciphertext: ByteArray,
)

internal fun Int.toBytesBE(): ByteArray = byteArrayOf(
    (this ushr 24).toByte(),
    (this ushr 16).toByte(),
    (this ushr 8).toByte(),
    this.toByte(),
)

/** Thrown on any Double Ratchet failure (auth failure, too many skipped messages, illegal state). */
class DoubleRatchetException(message: String) : Exception(message)
