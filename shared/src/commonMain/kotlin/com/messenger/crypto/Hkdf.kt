package com.messenger.crypto

/**
 * HKDF (RFC 5869) over a supplied HMAC-SHA256 function.
 *
 * libsodium's simple `crypto_auth_hmacsha256` fixes the key size to 32 bytes, which is
 * exactly what all our call sites use (root keys, zero salt, 32-byte PRK), so we require
 * a 32-byte salt rather than implementing the variable-length-key HMAC path.
 */
internal object Hkdf {

    private const val HASH_LEN = 32

    fun derive(
        hmac: (key: ByteArray, message: ByteArray) -> ByteArray,
        ikm: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        length: Int,
    ): ByteArray {
        require(salt.size == HASH_LEN) { "HKDF salt must be $HASH_LEN bytes (got ${salt.size})" }
        require(length in 1..(255 * HASH_LEN)) { "HKDF length must be in 1..${255 * HASH_LEN} (got $length)" }

        // Extract: PRK = HMAC(salt, IKM)
        val prk = hmac(salt, ikm)

        // Expand: T(i) = HMAC(PRK, T(i-1) || info || i)
        val okm = ByteArray(length)
        var previousBlock = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            val block = hmac(prk, previousBlock + info + byteArrayOf(counter.toByte()))
            val toCopy = minOf(block.size, length - offset)
            block.copyInto(okm, offset, 0, toCopy)
            offset += toCopy
            previousBlock = block
            counter++
        }
        return okm
    }
}
