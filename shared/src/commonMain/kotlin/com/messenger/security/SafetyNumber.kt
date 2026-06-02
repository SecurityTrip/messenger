package com.messenger.security

import com.messenger.crypto.CryptoProvider

/**
 * Computes a human-comparable **safety number** from two identities, so users can verify out-of-band
 * (read it aloud / scan) that no man-in-the-middle swapped keys. Same inputs → same 60-digit number
 * on both devices, independent of who is "local".
 *
 * Modeled on Signal's numeric fingerprint: each identity is hashed with many iterations (slows brute
 * force over the short displayed form), the two fingerprints are ordered deterministically and each
 * contributes 30 digits.
 */
object SafetyNumber {

    private const val ITERATIONS = 5200
    private const val FINGERPRINT_BYTES = 64
    private const val GROUPS_PER_PARTY = 6
    private const val GROUP_BYTES = 5
    private val VERSION_PREFIX = byteArrayOf(0x00, 0x00)

    /**
     * @param localUserId / [localIdentityKey] this device's stable id and Ed25519 identity key
     * @param remoteUserId / [remoteIdentityKey] the peer's stable id and Ed25519 identity key
     * @return a 60-digit string, grouped for display by the caller if desired
     */
    fun compute(
        crypto: CryptoProvider,
        localUserId: String,
        localIdentityKey: ByteArray,
        remoteUserId: String,
        remoteIdentityKey: ByteArray,
    ): String {
        val local = fingerprint(crypto, localUserId, localIdentityKey)
        val remote = fingerprint(crypto, remoteUserId, remoteIdentityKey)
        // Order deterministically so both parties produce identical output.
        val (first, second) = if (compareUnsigned(local, remote) <= 0) local to remote else remote to local
        return encode(first) + encode(second)
    }

    /** Convenience for display: groups of 5 digits separated by spaces. */
    fun formatForDisplay(safetyNumber: String): String =
        safetyNumber.chunked(5).joinToString(" ")

    private fun fingerprint(crypto: CryptoProvider, stableId: String, identityKey: ByteArray): ByteArray {
        val seed = VERSION_PREFIX + identityKey + stableId.encodeToByteArray()
        var hash = crypto.hash(seed, FINGERPRINT_BYTES)
        repeat(ITERATIONS) {
            hash = crypto.hash(hash + identityKey, FINGERPRINT_BYTES)
        }
        return hash
    }

    private fun encode(fingerprint: ByteArray): String {
        val sb = StringBuilder()
        for (group in 0 until GROUPS_PER_PARTY) {
            val offset = group * GROUP_BYTES
            var value = 0L
            for (i in 0 until GROUP_BYTES) {
                value = (value shl 8) or (fingerprint[offset + i].toLong() and 0xFF)
            }
            sb.append((value % 100000).toString().padStart(5, '0'))
        }
        return sb.toString()
    }

    private fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
        val n = minOf(a.size, b.size)
        for (i in 0 until n) {
            val diff = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (diff != 0) return diff
        }
        return a.size - b.size
    }
}
