package com.messenger.crypto

/** Lowercase hex encoding. Handy for debugging and test vectors. */
internal fun ByteArray.toHex(): String =
    joinToString(separator = "") { byte ->
        val v = byte.toInt() and 0xFF
        val hi = "0123456789abcdef"[v ushr 4]
        val lo = "0123456789abcdef"[v and 0x0F]
        "$hi$lo"
    }

internal fun String.hexToByteArray(): ByteArray {
    require(length % 2 == 0) { "Hex string must have even length" }
    return ByteArray(length / 2) { i ->
        val hi = this[i * 2].digitToInt(16)
        val lo = this[i * 2 + 1].digitToInt(16)
        ((hi shl 4) or lo).toByte()
    }
}
