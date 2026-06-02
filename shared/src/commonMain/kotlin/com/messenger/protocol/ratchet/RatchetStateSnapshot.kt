package com.messenger.protocol.ratchet

import kotlinx.serialization.Serializable

/**
 * Serializable snapshot of a [DoubleRatchet] session, so a conversation can survive app restarts.
 * Byte material is Base64-encoded for compact JSON. **Contains private keys** — persist only
 * encrypted at rest (see the storage layer / Keychain master key).
 */
@Serializable
data class RatchetStateSnapshot(
    val selfRatchetPublic: String,
    val selfRatchetPrivate: String,
    val remoteRatchet: String?,
    val rootKey: String,
    val sendChainKey: String?,
    val recvChainKey: String?,
    val sendCount: Int,
    val recvCount: Int,
    val previousSendCount: Int,
    val skipped: List<SkippedKeySnapshot>,
    val associatedData: String,
)

@Serializable
data class SkippedKeySnapshot(
    val ratchetPublicKey: String,
    val messageNumber: Int,
    val messageKey: String,
)
