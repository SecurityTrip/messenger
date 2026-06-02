package com.messenger.protocol.wire

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Client <-> relay-server API contracts. Shared so both ends agree on the JSON shape. The server
 * only ever sees public key material and ciphertext.
 */

@Serializable
data class WireOneTimePreKey(
    val id: Int,
    val publicKey: String,
)

/** Register an account and publish its long-term identity key. */
@Serializable
data class RegisterRequest(
    val userId: String,
    val identityKey: String,
    val registrationId: Int,
)

/** Issued on registration; the client presents this bearer token for key upload and the relay. */
@Serializable
data class RegisterResponse(
    val token: String,
)

/** Upload the signed prekey (+signature) and a batch of one-time prekeys to the server pool. */
@Serializable
data class UploadKeysRequest(
    val signedPreKeyId: Int,
    val signedPreKey: String,
    val signedPreKeySignature: String,
    val oneTimePreKeys: List<WireOneTimePreKey> = emptyList(),
)

/** A message handed to the server for relay: who it is [to]/[from] plus the encrypted payload. */
@Serializable
data class RelayEnvelope(
    val to: String,
    val from: String,
    val message: WireMessage,
)

/** Server -> sender acknowledgement that a relayed envelope was delivered or queued. */
@Serializable
data class RelayAck(
    val status: String = "accepted",
    val queued: Boolean = false,
)

/**
 * Frames the server pushes to a connected client over the WebSocket. A tagged union (JSON "type"
 * discriminator) so the client can tell a delivered message from an acknowledgement.
 */
@Serializable
sealed interface ServerFrame {
    @Serializable
    @SerialName("deliver")
    data class Deliver(val envelope: RelayEnvelope) : ServerFrame

    @Serializable
    @SerialName("ack")
    data class Ack(val ack: RelayAck) : ServerFrame
}
