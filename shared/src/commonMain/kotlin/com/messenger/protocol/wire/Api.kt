package com.messenger.protocol.wire

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Client <-> relay-server API contracts. Shared so both ends agree on the JSON shape. The server
 * only ever sees public key material and ciphertext.
 *
 * Multi-device: every endpoint is addressed by (userId, deviceId). A user has many devices, each
 * with its own identity key, prekeys and E2E sessions; a sender fans a message out to every device.
 */

@Serializable
data class WireOneTimePreKey(
    val id: Int,
    val publicKey: String,
)

/** Register a device under an account and publish its long-term identity key. */
@Serializable
data class RegisterRequest(
    val userId: String,
    val deviceId: String,
    val identityKey: String,
    val registrationId: Int,
)

/** Issued on registration; the client presents this bearer token for key upload and the relay. */
@Serializable
data class RegisterResponse(
    val token: String,
)

/** Upload the signed prekey (+signature) and a batch of one-time prekeys for one device. */
@Serializable
data class UploadKeysRequest(
    val signedPreKeyId: Int,
    val signedPreKey: String,
    val signedPreKeySignature: String,
    val oneTimePreKeys: List<WireOneTimePreKey> = emptyList(),
)

/** A prekey bundle for one specific device. */
@Serializable
data class DeviceBundle(
    val deviceId: String,
    val bundle: WirePreKeyBundle,
)

/** All currently-published device bundles for a user, returned when starting conversations. */
@Serializable
data class DeviceBundles(
    val userId: String,
    val devices: List<DeviceBundle>,
)

@Serializable
enum class ReceiptKind { DELIVERED, READ }

/** The payload of a relayed envelope: either E2E ciphertext or a delivery/read receipt. */
@Serializable
sealed interface RelayPayload {
    @Serializable
    @SerialName("ciphertext")
    data class Ciphertext(val message: WireMessage) : RelayPayload

    @Serializable
    @SerialName("receipt")
    data class Receipt(val referencesMessageId: String, val kind: ReceiptKind) : RelayPayload
}

/**
 * A message handed to the server for relay. [messageId] is the sender-generated id used both for
 * delivery acknowledgement (the recipient acks this id) and as the stable id receipts reference.
 */
@Serializable
data class RelayEnvelope(
    val messageId: String,
    val toUser: String,
    val toDevice: String,
    val fromUser: String,
    val fromDevice: String,
    val payload: RelayPayload,
)

/** Frames the client sends to the server over the WebSocket. */
@Serializable
sealed interface ClientFrame {
    @Serializable
    @SerialName("send")
    data class Send(val envelope: RelayEnvelope) : ClientFrame

    /** Acknowledge receipt so the server removes the message from this device's mailbox. */
    @Serializable
    @SerialName("ack")
    data class Ack(val messageId: String) : ClientFrame
}

/** Frames the server pushes to a connected client over the WebSocket. */
@Serializable
sealed interface ServerFrame {
    @Serializable
    @SerialName("deliver")
    data class Deliver(val envelope: RelayEnvelope) : ServerFrame

    /** Sent back to the originator: the server accepted the message (delivered live or queued). */
    @Serializable
    @SerialName("accepted")
    data class Accepted(val messageId: String, val queued: Boolean) : ServerFrame
}
