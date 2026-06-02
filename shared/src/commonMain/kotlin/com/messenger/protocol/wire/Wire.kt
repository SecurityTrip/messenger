package com.messenger.protocol.wire

import com.messenger.crypto.fromBase64
import com.messenger.crypto.toBase64
import com.messenger.protocol.ratchet.DoubleRatchetHeader
import com.messenger.protocol.ratchet.RatchetMessage
import com.messenger.protocol.x3dh.PreKeyBundle
import com.messenger.protocol.x3dh.X3dhInitialMessage
import kotlinx.serialization.Serializable

/**
 * Transport DTOs exchanged with the relay server. Everything here is either ciphertext or public
 * key material — the server never sees plaintext. Byte fields are Base64-encoded for JSON.
 */

@Serializable
data class WirePreKeyBundle(
    val identityKey: String,
    val signedPreKeyId: Int,
    val signedPreKey: String,
    val signedPreKeySignature: String,
    val oneTimePreKeyId: Int? = null,
    val oneTimePreKey: String? = null,
)

@Serializable
data class WireX3dhInitial(
    val identityKey: String,
    val ephemeralKey: String,
    val signedPreKeyId: Int,
    val oneTimePreKeyId: Int? = null,
)

@Serializable
data class WireRatchetHeader(
    val ratchetPublicKey: String,
    val previousChainLength: Int,
    val messageNumber: Int,
)

/**
 * One end-to-end encrypted message on the wire. [x3dhInitial] is present only on the first message
 * of a new session (it carries the X3DH preamble the recipient needs to set up their ratchet).
 */
@Serializable
data class WireMessage(
    val header: WireRatchetHeader,
    val ciphertext: String,
    val x3dhInitial: WireX3dhInitial? = null,
)

// --- mappers: protocol types <-> wire types ---

fun PreKeyBundle.toWire() = WirePreKeyBundle(
    identityKey = identityKey.toBase64(),
    signedPreKeyId = signedPreKeyId,
    signedPreKey = signedPreKey.toBase64(),
    signedPreKeySignature = signedPreKeySignature.toBase64(),
    oneTimePreKeyId = oneTimePreKeyId,
    oneTimePreKey = oneTimePreKey?.toBase64(),
)

fun WirePreKeyBundle.toModel() = PreKeyBundle(
    identityKey = identityKey.fromBase64(),
    signedPreKeyId = signedPreKeyId,
    signedPreKey = signedPreKey.fromBase64(),
    signedPreKeySignature = signedPreKeySignature.fromBase64(),
    oneTimePreKeyId = oneTimePreKeyId,
    oneTimePreKey = oneTimePreKey?.fromBase64(),
)

fun X3dhInitialMessage.toWire() = WireX3dhInitial(
    identityKey = identityKey.toBase64(),
    ephemeralKey = ephemeralKey.toBase64(),
    signedPreKeyId = signedPreKeyId,
    oneTimePreKeyId = oneTimePreKeyId,
)

fun WireX3dhInitial.toModel() = X3dhInitialMessage(
    identityKey = identityKey.fromBase64(),
    ephemeralKey = ephemeralKey.fromBase64(),
    signedPreKeyId = signedPreKeyId,
    oneTimePreKeyId = oneTimePreKeyId,
)

fun RatchetMessage.toWire(x3dhInitial: WireX3dhInitial? = null) = WireMessage(
    header = WireRatchetHeader(
        ratchetPublicKey = header.ratchetPublicKey.toBase64(),
        previousChainLength = header.previousChainLength,
        messageNumber = header.messageNumber,
    ),
    ciphertext = ciphertext.toBase64(),
    x3dhInitial = x3dhInitial,
)

fun WireMessage.toRatchetMessage() = RatchetMessage(
    header = DoubleRatchetHeader(
        ratchetPublicKey = header.ratchetPublicKey.fromBase64(),
        previousChainLength = header.previousChainLength,
        messageNumber = header.messageNumber,
    ),
    ciphertext = ciphertext.fromBase64(),
)
