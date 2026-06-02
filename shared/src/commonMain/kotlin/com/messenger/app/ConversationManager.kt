package com.messenger.app

import com.messenger.crypto.CryptoProvider
import com.messenger.crypto.SigningKeyPair
import com.messenger.crypto.fromBase64
import com.messenger.crypto.toBase64
import com.messenger.data.ContactStore
import com.messenger.data.IdentityStore
import com.messenger.data.MessageStore
import com.messenger.data.SessionStore
import com.messenger.domain.ChatMessage
import com.messenger.domain.Contact
import com.messenger.domain.MessageDirection
import com.messenger.domain.MessageStatus
import com.messenger.protocol.ratchet.DoubleRatchet
import com.messenger.protocol.wire.DeviceBundles
import com.messenger.protocol.wire.ReceiptKind
import com.messenger.protocol.wire.RegisterRequest
import com.messenger.protocol.wire.RelayEnvelope
import com.messenger.protocol.wire.RelayPayload
import com.messenger.protocol.wire.UploadKeysRequest
import com.messenger.protocol.wire.WireX3dhInitial
import com.messenger.protocol.wire.toModel
import com.messenger.protocol.wire.toRatchetMessage
import com.messenger.protocol.wire.toWire
import com.messenger.protocol.x3dh.X3dh
import kotlinx.datetime.Clock

/**
 * Application-level orchestrator tying the crypto protocols to local storage for one device
 * (userId, deviceId). It produces [RelayEnvelope]s for the network layer to send, and consumes
 * envelopes the network layer delivers.
 *
 * Multi-device: outgoing messages fan out — one envelope per recipient device, all sharing the same
 * [RelayEnvelope.messageId] (which equals the local outgoing [ChatMessage.id]) so receipts map back.
 */
class ConversationManager(
    private val crypto: CryptoProvider,
    private val identities: IdentityStore,
    private val sessions: SessionStore,
    private val messages: MessageStore,
    private val contacts: ContactStore,
    private val clock: () -> Long = { Clock.System.now().toEpochMilliseconds() },
) {
    private val x3dh = X3dh(crypto)

    /** Result of [receive]. */
    sealed interface ReceiveResult {
        /** A chat message was decrypted and stored; [deliveryReceipt] should be relayed to the sender. */
        data class MessageReceived(val message: ChatMessage, val deliveryReceipt: RelayEnvelope) : ReceiveResult

        /** A delivery/read receipt updated a previously-sent message's status. */
        data class ReceiptReceived(val referencesMessageId: String, val kind: ReceiptKind) : ReceiveResult
    }

    // --- provisioning ---

    fun ensureProvisioned(userId: String, deviceId: String, oneTimePreKeyCount: Int = 100): SigningKeyPair {
        identities.loadIdentity()?.let { return it }

        val identity = x3dh.generateIdentityKey()
        identities.saveAccount(userId, deviceId, identity, registrationId = randomRegistrationId(), now = clock())
        identities.saveSignedPreKey(x3dh.generateSignedPreKey(identity, id = SIGNED_PREKEY_ID), now = clock())
        identities.saveOneTimePreKeys(x3dh.generateOneTimePreKeys(startId = 1, count = oneTimePreKeyCount))
        return identity
    }

    fun registration(): RegisterRequest {
        val identity = identities.loadIdentity() ?: error("Account not provisioned")
        return RegisterRequest(myUser(), myDevice(), identity.publicKey.toBase64(), registrationId())
    }

    fun keysForUpload(): UploadKeysRequest {
        val signedPreKey = identities.loadLatestSignedPreKey() ?: error("No signed prekey")
        return UploadKeysRequest(
            signedPreKeyId = signedPreKey.id,
            signedPreKey = signedPreKey.keyPair.publicKey.toBase64(),
            signedPreKeySignature = signedPreKey.signature.toBase64(),
            oneTimePreKeys = identities.allUnusedOneTimePreKeyPublics(),
        )
    }

    fun rotateSignedPreKey(): Int {
        val identity = identities.loadIdentity() ?: error("Account not provisioned")
        val newId = identities.maxSignedPreKeyId() + 1
        identities.saveSignedPreKey(x3dh.generateSignedPreKey(identity, newId), now = clock())
        return newId
    }

    fun replenishOneTimePreKeysIfNeeded(threshold: Int = 10, target: Int = 100): Int {
        val unused = identities.unusedOneTimePreKeyCount()
        if (unused >= threshold) return 0
        val toGenerate = target - unused
        identities.saveOneTimePreKeys(x3dh.generateOneTimePreKeys(identities.maxOneTimePreKeyId() + 1, toGenerate))
        return toGenerate
    }

    // --- sending (fan-out across the recipient's devices) ---

    /** Open sessions with every device in [bundles] and produce the first encrypted envelopes. */
    fun startConversation(contactUserId: String, bundles: DeviceBundles, text: String): List<RelayEnvelope> {
        val identity = identities.loadIdentity() ?: error("Account not provisioned")
        val messageId = newMessageId()
        val envelopes = ArrayList<RelayEnvelope>()

        for (device in bundles.devices) {
            if (isSelf(contactUserId, device.deviceId)) continue
            val model = device.bundle.toModel()
            val initiation = x3dh.initiate(identity, model)
            val ratchet = DoubleRatchet.initAlice(
                crypto = crypto,
                sharedSecret = initiation.result.sharedSecret,
                remoteSignedPreKey = model.signedPreKey,
                associatedData = initiation.result.associatedData,
            )
            val ratchetMessage = ratchet.encrypt(text.encodeToByteArray())
            sessions.save(contactUserId, device.deviceId, ratchet, clock())
            envelopes += envelope(
                messageId = messageId,
                toUser = contactUserId,
                toDevice = device.deviceId,
                payload = RelayPayload.Ciphertext(ratchetMessage.toWire(initiation.header.toWire())),
            )
        }

        if (contacts.get(contactUserId) == null) {
            val anyIdentity = bundles.devices.firstOrNull()?.bundle?.identityKey?.fromBase64() ?: ByteArray(0)
            contacts.upsert(Contact(contactUserId, anyIdentity, displayName = null, verified = false))
        }
        persistOutgoing(messageId, contactUserId, text)
        return envelopes
    }

    /** Send a follow-up message on existing sessions (fans out to all known devices). */
    fun send(contactUserId: String, text: String): List<RelayEnvelope> {
        val deviceSessions = sessions.loadAllForContact(contactUserId)
        require(deviceSessions.isNotEmpty()) { "No sessions with $contactUserId" }

        val messageId = newMessageId()
        val envelopes = deviceSessions.map { (deviceId, ratchet) ->
            val ratchetMessage = ratchet.encrypt(text.encodeToByteArray())
            sessions.save(contactUserId, deviceId, ratchet, clock())
            envelope(messageId, contactUserId, deviceId, RelayPayload.Ciphertext(ratchetMessage.toWire()))
        }
        persistOutgoing(messageId, contactUserId, text)
        return envelopes
    }

    // --- receiving ---

    fun receive(envelope: RelayEnvelope): ReceiveResult = when (val payload = envelope.payload) {
        is RelayPayload.Ciphertext -> receiveCiphertext(envelope, payload)
        is RelayPayload.Receipt -> receiveReceipt(payload)
    }

    private fun receiveCiphertext(envelope: RelayEnvelope, payload: RelayPayload.Ciphertext): ReceiveResult {
        val fromUser = envelope.fromUser
        val fromDevice = envelope.fromDevice
        val wire = payload.message

        val ratchet = if (wire.x3dhInitial != null && !sessions.exists(fromUser, fromDevice)) {
            establishIncomingSession(fromUser, fromDevice, wire.x3dhInitial!!)
        } else {
            sessions.load(fromUser, fromDevice) ?: error("No session with $fromUser:$fromDevice")
        }

        val plaintext = ratchet.decrypt(wire.toRatchetMessage()).decodeToString()
        sessions.save(fromUser, fromDevice, ratchet, clock())

        val message = persistIncoming(fromUser, fromDevice, envelope.messageId, plaintext)
        val deliveryReceipt = receiptEnvelope(fromUser, fromDevice, envelope.messageId, ReceiptKind.DELIVERED)
        return ReceiveResult.MessageReceived(message, deliveryReceipt)
    }

    private fun receiveReceipt(payload: RelayPayload.Receipt): ReceiveResult {
        val target = messages.messageById(payload.referencesMessageId)
        if (target != null) {
            val newStatus = if (payload.kind == ReceiptKind.READ) MessageStatus.READ else MessageStatus.DELIVERED
            if (newStatus.ordinal > target.status.ordinal) messages.updateStatus(target.id, newStatus)
        }
        return ReceiveResult.ReceiptReceived(payload.referencesMessageId, payload.kind)
    }

    /** Build a READ receipt for an incoming message the user has now read (or null if not applicable). */
    fun markRead(messageId: String): RelayEnvelope? {
        val message = messages.messageById(messageId) ?: return null
        if (message.direction != MessageDirection.INCOMING) return null
        val device = message.peerDeviceId ?: return null
        val senderMessageId = message.senderMessageId ?: return null
        return receiptEnvelope(message.contactId, device, senderMessageId, ReceiptKind.READ)
    }

    private fun establishIncomingSession(fromUser: String, fromDevice: String, initialWire: WireX3dhInitial): DoubleRatchet {
        val identity = identities.loadIdentity() ?: error("Account not provisioned")
        val initial = initialWire.toModel()
        val signedPreKey = identities.loadSignedPreKey(initial.signedPreKeyId)
            ?: error("Unknown signed prekey ${initial.signedPreKeyId}")
        val oneTimePreKey = initial.oneTimePreKeyId?.let { identities.loadOneTimePreKey(it) }

        val result = x3dh.respond(identity, signedPreKey, oneTimePreKey, initial)
        initial.oneTimePreKeyId?.let { identities.markOneTimePreKeyUsed(it) }

        if (contacts.get(fromUser) == null) {
            contacts.upsert(Contact(fromUser, initial.identityKey, displayName = null, verified = false))
        }
        return DoubleRatchet.initBob(crypto, result.sharedSecret, signedPreKey.keyPair, result.associatedData)
    }

    // --- helpers ---

    private fun persistOutgoing(messageId: String, contactId: String, text: String): ChatMessage {
        val message = ChatMessage(messageId, contactId, MessageDirection.OUTGOING, text, clock(), MessageStatus.SENT)
        messages.insert(message)
        return message
    }

    private fun persistIncoming(contactId: String, peerDeviceId: String, senderMessageId: String, text: String): ChatMessage {
        val message = ChatMessage(
            id = newMessageId(),
            contactId = contactId,
            direction = MessageDirection.INCOMING,
            body = text,
            timestamp = clock(),
            status = MessageStatus.DELIVERED,
            peerDeviceId = peerDeviceId,
            senderMessageId = senderMessageId,
        )
        messages.insert(message)
        return message
    }

    private fun receiptEnvelope(toUser: String, toDevice: String, referencesMessageId: String, kind: ReceiptKind) =
        envelope(newMessageId(), toUser, toDevice, RelayPayload.Receipt(referencesMessageId, kind))

    private fun envelope(messageId: String, toUser: String, toDevice: String, payload: RelayPayload) =
        RelayEnvelope(messageId, toUser, toDevice, myUser(), myDevice(), payload)

    private fun isSelf(user: String, device: String) = user == myUser() && device == myDevice()

    private fun myUser(): String = identities.accountUserId() ?: error("Account not provisioned")
    private fun myDevice(): String = identities.accountDeviceId() ?: error("Account not provisioned")
    private fun registrationId(): Int = identities.registrationId() ?: error("Account not provisioned")

    private fun newMessageId(): String = crypto.randomBytes(16).toBase64()

    private fun randomRegistrationId(): Int {
        val b = crypto.randomBytes(4)
        return ((b[0].toInt() and 0x7F) shl 24) or
            ((b[1].toInt() and 0xFF) shl 16) or
            ((b[2].toInt() and 0xFF) shl 8) or
            (b[3].toInt() and 0xFF)
    }

    companion object {
        private const val SIGNED_PREKEY_ID = 1
    }
}
