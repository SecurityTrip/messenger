package com.messenger.app

import com.messenger.crypto.CryptoProvider
import com.messenger.crypto.SigningKeyPair
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
import com.messenger.protocol.wire.RegisterRequest
import com.messenger.protocol.wire.UploadKeysRequest
import com.messenger.protocol.wire.WireMessage
import com.messenger.protocol.wire.WirePreKeyBundle
import com.messenger.protocol.wire.WireX3dhInitial
import com.messenger.protocol.wire.toModel
import com.messenger.protocol.wire.toRatchetMessage
import com.messenger.protocol.wire.toWire
import com.messenger.protocol.x3dh.X3dh
import kotlinx.datetime.Clock

/**
 * Application-level orchestrator that ties the crypto protocols to local storage. It is the single
 * entry point the UI / networking layer uses to provision the account, publish prekeys, and send /
 * receive end-to-end encrypted messages. Sessions are loaded and saved per call, so the manager is
 * stateless across restarts — all durable state lives in the (encrypted) database.
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

    /** First-run provisioning. Idempotent: returns the existing identity if already provisioned. */
    fun ensureProvisioned(userId: String, oneTimePreKeyCount: Int = 100): SigningKeyPair {
        identities.loadIdentity()?.let { return it }

        val identity = x3dh.generateIdentityKey()
        identities.saveAccount(userId, identity, registrationId = randomRegistrationId(), now = clock())
        identities.saveSignedPreKey(x3dh.generateSignedPreKey(identity, id = SIGNED_PREKEY_ID), now = clock())
        identities.saveOneTimePreKeys(x3dh.generateOneTimePreKeys(startId = 1, count = oneTimePreKeyCount))
        return identity
    }

    /** Build a prekey bundle to upload to the server (advertises one unused one-time prekey). */
    fun publishBundle(): WirePreKeyBundle {
        val identity = identities.loadIdentity() ?: error("Account not provisioned")
        val signedPreKey = identities.loadLatestSignedPreKey() ?: error("No signed prekey")
        val oneTimePreKey = identities.nextUnusedOneTimePreKey()
        return x3dh.createBundle(identity, signedPreKey, oneTimePreKey).toWire()
    }

    /**
     * Rotate the signed prekey (do periodically, e.g. weekly). The new key becomes the one advertised
     * by [publishBundle] / [keysForUpload]; older signed prekeys are kept so in-flight initial messages
     * that referenced them can still be answered. Returns the new prekey's id.
     */
    fun rotateSignedPreKey(): Int {
        val identity = identities.loadIdentity() ?: error("Account not provisioned")
        val newId = identities.maxSignedPreKeyId() + 1
        identities.saveSignedPreKey(x3dh.generateSignedPreKey(identity, newId), now = clock())
        return newId
    }

    /**
     * Top up the one-time prekey pool when it runs low. Returns how many were generated (0 if the
     * pool was already above [threshold]). After calling this, re-upload via [keysForUpload].
     */
    fun replenishOneTimePreKeysIfNeeded(threshold: Int = 10, target: Int = 100): Int {
        val unused = identities.unusedOneTimePreKeyCount()
        if (unused >= threshold) return 0
        val toGenerate = target - unused
        val startId = identities.maxOneTimePreKeyId() + 1
        identities.saveOneTimePreKeys(x3dh.generateOneTimePreKeys(startId, toGenerate))
        return toGenerate
    }

    /** Account registration payload to send to the server's /register endpoint. */
    fun registration(): RegisterRequest {
        val identity = identities.loadIdentity() ?: error("Account not provisioned")
        val userId = identities.accountUserId() ?: error("Account not provisioned")
        val registrationId = identities.registrationId() ?: error("Account not provisioned")
        return RegisterRequest(userId, identity.publicKey.toBase64(), registrationId)
    }

    /** Signed prekey + the full one-time prekey pool to upload to the server's key store. */
    fun keysForUpload(): UploadKeysRequest {
        val signedPreKey = identities.loadLatestSignedPreKey() ?: error("No signed prekey")
        return UploadKeysRequest(
            signedPreKeyId = signedPreKey.id,
            signedPreKey = signedPreKey.keyPair.publicKey.toBase64(),
            signedPreKeySignature = signedPreKey.signature.toBase64(),
            oneTimePreKeys = identities.allUnusedOneTimePreKeyPublics(),
        )
    }

    /** Initiator side: open a session with [contactId] using their [bundle] and send [text]. */
    fun startConversation(contactId: String, bundle: WirePreKeyBundle, text: String): WireMessage {
        val identity = identities.loadIdentity() ?: error("Account not provisioned")
        val model = bundle.toModel()
        contacts.upsert(Contact(contactId, model.identityKey, displayName = null, verified = false))

        val initiation = x3dh.initiate(identity, model)
        val ratchet = DoubleRatchet.initAlice(
            crypto = crypto,
            sharedSecret = initiation.result.sharedSecret,
            remoteSignedPreKey = model.signedPreKey,
            associatedData = initiation.result.associatedData,
        )
        val ratchetMessage = ratchet.encrypt(text.encodeToByteArray())
        sessions.save(contactId, ratchet, clock())
        persist(contactId, text, MessageDirection.OUTGOING, MessageStatus.SENT)
        return ratchetMessage.toWire(initiation.header.toWire())
    }

    /** Send a follow-up message on an existing session. */
    fun send(contactId: String, text: String): WireMessage {
        val ratchet = sessions.load(contactId) ?: error("No session with $contactId")
        val ratchetMessage = ratchet.encrypt(text.encodeToByteArray())
        sessions.save(contactId, ratchet, clock())
        persist(contactId, text, MessageDirection.OUTGOING, MessageStatus.SENT)
        return ratchetMessage.toWire()
    }

    /**
     * Receive a wire message from [fromUserId]. If it carries an X3DH preamble and no session
     * exists yet, the session is established first. Returns the decrypted, persisted message.
     */
    fun receive(fromUserId: String, wire: WireMessage): ChatMessage {
        val ratchet = if (wire.x3dhInitial != null && !sessions.exists(fromUserId)) {
            establishIncomingSession(fromUserId, wire.x3dhInitial)
        } else {
            sessions.load(fromUserId) ?: error("No session with $fromUserId")
        }
        val plaintext = ratchet.decrypt(wire.toRatchetMessage()).decodeToString()
        sessions.save(fromUserId, ratchet, clock())
        return persist(fromUserId, plaintext, MessageDirection.INCOMING, MessageStatus.DELIVERED)
    }

    private fun establishIncomingSession(fromUserId: String, initialWire: WireX3dhInitial): DoubleRatchet {
        val identity = identities.loadIdentity() ?: error("Account not provisioned")
        val initial = initialWire.toModel()
        val signedPreKey = identities.loadSignedPreKey(initial.signedPreKeyId)
            ?: error("Unknown signed prekey ${initial.signedPreKeyId}")
        val oneTimePreKey = initial.oneTimePreKeyId?.let { identities.loadOneTimePreKey(it) }

        val result = x3dh.respond(identity, signedPreKey, oneTimePreKey, initial)
        initial.oneTimePreKeyId?.let { identities.markOneTimePreKeyUsed(it) }

        if (contacts.get(fromUserId) == null) {
            contacts.upsert(Contact(fromUserId, initial.identityKey, displayName = null, verified = false))
        }
        return DoubleRatchet.initBob(crypto, result.sharedSecret, signedPreKey.keyPair, result.associatedData)
    }

    private fun persist(
        contactId: String,
        text: String,
        direction: MessageDirection,
        status: MessageStatus,
    ): ChatMessage {
        val message = ChatMessage(newMessageId(), contactId, direction, text, clock(), status)
        messages.insert(message)
        return message
    }

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
