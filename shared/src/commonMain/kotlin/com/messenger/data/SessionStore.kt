package com.messenger.data

import com.messenger.crypto.CryptoProvider
import com.messenger.db.MessengerDatabase
import com.messenger.protocol.ratchet.DoubleRatchet
import com.messenger.protocol.ratchet.RatchetStateSnapshot
import com.messenger.security.BlobCipher
import kotlinx.serialization.json.Json

/**
 * Persists one Double Ratchet session per peer **device** (contactId = peer user, deviceId = peer
 * device). The session snapshot (which contains private keys) is JSON-serialized then encrypted at
 * rest via [cipher].
 */
class SessionStore(
    private val db: MessengerDatabase,
    private val cipher: BlobCipher,
    private val crypto: CryptoProvider,
    private val json: Json = Json,
) {
    fun save(contactId: String, deviceId: String, ratchet: DoubleRatchet, now: Long) {
        val plaintext = json
            .encodeToString(RatchetStateSnapshot.serializer(), ratchet.export())
            .encodeToByteArray()
        db.sessionQueries.upsertSession(contactId, deviceId, cipher.encrypt(plaintext), now)
    }

    fun load(contactId: String, deviceId: String): DoubleRatchet? {
        val blob = db.sessionQueries.selectSession(contactId, deviceId).executeAsOneOrNull() ?: return null
        return restore(blob)
    }

    /** All device sessions for a contact, keyed by deviceId (used to fan a message out). */
    fun loadAllForContact(contactId: String): Map<String, DoubleRatchet> =
        db.sessionQueries.selectSessionsForContact(contactId).executeAsList()
            .associate { it.deviceId to restore(it.stateEnc) }

    fun exists(contactId: String, deviceId: String): Boolean =
        db.sessionQueries.selectSession(contactId, deviceId).executeAsOneOrNull() != null

    fun delete(contactId: String, deviceId: String) = db.sessionQueries.deleteSession(contactId, deviceId)

    private fun restore(blob: ByteArray): DoubleRatchet {
        val plaintext = cipher.decrypt(blob) ?: error("Failed to decrypt session state")
        val snapshot = json.decodeFromString(RatchetStateSnapshot.serializer(), plaintext.decodeToString())
        return DoubleRatchet.restore(crypto, snapshot)
    }
}
