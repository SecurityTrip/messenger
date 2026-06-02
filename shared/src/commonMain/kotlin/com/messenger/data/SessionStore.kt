package com.messenger.data

import com.messenger.crypto.CryptoProvider
import com.messenger.db.MessengerDatabase
import com.messenger.protocol.ratchet.DoubleRatchet
import com.messenger.protocol.ratchet.RatchetStateSnapshot
import com.messenger.security.BlobCipher
import kotlinx.serialization.json.Json

/**
 * Persists one Double Ratchet session per contact. The session snapshot (which contains private
 * keys) is JSON-serialized then encrypted at rest via [cipher].
 */
class SessionStore(
    private val db: MessengerDatabase,
    private val cipher: BlobCipher,
    private val crypto: CryptoProvider,
    private val json: Json = Json,
) {
    fun save(contactId: String, ratchet: DoubleRatchet, now: Long) {
        val plaintext = json
            .encodeToString(RatchetStateSnapshot.serializer(), ratchet.export())
            .encodeToByteArray()
        db.sessionQueries.upsertSession(contactId, cipher.encrypt(plaintext), now)
    }

    fun load(contactId: String): DoubleRatchet? {
        val blob = db.sessionQueries.selectSession(contactId).executeAsOneOrNull() ?: return null
        val plaintext = cipher.decrypt(blob) ?: error("Failed to decrypt session state")
        val snapshot = json.decodeFromString(RatchetStateSnapshot.serializer(), plaintext.decodeToString())
        return DoubleRatchet.restore(crypto, snapshot)
    }

    fun exists(contactId: String): Boolean =
        db.sessionQueries.selectSession(contactId).executeAsOneOrNull() != null

    fun delete(contactId: String) = db.sessionQueries.deleteSession(contactId)
}
