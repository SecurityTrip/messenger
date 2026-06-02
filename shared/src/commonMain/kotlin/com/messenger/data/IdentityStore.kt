package com.messenger.data

import com.messenger.crypto.DhKeyPair
import com.messenger.crypto.SigningKeyPair
import com.messenger.crypto.toBase64
import com.messenger.db.MessengerDatabase
import com.messenger.protocol.wire.WireOneTimePreKey
import com.messenger.protocol.x3dh.OneTimePreKey
import com.messenger.protocol.x3dh.SignedPreKey
import com.messenger.security.BlobCipher

/**
 * Persists this device's long-term identity and its prekeys. All private key material is encrypted
 * at rest via [cipher] before it touches the database.
 */
class IdentityStore(
    private val db: MessengerDatabase,
    private val cipher: BlobCipher,
) {
    fun saveAccount(userId: String, deviceId: String, identity: SigningKeyPair, registrationId: Int, now: Long) {
        db.accountQueries.upsertAccount(
            userId = userId,
            deviceId = deviceId,
            identityPublicKey = identity.publicKey,
            identityPrivateKeyEnc = cipher.encrypt(identity.privateKey),
            registrationId = registrationId.toLong(),
            createdAt = now,
        )
    }

    fun accountUserId(): String? = db.accountQueries.selectAccount().executeAsOneOrNull()?.userId

    fun accountDeviceId(): String? = db.accountQueries.selectAccount().executeAsOneOrNull()?.deviceId

    fun registrationId(): Int? = db.accountQueries.selectAccount().executeAsOneOrNull()?.registrationId?.toInt()

    /** Public material of all unused one-time prekeys, for uploading the pool to the server. */
    fun allUnusedOneTimePreKeyPublics(): List<WireOneTimePreKey> =
        db.oneTimePreKeyQueries.selectAllUnusedOneTimePreKeys().executeAsList()
            .map { WireOneTimePreKey(it.id.toInt(), it.publicKey.toBase64()) }

    fun loadIdentity(): SigningKeyPair? {
        val row = db.accountQueries.selectAccount().executeAsOneOrNull() ?: return null
        val privateKey = cipher.decrypt(row.identityPrivateKeyEnc)
            ?: error("Failed to decrypt identity private key (wrong master key?)")
        return SigningKeyPair(row.identityPublicKey, privateKey)
    }

    fun saveSignedPreKey(signedPreKey: SignedPreKey, now: Long) {
        db.signedPreKeyQueries.insertSignedPreKey(
            id = signedPreKey.id.toLong(),
            publicKey = signedPreKey.keyPair.publicKey,
            privateKeyEnc = cipher.encrypt(signedPreKey.keyPair.privateKey),
            signature = signedPreKey.signature,
            createdAt = now,
        )
    }

    fun loadSignedPreKey(id: Int): SignedPreKey? {
        val row = db.signedPreKeyQueries.selectSignedPreKey(id.toLong()).executeAsOneOrNull() ?: return null
        val privateKey = cipher.decrypt(row.privateKeyEnc) ?: error("Failed to decrypt signed prekey")
        return SignedPreKey(row.id.toInt(), DhKeyPair(row.publicKey, privateKey), row.signature)
    }

    fun loadLatestSignedPreKey(): SignedPreKey? {
        val row = db.signedPreKeyQueries.selectLatestSignedPreKey().executeAsOneOrNull() ?: return null
        val privateKey = cipher.decrypt(row.privateKeyEnc) ?: error("Failed to decrypt signed prekey")
        return SignedPreKey(row.id.toInt(), DhKeyPair(row.publicKey, privateKey), row.signature)
    }

    fun maxSignedPreKeyId(): Int =
        db.signedPreKeyQueries.selectMaxSignedPreKeyId { max -> max?.toInt() ?: 0 }.executeAsOne()

    fun maxOneTimePreKeyId(): Int =
        db.oneTimePreKeyQueries.selectMaxOneTimePreKeyId { max -> max?.toInt() ?: 0 }.executeAsOne()

    fun saveOneTimePreKeys(keys: List<OneTimePreKey>) {
        db.transaction {
            for (key in keys) {
                db.oneTimePreKeyQueries.insertOneTimePreKey(
                    id = key.id.toLong(),
                    publicKey = key.keyPair.publicKey,
                    privateKeyEnc = cipher.encrypt(key.keyPair.privateKey),
                )
            }
        }
    }

    fun loadOneTimePreKey(id: Int): OneTimePreKey? {
        val row = db.oneTimePreKeyQueries.selectOneTimePreKey(id.toLong()).executeAsOneOrNull() ?: return null
        val privateKey = cipher.decrypt(row.privateKeyEnc) ?: error("Failed to decrypt one-time prekey")
        return OneTimePreKey(row.id.toInt(), DhKeyPair(row.publicKey, privateKey))
    }

    /** An unused one-time prekey to advertise in a bundle, or null if the pool is exhausted. */
    fun nextUnusedOneTimePreKey(): OneTimePreKey? {
        val row = db.oneTimePreKeyQueries.selectUnusedOneTimePreKey().executeAsOneOrNull() ?: return null
        val privateKey = cipher.decrypt(row.privateKeyEnc) ?: error("Failed to decrypt one-time prekey")
        return OneTimePreKey(row.id.toInt(), DhKeyPair(row.publicKey, privateKey))
    }

    fun markOneTimePreKeyUsed(id: Int) = db.oneTimePreKeyQueries.markOneTimePreKeyUsed(id.toLong())

    fun unusedOneTimePreKeyCount(): Int =
        db.oneTimePreKeyQueries.countUnusedOneTimePreKeys().executeAsOne().toInt()
}
