package com.messenger.app

import com.messenger.crypto.CryptoProvider
import com.messenger.data.ContactStore
import com.messenger.data.IdentityStore
import com.messenger.data.MessageStore
import com.messenger.data.SessionStore
import com.messenger.db.DatabaseDriverFactory
import com.messenger.db.createMessengerDatabase
import com.messenger.protocol.wire.DeviceBundle
import com.messenger.protocol.wire.DeviceBundles
import com.messenger.protocol.wire.WirePreKeyBundle
import com.messenger.security.BlobCipher
import com.messenger.security.InMemorySecureKeyStore
import com.messenger.security.MasterKey

/** A test "device": a ConversationManager over its own isolated in-memory stores. */
class TestDevice(
    val userId: String,
    val deviceId: String,
    val manager: ConversationManager,
    val identities: IdentityStore,
    val sessions: SessionStore,
    val messages: MessageStore,
    val contacts: ContactStore,
) {
    fun provision(oneTimePreKeyCount: Int = 20) = manager.ensureProvisioned(userId, deviceId, oneTimePreKeyCount)
}

fun testDevice(crypto: CryptoProvider, userId: String, deviceId: String, clock: () -> Long): TestDevice {
    val db = createMessengerDatabase(DatabaseDriverFactory(inMemory = true).create())
    val cipher = BlobCipher(crypto, MasterKey.loadOrCreate(crypto, InMemorySecureKeyStore()))
    val identities = IdentityStore(db, cipher)
    val sessions = SessionStore(db, cipher, crypto)
    val messages = MessageStore(db, cipher)
    val contacts = ContactStore(db)
    val manager = ConversationManager(crypto, identities, sessions, messages, contacts, clock)
    return TestDevice(userId, deviceId, manager, identities, sessions, messages, contacts)
}

/**
 * Build the [DeviceBundles] a server would return — straight from each provisioned device's
 * published keys — so manager-level tests can run the X3DH flow without a real server. All devices
 * passed must belong to the same user.
 */
fun deviceBundlesFor(vararg managers: ConversationManager): DeviceBundles {
    val userId = managers.first().registration().userId
    val list = managers.map { manager ->
        val reg = manager.registration()
        val keys = manager.keysForUpload()
        val otk = keys.oneTimePreKeys.firstOrNull()
        DeviceBundle(
            deviceId = reg.deviceId,
            bundle = WirePreKeyBundle(
                identityKey = reg.identityKey,
                signedPreKeyId = keys.signedPreKeyId,
                signedPreKey = keys.signedPreKey,
                signedPreKeySignature = keys.signedPreKeySignature,
                oneTimePreKeyId = otk?.id,
                oneTimePreKey = otk?.publicKey,
            ),
        )
    }
    return DeviceBundles(userId, list)
}
