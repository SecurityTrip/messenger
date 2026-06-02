package com.messenger.security

import com.messenger.crypto.CryptoProvider

/**
 * The at-rest master key: loaded from the [SecureKeyStore], or generated and persisted there on
 * first run. This key never leaves secure storage and is used only to wrap on-device data via
 * [BlobCipher].
 */
object MasterKey {
    const val ALIAS = "messenger.master_key.v1"

    fun loadOrCreate(crypto: CryptoProvider, store: SecureKeyStore): ByteArray {
        store.get(ALIAS)?.let { return it }
        val key = crypto.randomBytes(CryptoProvider.AEAD_KEY_SIZE)
        store.put(ALIAS, key)
        return key
    }
}
