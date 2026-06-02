package com.messenger.security

/**
 * Platform-backed secure storage for small secrets — primarily the at-rest [MasterKey].
 *
 * On iOS this is backed by the **Keychain** (implemented in the iOS app layer / iosMain on a Mac).
 * [InMemorySecureKeyStore] is provided for tests and ephemeral use.
 */
interface SecureKeyStore {
    fun get(alias: String): ByteArray?
    fun put(alias: String, value: ByteArray)
    fun delete(alias: String)
    fun contains(alias: String): Boolean = get(alias) != null
}
