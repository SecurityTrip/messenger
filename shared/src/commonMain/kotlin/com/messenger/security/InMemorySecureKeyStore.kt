package com.messenger.security

/**
 * Non-persistent, in-memory [SecureKeyStore]. **For tests and ephemeral use only** — on a real
 * device use the platform Keychain implementation. Stores defensive copies so callers can't mutate
 * retained secrets.
 */
class InMemorySecureKeyStore : SecureKeyStore {
    private val entries = mutableMapOf<String, ByteArray>()

    override fun get(alias: String): ByteArray? = entries[alias]?.copyOf()

    override fun put(alias: String, value: ByteArray) {
        entries[alias] = value.copyOf()
    }

    override fun delete(alias: String) {
        entries.remove(alias)
    }
}
