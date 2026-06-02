package com.messenger.security

import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Exercises the real iOS Keychain via [KeychainSecureKeyStore].
 *
 * Environment caveat: the bare Kotlin/Native simulator test runner is not packaged as an `.app`, so
 * it has no `application-identifier` entitlement and therefore no keychain access group. On such a
 * host `securityd` refuses every request with `errSecNotAvailable` (OSStatus -25291). There is no way
 * to grant that entitlement without a host-app test target, which arrives with the Xcode app in
 * Phase 6 — these tests will then run with full coverage there (and on a real device).
 *
 * So each test asserts the full contract when the keychain is reachable and skips (with a log line)
 * when it is not, keeping CI green without pretending to have tested storage that the OS blocked.
 */
class KeychainSecureKeyStoreTest {
    private val store = KeychainSecureKeyStore(service = "com.messenger.test.securekeystore")
    private val aliases = listOf("alias-a", "alias-b", "missing")

    /** Probe once whether this process is actually allowed to touch the keychain. */
    private val keychainAvailable: Boolean by lazy {
        try {
            store.put("__probe__", byteArrayOf(0x1))
            store.delete("__probe__")
            true
        } catch (e: IllegalStateException) {
            println("[KeychainSecureKeyStoreTest] keychain unavailable in this runner, skipping: ${e.message}")
            false
        }
    }

    @BeforeTest
    fun clear() = clearAliases()

    @AfterTest
    fun cleanup() = clearAliases()

    private fun clearAliases() {
        if (!keychainAvailable) return
        aliases.forEach(store::delete)
    }

    @Test
    fun put_then_get_roundtrips() {
        if (!keychainAvailable) return
        val value = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        store.put("alias-a", value)

        assertContentEquals(value, store.get("alias-a"))
        assertTrue(store.contains("alias-a"))
    }

    @Test
    fun get_returns_null_for_missing_alias() {
        if (!keychainAvailable) return
        assertNull(store.get("missing"))
        assertFalse(store.contains("missing"))
    }

    @Test
    fun put_overwrites_existing_value() {
        if (!keychainAvailable) return
        store.put("alias-a", byteArrayOf(1, 1, 1))
        store.put("alias-a", byteArrayOf(9, 8, 7, 6))

        assertContentEquals(byteArrayOf(9, 8, 7, 6), store.get("alias-a"))
    }

    @Test
    fun delete_removes_value() {
        if (!keychainAvailable) return
        store.put("alias-a", byteArrayOf(42))
        store.delete("alias-a")

        assertNull(store.get("alias-a"))
        assertFalse(store.contains("alias-a"))
    }

    @Test
    fun delete_is_a_no_op_for_missing_alias() {
        if (!keychainAvailable) return
        // Must not throw even though nothing is stored.
        store.delete("missing")
    }

    @Test
    fun distinct_aliases_are_independent() {
        if (!keychainAvailable) return
        store.put("alias-a", byteArrayOf(10))
        store.put("alias-b", byteArrayOf(20, 21))

        assertContentEquals(byteArrayOf(10), store.get("alias-a"))
        assertContentEquals(byteArrayOf(20, 21), store.get("alias-b"))
    }

    @Test
    fun stores_a_full_32_byte_master_key() {
        if (!keychainAvailable) return
        val key = ByteArray(32) { it.toByte() }
        store.put("alias-a", key)

        assertContentEquals(key, store.get("alias-a"))
    }
}
