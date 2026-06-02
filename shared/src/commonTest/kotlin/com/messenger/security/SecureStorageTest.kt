package com.messenger.security

import com.messenger.crypto.LibsodiumCryptoProvider
import com.messenger.crypto.initCrypto
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SecureStorageTest {

    private val crypto = LibsodiumCryptoProvider()

    @Test
    fun blobCipher_roundTrip() = runTest {
        initCrypto()
        val cipher = BlobCipher(crypto, crypto.randomBytes(32))
        val plaintext = "ratchet state blob".encodeToByteArray()

        val blob = cipher.encrypt(plaintext)
        assertContentEquals(plaintext, cipher.decrypt(blob))
    }

    @Test
    fun blobCipher_usesFreshNoncePerCall() = runTest {
        initCrypto()
        val cipher = BlobCipher(crypto, crypto.randomBytes(32))
        val pt = "same".encodeToByteArray()
        assertFalse(cipher.encrypt(pt).contentEquals(cipher.encrypt(pt)), "nonce must differ per call")
    }

    @Test
    fun blobCipher_rejectsWrongKeyAndTamper() = runTest {
        initCrypto()
        val blob = BlobCipher(crypto, crypto.randomBytes(32)).let { c ->
            c.encrypt("secret".encodeToByteArray())
        }
        // A cipher with a different key cannot decrypt.
        assertNull(BlobCipher(crypto, crypto.randomBytes(32)).decrypt(blob))

        // Tampering anywhere (incl. the nonce prefix) is detected.
        val cipher = BlobCipher(crypto, crypto.randomBytes(32))
        val good = cipher.encrypt("secret".encodeToByteArray())
        val tampered = good.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
        assertNull(cipher.decrypt(tampered))

        // Truncated/garbage blobs return null rather than throwing.
        assertNull(cipher.decrypt(ByteArray(5)))
    }

    @Test
    fun masterKey_isCreatedOnceAndReused() = runTest {
        initCrypto()
        val store = InMemorySecureKeyStore()
        assertFalse(store.contains(MasterKey.ALIAS))

        val first = MasterKey.loadOrCreate(crypto, store)
        assertEquals(32, first.size)
        assertTrue(store.contains(MasterKey.ALIAS))

        // A second call (e.g. next app launch with the same store) returns the same key.
        val second = MasterKey.loadOrCreate(crypto, store)
        assertContentEquals(first, second)
    }

    @Test
    fun inMemoryStore_storesDefensiveCopies() = runTest {
        val store = InMemorySecureKeyStore()
        val original = byteArrayOf(1, 2, 3)
        store.put("k", original)
        original[0] = 99 // mutate caller's copy after storing

        assertContentEquals(byteArrayOf(1, 2, 3), store.get("k"), "store must not alias caller's array")
        store.delete("k")
        assertNull(store.get("k"))
    }
}
