package com.messenger.security

import com.messenger.crypto.LibsodiumCryptoProvider
import com.messenger.crypto.initCrypto
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class SafetyNumberTest {

    private val crypto = LibsodiumCryptoProvider()

    @Test
    fun bothParties_computeTheSameNumber() = runTest {
        initCrypto()
        val alice = crypto.generateSigningKeyPair()
        val bob = crypto.generateSigningKeyPair()

        val fromAlice = SafetyNumber.compute(crypto, "alice", alice.publicKey, "bob", bob.publicKey)
        val fromBob = SafetyNumber.compute(crypto, "bob", bob.publicKey, "alice", alice.publicKey)

        assertEquals(fromAlice, fromBob, "safety number must match regardless of perspective")
        assertEquals(60, fromAlice.length)
        assertTrue(fromAlice.all { it.isDigit() })
    }

    @Test
    fun differentKey_yieldsDifferentNumber() = runTest {
        initCrypto()
        val alice = crypto.generateSigningKeyPair()
        val bob = crypto.generateSigningKeyPair()
        val mallory = crypto.generateSigningKeyPair() // attacker swaps in their key

        val honest = SafetyNumber.compute(crypto, "alice", alice.publicKey, "bob", bob.publicKey)
        val mitm = SafetyNumber.compute(crypto, "alice", alice.publicKey, "bob", mallory.publicKey)

        assertNotEquals(honest, mitm, "a swapped identity key must change the safety number")
    }

    @Test
    fun isDeterministic_andFormats() = runTest {
        initCrypto()
        val alice = crypto.generateSigningKeyPair()
        val bob = crypto.generateSigningKeyPair()

        val a = SafetyNumber.compute(crypto, "alice", alice.publicKey, "bob", bob.publicKey)
        val b = SafetyNumber.compute(crypto, "alice", alice.publicKey, "bob", bob.publicKey)
        assertEquals(a, b)
        assertEquals(12, SafetyNumber.formatForDisplay(a).split(" ").size) // 60 digits / 5 = 12 groups
    }
}
