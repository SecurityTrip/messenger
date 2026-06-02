package com.messenger.app

import com.messenger.app.ConversationManager.ReceiveResult
import com.messenger.crypto.LibsodiumCryptoProvider
import com.messenger.crypto.initCrypto
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class KeyLifecycleTest {

    private val crypto = LibsodiumCryptoProvider()
    private var clock = 0L

    private fun device(userId: String, deviceId: String) = testDevice(crypto, userId, deviceId) { ++clock }

    @Test
    fun rotatingSignedPreKey_keepsOldOneUsableForInFlightInitialMessages() = runTest {
        initCrypto()
        val alice = device("alice", "aliceD")
        val bob = device("bob", "bobD")
        alice.provision()
        bob.provision(oneTimePreKeyCount = 2)

        // Alice grabs Bob's current bundle (signed prekey #1) and prepares the first message.
        val bundles = deviceBundlesFor(bob.manager)
        assertEquals(1, bundles.devices.single().bundle.signedPreKeyId)
        val first = alice.manager.startConversation("bob", bundles, "queued before rotation").single()

        // Bob rotates his signed prekey before the message arrives.
        val newId = bob.manager.rotateSignedPreKey()
        assertEquals(2, newId)
        assertEquals(2, bob.manager.keysForUpload().signedPreKeyId, "new bundles advertise the rotated key")

        // The in-flight message (which referenced #1) still decrypts because the old key is retained.
        val received = bob.manager.receive(first) as ReceiveResult.MessageReceived
        assertEquals("queued before rotation", received.message.body)
    }

    @Test
    fun replenishingOneTimePreKeys_topsUpPoolWithFreshIds() = runTest {
        initCrypto()
        val bob = device("bob", "bobD")
        bob.provision(oneTimePreKeyCount = 3)
        assertEquals(3, bob.identities.unusedOneTimePreKeyCount())

        assertEquals(0, bob.manager.replenishOneTimePreKeysIfNeeded(threshold = 2, target = 10))

        val generated = bob.manager.replenishOneTimePreKeysIfNeeded(threshold = 5, target = 10)
        assertEquals(7, generated)
        assertEquals(10, bob.identities.unusedOneTimePreKeyCount())
        assertEquals(10, bob.identities.maxOneTimePreKeyId())

        val ids = bob.identities.allUnusedOneTimePreKeyPublics().map { it.id }
        assertEquals(ids.size, ids.toSet().size)
        assertTrue(ids.containsAll(listOf(1, 2, 3, 4, 10)))
    }
}
