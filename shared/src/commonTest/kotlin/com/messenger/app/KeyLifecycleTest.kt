package com.messenger.app

import com.messenger.db.DatabaseDriverFactory
import com.messenger.security.InMemorySecureKeyStore
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class KeyLifecycleTest {

    private suspend fun component() = MessengerComponent.create(
        driverFactory = DatabaseDriverFactory(inMemory = true),
        secureKeyStore = InMemorySecureKeyStore(),
        serverBaseUrl = "http://localhost:0",
    )

    @Test
    fun rotatingSignedPreKey_keepsOldOneUsableForInFlightInitialMessages() = runTest {
        val alice = component()
        val bob = component()
        alice.conversations.ensureProvisioned("alice")
        bob.conversations.ensureProvisioned("bob", oneTimePreKeyCount = 2)

        // Alice grabs the current bundle (signed prekey #1) and prepares the first message.
        val bundle = bob.conversations.publishBundle()
        assertEquals(1, bundle.signedPreKeyId)
        val wire = alice.conversations.startConversation("bob", bundle, "queued before rotation")

        // Bob rotates his signed prekey before the message arrives.
        val newId = bob.conversations.rotateSignedPreKey()
        assertEquals(2, newId)
        assertEquals(2, bob.conversations.publishBundle().signedPreKeyId, "new bundles advertise the rotated key")

        // The in-flight message (which referenced #1) still decrypts because the old key is retained.
        assertEquals("queued before rotation", bob.conversations.receive("alice", wire).body)

        alice.close(); bob.close()
    }

    @Test
    fun replenishingOneTimePreKeys_topsUpPoolWithFreshIds() = runTest {
        val bob = component()
        bob.conversations.ensureProvisioned("bob", oneTimePreKeyCount = 3)
        assertEquals(3, bob.identities.unusedOneTimePreKeyCount())

        // Above threshold → no-op.
        assertEquals(0, bob.conversations.replenishOneTimePreKeysIfNeeded(threshold = 2, target = 10))

        // Below threshold → tops up to target with non-colliding ids (max was 3 → new start at 4).
        val generated = bob.conversations.replenishOneTimePreKeysIfNeeded(threshold = 5, target = 10)
        assertEquals(7, generated)
        assertEquals(10, bob.identities.unusedOneTimePreKeyCount())
        assertEquals(10, bob.identities.maxOneTimePreKeyId())

        // All ids are unique (no collisions after replenishment).
        val ids = bob.identities.allUnusedOneTimePreKeyPublics().map { it.id }
        assertEquals(ids.size, ids.toSet().size)
        assertTrue(ids.containsAll(listOf(1, 2, 3, 4, 10)))

        bob.close()
    }
}
