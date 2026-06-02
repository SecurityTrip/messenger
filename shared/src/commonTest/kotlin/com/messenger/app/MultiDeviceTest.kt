package com.messenger.app

import com.messenger.app.ConversationManager.ReceiveResult
import com.messenger.crypto.LibsodiumCryptoProvider
import com.messenger.crypto.initCrypto
import com.messenger.protocol.wire.RelayEnvelope
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

class MultiDeviceTest {

    private val crypto = LibsodiumCryptoProvider()
    private var clock = 0L

    private fun device(userId: String, deviceId: String) = testDevice(crypto, userId, deviceId) { ++clock }

    @Test
    fun messageFansOutToAllRecipientDevices() = runTest {
        initCrypto()
        val alice = device("alice", "aliceD")
        val bobPhone = device("bob", "phone")
        val bobLaptop = device("bob", "laptop")
        alice.provision()
        bobPhone.provision()
        bobLaptop.provision()

        val bobDevices = mapOf(bobPhone.deviceId to bobPhone, bobLaptop.deviceId to bobLaptop)
        fun routeToBob(envelopes: List<RelayEnvelope>, expected: String) {
            assertEquals(2, envelopes.size, "must fan out to both of Bob's devices")
            assertEquals(1, envelopes.map { it.messageId }.toSet().size, "all copies share one messageId")
            for (env in envelopes) {
                val target = bobDevices.getValue(env.toDevice)
                val received = target.manager.receive(env) as ReceiveResult.MessageReceived
                assertEquals(expected, received.message.body)
            }
        }

        // First message establishes a session with each device.
        routeToBob(alice.manager.startConversation("bob", deviceBundlesFor(bobPhone.manager, bobLaptop.manager), "hi both"), "hi both")

        // Follow-up fans out over the two established sessions.
        routeToBob(alice.manager.send("bob", "second"), "second")

        // Each device has its own independent history.
        assertEquals(listOf("hi both", "second"), bobPhone.messages.messagesForContact("alice").map { it.body })
        assertEquals(listOf("hi both", "second"), bobLaptop.messages.messagesForContact("alice").map { it.body })
    }
}
