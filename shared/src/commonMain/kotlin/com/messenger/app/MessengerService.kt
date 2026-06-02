package com.messenger.app

import com.messenger.app.ConversationManager.ReceiveResult
import com.messenger.data.SessionStore
import com.messenger.net.MessengerApiClient
import com.messenger.net.RelayConnection
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Turns the [ConversationManager] + [MessengerApiClient] into a running client for one logged-in
 * device. On [start] it provisions the device, registers and publishes prekeys, opens the WebSocket
 * relay, and launches a receive loop that decrypts inbound envelopes, acknowledges them so the
 * server clears the mailbox, and relays delivery receipts back. The UI only calls [sendMessage] /
 * [markRead]; sessions, fan-out and persistence are handled by the manager.
 *
 * Platform-neutral and JVM-testable against the real relay (see `MessengerServiceNetworkTest`).
 */
class MessengerService(
    private val conversations: ConversationManager,
    private val sessions: SessionStore,
    private val api: MessengerApiClient,
    private val scope: CoroutineScope,
) {
    enum class State { Idle, Connecting, Connected, Failed }

    private val _state = MutableStateFlow(State.Idle)
    val state: StateFlow<State> = _state.asStateFlow()

    private var relay: RelayConnection? = null

    /** Provision (if needed), register, publish keys, open the relay, and start receiving. */
    suspend fun start(userId: String, deviceId: String) {
        _state.value = State.Connecting
        try {
            conversations.ensureProvisioned(userId, deviceId)
            api.register(conversations.registration())
            api.uploadKeys(userId, deviceId, conversations.keysForUpload())
            val conn = api.openRelay(userId, deviceId)
            relay = conn
            scope.launch { receiveLoop(conn) }
            _state.value = State.Connected
        } catch (t: Throwable) {
            _state.value = State.Failed
            throw t
        }
    }

    /** Send [text] to every device of [peerUserId], opening sessions on first contact. */
    suspend fun sendMessage(peerUserId: String, text: String) {
        val conn = relay ?: error("Not connected")
        val envelopes = if (sessions.loadAllForContact(peerUserId).isNotEmpty()) {
            conversations.send(peerUserId, text)
        } else {
            val bundles = api.fetchBundles(peerUserId) ?: error("Unknown user '$peerUserId'")
            conversations.startConversation(peerUserId, bundles, text)
        }
        envelopes.forEach { conn.send(it) }
    }

    /** Mark a received message read and relay a READ receipt back to its sender. */
    suspend fun markRead(localMessageId: String) {
        val conn = relay ?: return
        conversations.markRead(localMessageId)?.let { conn.send(it) }
    }

    suspend fun stop() {
        relay?.close()
        relay = null
        _state.value = State.Idle
    }

    private suspend fun receiveLoop(conn: RelayConnection) {
        conn.incoming.collect { envelope ->
            // Every delivered envelope (ciphertext or receipt) must be acked so the server drops it
            // from this device's mailbox; a decrypted message also gets a delivery receipt in return.
            when (val result = conversations.receive(envelope)) {
                is ReceiveResult.MessageReceived -> {
                    conn.ackDelivery(envelope.messageId)
                    conn.send(result.deliveryReceipt)
                }

                is ReceiveResult.ReceiptReceived -> {
                    conn.ackDelivery(envelope.messageId)
                }
            }
        }
    }
}
