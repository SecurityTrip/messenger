package com.messenger.ui

import com.messenger.app.MessengerComponent
import com.messenger.crypto.toBase64
import com.messenger.domain.ChatMessage
import com.messenger.domain.Contact
import com.messenger.domain.MessageDirection
import com.messenger.domain.MessageStatus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.datetime.Clock

/**
 * State holder for the demo chat screen. Backs the UI with the *real* shared stack: messages stream
 * reactively out of the encrypted SQLDelight store, and sending writes back into it.
 *
 * SEAM: for this runnable skeleton, [send] persists locally only. The network step will replace the
 * local insert with `component.conversations.send(...)` + an `api` relay push (after provisioning,
 * key upload, and bundle fetch), and an incoming relay loop will call `conversations.receive(...)`.
 */
class ChatViewModel(private val component: MessengerComponent) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    val messages: StateFlow<List<ChatMessage>> =
        component.messages.observeMessages(DEMO_CONTACT_ID, Dispatchers.Default)
            .stateIn(scope, SharingStarted.WhileSubscribed(5_000), emptyList())

    init {
        scope.launch(Dispatchers.Default) { seedDemoConversationIfEmpty() }
    }

    fun send(text: String) {
        val body = text.trim()
        if (body.isEmpty()) return
        scope.launch(Dispatchers.Default) {
            component.messages.insert(
                ChatMessage(
                    id = newId(),
                    contactId = DEMO_CONTACT_ID,
                    direction = MessageDirection.OUTGOING,
                    body = body,
                    timestamp = nowMs(),
                    status = MessageStatus.SENT,
                ),
            )
        }
    }

    fun dispose() = scope.cancel()

    private fun seedDemoConversationIfEmpty() {
        if (component.contacts.get(DEMO_CONTACT_ID) != null) return
        component.contacts.upsert(
            Contact(DEMO_CONTACT_ID, identityPublicKey = ByteArray(0), displayName = "Demo (local)", verified = false),
        )
        component.messages.insert(
            ChatMessage(
                id = newId(),
                contactId = DEMO_CONTACT_ID,
                direction = MessageDirection.INCOMING,
                body = "Welcome 👋 This is a local-only demo: the Compose UI is wired to the shared " +
                    "encrypted store. Messages you send are persisted (and encrypted at rest).",
                timestamp = nowMs(),
                status = MessageStatus.DELIVERED,
            ),
        )
    }

    private fun newId(): String = component.crypto.randomBytes(16).toBase64()

    private fun nowMs(): Long = Clock.System.now().toEpochMilliseconds()

    companion object {
        const val DEMO_CONTACT_ID = "demo"
    }
}
