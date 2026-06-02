package com.messenger.ui

import com.messenger.app.MessengerComponent
import com.messenger.app.MessengerService
import com.messenger.domain.ChatMessage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/**
 * Backs the chat screen for a conversation with [peerUserId]. Messages stream reactively out of the
 * encrypted store; [send] hands off to [MessengerService], which encrypts (X3DH + Double Ratchet) and
 * relays over the WebSocket — the stored copy then surfaces through the same reactive stream.
 */
class ChatViewModel(
    component: MessengerComponent,
    private val service: MessengerService,
    private val peerUserId: String,
    private val scope: CoroutineScope,
) {
    val messages: StateFlow<List<ChatMessage>> =
        component.messages.observeMessages(peerUserId, Dispatchers.Default)
            .stateIn(scope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    fun send(text: String) {
        val body = text.trim()
        if (body.isEmpty()) return
        scope.launch {
            try {
                service.sendMessage(peerUserId, body)
            } catch (t: Throwable) {
                _error.value = t.message ?: "Failed to send"
            }
        }
    }

    fun clearError() {
        _error.value = null
    }
}
