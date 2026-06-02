package com.messenger.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import com.messenger.app.MessengerComponent
import com.messenger.app.MessengerService
import kotlinx.coroutines.launch

private const val DEVICE_ID = "ios"

/** Optional pre-filled identities so the app can connect on launch (e.g. from launch env vars). */
data class AutoConnect(val me: String, val peer: String)

/**
 * App root. [componentFactory] builds the [MessengerComponent] asynchronously (it initializes
 * libsodium and opens the database), so we show a spinner until it's ready, then the messenger.
 * When [autoConnect] is set, the connect flow starts automatically (used for end-to-end testing).
 */
@Composable
fun App(componentFactory: suspend () -> MessengerComponent, autoConnect: AutoConnect? = null) {
    MaterialTheme {
        val component by produceState<MessengerComponent?>(initialValue = null) {
            value = componentFactory()
        }

        when (val ready = component) {
            null -> Loading()
            else -> Messenger(ready, autoConnect)
        }
    }
}

/** Owns the [MessengerService], runs the connect flow, and switches between setup and chat. */
@Composable
private fun Messenger(component: MessengerComponent, autoConnect: AutoConnect?) {
    val scope = rememberCoroutineScope()
    val service = remember(component) {
        MessengerService(component.conversations, component.sessions, component.api, scope)
    }
    val state by service.state.collectAsState()

    var peer by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    fun connect(me: String, withPeer: String) {
        error = null
        peer = withPeer
        scope.launch {
            try {
                service.start(me, DEVICE_ID)
            } catch (t: Throwable) {
                error = t.message ?: "Could not connect"
                peer = null
            }
        }
    }

    LaunchedEffect(autoConnect) {
        if (autoConnect != null && state == MessengerService.State.Idle) {
            connect(autoConnect.me, autoConnect.peer)
        }
    }

    val activePeer = peer
    if (activePeer != null && state == MessengerService.State.Connected) {
        val viewModel = remember(activePeer) { ChatViewModel(component, service, activePeer, scope) }
        ChatScreen(viewModel, peerName = activePeer)
    } else {
        SetupScreen(
            connecting = state == MessengerService.State.Connecting,
            error = error,
            onConnect = ::connect,
        )
    }
}

@Composable
private fun Loading() {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        CircularProgressIndicator()
    }
}
