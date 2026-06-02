package com.messenger.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import com.messenger.app.MessengerComponent

/**
 * App root. [componentFactory] builds the [MessengerComponent] asynchronously (it initializes
 * libsodium and opens the database), so we show a spinner until it's ready, then the chat screen.
 */
@Composable
fun App(componentFactory: suspend () -> MessengerComponent) {
    MaterialTheme {
        val component by produceState<MessengerComponent?>(initialValue = null) {
            value = componentFactory()
        }

        when (val ready = component) {
            null -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }

            else -> {
                val viewModel = remember(ready) { ChatViewModel(ready) }
                DisposableEffect(viewModel) { onDispose { viewModel.dispose() } }
                ChatScreen(viewModel)
            }
        }
    }
}
