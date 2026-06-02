package com.messenger.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * First screen: pick a username for this device and the peer to chat with, then connect (provision +
 * register + open the relay). [connecting] disables the button; [error] surfaces a failed attempt.
 */
@Composable
fun SetupScreen(
    connecting: Boolean,
    error: String?,
    onConnect: (me: String, peer: String) -> Unit,
) {
    var me by remember { mutableStateOf("") }
    var peer by remember { mutableStateOf("") }
    val canConnect = !connecting && me.isNotBlank() && peer.isNotBlank()

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
    ) {
        Text("Messenger", style = MaterialTheme.typography.headlineMedium)

        OutlinedTextField(
            value = me,
            onValueChange = { me = it },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            label = { Text("Your username") },
        )
        OutlinedTextField(
            value = peer,
            onValueChange = { peer = it },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            label = { Text("Chat with") },
        )

        Button(
            onClick = { onConnect(me.trim(), peer.trim()) },
            enabled = canConnect,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (connecting) "Connecting…" else "Connect")
        }

        if (connecting) CircularProgressIndicator()
        if (error != null) {
            Text(error, color = MaterialTheme.colorScheme.error)
        }
    }
}
