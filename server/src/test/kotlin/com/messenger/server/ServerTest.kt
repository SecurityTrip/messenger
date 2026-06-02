package com.messenger.server

import com.messenger.protocol.wire.RegisterRequest
import com.messenger.protocol.wire.RegisterResponse
import com.messenger.protocol.wire.RelayEnvelope
import com.messenger.protocol.wire.ServerFrame
import com.messenger.protocol.wire.UploadKeysRequest
import com.messenger.protocol.wire.WireMessage
import com.messenger.protocol.wire.WireOneTimePreKey
import com.messenger.protocol.wire.WirePreKeyBundle
import com.messenger.protocol.wire.WireRatchetHeader
import io.ktor.client.call.body
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.testing.testApplication
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketSession
import io.ktor.websocket.readText
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ServerTest {

    private val json = Json { ignoreUnknownKeys = true }

    private fun dummyMessage(text: String) = WireMessage(
        header = WireRatchetHeader(ratchetPublicKey = "cmF0Y2hldA==", previousChainLength = 0, messageNumber = 0),
        ciphertext = text, // stands in for ciphertext; the server treats it as opaque
    )

    private suspend fun WebSocketSession.nextText(): String {
        while (true) {
            val frame = incoming.receive()
            if (frame is Frame.Text) return frame.readText()
        }
    }

    @Test
    fun register_uploadKeys_andFetchBundleConsumesOneTimePreKey() = testApplication {
        application { messengerModule() }
        val client = createClient { install(ClientContentNegotiation) { json() } }

        val token = client.post("/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest("bob", identityKey = "aWtfYm9i", registrationId = 1))
        }.body<RegisterResponse>().token

        // Uploading keys without the token must be rejected.
        client.post("/keys/bob") {
            contentType(ContentType.Application.Json)
            setBody(UploadKeysRequest(1, "c3Br", "c2ln", listOf(WireOneTimePreKey(100, "b3Rr"))))
        }.let { assertEquals(HttpStatusCode.Unauthorized, it.status) }

        // With the bearer token it succeeds.
        client.post("/keys/bob") {
            contentType(ContentType.Application.Json)
            header(HttpHeaders.Authorization, "Bearer $token")
            setBody(UploadKeysRequest(1, "c3Br", "c2ln", listOf(WireOneTimePreKey(100, "b3Rr"))))
        }.let { assertEquals(HttpStatusCode.OK, it.status) }

        val bundle1 = client.get("/keys/bob").body<WirePreKeyBundle>()
        assertEquals(1, bundle1.signedPreKeyId)
        assertEquals(100, bundle1.oneTimePreKeyId)

        // The one-time prekey is single-use: the next fetch has none left.
        val bundle2 = client.get("/keys/bob").body<WirePreKeyBundle>()
        assertNull(bundle2.oneTimePreKeyId)
    }

    @Test
    fun fetchBundle_unknownUser_returns404() = testApplication {
        application { messengerModule() }
        val client = createClient { install(ClientContentNegotiation) { json() } }
        assertEquals(HttpStatusCode.NotFound, client.get("/keys/ghost").status)
    }

    @Test
    fun relay_deliversBetweenOnlineClients() = testApplication {
        application { messengerModule() }
        val client = createClient {
            install(ClientContentNegotiation) { json() }
            install(WebSockets)
        }
        val aliceToken = register(client, "alice")
        val bobToken = register(client, "bob")

        client.webSocket("/ws/bob?token=$bobToken") {
            val bob = this
            client.webSocket("/ws/alice?token=$aliceToken") {
                send(Frame.Text(json.encodeToString(RelayEnvelope.serializer(), RelayEnvelope("bob", "alice", dummyMessage("hello")))))
                val ack = json.decodeFromString(ServerFrame.serializer(), nextText()) as ServerFrame.Ack
                assertFalse(ack.ack.queued, "recipient online → not queued")
            }
            val relayed = json.decodeFromString(ServerFrame.serializer(), bob.nextText()) as ServerFrame.Deliver
            assertEquals("alice", relayed.envelope.from)
            assertEquals("hello", relayed.envelope.message.ciphertext)
        }
    }

    @Test
    fun relay_queuesForOfflineRecipient_andDeliversOnConnect() = testApplication {
        application { messengerModule() }
        val client = createClient {
            install(ClientContentNegotiation) { json() }
            install(WebSockets)
        }
        val aliceToken = register(client, "alice")
        val bobToken = register(client, "bob")

        // Bob is offline; Alice sends and waits for the ack confirming it was queued.
        client.webSocket("/ws/alice?token=$aliceToken") {
            send(Frame.Text(json.encodeToString(RelayEnvelope.serializer(), RelayEnvelope("bob", "alice", dummyMessage("offline-msg")))))
            val ack = json.decodeFromString(ServerFrame.serializer(), nextText()) as ServerFrame.Ack
            assertTrue(ack.ack.queued, "recipient offline → queued")
        }

        // Bob connects and receives the queued message.
        client.webSocket("/ws/bob?token=$bobToken") {
            val relayed = json.decodeFromString(ServerFrame.serializer(), nextText()) as ServerFrame.Deliver
            assertEquals("alice", relayed.envelope.from)
            assertEquals("offline-msg", relayed.envelope.message.ciphertext)
        }
    }

    private suspend fun register(client: io.ktor.client.HttpClient, userId: String): String =
        client.post("/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest(userId, identityKey = "aWtf$userId", registrationId = 1))
        }.body<RegisterResponse>().token
}
