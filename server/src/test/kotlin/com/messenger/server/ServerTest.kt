package com.messenger.server

import com.messenger.protocol.wire.ClientFrame
import com.messenger.protocol.wire.DeviceBundles
import com.messenger.protocol.wire.RegisterRequest
import com.messenger.protocol.wire.RegisterResponse
import com.messenger.protocol.wire.RelayEnvelope
import com.messenger.protocol.wire.RelayPayload
import com.messenger.protocol.wire.ServerFrame
import com.messenger.protocol.wire.UploadKeysRequest
import com.messenger.protocol.wire.WireMessage
import com.messenger.protocol.wire.WireOneTimePreKey
import com.messenger.protocol.wire.WireRatchetHeader
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
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

    private fun envelope(messageId: String, toUser: String, toDevice: String, from: String, fromDevice: String, text: String) =
        RelayEnvelope(
            messageId = messageId,
            toUser = toUser,
            toDevice = toDevice,
            fromUser = from,
            fromDevice = fromDevice,
            payload = RelayPayload.Ciphertext(
                WireMessage(WireRatchetHeader("cmF0Y2hldA==", 0, 0), ciphertext = text),
            ),
        )

    private suspend fun WebSocketSession.send(frame: ClientFrame) =
        send(Frame.Text(json.encodeToString(ClientFrame.serializer(), frame)))

    private suspend fun WebSocketSession.nextServerFrame(): ServerFrame {
        while (true) {
            val frame = incoming.receive()
            if (frame is Frame.Text) return json.decodeFromString(ServerFrame.serializer(), frame.readText())
        }
    }

    private suspend fun register(client: HttpClient, userId: String, deviceId: String): String =
        client.post("/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest(userId, deviceId, identityKey = "ik-$userId-$deviceId", registrationId = 1))
        }.body<RegisterResponse>().token

    @Test
    fun register_uploadKeys_andFetchBundlesConsumesOneTimePreKey() = testApplication {
        application { messengerModule() }
        val client = createClient { install(ClientContentNegotiation) { json() } }

        val token = register(client, "bob", "bobD")

        // Upload requires the bearer token.
        client.post("/keys/bob/bobD") {
            contentType(ContentType.Application.Json)
            setBody(UploadKeysRequest(1, "spk", "sig", listOf(WireOneTimePreKey(100, "otk"))))
        }.let { assertEquals(HttpStatusCode.Unauthorized, it.status) }

        client.post("/keys/bob/bobD") {
            contentType(ContentType.Application.Json)
            header(HttpHeaders.Authorization, "Bearer $token")
            setBody(UploadKeysRequest(1, "spk", "sig", listOf(WireOneTimePreKey(100, "otk"))))
        }.let { assertEquals(HttpStatusCode.OK, it.status) }

        val bundles1 = client.get("/keys/bob").body<DeviceBundles>()
        assertEquals(1, bundles1.devices.size)
        assertEquals("bobD", bundles1.devices.single().deviceId)
        assertEquals(100, bundles1.devices.single().bundle.oneTimePreKeyId)

        // The one-time prekey is single-use.
        assertNull(client.get("/keys/bob").body<DeviceBundles>().devices.single().bundle.oneTimePreKeyId)
    }

    @Test
    fun fetchBundles_unknownUser_returns404() = testApplication {
        application { messengerModule() }
        val client = createClient { install(ClientContentNegotiation) { json() } }
        assertEquals(HttpStatusCode.NotFound, client.get("/keys/ghost").status)
    }

    @Test
    fun relay_deliversBetweenOnlineDevices() = testApplication {
        application { messengerModule() }
        val client = createClient {
            install(ClientContentNegotiation) { json() }
            install(WebSockets)
        }
        val aliceToken = register(client, "alice", "aliceD")
        val bobToken = register(client, "bob", "bobD")

        client.webSocket("/ws/bob/bobD?token=$bobToken") {
            val bob = this
            client.webSocket("/ws/alice/aliceD?token=$aliceToken") {
                send(ClientFrame.Send(envelope("m1", "bob", "bobD", "alice", "aliceD", "hello")))
                val accepted = nextServerFrame() as ServerFrame.Accepted
                assertFalse(accepted.queued, "recipient online → delivered, not queued")
            }
            val delivered = bob.nextServerFrame() as ServerFrame.Deliver
            assertEquals("alice", delivered.envelope.fromUser)
            assertEquals("hello", (delivered.envelope.payload as RelayPayload.Ciphertext).message.ciphertext)
        }
    }

    @Test
    fun relay_offlineQueue_redeliversUntilAcked() = testApplication {
        application { messengerModule() }
        val client = createClient {
            install(ClientContentNegotiation) { json() }
            install(WebSockets)
        }
        val aliceToken = register(client, "alice", "aliceD")
        val bobToken = register(client, "bob", "bobD")

        // Alice sends to offline Bob → queued.
        client.webSocket("/ws/alice/aliceD?token=$aliceToken") {
            send(ClientFrame.Send(envelope("m1", "bob", "bobD", "alice", "aliceD", "offline-msg")))
            assertTrue((nextServerFrame() as ServerFrame.Accepted).queued)
        }

        // Bob connects, receives it, but does NOT ack, then disconnects.
        client.webSocket("/ws/bob/bobD?token=$bobToken") {
            assertEquals("offline-msg", ((nextServerFrame() as ServerFrame.Deliver).envelope.payload as RelayPayload.Ciphertext).message.ciphertext)
        }

        // On reconnect the un-acked message is redelivered; this time Bob acks it.
        client.webSocket("/ws/bob/bobD?token=$bobToken") {
            val redelivered = nextServerFrame() as ServerFrame.Deliver
            assertEquals("m1", redelivered.envelope.messageId)
            send(ClientFrame.Ack("m1"))
        }

        // After the ack, alice sends a second message; on the next connect Bob only sees the new one.
        client.webSocket("/ws/alice/aliceD?token=$aliceToken") {
            send(ClientFrame.Send(envelope("m2", "bob", "bobD", "alice", "aliceD", "second")))
            nextServerFrame() // accepted
        }
        client.webSocket("/ws/bob/bobD?token=$bobToken") {
            val delivered = nextServerFrame() as ServerFrame.Deliver
            assertEquals("m2", delivered.envelope.messageId, "acked m1 must not be redelivered")
        }
    }
}
