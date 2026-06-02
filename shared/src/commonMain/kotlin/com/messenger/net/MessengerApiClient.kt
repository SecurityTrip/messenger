package com.messenger.net

import com.messenger.protocol.wire.ClientFrame
import com.messenger.protocol.wire.DeviceBundles
import com.messenger.protocol.wire.RegisterRequest
import com.messenger.protocol.wire.RegisterResponse
import com.messenger.protocol.wire.RelayEnvelope
import com.messenger.protocol.wire.ServerFrame
import com.messenger.protocol.wire.UploadKeysRequest
import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.websocket.DefaultClientWebSocketSession
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import io.ktor.websocket.readText
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json

private val ClientJson = Json { ignoreUnknownKeys = true }

internal fun HttpClientConfig<*>.installMessengerClientPlugins(json: Json) {
    install(ContentNegotiation) { json(json) }
    install(WebSockets)
}

/**
 * Talks to the relay server: per-device registration, prekey publish/fetch, and the WebSocket
 * relay. It only ever transmits public key material and ciphertext.
 */
class MessengerApiClient(
    private val baseUrl: String,
    private val httpClient: HttpClient = HttpClient { installMessengerClientPlugins(ClientJson) },
    private val json: Json = ClientJson,
) {
    var authToken: String? = null
        private set

    suspend fun register(request: RegisterRequest): String {
        val response: RegisterResponse = httpClient.post("$baseUrl/register") {
            contentType(ContentType.Application.Json)
            setBody(request)
        }.body()
        authToken = response.token
        return response.token
    }

    suspend fun uploadKeys(userId: String, deviceId: String, request: UploadKeysRequest) {
        httpClient.post("$baseUrl/keys/$userId/$deviceId") {
            contentType(ContentType.Application.Json)
            authToken?.let { header(HttpHeaders.Authorization, "Bearer $it") }
            setBody(request)
        }
    }

    /** Fetch prekey bundles for all of [userId]'s devices, or null if the user is unknown (404). */
    suspend fun fetchBundles(userId: String): DeviceBundles? {
        val response = httpClient.get("$baseUrl/keys/$userId")
        if (response.status == HttpStatusCode.NotFound) return null
        return response.body()
    }

    /** Open the realtime relay channel for (userId, deviceId), authenticated with the token. */
    suspend fun openRelay(userId: String, deviceId: String): RelayConnection {
        val tokenQuery = authToken?.let { "?token=$it" }.orEmpty()
        val wsUrl = baseUrl.replaceFirst("http", "ws") + "/ws/$userId/$deviceId" + tokenQuery
        return RelayConnection(httpClient.webSocketSession(wsUrl), json)
    }

    fun close() = httpClient.close()
}

/**
 * A live WebSocket relay channel. [incoming] streams envelopes the server delivers to us; [send]
 * transmits one and waits for the server's acceptance. After processing a delivered envelope, call
 * [ackDelivery] so the server drops it from this device's mailbox (at-least-once delivery).
 */
class RelayConnection internal constructor(
    private val session: DefaultClientWebSocketSession,
    private val json: Json,
) {
    private val deliveries = Channel<RelayEnvelope>(Channel.UNLIMITED)
    private val accepted = Channel<ServerFrame.Accepted>(Channel.UNLIMITED)
    private val sendMutex = Mutex()

    init {
        session.launch {
            try {
                for (frame in session.incoming) {
                    if (frame !is Frame.Text) continue
                    when (val serverFrame = json.decodeFromString(ServerFrame.serializer(), frame.readText())) {
                        is ServerFrame.Deliver -> deliveries.send(serverFrame.envelope)
                        is ServerFrame.Accepted -> accepted.send(serverFrame)
                    }
                }
            } finally {
                deliveries.close()
                accepted.close()
            }
        }
    }

    /** Stream of envelopes relayed to us. Collect from a single coroutine. */
    val incoming: Flow<RelayEnvelope> get() = deliveries.receiveAsFlow()

    /** Send [envelope] and wait for the server to accept it. */
    suspend fun send(envelope: RelayEnvelope): ServerFrame.Accepted = sendMutex.withLock {
        sendFrame(ClientFrame.Send(envelope))
        accepted.receive()
    }

    /** Acknowledge a delivered message so the server removes it from our mailbox. */
    suspend fun ackDelivery(messageId: String) = sendFrame(ClientFrame.Ack(messageId))

    /** Suspend until the next envelope is delivered (convenience for request/response flows). */
    suspend fun receiveNext(): RelayEnvelope = deliveries.receive()

    suspend fun close() = session.close()

    private suspend fun sendFrame(frame: ClientFrame) {
        session.send(Frame.Text(json.encodeToString(ClientFrame.serializer(), frame)))
    }
}
