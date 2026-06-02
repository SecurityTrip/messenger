package com.messenger.net

import com.messenger.protocol.wire.RegisterRequest
import com.messenger.protocol.wire.RegisterResponse
import com.messenger.protocol.wire.RelayAck
import com.messenger.protocol.wire.RelayEnvelope
import com.messenger.protocol.wire.ServerFrame
import com.messenger.protocol.wire.UploadKeysRequest
import com.messenger.protocol.wire.WirePreKeyBundle
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

/** JSON used by the client; tolerant of unknown fields for forward compatibility. */
private val ClientJson = Json { ignoreUnknownKeys = true }

internal fun HttpClientConfig<*>.installMessengerClientPlugins(json: Json) {
    install(ContentNegotiation) { json(json) }
    install(WebSockets)
}

/**
 * Talks to the relay server: account registration, prekey publish/fetch, and the WebSocket relay.
 * It only ever transmits public key material and ciphertext.
 */
class MessengerApiClient(
    private val baseUrl: String,
    private val httpClient: HttpClient = HttpClient { installMessengerClientPlugins(ClientJson) },
    private val json: Json = ClientJson,
) {
    /** Bearer token from registration, attached to authenticated calls. */
    var authToken: String? = null
        private set

    /** Register the account; stores and returns the issued bearer token. */
    suspend fun register(request: RegisterRequest): String {
        val response: RegisterResponse = httpClient.post("$baseUrl/register") {
            contentType(ContentType.Application.Json)
            setBody(request)
        }.body()
        authToken = response.token
        return response.token
    }

    suspend fun uploadKeys(userId: String, request: UploadKeysRequest) {
        httpClient.post("$baseUrl/keys/$userId") {
            contentType(ContentType.Application.Json)
            authToken?.let { header(HttpHeaders.Authorization, "Bearer $it") }
            setBody(request)
        }
    }

    /** Fetch a prekey bundle for [userId], or null if the user/keys are unknown (404). */
    suspend fun fetchBundle(userId: String): WirePreKeyBundle? {
        val response = httpClient.get("$baseUrl/keys/$userId")
        if (response.status == HttpStatusCode.NotFound) return null
        return response.body()
    }

    /** Open the realtime relay channel for [userId] (authenticated with the registration token). */
    suspend fun openRelay(userId: String): RelayConnection {
        val tokenQuery = authToken?.let { "?token=$it" }.orEmpty()
        val wsUrl = baseUrl.replaceFirst("http", "ws") + "/ws/$userId" + tokenQuery
        return RelayConnection(httpClient.webSocketSession(wsUrl), json)
    }

    fun close() = httpClient.close()
}

/**
 * A live WebSocket relay channel. [incoming] is the stream of messages delivered to us; [send]
 * transmits an envelope and suspends until the server's delivery/queue acknowledgement returns.
 * Not safe for concurrent [send] from multiple coroutines beyond the internal ordering guarantee.
 */
class RelayConnection internal constructor(
    private val session: DefaultClientWebSocketSession,
    private val json: Json,
) {
    private val deliveries = Channel<RelayEnvelope>(Channel.UNLIMITED)
    private val acks = Channel<RelayAck>(Channel.UNLIMITED)
    private val sendMutex = Mutex()

    init {
        session.launch {
            try {
                for (frame in session.incoming) {
                    if (frame !is Frame.Text) continue
                    when (val serverFrame = json.decodeFromString(ServerFrame.serializer(), frame.readText())) {
                        is ServerFrame.Deliver -> deliveries.send(serverFrame.envelope)
                        is ServerFrame.Ack -> acks.send(serverFrame.ack)
                    }
                }
            } finally {
                deliveries.close()
                acks.close()
            }
        }
    }

    /** Stream of messages relayed to us. Collect from a single coroutine. */
    val incoming: Flow<RelayEnvelope> get() = deliveries.receiveAsFlow()

    /** Send [envelope] and wait for the server acknowledgement. */
    suspend fun send(envelope: RelayEnvelope): RelayAck = sendMutex.withLock {
        session.send(Frame.Text(json.encodeToString(RelayEnvelope.serializer(), envelope)))
        acks.receive()
    }

    /** Suspend until the next message is delivered to us (convenience for request/response flows). */
    suspend fun receiveNext(): RelayEnvelope = deliveries.receive()

    suspend fun close() = session.close()
}
