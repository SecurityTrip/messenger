package com.messenger.server

import com.messenger.protocol.wire.RegisterRequest
import com.messenger.protocol.wire.RegisterResponse
import com.messenger.protocol.wire.RelayAck
import com.messenger.protocol.wire.RelayEnvelope
import com.messenger.protocol.wire.ServerFrame
import com.messenger.protocol.wire.UploadKeysRequest
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.websocket.DefaultWebSocketServerSession
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.webSocket
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import io.ktor.websocket.readText
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.util.concurrent.ConcurrentHashMap

fun main() {
    embeddedServer(Netty, port = 8080, host = "0.0.0.0") { messengerModule() }.start(wait = true)
}

@Serializable
private data class CountResponse(val count: Int)

private val serverJson = Json { ignoreUnknownKeys = true }

private suspend fun DefaultWebSocketServerSession.sendFrame(frame: ServerFrame) {
    send(Frame.Text(serverJson.encodeToString(ServerFrame.serializer(), frame)))
}

private fun ApplicationCall.bearerToken(): String? =
    request.headers[HttpHeaders.Authorization]
        ?.takeIf { it.startsWith("Bearer ") }
        ?.removePrefix("Bearer ")

/**
 * The relay server. It distributes prekey bundles and store-and-forwards encrypted envelopes
 * between clients over WebSockets. It cannot read message contents — it only sees ciphertext.
 */
fun Application.messengerModule(store: InMemoryStore = InMemoryStore()) {
    install(ContentNegotiation) { json(serverJson) }
    install(WebSockets)

    // Currently-connected clients, keyed by userId (single device per user for now).
    val connections = ConcurrentHashMap<String, DefaultWebSocketServerSession>()

    routing {
        post("/register") {
            val token = store.register(call.receive<RegisterRequest>())
            call.respond(RegisterResponse(token))
        }

        post("/keys/{userId}") {
            val userId = call.parameters["userId"] ?: return@post call.respond(HttpStatusCode.BadRequest)
            if (!store.exists(userId)) return@post call.respond(HttpStatusCode.NotFound)
            if (!store.validateToken(userId, call.bearerToken())) {
                return@post call.respond(HttpStatusCode.Unauthorized)
            }
            store.uploadKeys(userId, call.receive<UploadKeysRequest>())
            call.respond(HttpStatusCode.OK)
        }

        get("/keys/{userId}") {
            val userId = call.parameters["userId"] ?: return@get call.respond(HttpStatusCode.BadRequest)
            val bundle = store.fetchBundle(userId) ?: return@get call.respond(HttpStatusCode.NotFound)
            call.respond(bundle)
        }

        get("/keys/{userId}/count") {
            val userId = call.parameters["userId"] ?: return@get call.respond(HttpStatusCode.BadRequest)
            call.respond(CountResponse(store.unusedOneTimePreKeyCount(userId)))
        }

        webSocket("/ws/{userId}") {
            val userId = call.parameters["userId"]
            val token = call.request.queryParameters["token"]
            if (userId == null || !store.exists(userId) || !store.validateToken(userId, token)) {
                close(CloseReason(CloseReason.Codes.VIOLATED_POLICY, "unauthorized"))
                return@webSocket
            }
            connections[userId] = this
            try {
                // Deliver anything queued while this user was offline.
                store.drainQueue(userId).forEach { envelope -> sendFrame(ServerFrame.Deliver(envelope)) }

                for (frame in incoming) {
                    if (frame !is Frame.Text) continue
                    val envelope = serverJson.decodeFromString(RelayEnvelope.serializer(), frame.readText())
                    // Prevent sender spoofing: the envelope's "from" must be the authenticated user.
                    if (envelope.from != userId) {
                        sendFrame(ServerFrame.Ack(RelayAck(status = "rejected_sender_mismatch", queued = false)))
                        continue
                    }
                    val target = connections[envelope.to]
                    val queued: Boolean
                    if (target != null) {
                        target.sendFrame(ServerFrame.Deliver(envelope))
                        queued = false
                    } else {
                        store.enqueue(envelope)
                        queued = true
                    }
                    // Acknowledge to the sender (also makes delivery ordering observable to clients).
                    sendFrame(ServerFrame.Ack(RelayAck(queued = queued)))
                }
            } finally {
                connections.remove(userId, this)
            }
        }
    }
}
