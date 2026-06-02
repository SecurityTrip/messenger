package com.messenger.server

import com.messenger.protocol.wire.ClientFrame
import com.messenger.protocol.wire.RegisterRequest
import com.messenger.protocol.wire.RegisterResponse
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
import kotlinx.serialization.json.Json
import java.util.concurrent.ConcurrentHashMap

fun main() {
    embeddedServer(Netty, port = 8080, host = "0.0.0.0") { messengerModule() }.start(wait = true)
}

private val serverJson = Json { ignoreUnknownKeys = true }

private fun connectionKey(userId: String, deviceId: String) = "$userId $deviceId"

private suspend fun DefaultWebSocketServerSession.sendFrame(frame: ServerFrame) {
    send(Frame.Text(serverJson.encodeToString(ServerFrame.serializer(), frame)))
}

private fun ApplicationCall.bearerToken(): String? =
    request.headers[HttpHeaders.Authorization]
        ?.takeIf { it.startsWith("Bearer ") }
        ?.removePrefix("Bearer ")

/**
 * The relay server. Distributes per-device prekey bundles and store-and-forwards encrypted
 * envelopes between devices over WebSockets with at-least-once delivery (a per-device [MailboxStore]
 * holds messages until the recipient acknowledges them). It cannot read message contents.
 */
fun Application.messengerModule(
    store: InMemoryStore = InMemoryStore(),
    mailbox: MailboxStore = InMemoryMailboxStore(),
) {
    install(ContentNegotiation) { json(serverJson) }
    install(WebSockets)

    // Connected devices, keyed by (userId, deviceId).
    val connections = ConcurrentHashMap<String, DefaultWebSocketServerSession>()

    routing {
        post("/register") {
            val token = store.register(call.receive<RegisterRequest>())
            call.respond(RegisterResponse(token))
        }

        post("/keys/{userId}/{deviceId}") {
            val userId = call.parameters["userId"] ?: return@post call.respond(HttpStatusCode.BadRequest)
            val deviceId = call.parameters["deviceId"] ?: return@post call.respond(HttpStatusCode.BadRequest)
            if (!store.exists(userId, deviceId)) return@post call.respond(HttpStatusCode.NotFound)
            if (!store.validateToken(userId, deviceId, call.bearerToken())) {
                return@post call.respond(HttpStatusCode.Unauthorized)
            }
            store.uploadKeys(userId, deviceId, call.receive<UploadKeysRequest>())
            call.respond(HttpStatusCode.OK)
        }

        get("/keys/{userId}") {
            val userId = call.parameters["userId"] ?: return@get call.respond(HttpStatusCode.BadRequest)
            val bundles = store.fetchAllBundles(userId) ?: return@get call.respond(HttpStatusCode.NotFound)
            call.respond(bundles)
        }

        webSocket("/ws/{userId}/{deviceId}") {
            val userId = call.parameters["userId"]
            val deviceId = call.parameters["deviceId"]
            val token = call.request.queryParameters["token"]
            if (userId == null || deviceId == null || !store.exists(userId, deviceId) ||
                !store.validateToken(userId, deviceId, token)
            ) {
                close(CloseReason(CloseReason.Codes.VIOLATED_POLICY, "unauthorized"))
                return@webSocket
            }

            val key = connectionKey(userId, deviceId)
            connections[key] = this
            try {
                // (Re)deliver everything still pending for this device.
                mailbox.pending(userId, deviceId).forEach { sendFrame(ServerFrame.Deliver(it)) }

                for (frame in incoming) {
                    if (frame !is Frame.Text) continue
                    when (val clientFrame = serverJson.decodeFromString(ClientFrame.serializer(), frame.readText())) {
                        is ClientFrame.Send -> {
                            val envelope = clientFrame.envelope
                            // Prevent sender spoofing: "from" must be the authenticated device.
                            if (envelope.fromUser != userId || envelope.fromDevice != deviceId) {
                                close(CloseReason(CloseReason.Codes.VIOLATED_POLICY, "sender mismatch"))
                                return@webSocket
                            }
                            mailbox.put(envelope.toUser, envelope.toDevice, envelope)
                            val target = connections[connectionKey(envelope.toUser, envelope.toDevice)]
                            target?.sendFrame(ServerFrame.Deliver(envelope))
                            sendFrame(ServerFrame.Accepted(envelope.messageId, queued = target == null))
                        }

                        is ClientFrame.Ack -> {
                            // This device confirms receipt of a delivered message → drop from its mailbox.
                            mailbox.remove(userId, deviceId, clientFrame.messageId)
                        }
                    }
                }
            } finally {
                connections.remove(key, this)
            }
        }
    }
}
