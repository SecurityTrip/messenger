package com.messenger.net

import com.messenger.protocol.wire.DeviceBundle
import com.messenger.protocol.wire.DeviceBundles
import com.messenger.protocol.wire.RegisterRequest
import com.messenger.protocol.wire.RegisterResponse
import com.messenger.protocol.wire.UploadKeysRequest
import com.messenger.protocol.wire.WireOneTimePreKey
import com.messenger.protocol.wire.WirePreKeyBundle
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class MessengerApiClientTest {

    private val json = Json { ignoreUnknownKeys = true }

    private fun clientWith(engine: MockEngine) =
        MessengerApiClient(
            baseUrl = "http://test",
            httpClient = HttpClient(engine) { install(ContentNegotiation) { json(json) } },
            json = json,
        )

    @Test
    fun fetchBundles_parsesServerResponse() = runTest {
        val bundles = DeviceBundles(
            userId = "bob",
            devices = listOf(
                DeviceBundle("phone", WirePreKeyBundle("aWs=", 1, "c3Br", "c2ln", 100, "b3Rr")),
                DeviceBundle("laptop", WirePreKeyBundle("aWsy", 1, "c3Br", "c2ln", null, null)),
            ),
        )
        val engine = MockEngine {
            respond(
                content = json.encodeToString(DeviceBundles.serializer(), bundles),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json"),
            )
        }

        val result = clientWith(engine).fetchBundles("bob")
        assertEquals(2, result?.devices?.size)
        assertEquals("phone", result?.devices?.first()?.deviceId)
        assertEquals(100, result?.devices?.first()?.bundle?.oneTimePreKeyId)
    }

    @Test
    fun fetchBundles_returnsNullOn404() = runTest {
        val engine = MockEngine { respond("", HttpStatusCode.NotFound) }
        assertNull(clientWith(engine).fetchBundles("ghost"))
    }

    @Test
    fun registerStoresToken_andUploadKeysSendsBearer() = runTest {
        val engine = MockEngine { request ->
            when (request.url.encodedPath) {
                "/register" -> respond(
                    content = json.encodeToString(RegisterResponse.serializer(), RegisterResponse("tok123")),
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json"),
                )
                else -> respond("", HttpStatusCode.OK)
            }
        }
        val client = clientWith(engine)

        val token = client.register(RegisterRequest("alice", "aliceD", "aWs=", registrationId = 5))
        assertEquals("tok123", token)
        assertEquals("tok123", client.authToken)

        client.uploadKeys("alice", "aliceD", UploadKeysRequest(1, "c3Br", "c2ln", listOf(WireOneTimePreKey(1, "b3Rr"))))

        assertEquals(2, engine.requestHistory.size)
        assertEquals("/register", engine.requestHistory[0].url.encodedPath)
        assertEquals("/keys/alice/aliceD", engine.requestHistory[1].url.encodedPath)
        assertEquals(HttpMethod.Post, engine.requestHistory[1].method)
        assertEquals("Bearer tok123", engine.requestHistory[1].headers[HttpHeaders.Authorization])
    }
}
