package com.messenger.server

import com.messenger.protocol.wire.DeviceBundle
import com.messenger.protocol.wire.DeviceBundles
import com.messenger.protocol.wire.RegisterRequest
import com.messenger.protocol.wire.UploadKeysRequest
import com.messenger.protocol.wire.WireOneTimePreKey
import com.messenger.protocol.wire.WirePreKeyBundle
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/**
 * In-memory accounts/keys/tokens for the dev relay server, addressed per (userId, deviceId). Holds
 * only public key material — never plaintext or private keys. Swap for a persistent store later.
 */
class InMemoryStore {

    private data class Account(val userId: String, val deviceId: String, val identityKey: String, val registrationId: Int)

    private class KeyMaterial(
        @Volatile var signedPreKeyId: Int,
        @Volatile var signedPreKey: String,
        @Volatile var signedPreKeySignature: String,
        val oneTimePreKeys: ArrayDeque<WireOneTimePreKey>,
    )

    // userId -> deviceId -> value
    private val accounts = ConcurrentHashMap<String, ConcurrentHashMap<String, Account>>()
    private val keys = ConcurrentHashMap<String, ConcurrentHashMap<String, KeyMaterial>>()
    private val tokens = ConcurrentHashMap<String, ConcurrentHashMap<String, String>>()
    private val secureRandom = SecureRandom()

    /** Register (or re-register) a device and return a fresh bearer token. */
    fun register(request: RegisterRequest): String {
        accounts.getOrPut(request.userId) { ConcurrentHashMap() }[request.deviceId] =
            Account(request.userId, request.deviceId, request.identityKey, request.registrationId)
        val token = newToken()
        tokens.getOrPut(request.userId) { ConcurrentHashMap() }[request.deviceId] = token
        return token
    }

    fun exists(userId: String, deviceId: String): Boolean = accounts[userId]?.containsKey(deviceId) == true

    fun validateToken(userId: String, deviceId: String, token: String?): Boolean {
        if (token == null) return false
        return tokens[userId]?.get(deviceId) == token
    }

    @Synchronized
    fun uploadKeys(userId: String, deviceId: String, request: UploadKeysRequest) {
        keys.getOrPut(userId) { ConcurrentHashMap() }[deviceId] = KeyMaterial(
            signedPreKeyId = request.signedPreKeyId,
            signedPreKey = request.signedPreKey,
            signedPreKeySignature = request.signedPreKeySignature,
            oneTimePreKeys = ArrayDeque(request.oneTimePreKeys),
        )
    }

    /** Prekey bundles for every registered device of [userId], consuming one OTK each. */
    @Synchronized
    fun fetchAllBundles(userId: String): DeviceBundles? {
        val devices = accounts[userId] ?: return null
        if (devices.isEmpty()) return null
        val bundles = devices.keys.sorted().mapNotNull { deviceId ->
            bundleLocked(userId, deviceId)?.let { DeviceBundle(deviceId, it) }
        }
        if (bundles.isEmpty()) return null
        return DeviceBundles(userId, bundles)
    }

    private fun bundleLocked(userId: String, deviceId: String): WirePreKeyBundle? {
        val account = accounts[userId]?.get(deviceId) ?: return null
        val material = keys[userId]?.get(deviceId) ?: return null
        val oneTime = material.oneTimePreKeys.removeFirstOrNull()
        return WirePreKeyBundle(
            identityKey = account.identityKey,
            signedPreKeyId = material.signedPreKeyId,
            signedPreKey = material.signedPreKey,
            signedPreKeySignature = material.signedPreKeySignature,
            oneTimePreKeyId = oneTime?.id,
            oneTimePreKey = oneTime?.publicKey,
        )
    }

    private fun newToken(): String {
        val bytes = ByteArray(32).also { secureRandom.nextBytes(it) }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
}
