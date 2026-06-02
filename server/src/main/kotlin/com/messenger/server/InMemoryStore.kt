package com.messenger.server

import com.messenger.protocol.wire.RegisterRequest
import com.messenger.protocol.wire.RelayEnvelope
import com.messenger.protocol.wire.UploadKeysRequest
import com.messenger.protocol.wire.WireOneTimePreKey
import com.messenger.protocol.wire.WirePreKeyBundle
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * In-memory backing store for the dev relay server. Holds only public key material and ciphertext
 * envelopes — never plaintext or private keys. Swap for a persistent store (Postgres/Redis) later.
 */
class InMemoryStore {

    private data class Account(val userId: String, val identityKey: String, val registrationId: Int)

    private class KeyMaterial(
        @Volatile var signedPreKeyId: Int,
        @Volatile var signedPreKey: String,
        @Volatile var signedPreKeySignature: String,
        val oneTimePreKeys: ArrayDeque<WireOneTimePreKey>,
    )

    private val accounts = ConcurrentHashMap<String, Account>()
    private val keys = ConcurrentHashMap<String, KeyMaterial>()
    private val queues = ConcurrentHashMap<String, ConcurrentLinkedQueue<RelayEnvelope>>()
    private val tokens = ConcurrentHashMap<String, String>()
    private val secureRandom = SecureRandom()

    /** Register (or re-register) the account and return a fresh bearer token. */
    fun register(request: RegisterRequest): String {
        accounts[request.userId] = Account(request.userId, request.identityKey, request.registrationId)
        val token = newToken()
        tokens[request.userId] = token
        return token
    }

    fun exists(userId: String): Boolean = accounts.containsKey(userId)

    /** Constant-time-ish check that [token] is the current token issued to [userId]. */
    fun validateToken(userId: String, token: String?): Boolean {
        if (token == null) return false
        val expected = tokens[userId] ?: return false
        return expected == token
    }

    private fun newToken(): String {
        val bytes = ByteArray(32).also { secureRandom.nextBytes(it) }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    @Synchronized
    fun uploadKeys(userId: String, request: UploadKeysRequest) {
        keys[userId] = KeyMaterial(
            signedPreKeyId = request.signedPreKeyId,
            signedPreKey = request.signedPreKey,
            signedPreKeySignature = request.signedPreKeySignature,
            oneTimePreKeys = ArrayDeque(request.oneTimePreKeys),
        )
    }

    /** Build a prekey bundle, consuming one one-time prekey if any remain. */
    @Synchronized
    fun fetchBundle(userId: String): WirePreKeyBundle? {
        val account = accounts[userId] ?: return null
        val material = keys[userId] ?: return null
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

    fun unusedOneTimePreKeyCount(userId: String): Int = keys[userId]?.let { synchronized(this) { it.oneTimePreKeys.size } } ?: 0

    fun enqueue(envelope: RelayEnvelope) {
        queues.computeIfAbsent(envelope.to) { ConcurrentLinkedQueue() }.add(envelope)
    }

    /** Remove and return all queued envelopes for [userId] (delivered on (re)connect). */
    fun drainQueue(userId: String): List<RelayEnvelope> {
        val queue = queues[userId] ?: return emptyList()
        val drained = ArrayList<RelayEnvelope>()
        while (true) {
            drained.add(queue.poll() ?: break)
        }
        return drained
    }
}
