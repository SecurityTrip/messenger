package com.messenger.protocol.ratchet

import com.messenger.crypto.CryptoProvider
import com.messenger.crypto.DhKeyPair
import com.messenger.crypto.fromBase64
import com.messenger.crypto.toBase64

/**
 * Double Ratchet session (Signal spec: https://signal.org/docs/specifications/doubleratchet/).
 *
 * Combines a **DH ratchet** (a new DH key pair each round-trip → post-compromise security) with
 * **symmetric chain ratchets** for sending/receiving (a new message key per message → forward
 * secrecy). Out-of-order and missing messages are handled by storing skipped message keys.
 *
 * Create a session with [initAlice] (the X3DH initiator) or [initBob] (the responder). Bob cannot
 * [encrypt] until he has [decrypt]ed at least one message (his sending chain is established by the
 * first DH ratchet step).
 *
 * This class is **not** thread-safe; serialize access per conversation.
 */
class DoubleRatchet private constructor(
    private val crypto: CryptoProvider,
    private val state: State,
) {

    fun encrypt(plaintext: ByteArray): RatchetMessage {
        val sendChainKey = state.sendChainKey
            ?: throw DoubleRatchetException("No sending chain yet — receive a message before sending")

        val (nextChainKey, messageKey) = kdfChainKey(sendChainKey)
        state.sendChainKey = nextChainKey

        val header = DoubleRatchetHeader(
            ratchetPublicKey = state.selfRatchet.publicKey,
            previousChainLength = state.previousSendCount,
            messageNumber = state.sendCount,
        )
        state.sendCount += 1

        val (encKey, nonce) = deriveMessageKeys(messageKey)
        val aad = state.associatedData + header.encode()
        val ciphertext = crypto.aeadEncrypt(encKey, nonce, plaintext, aad)
        return RatchetMessage(header, ciphertext)
    }

    fun decrypt(message: RatchetMessage): ByteArray {
        // 1. Was this message's key already derived & stored as skipped?
        trySkippedMessageKey(message)?.let { return it }

        // 2. New ratchet public key from the peer → perform a DH ratchet step.
        val remote = state.remoteRatchet
        if (remote == null || !message.header.ratchetPublicKey.contentEquals(remote)) {
            skipMessageKeys(message.header.previousChainLength)
            dhRatchet(message.header)
        }

        // 3. Skip ahead within the current receiving chain to this message's number.
        skipMessageKeys(message.header.messageNumber)

        // 4. Derive this message's key and advance the receiving chain.
        val recvChainKey = state.recvChainKey
            ?: throw DoubleRatchetException("No receiving chain established")
        val (nextChainKey, messageKey) = kdfChainKey(recvChainKey)
        state.recvChainKey = nextChainKey
        state.recvCount += 1

        return decryptWith(messageKey, message)
    }

    /**
     * Capture the full session state for persistence. The result contains private keys — store it
     * only encrypted at rest. Restore later with [restore].
     */
    fun export(): RatchetStateSnapshot = RatchetStateSnapshot(
        selfRatchetPublic = state.selfRatchet.publicKey.toBase64(),
        selfRatchetPrivate = state.selfRatchet.privateKey.toBase64(),
        remoteRatchet = state.remoteRatchet?.toBase64(),
        rootKey = state.rootKey.toBase64(),
        sendChainKey = state.sendChainKey?.toBase64(),
        recvChainKey = state.recvChainKey?.toBase64(),
        sendCount = state.sendCount,
        recvCount = state.recvCount,
        previousSendCount = state.previousSendCount,
        skipped = state.skipped.entries.map { (id, messageKey) ->
            SkippedKeySnapshot(id.ratchetPublicKey.toBase64(), id.messageNumber, messageKey.toBase64())
        },
        associatedData = state.associatedData.toBase64(),
    )

    // --- DH ratchet ---

    private fun dhRatchet(header: DoubleRatchetHeader) {
        state.previousSendCount = state.sendCount
        state.sendCount = 0
        state.recvCount = 0
        state.remoteRatchet = header.ratchetPublicKey

        // Derive the receiving chain from a DH with the peer's new ratchet key.
        val (rootAfterRecv, recvChainKey) = kdfRootKey(
            state.rootKey,
            crypto.dh(state.selfRatchet.privateKey, header.ratchetPublicKey),
        )
        state.rootKey = rootAfterRecv
        state.recvChainKey = recvChainKey

        // Rotate our own ratchet key and derive the new sending chain.
        state.selfRatchet = crypto.generateDhKeyPair()
        val (rootAfterSend, sendChainKey) = kdfRootKey(
            state.rootKey,
            crypto.dh(state.selfRatchet.privateKey, header.ratchetPublicKey),
        )
        state.rootKey = rootAfterSend
        state.sendChainKey = sendChainKey
    }

    // --- skipped message keys (out-of-order / dropped delivery) ---

    private fun trySkippedMessageKey(message: RatchetMessage): ByteArray? {
        val id = SkippedKeyId(message.header.ratchetPublicKey, message.header.messageNumber)
        val messageKey = state.skipped[id] ?: return null
        val plaintext = decryptWith(messageKey, message)
        state.skipped.remove(id) // a skipped key is single-use
        return plaintext
    }

    private fun skipMessageKeys(until: Int) {
        if (state.recvCount + MAX_SKIP < until) {
            throw DoubleRatchetException("Too many skipped messages (${until - state.recvCount} > $MAX_SKIP)")
        }
        val chainKey = state.recvChainKey ?: return
        var currentChainKey = chainKey
        while (state.recvCount < until) {
            val (nextChainKey, messageKey) = kdfChainKey(currentChainKey)
            currentChainKey = nextChainKey
            val id = SkippedKeyId(requireNotNull(state.remoteRatchet), state.recvCount)
            state.skipped[id] = messageKey
            evictOldestSkippedIfNeeded()
            state.recvCount += 1
        }
        state.recvChainKey = currentChainKey
    }

    private fun evictOldestSkippedIfNeeded() {
        if (state.skipped.size > MAX_SKIP_STORED) {
            val oldest = state.skipped.keys.firstOrNull() ?: return
            state.skipped.remove(oldest)
        }
    }

    // --- AEAD ---

    private fun decryptWith(messageKey: ByteArray, message: RatchetMessage): ByteArray {
        val (encKey, nonce) = deriveMessageKeys(messageKey)
        val aad = state.associatedData + message.header.encode()
        return crypto.aeadDecrypt(encKey, nonce, message.ciphertext, aad)
            ?: throw DoubleRatchetException("Message authentication failed")
    }

    /** Expand a message key into an AEAD (encryption key, nonce) pair via HKDF. */
    private fun deriveMessageKeys(messageKey: ByteArray): Pair<ByteArray, ByteArray> {
        val okm = crypto.hkdf(
            ikm = messageKey,
            salt = ByteArray(CryptoProvider.HASH_SIZE),
            info = MESSAGE_KEY_INFO,
            length = CryptoProvider.AEAD_KEY_SIZE + CryptoProvider.AEAD_NONCE_SIZE,
        )
        val encKey = okm.copyOf(CryptoProvider.AEAD_KEY_SIZE)
        val nonce = okm.copyOfRange(CryptoProvider.AEAD_KEY_SIZE, okm.size)
        return encKey to nonce
    }

    // --- KDFs ---

    /** KDF_RK: (rootKey', chainKey) = HKDF(salt = rootKey, ikm = dhOutput). */
    private fun kdfRootKey(rootKey: ByteArray, dhOutput: ByteArray): Pair<ByteArray, ByteArray> {
        val okm = crypto.hkdf(ikm = dhOutput, salt = rootKey, info = ROOT_KEY_INFO, length = 64)
        return okm.copyOf(32) to okm.copyOfRange(32, 64)
    }

    /** KDF_CK: chainKey' = HMAC(chainKey, 0x02); messageKey = HMAC(chainKey, 0x01). */
    private fun kdfChainKey(chainKey: ByteArray): Pair<ByteArray, ByteArray> {
        val messageKey = crypto.hmacSha256(chainKey, byteArrayOf(0x01))
        val nextChainKey = crypto.hmacSha256(chainKey, byteArrayOf(0x02))
        return nextChainKey to messageKey
    }

    private class State(
        var selfRatchet: DhKeyPair,
        var remoteRatchet: ByteArray?,
        var rootKey: ByteArray,
        var sendChainKey: ByteArray?,
        var recvChainKey: ByteArray?,
        var sendCount: Int,
        var recvCount: Int,
        var previousSendCount: Int,
        val skipped: MutableMap<SkippedKeyId, ByteArray>,
        val associatedData: ByteArray,
    )

    private class SkippedKeyId(val ratchetPublicKey: ByteArray, val messageNumber: Int) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is SkippedKeyId) return false
            return messageNumber == other.messageNumber && ratchetPublicKey.contentEquals(other.ratchetPublicKey)
        }

        override fun hashCode(): Int = 31 * ratchetPublicKey.contentHashCode() + messageNumber
    }

    companion object {
        /** Reject a single jump of more than this many missing messages (anti-DoS). */
        const val MAX_SKIP = 1000

        /** Cap on retained skipped message keys across the session. */
        const val MAX_SKIP_STORED = 2000

        private val ROOT_KEY_INFO = "Messenger_DoubleRatchet_RootKey_v1".encodeToByteArray()
        private val MESSAGE_KEY_INFO = "Messenger_DoubleRatchet_MessageKey_v1".encodeToByteArray()

        /**
         * Initialize the **initiator's** session (Alice). [sharedSecret] is the X3DH output and
         * [remoteSignedPreKey] is Bob's signed prekey public, which doubles as his initial ratchet
         * key. [associatedData] is the X3DH AD (IK_A || IK_B) bound into every message.
         */
        fun initAlice(
            crypto: CryptoProvider,
            sharedSecret: ByteArray,
            remoteSignedPreKey: ByteArray,
            associatedData: ByteArray,
        ): DoubleRatchet {
            val selfRatchet = crypto.generateDhKeyPair()
            val okm = crypto.hkdf(
                ikm = crypto.dh(selfRatchet.privateKey, remoteSignedPreKey),
                salt = sharedSecret,
                info = ROOT_KEY_INFO,
                length = 64,
            )
            val state = State(
                selfRatchet = selfRatchet,
                remoteRatchet = remoteSignedPreKey,
                rootKey = okm.copyOf(32),
                sendChainKey = okm.copyOfRange(32, 64),
                recvChainKey = null,
                sendCount = 0,
                recvCount = 0,
                previousSendCount = 0,
                skipped = LinkedHashMap(),
                associatedData = associatedData,
            )
            return DoubleRatchet(crypto, state)
        }

        /**
         * Initialize the **responder's** session (Bob). [signedPreKey] is Bob's signed prekey key
         * pair (the same key Alice used as her initial remote ratchet key).
         */
        fun initBob(
            crypto: CryptoProvider,
            sharedSecret: ByteArray,
            signedPreKey: DhKeyPair,
            associatedData: ByteArray,
        ): DoubleRatchet {
            val state = State(
                selfRatchet = signedPreKey,
                remoteRatchet = null,
                rootKey = sharedSecret,
                sendChainKey = null,
                recvChainKey = null,
                sendCount = 0,
                recvCount = 0,
                previousSendCount = 0,
                skipped = LinkedHashMap(),
                associatedData = associatedData,
            )
            return DoubleRatchet(crypto, state)
        }

        /** Rebuild a session previously captured with [export]. */
        fun restore(crypto: CryptoProvider, snapshot: RatchetStateSnapshot): DoubleRatchet {
            val skipped = LinkedHashMap<SkippedKeyId, ByteArray>()
            for (entry in snapshot.skipped) {
                skipped[SkippedKeyId(entry.ratchetPublicKey.fromBase64(), entry.messageNumber)] =
                    entry.messageKey.fromBase64()
            }
            val state = State(
                selfRatchet = DhKeyPair(
                    publicKey = snapshot.selfRatchetPublic.fromBase64(),
                    privateKey = snapshot.selfRatchetPrivate.fromBase64(),
                ),
                remoteRatchet = snapshot.remoteRatchet?.fromBase64(),
                rootKey = snapshot.rootKey.fromBase64(),
                sendChainKey = snapshot.sendChainKey?.fromBase64(),
                recvChainKey = snapshot.recvChainKey?.fromBase64(),
                sendCount = snapshot.sendCount,
                recvCount = snapshot.recvCount,
                previousSendCount = snapshot.previousSendCount,
                skipped = skipped,
                associatedData = snapshot.associatedData.fromBase64(),
            )
            return DoubleRatchet(crypto, state)
        }
    }
}
