package com.messenger.domain

/** Who sent a message, from this device's point of view. */
enum class MessageDirection {
    INCOMING,
    OUTGOING,
    ;

    companion object {
        fun fromOrdinal(ordinal: Int): MessageDirection = entries[ordinal]
    }
}

/** Delivery lifecycle of an outgoing (or incoming) message. */
enum class MessageStatus {
    SENDING,
    SENT,
    DELIVERED,
    READ,
    FAILED,
    ;

    companion object {
        fun fromOrdinal(ordinal: Int): MessageStatus = entries[ordinal]
    }
}

/** A decrypted chat message as the UI sees it. */
data class ChatMessage(
    val id: String,
    val contactId: String,
    val direction: MessageDirection,
    val body: String,
    val timestamp: Long,
    val status: MessageStatus,
)

/** A remote peer. [identityPublicKey] is their Ed25519 identity (basis for safety-number checks). */
class Contact(
    val userId: String,
    val identityPublicKey: ByteArray,
    val displayName: String?,
    val verified: Boolean,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Contact) return false
        return userId == other.userId &&
            identityPublicKey.contentEquals(other.identityPublicKey) &&
            displayName == other.displayName &&
            verified == other.verified
    }

    override fun hashCode(): Int {
        var result = userId.hashCode()
        result = 31 * result + identityPublicKey.contentHashCode()
        result = 31 * result + (displayName?.hashCode() ?: 0)
        result = 31 * result + verified.hashCode()
        return result
    }
}
