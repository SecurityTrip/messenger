package com.messenger.data

import app.cash.sqldelight.coroutines.asFlow
import app.cash.sqldelight.coroutines.mapToList
import com.messenger.db.MessengerDatabase
import com.messenger.domain.ChatMessage
import com.messenger.domain.MessageDirection
import com.messenger.domain.MessageStatus
import com.messenger.security.BlobCipher
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlin.coroutines.CoroutineContext

/** Stores chat history with message bodies encrypted at rest via [cipher]. */
class MessageStore(
    private val db: MessengerDatabase,
    private val cipher: BlobCipher,
) {
    fun insert(message: ChatMessage) {
        db.messageQueries.insertMessage(
            id = message.id,
            contactId = message.contactId,
            direction = message.direction.ordinal.toLong(),
            bodyEnc = cipher.encrypt(message.body.encodeToByteArray()),
            timestamp = message.timestamp,
            status = message.status.ordinal.toLong(),
        )
    }

    fun messagesForContact(contactId: String): List<ChatMessage> =
        db.messageQueries.selectMessagesForContact(contactId).executeAsList().map { it.toChatMessage() }

    /** A reactive stream of the conversation, updating whenever messages change. */
    fun observeMessages(contactId: String, context: CoroutineContext): Flow<List<ChatMessage>> =
        db.messageQueries.selectMessagesForContact(contactId)
            .asFlow()
            .mapToList(context)
            .map { rows -> rows.map { it.toChatMessage() } }

    fun updateStatus(id: String, status: MessageStatus) =
        db.messageQueries.updateMessageStatus(status.ordinal.toLong(), id)

    private fun com.messenger.db.Message.toChatMessage(): ChatMessage = ChatMessage(
        id = id,
        contactId = contactId,
        direction = MessageDirection.fromOrdinal(direction.toInt()),
        body = cipher.decrypt(bodyEnc)?.decodeToString() ?: "<decryption failed>",
        timestamp = timestamp,
        status = MessageStatus.fromOrdinal(status.toInt()),
    )
}
