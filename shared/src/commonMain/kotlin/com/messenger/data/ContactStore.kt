package com.messenger.data

import com.messenger.db.MessengerDatabase
import com.messenger.domain.Contact

/** Stores remote peers (their identity key, display name, verification status). */
class ContactStore(private val db: MessengerDatabase) {

    fun upsert(contact: Contact) {
        db.contactQueries.upsertContact(
            userId = contact.userId,
            identityPublicKey = contact.identityPublicKey,
            displayName = contact.displayName,
            verified = if (contact.verified) 1L else 0L,
        )
    }

    fun get(userId: String): Contact? {
        val row = db.contactQueries.selectContact(userId).executeAsOneOrNull() ?: return null
        return Contact(row.userId, row.identityPublicKey, row.displayName, row.verified != 0L)
    }

    fun all(): List<Contact> =
        db.contactQueries.selectAllContacts().executeAsList().map {
            Contact(it.userId, it.identityPublicKey, it.displayName, it.verified != 0L)
        }

    fun setVerified(userId: String, verified: Boolean) =
        db.contactQueries.setContactVerified(if (verified) 1L else 0L, userId)
}
