package com.messenger.security

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.CoreFoundation.CFDataCreate
import platform.CoreFoundation.CFDataGetBytePtr
import platform.CoreFoundation.CFDataGetLength
import platform.CoreFoundation.CFDataRef
import platform.CoreFoundation.CFDictionaryAddValue
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFStringCreateWithCString
import platform.CoreFoundation.CFStringRef
import platform.CoreFoundation.CFTypeRefVar
import platform.CoreFoundation.kCFBooleanTrue
import platform.CoreFoundation.kCFStringEncodingUTF8
import platform.Security.SecItemAdd
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.errSecItemNotFound
import platform.Security.errSecSuccess
import platform.Security.kSecAttrAccessible
import platform.Security.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
import platform.Security.kSecAttrAccount
import platform.Security.kSecAttrService
import platform.Security.kSecClass
import platform.Security.kSecClassGenericPassword
import platform.Security.kSecMatchLimit
import platform.Security.kSecMatchLimitOne
import platform.Security.kSecReturnData
import platform.Security.kSecValueData
import platform.posix.memcpy

/**
 * iOS Keychain-backed [SecureKeyStore]. Each secret is stored as a generic-password item keyed by
 * ([service], alias). This is the production store for the at-rest [MasterKey] on a real device /
 * the simulator. Items are written `AfterFirstUnlockThisDeviceOnly`: readable in the background once
 * the device has been unlocked once after boot, never synced to iCloud, and never migrated to a new
 * device. (Compiled on macOS/CI.)
 */
@OptIn(ExperimentalForeignApi::class)
class KeychainSecureKeyStore(
    private val service: String = DEFAULT_SERVICE,
) : SecureKeyStore {

    override fun get(alias: String): ByteArray? = memScoped {
        val cfService = cfString(service)
        val cfAccount = cfString(alias)
        val query = CFDictionaryCreateMutable(null, 0, null, null)
        CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword)
        CFDictionaryAddValue(query, kSecAttrService, cfService)
        CFDictionaryAddValue(query, kSecAttrAccount, cfAccount)
        CFDictionaryAddValue(query, kSecReturnData, kCFBooleanTrue)
        CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitOne)

        val result = alloc<CFTypeRefVar>()
        val status = SecItemCopyMatching(query, result.ptr)

        val bytes = if (status == errSecSuccess) {
            val data: CFDataRef? = result.value?.reinterpret()
            data?.let { cfDataToByteArray(it) }.also { if (data != null) CFRelease(data) }
        } else {
            null
        }

        CFRelease(query)
        CFRelease(cfService)
        CFRelease(cfAccount)
        bytes
    }

    override fun put(alias: String, value: ByteArray) {
        // Delete-then-add keeps the write idempotent and avoids the add-vs-update branch.
        delete(alias)

        val cfService = cfString(service)
        val cfAccount = cfString(alias)
        val cfData = cfData(value)
        val attributes = CFDictionaryCreateMutable(null, 0, null, null)
        CFDictionaryAddValue(attributes, kSecClass, kSecClassGenericPassword)
        CFDictionaryAddValue(attributes, kSecAttrService, cfService)
        CFDictionaryAddValue(attributes, kSecAttrAccount, cfAccount)
        CFDictionaryAddValue(attributes, kSecValueData, cfData)
        CFDictionaryAddValue(
            attributes,
            kSecAttrAccessible,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        )

        val status = SecItemAdd(attributes, null)

        CFRelease(attributes)
        CFRelease(cfData)
        CFRelease(cfService)
        CFRelease(cfAccount)

        check(status == errSecSuccess) { "Keychain SecItemAdd failed for '$alias' (OSStatus=$status)" }
    }

    override fun delete(alias: String) {
        val cfService = cfString(service)
        val cfAccount = cfString(alias)
        val query = CFDictionaryCreateMutable(null, 0, null, null)
        CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword)
        CFDictionaryAddValue(query, kSecAttrService, cfService)
        CFDictionaryAddValue(query, kSecAttrAccount, cfAccount)

        val status = SecItemDelete(query)

        CFRelease(query)
        CFRelease(cfService)
        CFRelease(cfAccount)

        check(status == errSecSuccess || status == errSecItemNotFound) {
            "Keychain SecItemDelete failed for '$alias' (OSStatus=$status)"
        }
    }

    private fun cfString(value: String): CFStringRef? =
        CFStringCreateWithCString(null, value, kCFStringEncodingUTF8)

    private fun cfData(bytes: ByteArray): CFDataRef? =
        if (bytes.isEmpty()) {
            CFDataCreate(null, null, 0)
        } else {
            bytes.usePinned { pinned ->
                CFDataCreate(null, pinned.addressOf(0).reinterpret(), bytes.size.convert())
            }
        }

    private fun cfDataToByteArray(data: CFDataRef): ByteArray {
        val length = CFDataGetLength(data).toInt()
        if (length <= 0) return ByteArray(0)
        val bytePtr = CFDataGetBytePtr(data) ?: return ByteArray(0)
        return ByteArray(length).apply {
            usePinned { pinned -> memcpy(pinned.addressOf(0), bytePtr, length.convert()) }
        }
    }

    companion object {
        const val DEFAULT_SERVICE = "com.messenger.securekeystore.v1"
    }
}
