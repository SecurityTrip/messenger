package com.messenger.crypto

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/** Standard Base64 encoding — used for compact, human-readable serialization of key material. */
@OptIn(ExperimentalEncodingApi::class)
fun ByteArray.toBase64(): String = Base64.encode(this)

@OptIn(ExperimentalEncodingApi::class)
fun String.fromBase64(): ByteArray = Base64.decode(this)
