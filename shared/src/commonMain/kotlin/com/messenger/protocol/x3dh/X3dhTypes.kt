package com.messenger.protocol.x3dh

import com.messenger.crypto.DhKeyPair

/**
 * Bob's medium-term **signed prekey**: an X25519 key pair whose public key is signed by the
 * long-term identity key. Rotated periodically (e.g. weekly). Private part stays on-device.
 */
class SignedPreKey(
    val id: Int,
    val keyPair: DhKeyPair,
    /** Ed25519 signature over [keyPair].publicKey, produced with the identity key. */
    val signature: ByteArray,
)

/**
 * A single-use X25519 **one-time prekey**. A batch is generated and their public parts uploaded;
 * each is deleted right after it is consumed by an incoming session.
 */
class OneTimePreKey(
    val id: Int,
    val keyPair: DhKeyPair,
)

/**
 * The public **prekey bundle** Bob publishes to the server. Alice fetches one to start a session
 * even while Bob is offline. Contains only public key material.
 */
class PreKeyBundle(
    /** IK_B — Bob's long-term identity key, Ed25519 public. */
    val identityKey: ByteArray,
    val signedPreKeyId: Int,
    /** SPK_B — Bob's signed prekey, X25519 public. */
    val signedPreKey: ByteArray,
    /** Signature over [signedPreKey] by [identityKey]. */
    val signedPreKeySignature: ByteArray,
    /** OPK_B — one of Bob's one-time prekeys (X25519 public); null if his pool is exhausted. */
    val oneTimePreKeyId: Int?,
    val oneTimePreKey: ByteArray?,
)

/**
 * The header Alice attaches to her first message so Bob can reconstruct the same shared secret.
 * Carries Alice's public identity & ephemeral keys and tells Bob which of his prekeys were used.
 */
class X3dhInitialMessage(
    /** IK_A — Alice's identity key, Ed25519 public. */
    val identityKey: ByteArray,
    /** EK_A — Alice's ephemeral key for this session, X25519 public. */
    val ephemeralKey: ByteArray,
    val signedPreKeyId: Int,
    val oneTimePreKeyId: Int?,
)

/**
 * Output of an X3DH agreement: the 32-byte [sharedSecret] (used to seed the Double Ratchet root
 * key) and the [associatedData] (IK_A || IK_B) bound into the first AEAD as authenticated context.
 */
class X3dhResult(
    val sharedSecret: ByteArray,
    val associatedData: ByteArray,
)
