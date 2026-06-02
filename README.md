# Messenger — End-to-End Encrypted Messenger (Kotlin Multiplatform)

An end-to-end encrypted messenger targeting **iOS**, built with **Kotlin Multiplatform**. All
security-critical logic (the cryptographic protocols, storage, orchestration and networking) lives
in a shared Kotlin module and is covered by tests that run on both the JVM and the iOS simulator.

> **Status:** the full backend & shared logic are implemented and tested (**49 tests green**).
> The iOS UI (Compose Multiplatform) and the iOS Keychain backend are the remaining pieces and are
> built on macOS (see [Roadmap](#roadmap)).

## Security design

The protocol follows the Signal approach — the gold standard for E2E messaging:

| Property | How |
| --- | --- |
| **End-to-end encryption** | XChaCha20-Poly1305 AEAD; keys never leave the device |
| **Session setup while offline** | **X3DH** over published prekey bundles |
| **Forward secrecy** | **Double Ratchet** symmetric-key ratchet — a new message key per message |
| **Post-compromise security** | Double Ratchet DH ratchet — security self-heals after a key leak |
| **Out-of-order / dropped messages** | skipped-message-key store with an anti-DoS cap |
| **Tamper protection** | every message's header is bound into the AEAD associated data |
| **MITM resistance** | signed prekeys; forged signatures rejected; contact identity keys recorded |
| **At-rest protection** | private keys, ratchet state and message bodies encrypted with a Keychain-held master key |

**Primitives** (via [libsodium](https://github.com/ionspin/kotlin-multiplatform-libsodium), one
implementation for JVM + iOS): X25519 (DH), Ed25519 (identity/signatures, converted to X25519 for
X3DH), XChaCha20-Poly1305-IETF (AEAD), HKDF-SHA256 / HMAC-SHA256 (KDFs).

The relay **server only ever sees ciphertext and public keys** — it cannot read messages.

## Architecture

```
shared/                      Kotlin Multiplatform (JVM + iOS) — all the logic
  com/messenger/
    crypto/                  CryptoProvider + libsodium impl, HKDF, base64
    protocol/x3dh/           X3DH key agreement
    protocol/ratchet/        Double Ratchet (+ serializable state snapshot)
    protocol/wire/           transport DTOs (client <-> server) + mappers
    security/                SecureKeyStore, BlobCipher (at-rest), MasterKey
    db/                      SQLDelight schema + DatabaseDriverFactory (expect/actual)
    data/                    IdentityStore, ContactStore, SessionStore, MessageStore
    domain/                  Models (ChatMessage, Contact, enums)
    net/                     MessengerApiClient (REST + WebSocket relay)
    app/                     ConversationManager (orchestrator) + MessengerComponent (DI root)

server/                      Ktor (JVM) relay server — depends on :shared
  com/messenger/server/      REST (register / prekeys) + WebSocket store-and-forward relay
```

The UI talks only to `MessengerComponent` / `ConversationManager`.

## Build & test

Requires JDK 17. Uses the Gradle wrapper (Gradle 8.11.1, Kotlin 2.1.20).

```bash
# Whole backend (crypto, protocols, storage, server) — runs anywhere, incl. Windows:
./gradlew :shared:jvmTest :server:test

# Run the relay server (defaults to port 8080):
./gradlew :server:run

# iOS targets (require macOS + Xcode):
./gradlew :shared:iosSimulatorArm64Test                 # run the shared tests on the simulator
./gradlew :shared:linkDebugFrameworkIosSimulatorArm64   # build the framework for the iOS app
```

> **Note on Windows:** Kotlin/Native iOS targets and the Compose iOS app can only be built on
> macOS. On Windows, develop and validate everything via the JVM target; iOS builds run on a Mac or
> the macOS CI job (`.github/workflows/ci.yml`).

## How a message flows

1. Each device provisions an identity, a signed prekey and a pool of one-time prekeys
   (`ConversationManager.ensureProvisioned`), then `register`s and uploads the public bundle.
2. To start a chat, the initiator fetches the recipient's prekey bundle, runs **X3DH**, seeds a
   **Double Ratchet**, encrypts the first message and sends it with an X3DH preamble.
3. The recipient completes X3DH from the preamble, seeds its ratchet and decrypts.
4. Subsequent messages ratchet forward; sessions are persisted (encrypted) and survive restarts.
5. The server relays ciphertext envelopes over WebSockets, queueing for offline recipients.

## Roadmap

- [x] Phase 1 — crypto primitives (X25519, Ed25519, AEAD, HKDF)
- [x] Phase 2 — X3DH key agreement
- [x] Phase 3 — Double Ratchet (forward secrecy, PCS, skipped keys)
- [x] Phase 4 — domain + SQLDelight storage, at-rest encryption, ConversationManager
- [x] Phase 5 — Ktor relay server + shared network client (validated end-to-end over the network)
- [ ] Phase 6 — Compose Multiplatform iOS UI, iOS Keychain `SecureKeyStore`, Xcode app, push (APNs)
