# CLAUDE.md — project context for AI sessions

Portable project memory: Claude Code auto-loads this file in any session in this repo, on any
machine. (The richer, machine-local auto-memory lives outside the repo under
`~/.claude/projects/<path-key>/memory/` and does not travel with `git clone` — this file does.)

## What this is
An **end-to-end encrypted messenger for iOS**, built with **Kotlin Multiplatform**. All
security-critical logic (crypto protocols, storage, networking, orchestration) lives in the shared
Kotlin module and is tested on both the JVM and the iOS simulator. A Ktor server acts as a "dumb"
relay that only ever sees ciphertext and public keys.

## Environment & hard constraints
- **Primary dev machine is Windows** → cannot build/run iOS targets (needs macOS + Xcode). Develop
  and test against the **JVM target**; iOS is validated by CI on a `macos-14` runner.
- **Kotlin 2.1.20**, **Gradle wrapper 8.11.1** (do NOT use system Gradle 9.x — too new for the KMP
  plugin). Always use `./gradlew`.
- **Native-dependency ABI rule:** every KMP dependency must be built with Kotlin ≤ 2.1.20 (klib
  `abi_version ≤ 1.201.0`). Kotlin/Native is ABI-gated; the JVM is not (so a bad dep passes JVM but
  fails the iOS build). This is why `kotlinx-serialization-json` is pinned to **1.8.1** (1.9.0 is
  built with Kotlin 2.2.0 → its klib is unconsumable). To vet a dep: download
  `<artifact>-iossimulatorarm64-<ver>.klib` from Maven Central, unzip, read `compiler_version` /
  `abi_version` from the `default/manifest` entry.

## Decisions
- UI: **Compose Multiplatform** (not SwiftUI). Platforms: **iOS now**, `shared` kept platform-neutral
  so Android can be added later. Backend: **own Ktor server**. Crypto: **full X3DH + Double Ratchet**
  from the start.

## Stack
Kotlin 2.1.20 · coroutines 1.10.2 · serialization-json 1.8.1 · datetime 0.6.2 · SQLDelight 2.1.0 ·
Ktor 3.1.2 · libsodium bindings (ionspin) 0.9.2. Version catalog: `gradle/libs.versions.toml`.

## Crypto
libsodium via ionspin `multiplatform-crypto-libsodium-bindings` (used directly in commonMain — no
expect/actual). X25519 DH; Ed25519 identity (ed25519↔curve25519 conversion for X3DH);
XChaCha20-Poly1305-IETF AEAD (24-byte nonce → random nonces safe); HKDF-SHA256 / HMAC-SHA256
(libsodium's HMAC fixes a 32-byte key → HKDF salt must be 32 bytes); BLAKE2b hash (safety numbers).
`CryptoProvider` interface + `LibsodiumCryptoProvider` impl. Call `initCrypto()` before use.

## Code layout
```
shared/src/commonMain/kotlin/com/messenger/
  crypto/      CryptoProvider + LibsodiumCryptoProvider, Hkdf, Encoding (base64), Keys
  protocol/x3dh/      X3DH key agreement
  protocol/ratchet/   DoubleRatchet (+ RatchetStateSnapshot export/restore)
  protocol/wire/      Wire.kt (E2E transport DTOs + mappers), Api.kt (client<->server API DTOs)
  security/    SecureKeyStore + InMemory, BlobCipher (at-rest AEAD), MasterKey, SafetyNumber
  db/          SQLDelight .sq (under sqldelight/com/messenger/db/), DatabaseDriverFactory (expect)
  data/        IdentityStore, ContactStore, SessionStore, MessageStore
  domain/      Models.kt (ChatMessage, Contact, MessageDirection/Status)
  app/         ConversationManager (orchestrator), MessengerComponent (DI root), net/MessengerApiClient
shared/src/jvmMain, iosMain   platform actuals (DatabaseDriverFactory; iOS Keychain TODO)
server/       Ktor + Netty JVM relay, depends on :shared
```

## Build & test
- Backend (works on Windows): `./gradlew :shared:jvmTest :server:test --console=plain`
- iOS (macOS only): `./gradlew :shared:iosSimulatorArm64Test` · `./gradlew :shared:linkDebugFrameworkIosSimulatorArm64`
- Run server: `./gradlew :server:run` (port 8080)
- **Gotchas:** never pipe gradle through `tail` (it masks the exit code — capture `${PIPESTATUS[0]}`
  or `rc=$?` first). Transient TLS failures to repo.maven.apache.org / github.com from this env —
  just retry. `server` `EndToEndNetworkTest` is opt-in (set env `RUN_NETWORK_TESTS=1`); it binds real
  sockets and hangs CI otherwise. SQLDelight codegen task: `generateCommonMainMessengerDatabaseInterface`.

## Status / roadmap
- ✅ Phases 1–5c complete, **54 tests green**, CI green (JVM + iOS): crypto, X3DH, Double Ratchet
  (forward secrecy, PCS, skipped keys, persistence), SQLDelight storage with at-rest encryption,
  Ktor relay server, shared network client, hardening (safety numbers, signed-prekey rotation,
  one-time-prekey replenishment, server auth tokens + sender-spoof protection).
- ✅ **Phase 5d complete — multi-device + reliable delivery + read receipts (55 tests green).**
  - Addressing is per **(userId, deviceId)**; each device has its own identity key, prekeys, sessions
    (Account has deviceId; Session PK is (contactId, deviceId); SessionStore.loadAllForContact).
  - `GET /keys/{user}` returns `DeviceBundles` (all devices); `ConversationManager.startConversation`
    /`send` **fan out** one envelope per recipient device (shared `messageId` = local ChatMessage.id).
  - `RelayEnvelope{messageId, toUser, toDevice, fromUser, fromDevice, payload}`;
    `RelayPayload` sealed = `Ciphertext(WireMessage)` | `Receipt(referencesMessageId, kind)`.
  - WS frames: `ClientFrame` = `Send|Ack`; `ServerFrame` = `Deliver|Accepted`.
  - Reliable delivery: server `MailboxStore` (interface + `InMemoryMailboxStore`) keyed by
    (user,device) keeps each message until the recipient sends `ClientFrame.Ack(messageId)`;
    redelivers all pending on (re)connect → at-least-once. (Client should dedup duplicate deliveries
    by messageId — not yet implemented; tests ack so no dups occur.)
  - Read receipts: `ConversationManager.receive` returns `MessageReceived(message, deliveryReceipt)`
    or `ReceiptReceived`; `markRead(localMessageId)` builds a READ receipt; receipts upgrade
    `MessageStatus` (SENT→DELIVERED→READ). Message rows store peerDeviceId + senderMessageId so a
    receipt can be addressed back and mapped to the sender's original message.
- ⌛ Phase 6 (needs a Mac): Compose Multiplatform iOS UI, iOS Keychain `SecureKeyStore` impl, Xcode
  app, APNs push. Also pending: TLS/wss (deployment — reverse proxy or Ktor cert).

## Git
`origin` = https://github.com/SecurityTrip/messenger.git, branch `master`.
