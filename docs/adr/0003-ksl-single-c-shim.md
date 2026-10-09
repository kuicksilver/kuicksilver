# ADR-0003. One narrow C shim `ksl` with a shared header for JNI and cinterop

Date: 2026-10-02. Status: accepted (approved by the owner 2026-10-02).

## Context

We need JNI (JVM, Android) and cinterop (Native) bindings to OpenSSL. Direct cinterop to `openssl/ssl.h` pulls in a huge API, and JNI to the same API would have to be written separately. OpenSSL callbacks into Kotlin are upcalls from C, expensive and complicated on both bindings.

## Decision

One shim `ksl` (`ksl.h`, a stable C ABI, a few dozen functions). JNI and cinterop bind to the same header. Inside: TLS contexts, the QUIC TLS interface, AEAD/header protection by key handle, TLS over TCP through memory (memory BIO), certificate verification with a pause. OpenSSL callbacks are implemented in `ksl` and push events into an internal queue; Kotlin drains it by polling. There are no upcalls from C into Kotlin. Secrets never leave native memory: Kotlin only receives key handles.

## Consequences

- One set of functions for fuzzing (libFuzzer) and for both bindings.
- All sockets stay in Kotlin → TLS over any channel.
- The initial estimate was ~30 functions; the sketch gives ~40 (separate TCP, UDP and KslCrypto groups).

## Implementation in K1 (2026-10-02)

`ksl.h` closed at 50 functions (`KSL_ABI_VERSION 1`): options and getters go through selectors (`ksl_ctx_set_option`, `ksl_ssl_get`), one `ksl_drive` serves QUIC and TCP, the event queue has `peek` (an event that does not fit the JNI buffer stays in the queue). The CRYPTO buffer is not reallocated while a record is handed to OpenSSL (`rcd_level` + stash). Errors are copied into the object in the same call; alerts are recorded by the info callback in both modes. JNI (`RegisterNatives`, `JNI_OnLoad` 1_8/1_6) and cinterop (`ksl.def`, `staticLibraries`) bind to the same header; on K/N handles are `Long` via `interpretCPointer`.

## Implementation in K3: endpoint keys (2026-10-08)

Retry token and stateless reset keys live in `ksl` and never reach Kotlin (secrets stay in native memory; see docs/architecture.md, `kuicksilver-native`): `ksl_key_random(KSL_EKEY_TOKEN)` creates
an AES-256-GCM key from 32 random bytes for `ksl_seal`/`ksl_open` (the token nonce is a 64-bit "packet number"), `ksl_key_random(KSL_EKEY_RESET)` creates
an HMAC-SHA256 key for `ksl_key_mac16` (the first 16 bytes of a MAC over the CID). Both objects are immutable after creation, `ksl_key_mac16` is safe for
concurrent calls (one MAC context per call). The reset key is deliberately separate from the CID generator (lesson of Netty CVE-2026-50009) and random per process:
after a restart the server cannot reset old connections — a persistent key would require passing the secret through Kotlin. `ksl` ABI 3,
51 functions (the ceiling of 50 was raised by owner decision 2026-10-08). The accelerated UDP work in K3 added `ksl_udp_open/send/recv/get/shutdown/close` — 57 functions in the same ABI 3 (56 were planned: a separate `ksl_udp_shutdown` is needed to wake a blocked receive from another thread without freeing the object, see ADR-0006 "Implementation in K3"). Also in K3: one tuple of key exchange groups on both contexts (`X25519MLKEM768:X25519:…`), otherwise OpenSSL answered clients with a single X25519 share with a HelloRetryRequest.
In Kotlin these are `QuicCrypto.newTokenKey()`/`newResetKey()` (`TokenKey`, `ResetKey`); `NullCryptoProvider` gives deterministic variants for the simulator.

## ABI 4: sessions stay in `ksl` (native-tls review, 2026-10-08)

`KSL_GET_SESSION` handed Kotlin `i2d_SSL_SESSION` — with the TLS 1.2 master secret and the TLS 1.3 resumption PSK — and `SessionCache` kept these bytes on the heap for up to 7 days, contrary to the decision "secrets never leave native memory". ABI 4: an opaque `ksl_session` (an `SSL_SESSION` with reference counting): `ksl_ssl_get1_session` (a new reference or `NULL`; the same pointer while the session has not changed), `ksl_ssl_set_session(ksl_ssl *, ksl_session *)` instead of serialized bytes, `ksl_session_free` (the last reference wipes the secret in `SSL_SESSION_free`); selector 3 of `ksl_ssl_get` no longer returns anything. An incompatible change — `KSL_ABI_VERSION 4`, `KslLoader` rejects an ABI 3 library (`KslException.AbiMismatch`). Also in ABI 4: `ksl_ctx_set_session_context`: the `sid_ctx` of a server context, derived from its trust configuration; a ticket resumes only under the same context, otherwise OpenSSL performs a full handshake. 60 functions.
