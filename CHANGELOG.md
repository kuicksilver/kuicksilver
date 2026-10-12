<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, any 0.x release may contain breaking changes.

## [Unreleased]

Nothing has been released yet. This section summarises the development of the first 0.x version.

### Fixed
- Platform trust reports `VerifyReason.UnknownRevocationStatus` when the JVM PKIX validator (`UNDETERMINED_REVOCATION_STATUS`) or Apple (`errSecIncompleteCertRevocationCheck`) could not determine revocation, and `VerifyReason.CertificateTransparency` when Android's CT policy rejects a chain, instead of `UnknownIssuer`.
- `QuicTlsSession` (`setTransportParameters`, `provide`, `resumeVerify`, `exportKeyingMaterial`) and `TlsConnection.exportKeyingMaterial` no longer leak the native `KslException.Internal`: a call in the wrong state throws `IllegalStateException`, other TLS errors `TlsException.Protocol`.
- `TrustConfig.Pinned` refuses a `Custom` base wrapped in `ExpectedName` as it already refused a bare `Custom` (the spec: pins are checked against a chain the library validated, a custom verifier decides alone).
- `TlsConfig` counts ALPN names in UTF-8 bytes (a 200-character `é` name passed as 200) and refuses a list longer than 255 bytes on the wire; a server's `ServerTlsOverride` passes the same ALPN and client-certificate trust checks as `build()` instead of none. Both copy the ALPN list before validating it, so the stored list is the one that was checked.
- The TCP client session cache holds at most 256 sessions (the least recently stored one is evicted and its native session freed) and each Ktor client engine owns its own cache, which it clears when it closes; before, one process-wide cache grew without bound and outlived every engine.
- `KslLoader` (JVM) refuses a work directory that is a symbolic link, not a directory, owned by another user or not private to it (`IntegrityMismatch`), and no longer deletes the extracted, verified library on exit, so a second JVM that shares the directory is not pulled from under its own `System.load`. It creates the work directory owner-only in one call (not under the umask), reuses an extracted library only when this user owns it (otherwise it reinstalls it atomically) and refuses to load when the user of the process cannot be determined on a POSIX file system.
- `ksl`: `KSL_OPT_CLIENT_CERT` is refused on a client context (it rewrote `SSL_CTX_set_verify` and switched server verification off); `KSL_OPT_VERIFY_MODE` and `KSL_OPT_CLIENT_CERT` reject values outside 0..2.
- `ksl`: setting the verify name a second time with the other identifier type (host after IP literal or the reverse) clears the previous one instead of checking both.
- `TlsIdentity.fromPem` decodes the key straight from its `CharArray` instead of turning it into `String`s (which stayed on the heap) and wipes every decoded key block, also when the import fails.
- `keylogFile(path)` refuses a symlink, a non-regular file, a file with more than one hard link, a file of another user or a file system without POSIX permissions, tightens an existing file to 0600 and reopens it without following links for every line (threat model section 3.7). On the JVM the sink keeps the one descriptor it checked for its lifetime (it is `java.io.Closeable`) instead of reopening the path for every line without re-checking the owner, so a file recreated at the path by another local user receives no secrets.

### Changed
- `ksl` ABI 5: identity private keys stay in OpenSSL. `TlsIdentity.fromDer`/`fromPem` parse the key once into a native `ksl_pkey` (`ksl_pkey_new`, `ksl_pkey_free`, `ksl_ctx_set_identity_pkey`) and keep only its handle, so a heap dump no longer holds the key; `TlsIdentity.InMemory.close()` frees it once the contexts built from it are gone. A library of ABI 4 is refused (`AbiMismatch`).

### Changed (API freeze before 0.1.0)
- `NullCryptoProvider` is `@InternalKuicksilverApi` (a test fixture, not a transport); `ConnectionStats` and `EndpointStats` are built by the library only.
- `PathChanged` is nested as `PathEvent.Changed` beside `Validated` and `Failed`; the top-level name is a deprecated alias until 0.2.0.
- `QuicEndpoint.closeAndJoin()` waits until the connections are closed and the socket is released (`close()` stays asynchronous).
- `QuicConnection.trySendDatagram` answers `DatagramSendResult.Closed` on a closed connection instead of throwing (an exhaustive `when` needs the new branch).
- `VersionProfile` lives in `io.kuicksilver.quic`; `io.kuicksilver.quic.wire.VersionProfile` is a deprecated alias until 0.2.0.
- `ConnectionStats.ecnState` is an `EcnState` enum (`Disabled`, `Testing`, `Unknown`, `Capable`, `Failed`) instead of a string.

### Removed
- The `macosX64` Kotlin/Native target (deprecated by Kotlin, never part of the test matrix). The JVM on Intel Macs keeps its `osx-x86_64` JNI library.

### Added

- Android armeabi-v7a: the `kuicksilver-native` AAR ships `libksl.so` for arm64-v8a, armeabi-v7a and x86_64 (OpenSSL
  target `android-arm`, `minSdk` 24, 16 KiB pages); `-Pkuicksilver.android.armv7=false` leaves it out of a local build.
- `KslLoader.availability()` and `KslLoader.isAvailable()` (`@ExperimentalKuicksilverApi`): a non-throwing check whether the native library can be used, so an application on an OS or ABI without a build falls back to another transport; `NativeAvailability.Unavailable` carries a `NativeUnavailableReason` (`NoLibraryForPlatform`, `LoadFailed`, `IntegrityMismatch`, `AbiMismatch`) and the original exception. The outcome of the one load attempt is cached: `ensureLoaded()` no longer retries after a failure and rethrows the same exception.
- `QuicConfig.initialRtt` is validated (positive, at most 10 s) and documented: it sets the first PTO (3 x `initialRtt`,
  doubling) and the floor of a path validation; a lower value shortens a handshake under loss at the price of spurious
  retransmissions (`docs/guide/quic.md`, "Configuration").
- `kuicksilver-bom`: a bill of materials that pins every module to one version (`implementation(platform("io.kuicksilver:kuicksilver-bom:<version>"))`).

- **Native layer** (`kuicksilver-native`): the `ksl` C shim over OpenSSL 3.5 with one header for JNI and cinterop
  (ABI version 5); OpenSSL 3.5.9 built from a pinned, PGP-verified tarball with a minimal configuration; OpenSSL
  symbols prefixed with `ksl_ossl_` on Kotlin/Native; a JVM loader that checks the library's SHA-256 and ABI version;
  an Android AAR (arm64-v8a, armeabi-v7a, x86_64) aligned for 16 KiB pages; JVM jar manifest entries for the OpenSSL release.
- **TLS** (`kuicksilver-tls`, `kuicksilver-ktor-network`): TLS 1.3 (and opt-in TLS 1.2) over any byte channel and over
  ktor-network sockets on every target; `TrustConfig` with platform trust, private CAs, SPKI pins, TOFU and custom
  verifiers, one RFC 9525 host name matcher on every platform; client certificates; session tickets; post-quantum
  hybrid key exchange `X25519MLKEM768` by default; explicit key logging only (`KeylogSink`); `Certificate.parsePem`.
- **QUIC** (`kuicksilver-quic`): QUIC v1 and v2 with compatible version negotiation (RFC 9000/9001/9002/9368/9369);
  a sans-IO core (`ConnectionCore`, `EndpointCore`) and a coroutine API (`QuicEndpoint`, `QuicConnection`,
  `QuicStream`, `incomingConnections()`, `incomingStreams()`); streams with priorities; datagrams (RFC 9221) with
  drop policies; Retry and `ConnectionAdmission`; stateless reset; key update and AEAD limits; passive migration, NAT
  rebinding and active client migration; CUBIC with HyStart++ (default) and NewReno; DPLPMTUD (RFC 8899); ECN; an
  accelerated UDP socket on Linux and Android (GSO, GRO, ECN, batches) and portable sockets elsewhere; several
  endpoint loops on one port (`SO_REUSEPORT`); a glitch budget against abusive peers; qlog output.
- **HTTP/3** (`kuicksilver-http3`): RFC 9114 with QPACK (RFC 9204, dynamic table), extensible priorities (RFC 9218),
  Extended CONNECT (RFC 9220), HTTP datagrams and capsules (RFC 9297), trailers, 1xx responses, GOAWAY.
- **Ktor engines**: `HttpClient(Kuicksilver)` with HTTP/1.1 over TLS and HTTP/3, `Alt-Svc` discovery, connection
  racing and fallback that keeps pins, WebSockets and SSE; `embeddedServer(Kuicksilver)` serving HTTP/1.1 over TLS and
  HTTP/3 on one port, `Alt-Svc`, WebSockets over HTTP/3, graceful stop with GOAWAY, `EngineMain`. Both run Ktor 3.6.0's
  engine contract tests (vendored) over HTTP/1.1 and HTTP/3.
- **Testing and tooling**: a deterministic network simulator and `MemoryNetwork` (`kuicksilver-testing`, not
  published); RFC test vectors; Jazzer fuzz targets for packets, frames, transport parameters, QPACK and HTTP/3 frames
  with a seed corpus; allocation gates and benchmarks; a QUIC Interop Runner endpoint (JVM and Kotlin/Native images);
  architecture, layering, SPDX, ABI, symbol-export, glibc-floor, page-alignment and size checks.
- Documentation: user guides, architecture overview, ADRs, RFC compliance matrix, threat model; the
  `samples/realtime-telemetry` application.

### Changed

- QUIC API for 0.2.0 (breaking, before 1.0): `QuicException.ConnectionLost.TransportClosed.frameType` is a non-null `Long`
  (0 when no frame triggered the error; it was never null); `TimeoutKind.Disconnect`, never produced, is removed;
  `QuicStream.priority` reports the priority the stream was opened with instead of `StreamPriority.Default`;
  `ConnectionCore.pathState` answers `PathState.Closed` for a path the connection closed or evicted (`Unknown` stays for
  ids it never issued), so `QuicPath.state` of a path evicted by migration reads `Closed`.
- JVM jars and the Android AAR carry `LICENSE`, `NOTICE` and the OpenSSL license.
- Public ABI dumps no longer include declarations marked `@InternalKuicksilverApi`.
- TCP session resumption keeps sessions in native memory (handles instead of serialized session bytes); `ksl` ABI 3 → 4.
- `QuicEndpoint` refuses `maxUdpPayloadSize` above its 1500-byte datagram slots; `QuicPath.close()` on the active path
  throws `IllegalStateException`; `accept()` after `close()` throws; the outgoing datagram queue is bounded.

### Fixed

Hardening of the QUIC core for 0.2.0 (review of 2026-10-08, deferred items):

- QUIC: an unanswered `PATH_CHALLENGE` is repeated with an exponentially growing gap (1, 1, 2, 4 ... x PTO, so
  three challenges fit in the 3 x PTO validation timeout) instead of once per PTO (RFC 9000 §8.2.1, §8.2.4, RFC 9002 §6.2.1).
- QUIC server: a client that migrates several times before its new addresses can answer no longer loses its newest
  address: with all four path slots taken, a migration abandons the oldest validation of a path the client has left
  (RFC 9000 §8.2.4); a probe takes the slot of a validating path only after max(3 x PTO, 5 s) of silence.
- QUIC: a handshaking server that follows a new address on an Initial no longer re-runs its timers continuously once
  that path's validation deadline passed without a Handshake packet (one forged Initial was enough).
- QUIC: a packet buffered until its keys arrive is processed with the ECN mark, socket, source and length of its own
  datagram, not of the datagram that delivered the keys (RFC 9000 §13.4.1).
- QUIC: a lost `NEW_CONNECTION_ID` whose sequence is below our own `retire_prior_to` is no longer retransmitted,
  and that connection ID stops routing 3 x PTO after the loss instead of staying registered (RFC 9000 §5.1.2, §19.15).
- QUIC server: a Retry token is bound to the Retry's Source Connection ID; an Initial presenting it under another DCID is
  refused with a stateless `INVALID_TOKEN` close instead of becoming a connection (RFC 9000 §8.1.2–§8.1.4). Tokens minted
  before this change are not accepted (they live 10 s).
- QUIC: ECN validation looks only at ACKs that raise the largest acknowledged packet, keeps the peer's counts per packet
  number space instead of per path, and counts newly acknowledged marked packets per path; a reordered ACK no longer
  fails ECN on the path, and a new path no longer takes the first counts it sees for a CE signal (RFC 9000 §13.4.2.1).
- QUIC: work a peer can trigger no longer grows with what it controls (RFC 9000 §21.6): an ACK costs a binary search per
  range instead of a walk over every packet in flight, a `MAX_DATA` that raises nothing touches no stream, and choosing or
  scheduling a stream is logarithmic in the number of streams instead of linear.
- QUIC: `ConnectionEvent.StreamWritable` and `StreamsAvailable` are raised (their KDoc said "not raised in this version"):
  after a refused write once acknowledgements free buffer room or new flow-control credit reaches waiting data, and after
  `MAX_STREAMS` raises a limit that refused an open; the coroutine API wakes the waiting writer or `openBidi`/`openUni`
  directly. The KDoc of `StreamFinished`, which was always raised, now says so (RFC 9000 §4.1, §4.6).

Fixes from a full five-reviewer pass over the code before the first release, among them:

- Streams reset or stopped by the peer, or stopped locally, are retired and return their stream credit; lost
  `MAX_STREAMS` frames are retransmitted.
- An endpoint loop group could start half-initialised; a cancelled `connect` leaked its connection; a cancelled
  `flush` could drop data from the middle of a stream; waiters got `ClosedReceiveChannelException` instead of
  `ConnectionLost`; uncaught exceptions in endpoint coroutines could crash the process.
- Path probes now use a fresh peer connection ID (RFC 9000 section 9.5); ACK ranges no longer grow for the life of a
  connection; congestion loss is no longer mistaken for an MTU black hole; the client discards packets from unknown
  server addresses and a second Version Negotiation packet; the server checks reserved bits and token length.
- The HTTP/1.1 client no longer treats a 1xx response as final; unread HTTP/3 response bodies are stopped with
  `STOP_SENDING`; CONNECT tunnels and WebSockets over HTTP/3 support half-close; GOAWAY reaches every connection on
  graceful stop; cookie crumbs are joined; truncated frames and oversized `content-length` are rejected.
- `ksl_udp` treats per-destination send errors as the loss of one datagram instead of a socket failure; Initials
  from source port 0 are dropped; the certificate parser accepts the time formats OpenSSL accepts.

### Security

- Connection IDs, tokens, path challenges and packet-number skips come from OpenSSL's `RAND_bytes` through a
  thread-safe per-loop source; a non-cryptographic generator is no longer used on production paths.
- HTTP/3 header frames are read incrementally instead of allocating their declared length up front.
- TLS-over-TCP session tickets are bound to the server's client-authentication and trust configuration, so a ticket
  only resumes under the configuration that issued it.
- Bounds checks on every buffer copy in the JNI and cinterop bindings.
