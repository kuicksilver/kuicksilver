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
- `kuicksilver-bom`: a bill of materials that pins every module to one version (`implementation(platform("io.kuicksilver:kuicksilver-bom:<version>"))`).

- **Native layer** (`kuicksilver-native`): the `ksl` C shim over OpenSSL 3.5 with one header for JNI and cinterop
  (ABI version 4); OpenSSL 3.5.9 built from a pinned, PGP-verified tarball with a minimal configuration; OpenSSL
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
- `MemoryNetwork(receiveBuffer, assignEphemeralPorts)` (`@ExperimentalKuicksilverApi`): sockets of the in-memory network
  hold at most `receiveBuffer` unread datagrams (256 by default) and count what a full buffer drops, `open` on port 0 binds
  an ephemeral port, oversized datagrams are dropped instead of truncated, and `trySend` counts only addressed datagrams.

### Changed

- JVM jars and the Android AAR carry `LICENSE`, `NOTICE` and the OpenSSL license.
- Public ABI dumps no longer include declarations marked `@InternalKuicksilverApi`.
- TCP session resumption keeps sessions in native memory (handles instead of serialized session bytes); `ksl` ABI 3 → 4.
- `QuicEndpoint` refuses `maxUdpPayloadSize` above its 1500-byte datagram slots; `QuicPath.close()` on the active path
  throws `IllegalStateException`; `accept()` after `close()` throws; the outgoing datagram queue is bounded.

### Fixed

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
- The endpoint's receive loop yields after 16 rounds or 2 ms of continuous traffic, so a socket that never runs dry
  (a flood) no longer starves the connection timers and queued application commands.
- No resolver call on the endpoint loop: on Kotlin/Native the address bytes of a datagram's source are parsed from its IP
  literal instead of `getaddrinfo`, and Stateless Reset candidates are keyed by address bytes and port, so a reset from
  `0:0:0:0:0:0:0:1` matches a connection to `::1`.
- A server whose peer keeps moving no longer keeps a path object per address it ever saw: paths the connection evicts
  (at most four) leave `QuicConnection.paths` and their sockets are closed.
- Datagrams the socket did not take (a failed send, or a full buffer that took part of a batch) are counted in the new
  `ConnectionStats.datagramsDroppedSocket` (`@ExperimentalKuicksilverApi`); the portable JVM socket waits once, briefly,
  for room instead of treating a refused datagram as sent.
- A socket whose `capabilities` lose ECN marking or DF (for example the portable socket clearing IP_TOS after a failed
  ECN validation) now downgrades the connections already on it, the endpoint's socket and a migrating client's extra
  sockets alike, instead of only the connections that start afterwards.
- The accept queue never holds more than `acceptQueue` connections: a handshake that completes while the queue is full
  is closed with CONNECTION_REFUSED. Admission counts only the connections waiting for `accept()`, so half-open
  handshakes from spoofed sources cannot lock real clients out.
- `samples/realtime-telemetry` reads control lines with a 1024-byte limit; a longer line closes the connection (code 2)
  instead of growing the server's buffer.

### Security

- Connection IDs, tokens, path challenges and packet-number skips come from OpenSSL's `RAND_bytes` through a
  thread-safe per-loop source; a non-cryptographic generator is no longer used on production paths.
- HTTP/3 header frames are read incrementally instead of allocating their declared length up front.
- TLS-over-TCP session tickets are bound to the server's client-authentication and trust configuration, so a ticket
  only resumes under the configuration that issued it.
- Bounds checks on every buffer copy in the JNI and cinterop bindings.
