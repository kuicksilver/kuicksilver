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

- Linux Native: a host without a CA store (distroless, `scratch`) fails when a `TrustConfig.Platform` client configuration is built, with a `TlsException.Config` that names every path searched and `SSL_CERT_FILE`/`SSL_CERT_DIR`; before, a missing `/etc/ssl/certs` was accepted and every handshake failed with `UnknownIssuer`. When `SSL_CERT_FILE` or `SSL_CERT_DIR` is set, only they are used (as in Go), instead of falling back to the distribution paths. The search order is documented in the TLS guide.
- Windows: the accelerated UDP socket opens a dual-stack IPv6 socket for `0.0.0.0`, as on Linux and Apple, so the Ktor client (which binds `0.0.0.0:0`) reaches IPv6 HTTP/3 servers on Windows too; without IPv6 it falls back to IPv4. DF stays on where Windows refuses `IP_MTU_DISCOVER = PROBE` (some Windows 11 builds), as msquic runs.
- QUIC: a burst of losses that left more than `maxReassemblyRanges` gaps in a stream (every other packet lost within one RTT, e.g. a full receive buffer) closed the connection with FLOW_CONTROL_ERROR although the peer stayed within flow control; the packet that would open one gap too many is now dropped unacknowledged and retransmitted by the peer, and the memory bound is unchanged (RFC 9000 §21.7).
- `FileAltSvcStore` persists on Android API 24-25: kotlinx-io's `atomicMove` needs `java.nio.file` (API 26), so every write failed and the store silently kept alternatives in memory only; it now falls back to `java.io.File.renameTo`, and a store that cannot be written logs one warning.
- `keylogFile` (and `keylogFile(context)`) on Android below API 26 throws `IllegalArgumentException` (the file cannot be checked without `java.nio.file`) instead of `NoClassDefFoundError`.
- `KslUdpSocket.supported` answers false when its loopback probe fails for any reason (for example `bind` refused by the App Sandbox) instead of throwing, and `DatagramIo.open` falls back to the portable socket when the accelerated one is refused at bind time, with one line on standard error.
- The accelerated UDP socket (Linux, Apple) opens a dual-stack IPv6 socket for a wildcard address (`0.0.0.0` or `::`), as NIO did: the Ktor client (whose endpoint binds `0.0.0.0:0`) reaches IPv6 HTTP/3 servers, and a Ktor server on the default host serves HTTP/3 to IPv6 clients. Before, `0.0.0.0` gave an IPv4-only socket, so datagrams to IPv6 peers were dropped and the handshake timed out. ECN and DF cover both address families; IPv4 peers are reported as IPv4.
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
- `QuicEndpointConfig.acceptQueue` defaults to 128 (was 32), and a client Initial that arrives while the accept queue is full is refused at once with a stateless Initial CONNECTION_CLOSE carrying CONNECTION_REFUSED (0x02), under the stateless rate limits, instead of being dropped: the client's `connect` fails with `ConnectionLost.TransportClosed(code = 0x02)` within a round trip rather than at its handshake timeout, and the server spends no TLS handshake on it (RFC 9000 section 5.2.2, as quic-go does). Handshakes in flight still do not count against the queue; one admitted earlier that completes into a full queue is still closed with CONNECTION_REFUSED.
- The JVM on macOS uses the accelerated `ksl` socket (`KslDatagramIo`) by default instead of NIO, as Linux already did: DF is set (PMTUD can grow past 1200 bytes, up to 1452 on loopback), ECN marks are read per datagram so paths can validate ECN, receives run as 100 ms blocking slices on `Dispatchers.IO`, and a wildcard bind is dual-stack as with NIO. A refused socket falls back to NIO; `DatagramIo.open(local, IoPreference.Portable)` (or an endpoint built on it) keeps NIO.
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
- QUIC server on Kotlin/Native Windows (`mingwX64`): `ksl_udp` over Winsock (`WSASendMsg`/`WSARecvMsg` with `WSAPoll` and a wake socket, ECN through `IP_ECN`/`IPV6_ECN` on Windows 10 2004+ / Server 2022, USO/URO where the system grants them, DF, dual-stack IPv6, `SO_EXCLUSIVEADDRUSE`); the JVM on Windows uses the same socket through JNI. Winsock is started when the Kotlin/Native runtime starts (not from a C constructor, which in a `sharedLib` would run under the loader lock), so address lookups before the first socket no longer fail with `WSANOTINITIALISED`. Verified by the CI windows job only. `loops > 1` without `SO_REUSEPORT` granted on the first socket (Windows always) throws the documented `UnsupportedOperationException` instead of failing the second bind with `KslException.Internal`.
- 0-RTT, opt-in and experimental (ADR-0015, RFC 9001 section 4.6, RFC 8470): `QuicClientConfig.earlyData`,
  `QuicServerConfig.earlyData`/`earlyDataContext`, `QuicEndpoint.connectEarly`, `QuicConnection.awaitHandshake`/
  `earlyDataAccepted`/`isHandshakeComplete`, `QuicStream.receivedEarly`, `QuicException.ConnectionLost.ZeroRttRejected`;
  HTTP/3 `Http3Endpoint.connectEarly`, `Http3Request.allowEarlyData`, `Http3Settings.earlyData`
  (`Http3EarlyDataPolicy.WaitForHandshake`/`Reject425`), `Http3ServerRequest.receivedEarly`; Ktor client
  `http3 { earlyData }`, server `quicEarlyData` and `ApplicationRequest.receivedEarly`. Anti-replay: OpenSSL ticket-age
  freshness, a per-server replay register keyed by ticket, tickets bound to the server configuration, safe methods
  only before the handshake. Off by default. `ksl` ABI 6 (`KSL_OPT_EARLY_DATA`, `KSL_SET_EARLY_CONTEXT`,
  `KSL_SET_EARLY_DATA`, `KSL_GET_EARLY_DATA`); `EarlyDataState` gains `Allowed` and `Required`, and
  `QuicTlsSession.earlyData` becomes `earlyDataAccepted`.
- QUIC server on Kotlin/Native macOS: the accelerated `ksl` UDP socket (ADR-0006) now works on Apple platforms — ECN marks sent and read per datagram, DF set for PMTUD (`IP_DONTFRAG`), no GSO/GRO (Darwin has none). `QuicEndpoint.bind` with a server and the Ktor server engine over HTTP/3 run on `macosArm64` (iOS compiles and links the same code); the JVM on macOS uses the accelerated socket by default instead of NIO. `loops > 1` stays Linux/Android-only: Darwin has no `SO_REUSEPORT` flow hashing, so `bind` refuses it there.
- `NetworkMigrator` (experimental): a client connection follows a `Flow` of networks, migrating to each new one (RFC 9000 section 9) and closing the path it left; a failed migration keeps the old path, `disable_active_migration` is respected, `MigrationEvent` reports `Migrated`, `Failed`, `NetworkLost` and `SourceFailed` (the network flow threw; the migrator stops without failing the caller's scope). `start()` and `close()` are thread-safe.
- Android: `QuicConnection.followDefaultNetwork(connectivityManager, scope)` keeps a client connection on the device's default network (Wi-Fi ↔ cellular), `ConnectivityManager.defaultNetworks()` (one shared callback per manager, whatever the number of connections) and `DatagramIo.open(local, network, prefer)`, which binds a socket to an `android.net.Network`. The `kuicksilver-quic` AAR now declares `ACCESS_NETWORK_STATE`.
- CI/tools: throughput floors for the QUIC Interop Runner measurements — `tools/interop/perf-thresholds.json` (goodput and
  crosstraffic per peer and role, from the recorded runs minus 25 % / 40 %), `tools/interop/check-perf.sh` (table of
  measured vs floor, exit 1 on a regression or a missing cell, `--update` proposes new floors),
  `tools/interop/run-local.sh --perf` and the weekly `.github/workflows/perf.yml` (JVM image vs ngtcp2 and quinn, results kept 7 days, runner logs
  only of failed runs). The floors warn instead of failing (`"blocking": false`) until re-measured on GitHub-hosted runners.
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
- `MemoryNetwork(receiveBuffer, assignEphemeralPorts)` (`@ExperimentalKuicksilverApi`): sockets of the in-memory network
  hold at most `receiveBuffer` unread datagrams (256 by default) and count what a full buffer drops, `open` on port 0 binds
  an ephemeral port, oversized datagrams are dropped instead of truncated, and `trySend` counts only addressed datagrams.

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

K7 (0.2.0), HTTP/3 and the Ktor engines:

- A QPACK encoder-stream instruction cut into many fragments by the transport was re-copied and re-parsed per
  fragment (quadratic in its length); it is now appended to once and parsed when its known length has arrived
  (RFC 9204 section 7.4).
- Request-stream frame hygiene: a flood of unknown frames on a request stream (reserved GREASE types excepted) spends
  glitch tokens and closes the
  connection with `H3_EXCESSIVE_LOAD` like one on the control stream (RFC 9114 section 7.2.8); DATA on a response to
  HEAD or with status 204 or 304 is a malformed message (`Http3Exception.MessageError`) instead of a body; `te` is
  accepted in requests only — a response or trailers carrying it are malformed, the server engine drops it from
  application responses (RFC 9110 section 10.1.4).
- HTTP/3 server: a request whose HEADERS were still arriving when the final GOAWAY went out counted as idle, so the
  connection could close under it; a request stream now counts as in flight from its first byte (RFC 9114 section 5.2), and is
  rejected with `H3_REQUEST_REJECTED` if its HEADERS are still incomplete 10 seconds after the final GOAWAY.
- Ktor server: with `port = 0` the HTTP/3 endpoint bound the UDP twin of the port the OS gave TCP, and the start
  failed with `BindException` when that UDP port was taken; the TCP + UDP pair is now retried on a new port up to 16
  times, then HTTP/3 is skipped with a warning and HTTP/1.1 is served alone.
- HTTP/3 server: a body the application wrote to a response to HEAD, or with status 204 or 304, went out as DATA
  (Ktor's `respondText` on a HEAD route did that), which a conforming client treats as a malformed message; it is now
  dropped and `content-length` is kept (RFC 9110 sections 9.3.2, 15.3.5, 15.4.5).
- HTTP/3 client: the `Http3Request.onInformational` and `trailers` callbacks ran on the connection's single-threaded
  dispatcher, so a slow callback stalled every stream of the connection; they now run on the caller's dispatcher.
- HTTP/3: the peer's `SETTINGS_MAX_FIELD_SECTION_SIZE` is honoured when sending (RFC 9114 section 4.2.2): a request
  above it fails with `Http3Exception.FieldSectionTooLarge` before a stream is opened, response headers and trailers
  above it fail `respond`/`finish` (refused trailers reset the stream with `H3_INTERNAL_ERROR` rather than
  leaving it without FIN), request trailers reset the stream and fail the request or its response
  body with `FieldSectionTooLarge` — instead of being sent for the peer to refuse.
- Ktor client: a non-idempotent request that failed on a pooled HTTP/1.1 connection the server had closed is no
  longer sent again (RFC 9112 section 9.3.1); only idempotent requests get the transparent retry, and connections
  already closed for reading are dropped when taken from the pool.
- Ktor client: the h3/h1 connection race makes one HTTP/1.1 attempt (a second TCP connection was opened when both
  setups failed), closes an HTTP/1.1 connection that lost the race instead of leaking it (also when the caller is
  cancelled), and marks the alternative broken when a request fell back to HTTP/1.1 after its HTTP/3 connection
  failed — not for a single stream error (RFC 7838 section 2.4, RFC 8305 section 5).
- Ktor client: the Alt-Svc stores, broken-alternative marks and per-origin RTTs are bounded — 8 alternatives per origin (the first ones
  of the header), 1000 origins with the least recently used dropped — so a server, or many origins, can no longer grow
  them without limit. `FileAltSvcStore` reads at most that many records, skips the rewrite when a repeated header only
  moves the expiry later by less than half its lifetime (a shorter `ma` always replaces the cached expiry), writes through a uniquely named temporary file, and, behind the
  when used by the engine, writes after the engine's lock is released instead of blocking every request on disk I/O (a write is not lost
  when its request is cancelled, and a pending one is flushed when the engine closes). `AltSvcEntry`
  equality compares the alternative, not its expiry (RFC 7838 sections 2.2, 3, 9.4).
- Ktor server: a `tlsConnector` with a `sniSelector` and HTTP/3 on failed to start with `TlsException.Config`; it now
  serves HTTP/1.1 and skips HTTP/3 with a warning (no `Alt-Svc`), as on a platform without a QUIC server.
- Ktor server contract: the two multipart-upload tests run over HTTP/3 as well (they were marked HTTP/1.1-only;
  they pass unchanged).

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
- An `accept()` cancelled just as the queue handed it a connection no longer keeps that queue slot and leaves the
  connection open: the connection is closed and the slot released.
- `samples/realtime-telemetry` reads control lines with a 1024-byte limit; a longer line closes the connection (code 2)
  instead of growing the server's buffer.

### Security

- Connection IDs, tokens, path challenges and packet-number skips come from OpenSSL's `RAND_bytes` through a
  thread-safe per-loop source; a non-cryptographic generator is no longer used on production paths.
- HTTP/3 header frames are read incrementally instead of allocating their declared length up front.
- TLS-over-TCP session tickets are bound to the server's client-authentication and trust configuration, so a ticket
  only resumes under the configuration that issued it.
- Bounds checks on every buffer copy in the JNI and cinterop bindings.
