<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, any 0.x release may contain breaking changes.

## [Unreleased]

Nothing has been published yet. This section lists the work for 0.2.0, the first version to be published on Maven
Central, made on top of the 0.1.0 candidate. That candidate, frozen on 2026-10-09, was never published (no tag, no
Central deployment); it is summarised in the last section, and its changes reach users with 0.2.0.

### Added

QUIC (`kuicksilver-quic`, `kuicksilver-native`):

- 0-RTT, opt-in and experimental (ADR-0015, RFC 9001 section 4.6, RFC 8470): `QuicClientConfig.earlyData`,
  `QuicServerConfig.earlyData`/`earlyDataContext`, `QuicEndpoint.connectEarly`, `QuicConnection.awaitHandshake`/
  `earlyDataAccepted`/`isHandshakeComplete`, `QuicStream.receivedEarly`, `QuicException.ConnectionLost.ZeroRttRejected`;
  HTTP/3 `Http3Endpoint.connectEarly`, `Http3Request.allowEarlyData`, `Http3Settings.earlyData`
  (`Http3EarlyDataPolicy.WaitForHandshake`/`Reject425`), `Http3ServerRequest.receivedEarly`; Ktor client
  `http3 { earlyData }`, server `quicEarlyData` and `ApplicationRequest.receivedEarly`. Off by default. Anti-replay:
  OpenSSL ticket-age freshness, a per-server replay register keyed by ticket, tickets bound to the server
  configuration, safe methods only before the handshake.
- QUIC server on Kotlin/Native macOS: the accelerated `ksl` UDP socket (ADR-0006) works on Apple platforms — ECN marks
  sent and read per datagram, DF set for PMTUD (`IP_DONTFRAG`), no GSO/GRO (Darwin has none). `QuicEndpoint.bind` with
  a server and the Ktor server engine over HTTP/3 run on `macosArm64`; iOS compiles and links the same code.
- QUIC server on Kotlin/Native Windows (`mingwX64`): `ksl_udp` over Winsock (`WSASendMsg`/`WSARecvMsg` with `WSAPoll` and
  a wake socket, ECN through `IP_ECN`/`IPV6_ECN` on Windows 10 2004+ / Server 2022, USO/URO where the system grants them,
  DF, dual-stack IPv6 sockets, `SO_EXCLUSIVEADDRUSE`); the JVM on Windows uses the same socket through JNI. Winsock is
  started when the Kotlin/Native runtime starts (not from a C constructor, which in a `sharedLib` would run under the
  loader lock), so address lookups before the first socket do not fail with `WSANOTINITIALISED`. Verified in a local
  Windows 11 VM (Kotlin/Native and the JVM); GitHub Actions is not used.
- `NetworkMigrator` (experimental): a client connection follows a `Flow` of networks, migrating to each new one (RFC 9000
  section 9) and closing the path it left; a failed migration keeps the old path, `disable_active_migration` is
  respected, `MigrationEvent` reports `Migrated`, `Failed`, `NetworkLost` and `SourceFailed` (the network flow threw; the
  migrator stops without failing the caller's scope). `start()` and `close()` are thread-safe.
- Android: `QuicConnection.followDefaultNetwork(connectivityManager, scope)` keeps a client connection on the device's
  default network (Wi-Fi ↔ cellular), `ConnectivityManager.defaultNetworks()` (one shared callback per manager, whatever
  the number of connections) and `DatagramIo.open(local, network, prefer)`, which binds a socket to an
  `android.net.Network`. The `kuicksilver-quic` AAR now declares `ACCESS_NETWORK_STATE`.

- BBR congestion control, opt-in and experimental: `quicConfig { congestionController = { Bbr() } }`
  (draft-ietf-ccwg-bbr-06, BBRv3: delivery-rate sampling, windowed max bandwidth and min RTT,
  Startup/Drain/ProbeBW/ProbeRTT, `inflight_longterm` and the short-term bounds from loss, ECN-CE treated as loss, undo
  of a loss episode found spurious, pacing at the estimate after an idle period, floors that follow PMTUD). CUBIC stays
  the default. BBR is paced even when the smoothed RTT is below 1 ms (its pacing rate is its main control); window-based
  controllers keep the sub-millisecond exemption. On a simulated 50 Mbit/s, 40 ms link with 1 % random loss BBR moved
  37-40 Mbit/s where CUBIC moved 2.7-2.9; with 1 % of packets reordered by 8 ms 43 against 3.0; in an 8 BDP buffer it
  kept a 2.3 ms mean queue where CUBIC queued 274 ms (`guide/quic.md`). Loss detection now reports a packet declared
  lost and acknowledged later (RFC 9002 section 6.1).

- Observability, experimental (docs/guide/quic.md "Observability"): `QuicEndpoint.stats` sums `EndpointStats` over every
  loop and gains connection (active, accepted, refused by accept queue, admission, limits or shutdown), handshake
  (completed, failed by timeout, TLS alert or other), 0-RTT (offered, accepted, rejected), datagram (in, out, dropped at
  the socket, a queue, undecryptable, unanswered), path validation and internal failure counters (`uncaughtFailures`,
  `sendFailures`, `listenerFailures`), all plain loop fields with no cost per packet; `KuicksilverLogger`
  (`QuicEndpointConfig.logger`, default `KuicksilverLogger.Stderr`, which keeps the old warning on standard error) with
  `Debug` connection lifecycle lines that never carry keys, secrets, tickets or tokens; `ConnectionListener`
  (`QuicEndpointConfig.listener`: opened, handshake complete, 0-RTT outcome, path changed, closed with its
  `ConnectionLost` reason); `AsyncQlogSink`, which runs any `QlogSink` on its own writer with a bounded queue (drops
  counted) and 1-in-N sampling so a slow disk never stalls the endpoint loop; `QuicConfig.toBuilder()`.
- Graceful shutdown, experimental: `QuicEndpoint.shutdown(grace, code, reason)` refuses new clients at their first
  Initial with a stateless CONNECTION_REFUSED (the accept-queue refusal), lets live connections finish within `grace`,
  then closes the rest with an application CONNECTION_CLOSE and the endpoint.

- iOS and macOS network following (experimental, `appleMain`): `nwPathUpdates()` reports the default path of one shared
  `NWPathMonitor` as `NwPathKey` (preferred interface index and kind, null while unsatisfied), `DatagramIo.open(local,
  interfaceIndex)` binds the accelerated socket to an interface with `IP_BOUND_IF`/`IPV6_BOUND_IF`, and
  `QuicConnection.followDefaultNetwork(scope)` returns a started `NetworkMigrator` over both, as
  `followDefaultNetwork(connectivity, scope)` does on Android.
- Lost sockets (experimental): a socket error that means the socket is gone (`ENOTCONN`, `EBADF`, `EPIPE`, `ENOTSOCK` as
  iOS reports for a suspended app's sockets, and `ENETDOWN`, `ENETUNREACH`, `EHOSTUNREACH` on receive) is
  `SocketDefunctException` on the accelerated and the portable transports; the loop stops using that socket and reports
  `PathEvent.SocketLost` instead of failing the connection (a migrated path's socket) or the client endpoint (its own
  socket), and `QuicConnection.rebind()` moves the connection to a fresh socket. A `NetworkMigrator` rebinds on its own
  when the active path's socket is lost. A client endpoint whose socket is lost refuses `connect` at once; a server
  endpoint's socket loss still ends the endpoint.

HTTP/3 (`kuicksilver-http3`):

- `Http3Endpoint.stats` (the endpoint's `EndpointStats`) and `Http3Endpoint.shutdown`, which shuts the QUIC endpoint
  down gracefully and closes what is left with H3_NO_ERROR (experimental).

Ktor client (`kuicksilver-ktor-client`):

- Observability, experimental (docs/guide/ktor.md "Observability"): `KuicksilverEventListener` (call start/end/failure,
  protocol chosen and why, race outcome, Alt-Svc used and marked broken, fallback, retry, pool acquire/release),
  `logger`, `http3.qlog`, `http3.connectionListener`.
- Connection limits and idle cleanup (`@ExperimentalKuicksilverApi`): `maxConnectionsCount` (1000) and
  `maxConnectionsPerRoute` (100) bound the HTTP/1.1 connections of an engine and of one route, as in Ktor CIO; requests
  beyond them wait in FIFO order within the connect timeout (`ConnectTimeoutException`), cancellation-safe.
  `idleTimeout` (5 minutes, as OkHttp) closes idle keep-alive connections and HTTP/3 connections without requests, and
  `maxConnectionLifetime` (infinite) retires connections by age; a background reaper does both and drops the bookkeeping
  of origins without connections. HTTP/3 keeps one connection per origin and queues requests for the peer's MAX_STREAMS
  credit (bounded by the request timeout) instead of failing or opening more connections.

Both Ktor engines (`kuicksilver-ktor-network`, `kuicksilver-ktor-client`, `kuicksilver-ktor-server`):

- Ktor version policy: the engines support Ktor 3.6.x. Creating a client engine and starting a server engine on the JVM
  or Android read the Ktor jars' manifest versions and fail with an `IllegalStateException` that says what to do when
  the major.minor differs; `-Dkuicksilver.ktor.versionCheck=false` turns the check off. Kotlin/Native fails at link time
  instead.

Ktor server (`kuicksilver-ktor-server`):

- Observability, experimental: `KuicksilverServerEventListener` (connections and requests over HTTP/1.1 and HTTP/3,
  failed TLS handshakes), `logger`, `qlog`, `connectionListener`. The server's `stop(gracePeriod, timeout)` now shuts
  each HTTP/3 endpoint down with `QuicEndpoint.shutdown` next to its GOAWAY, so a client arriving during the grace
  period is refused within a round trip instead of timing out.

Testing (`kuicksilver-testing`, not published) and tooling:

- The ABI dumps leave out the companion objects and nested classes of `@InternalKuicksilverApi` classes (the JVM and
  Android dumps listed `KslUdpSocket.Companion` and `KslUdpSocket.Stats`); `checkInternalAbi`, part of `check` and run
  after `checkKotlinAbi`, fails when a JVM or Android dump lists a class that is, or is nested in, an internal class.
- `MemoryNetwork(receiveBuffer, assignEphemeralPorts)` (`@ExperimentalKuicksilverApi`): sockets of the in-memory network
  hold at most `receiveBuffer` unread datagrams (256 by default) and count what a full buffer drops, `open` on port 0
  binds an ephemeral port, oversized datagrams are dropped instead of truncated, and `trySend` counts only addressed
  datagrams.
- Windows Native platform trust tests against the Internet (`www.google.com`, badssl.com's broken certificates), run
  only with `KUICKSILVER_NETWORK_TESTS=1`; the TLS guide gains a per-platform table of what `TrustConfig.Platform`
  verifies with and checks for revocation.
- The Ktor server's HTTP/3 tests and the vendored Ktor 3.6.0 engine contract suites run from `commonTest` on every
  target (HTTP/3 where a QUIC server can bind); the two multipart-upload contract tests run over HTTP/3 as well (they
  were marked HTTP/1.1-only and pass unchanged).
- Coverage of the JVM tests with Kover: `-Pkuicksilver.coverage :koverHtmlReportJvmTests` (or `:koverXmlReportJvmTests`)
  merges the published modules; no threshold, by decision, and ordinary test runs are not instrumented.
- Throughput floors for the QUIC Interop Runner measurements: `tools/interop/perf-thresholds.json` (goodput and
  crosstraffic per peer and role, from the recorded runs minus 25 % / 40 %), `tools/interop/check-perf.sh` (measured vs
  floor, exit 1 on a regression or a missing cell, `--update` proposes new floors), `tools/interop/run-local.sh --perf`
  and the weekly `.github/workflows/perf.yml` (JVM image vs ngtcp2 and quinn, results kept 7 days, runner logs only of
  failed runs). The floors warn instead of failing (`"blocking": false`) until re-measured on GitHub-hosted runners.
- Reproducible builds: base images pinned by digest, the Gradle wrapper by checksum, `-ffile-prefix-map` in the native
  builds, and `tools/check/double-build.sh` (builds the native libraries from two checkout paths and compares them) and
  `tools/check/pins.sh`; the CI scripts and OpenSSL tasks run on fresh GitHub runners.
- Releases from the owner's Mac, no GitHub runner (`docs/release.md`): `tools/release/local-release.sh <version>`
  builds the mingw-w64 OpenSSL and the five JVM JNI libraries (manylinux2014 `.so` for x86_64 and aarch64 in Docker,
  `.dylib` for arm64 and x86_64, the mingw-w64 `.dll`), checks each as CI does (exports, imports, glibc floor, the
  pinned OpenSSL inside, `manifest.sha256`), checks that the jar carries all five, counts the deployment against the
  Central limits and runs `publishToMavenCentral` once; `--dry-run` stops before the upload and publishes into
  `build/release/m2`. It refuses a version, branch, tree or toolchain that does not fit, and a commit without a
  passing gate record: `tools/ci/local-matrix.sh` now writes `build/ci/gate/<commit>.stamp` and gains `--with-windows`
  (the JVM suites in a Windows 11 VM). `tools/check/consumer-smoke.sh` reads another local repository from
  `KSL_MAVEN_REPO`. The `release` workflow stays as an alternative and is not used for 0.2.0.
- Soak and churn harness `kuicksilver-soak` (not published): a Ktor server (HTTP/1.1 + HTTP/3) and raw QUIC servers on
  real UDP under a weighted mix of client scenarios, with RSS, heap, descriptor, `ksl` live-object and library-table
  sampling, a Theil–Sen flatness verdict and a return-to-baseline check (CONTRIBUTING.md, "Soak and churn").
  `ksl_live_objects` (additive in `ksl` ABI 6) counts live native contexts, sessions, keys, key and session handles, UDP
  sockets and wake descriptors.
- Interop endpoint: the runner's `resumption` and `zerortt` cases (session tickets and opt-in 0-RTT, ADR-0015), green
  against quic-go, ngtcp2, quiche, picoquic, quinn and msquic in both roles with the JVM and native images; the K7
  matrix and its analysis are in `docs/spec/rfc-compliance.md` ("Interop matrix K7"), including BBR vs CUBIC
  measurements against quic-go and ngtcp2.
- `LinkParams.queueLimitBytes` (tail drop) and a shared bottleneck for several simulated connections; BBR property
  tests, a Jazzer target (`bbrInvariants`) and harsh BBR-versus-CUBIC simulator scenarios. The interop endpoint takes
  `KSL_CC=bbr` (or `newreno`, `cubic`) to select its congestion controller.
- `:kuicksilver-ktor-client:iosHostInteropTest`: the iOS simulator against a host peer (JVM) that the task starts and
  stops, its control port passed as `SIMCTL_CHILD_KSL_PEER_PORT`; Ktor HTTP/3 and HTTP/1.1 to the host, raw QUIC echo to
  the host and from a host JVM client to a server on iOS, over 127.0.0.1 and ::1. Without the variable the tests pass
  without running.
- iOS sample (`samples/ios`, not published): a SwiftUI app over a Kotlin Multiplatform `shared` module (HTTP/3 GET,
  a QUIC echo session with path events, a QUIC/HTTP/3 server advertised over Bonjour, trust choices), the
  `kuicksilver-swift` umbrella that builds `Kuicksilver.xcframework` with its privacy manifest
  (`kuicksilver-native/apple/PrivacyInfo.xcprivacy`), and the checks `tools/check/ios-sample-smoke.sh` (simulator build,
  `-smoke` launch, XCTest), `ios-symbols.sh` (no clash with an unprefixed OpenSSL in the same app), `ios-size.sh` and
  `ios-private-api.py`. Guides: `docs/guide/ios.md` (consumption, privacy manifest, export compliance, size, device
  checklist) and `docs/guide/app-store.md` (App Store and Mac App Store publishing, with templates).

Documentation:

- `docs/stability.md`: what 0.2.0 promises per stability level (stable, `@ExperimentalKuicksilverApi`,
  `@DelicateKuicksilverApi`, `@InternalKuicksilverApi`, unpublished modules) across patch and minor releases, the
  deprecation cycle, how `checkKotlinAbi` and the ABI dumps guard it, the `ksl` ABI (6) and its loader check, the Ktor
  3.6.x version check, the OpenSSL 3.5 policy, the platforms and how each was verified, and the experimental API of
  every published module.
- `docs/guide/configuration.md`: every option of `QuicConfig`, `QuicClientConfig`, `QuicServerConfig`,
  `QuicEndpointConfig`, `TlsConfig`, `TrustConfig`, `Http3Settings` and both Ktor engines with its type, default and
  range, the system properties and environment variables, and the limits that are not configurable.
- `docs/guide/troubleshooting.md`: symptom, cause and fix for handshake timeouts, refusals, certificate errors,
  idle timeouts, migration failures, MTU black holes, the portable-socket fallback, Windows and Apple specifics,
  native loader errors, the Ktor version check and HTTP/3 discovery, with the logger, counters and qlog for diagnosis.
- Stale statements corrected: Windows (Kotlin/Native and the JVM) was verified in a Windows 11 VM, binds `0.0.0.0`
  dual-stack and has `TrustConfig.Platform` (README, roadmap, QUIC and Ktor guides); the iOS guide's size and import
  figures are re-measured (stripped app 5955 KiB, 647 imports) and it names `followDefaultNetwork`; ADR-0006 says how
  Windows 11 treats a CE mark.

### Changed

QUIC (`kuicksilver-quic`):

- Configuration validation: `QuicConfig.handshakeTimeout` must be positive, `maxSendBuffer` 1..2^62, `maxIdleTimeout`
  zero or positive and finite, `keepAlive` positive and finite; `TlsConfig.handshakeTimeout` must be positive,
  `SessionTicketConfig.rotateEvery` positive and `ticketLifetime` at least 1 s. Zero, negative or infinite values were
  accepted and misbehaved later (a zero `keepAlive` sent a PING in every packet). `QuicEndpointConfig` names
  `maxConnections` and `acceptQueue` in its refusals instead of "Failed requirement.", as does
  `ConnectionAdmission.default`.
- `keepAlive` is allowed with `maxIdleTimeout = ZERO` (only the peer's idle timeout applies then, and keep-alive is what
  holds the connection), and PINGs go out at least every half of the effective idle timeout, so a peer whose timeout is
  shorter than the interval no longer closes the connection (quic-go's `KeepAlivePeriod` semantics).
- `NetworkMigrator` also migrates when the active path's socket is lost (`PathEvent.SocketLost`), to a fresh socket on
  the current network.
- `QuicConnection.pathEvents` may report the new `PathEvent.SocketLost`; an exhaustive `when` over `PathEvent` needs a
  branch for it.
- `QuicEndpointConfig.acceptQueue` defaults to 128 (was 32), and a client Initial that arrives while the accept queue is
  full is refused at once with a stateless Initial CONNECTION_CLOSE carrying CONNECTION_REFUSED (0x02), under the
  stateless rate limits, instead of being dropped: the client's `connect` fails with
  `ConnectionLost.TransportClosed(code = 0x02)` within a round trip rather than at its handshake timeout, and the server
  spends no TLS handshake on it (RFC 9000 section 5.2.2, as quic-go does). Handshakes in flight still do not count
  against the queue; one admitted earlier that completes into a full queue is still closed with CONNECTION_REFUSED.
- The JVM on macOS uses the accelerated `ksl` socket (`KslDatagramIo`) by default instead of NIO, as Linux already did:
  DF is set (PMTUD can grow past 1200 bytes, up to 1452 on loopback), ECN marks are read per datagram so paths can
  validate ECN, receives run as 100 ms blocking slices on `Dispatchers.IO`, and a wildcard bind is dual-stack as with
  NIO. A refused socket falls back to NIO; `DatagramIo.open(local, IoPreference.Portable)` (or an endpoint built on it)
  keeps NIO.
- A STREAM frame that would open more than `maxReassemblyRanges` gaps in a stream is dropped unacknowledged (the peer
  retransmits it) instead of closing the connection with FLOW_CONTROL_ERROR: a burst that lost every other packet within
  one RTT (e.g. a full receive buffer) closed connections whose peer stayed within flow control. The memory bound is
  unchanged (RFC 9000 §21.7).
- `QuicConfig.initialRtt` is validated (positive, at most 10 s) and documented: it sets the first PTO (3 x `initialRtt`,
  doubling) and the floor of a path validation; a lower value shortens a handshake under loss at the price of spurious
  retransmissions (`docs/guide/quic.md`, "Configuration").
- QUIC API (breaking, before 1.0): `QuicException.ConnectionLost.TransportClosed.frameType` is a non-null `Long` (0 when
  no frame triggered the error; it was never null); `TimeoutKind.Disconnect`, never produced, is removed;
  `QuicStream.priority` reports the priority the stream was opened with instead of `StreamPriority.Default`;
  `ConnectionCore.pathState` answers `PathState.Closed` for a path the connection closed or evicted (`Unknown` stays for
  ids it never issued), so `QuicPath.state` of a path evicted by migration reads `Closed`.
- `loops > 1` needs `SO_REUSEPORT` granted on the first socket, so it stays Linux/Android-only; elsewhere (Darwin has no
  `SO_REUSEPORT` flow hashing, Windows binds exclusively) `bind` throws the documented `UnsupportedOperationException`
  instead of failing the second bind with `KslException.Internal`.

Native layer and TLS (`kuicksilver-native`, `kuicksilver-tls`):

- KDoc corrections: `SessionTicketConfig` and `TlsConfig.sessionTickets` also apply to a QUIC server with `earlyData`
  (they said QUIC ignores them); `KeylogSink`, `keylogFile` and `TlsConfig.keylog` say that `keylogFromEnvironment()`
  reads `SSLKEYLOGFILE` when called and that a system-OpenSSL Linux build refuses to load while it is set (they said it
  is never read).
- `EarlyDataState` is `@ExperimentalKuicksilverApi`, like every other part of the 0-RTT API it belongs to.
- Apple platform trust (`TrustConfig.Platform`, also under `Pinned` and `ExpectedName`) evaluates with
  `SecTrustEvaluateAsyncWithError` on a global dispatch queue and suspends the caller: an evaluation waiting on OCSP or
  AIA fetches no longer holds a `Dispatchers.Default` thread, so slow servers cannot stall other connections' handshakes.
- `Ksl.version()` (`ksl_version()`) reads `ksl abi 6 / OpenSSL 3.5.9 …` instead of `ksl 0.1.0 / …`: the shim is
  named by its ABI, as its library files are, so one native build serves every release of that ABI unchanged.
- `ksl` ABI 4 → 5 → 6; a library of an older ABI is refused (`AbiMismatch`).
  ABI 5: identity private keys stay in OpenSSL. `TlsIdentity.fromDer`/`fromPem` parse the key once into a native
  `ksl_pkey` (`ksl_pkey_new`, `ksl_pkey_free`, `ksl_ctx_set_identity_pkey`) and keep only its handle, so a heap dump no
  longer holds the key; `TlsIdentity.InMemory.close()` frees it once the contexts built from it are gone.
  ABI 6: early-data controls for 0-RTT (`KSL_OPT_EARLY_DATA`, `KSL_SET_EARLY_CONTEXT`, `KSL_SET_EARLY_DATA`,
  `KSL_GET_EARLY_DATA`); `EarlyDataState` gains `Allowed` and `Required`, and `QuicTlsSession.earlyData` becomes
  `earlyDataAccepted`.

Ktor client (`kuicksilver-ktor-client`):

- `maxConnectionsPerHost` is documented as what it always was, the number of idle HTTP/1.1 connections kept per route;
  it no longer stands in for a connection limit. The idle map of the HTTP/1.1 pool, which grew by one entry per origin
  and was never pruned, is gone: a route is dropped with its last connection.

### Removed

API that was never published (0.1.0 was not released), removed before 0.2.0 binds the API
([stability](docs/stability.md)):

- The deprecated type aliases `io.kuicksilver.quic.PathChanged` (use `PathEvent.Changed`) and
  `io.kuicksilver.quic.wire.VersionProfile` (use `io.kuicksilver.quic.VersionProfile`).
- `TimeoutKind.PathValidation`, which was never produced (a failed path validation ends in
  `ConnectionLost.NoViablePath`).
- Ktor client `http3 { softDelay }`, which was accepted but never acted on (the race uses `hardDelay` or the RTT-based
  head start).
- `TlsIdentity.Signer`, whose constructor always threw, and `PrivateKeySigner`: external signers are not implemented.
- `kuicksilver-native`: `JvmLoader` and `JvmNativeNames`, the loader's pieces made public for its tests, and the
  constant `KSL_ABI_VERSION` are internal; a mismatch still reports both versions in `KslException.AbiMismatch`.

### Fixed

Found by the fuzzing campaigns (threat model section 3.10):

- `QuicTlsSession.earlyDataAccepted` (and `ConnectionCore.earlyDataAccepted`) of a session whose handshake failed
  threw the native `KslException.Internal`; it now reports the last verdict (found by the `zeroRttHello` fuzz target).
- QUIC client: a `QuicSessionTicket.remembered` blob whose ALPN length runs past its end (the property is public) threw
  out of the ticket's use; it now gives no 0-RTT (found by the `rememberedTicket` fuzz target).
- QUIC: a flow-control error no longer leaves the connection's received-bytes total above the advertised limit (the
  total is checked before it is updated).
- QUIC: transport parameters listing more than about 250 versions in version_information could not be encoded (the
  encoder's buffer was a fixed 1024 bytes); the buffer now grows with the list (found by the `rememberedTicket` fuzz
  target; only our own parameters are encoded, so a peer could not trigger it).

QUIC migration right after the handshake (0.2.0 bug 1, iOS library report):

- A network change in the first moments of a connection no longer fails with "path validation failed" and leaves the
  connection on a dead path. A client that received the server's 0.5-RTT flight (its NEW_CONNECTION_ID frames) before
  it held both directions of the 1-RTT keys kept those packets buffered until the server's loss recovery resent them;
  it now replays them once the keys are complete, so the spare IDs arrive with the handshake (RFC 9000 §5.1.1). A
  probe that still finds no unused server connection ID waits up to max(3 x PTO, 6 x initial RTT) for one and probes
  when it arrives, never reusing the active path's ID (§9.5), and otherwise fails with the new, experimental
  `PathFailureReason.NoSpareConnectionId` (`ConnectionEvent.PathFailed.reason`, `PathEvent.Failed.reason`;
  `QuicConnection.migrate` throws `PathValidationException`, an `IllegalStateException`). `NetworkMigrator` reports
  that failure and migrates to the same network again as soon as a spare ID arrives.

QUIC core (review of 2026-10-08, deferred items):

- An unanswered `PATH_CHALLENGE` is repeated with an exponentially growing gap (1, 1, 2, 4 ... x PTO, so three
  challenges fit in the 3 x PTO validation timeout) instead of once per PTO (RFC 9000 §8.2.1, §8.2.4, RFC 9002 §6.2.1).
- Server: a client that migrates several times before its new addresses can answer no longer loses its newest address:
  with all four path slots taken, a migration abandons the oldest validation of a path the client has left (RFC 9000
  §8.2.4); a probe takes the slot of a validating path only after max(3 x PTO, 5 s) of silence.
- A handshaking server that follows a new address on an Initial no longer re-runs its timers continuously once that
  path's validation deadline passed without a Handshake packet (one forged Initial was enough).
- A packet buffered until its keys arrive is processed with the ECN mark, socket, source and length of its own datagram,
  not of the datagram that delivered the keys (RFC 9000 §13.4.1).
- A lost `NEW_CONNECTION_ID` whose sequence is below our own `retire_prior_to` is no longer retransmitted, and that
  connection ID stops routing 3 x PTO after the loss instead of staying registered (RFC 9000 §5.1.2, §19.15).
- Server: a Retry token is bound to the Retry's Source Connection ID; an Initial presenting it under another DCID is
  refused with a stateless `INVALID_TOKEN` close instead of becoming a connection (RFC 9000 §8.1.2–§8.1.4). Tokens minted
  before this change are not accepted (they live 10 s).
- ECN validation looks only at ACKs that raise the largest acknowledged packet, keeps the peer's counts per packet number
  space instead of per path, and counts newly acknowledged marked packets per path; a reordered ACK no longer fails ECN
  on the path, and a new path no longer takes the first counts it sees for a CE signal (RFC 9000 §13.4.2.1).
- Work a peer can trigger no longer grows with what it controls (RFC 9000 §21.6): an ACK costs a binary search per range
  instead of a walk over every packet in flight, a `MAX_DATA` that raises nothing touches no stream, and choosing or
  scheduling a stream is logarithmic in the number of streams instead of linear.
- `ConnectionEvent.StreamWritable` and `StreamsAvailable` are raised (their KDoc said "not raised in this version"): after
  a refused write once acknowledgements free buffer room or new flow-control credit reaches waiting data, and after
  `MAX_STREAMS` raises a limit that refused an open; the coroutine API wakes the waiting writer or `openBidi`/`openUni`
  directly. The KDoc of `StreamFinished`, which was always raised, now says so (RFC 9000 §4.1, §4.6).
- DPLPMTUD no longer drops to 1200 bytes because the peer merely stalled. Two PTOs in a row above the base size count
  as a black hole only while a packet above 1200 bytes is among the unanswered ones (a receiver's small ACK and
  flow-control packets cannot be lost to the MTU), and a black-hole verdict is undone — MTU and search state back, no
  60 s pause — when a full-size packet sent after the packets it rested on is acknowledged afterwards. On a loaded host a
  50 MiB loopback upload ended at 1200 bytes on the client or the server in 12 of 33 runs, each time with no packet lost
  (RFC 8899 §4.1, §4.3).

Flow control (`kuicksilver-quic`; found with the BBR simulations, 2026-10-13):

- An upload no longer stalls for 10+ s when the window update that would let it continue is lost: the sender had nothing
  in flight and the receiver's only copy of its `MAX_DATA` / `MAX_STREAM_DATA` waited behind its PTO backoff (64 x PTO,
  about 11 s, with 75 % loss on the return path). A PTO probe now carries the stream control frames of the packet it
  stands in for (it was a bare PING when that packet held only `MAX_DATA` / `MAX_STREAM_DATA`); a blocked sender repeats
  `DATA_BLOCKED` / `STREAM_DATA_BLOCKED` / `STREAMS_BLOCKED` when the report is lost and, while it stays blocked,
  repeats `DATA_BLOCKED` / `STREAM_DATA_BLOCKED` one PTO later, then at gaps of 2, 4 and 8 PTOs through the 32nd repeat,
  then at doubling gaps up to a third of the idle timeout (the smaller of both sides' `max_idle_timeout`; 10 s when
  neither has one), so a receiver that stops reading costs about 95 reports in 10 minutes (30 s idle timeout, 36 ms PTO)
  instead of about 2 000 (a report every 1–3 s on a WAN path), and the reports still keep a blocked connection from
  idling out (with a short idle timeout the old 8 PTO gap let it idle out); a report at a new limit goes out at once and
  starts the fast gaps again. A receiver that already granted more answers a stale `DATA_BLOCKED` /
  `STREAM_DATA_BLOCKED` with its current limit at once (RFC 9000 §4.1, §13.3, §19.12–§19.14). One answer per smoothed
  RTT per connection or stream; a faster repeat is not answered and spends a glitch token (it used to be a repeat of the
  same limit). Simulated 50 Mbit/s, 40 ms upload with 75 % ACK-path loss, 20 seeds: mean goodput 7.2 → 18.5 Mbit/s
  (CUBIC) and 7.3 → 21.0 Mbit/s (BBR), longest stall after the handshake at most 7.5 s instead of 13.6 s. quic-go,
  quiche, ngtcp2 and msquic send each report once per limit and at most retransmit it on loss (msquic also re-sends
  `STREAM_DATA_BLOCKED` on every acknowledgement); `docs/spec/rfc-compliance.md` compares them.
- Receive-window auto-tuning works: the stream manager's clock was never set, so every window update looked
  instantaneous and doubled the window, and every connection that moved more than a few MB grew to the ceilings
  (6 MiB per stream, 15 MiB per connection) whatever its application read. The core now hands its clock and smoothed RTT
  to the stream manager with each datagram and timer, and the rule is quic-go's (`maybeAdjustWindowSize`): a window
  doubles only while the application reads a whole window in under four RTTs (it doubled when a quarter took under two,
  which settled at 8–16 x the bandwidth-delay product). A slow reader keeps its initial window. Defaults unchanged
  (quic-go's: 512 KiB → 6 MiB per stream, 768 KiB → 15 MiB per connection). Simulated 50 Mbit/s, 40 ms upload,
  greedy reader, seeds 31–35: goodput unchanged (clean: CUBIC 48.2, BBR 46.7 Mbit/s; 1 % loss: CUBIC 2.8, BBR 38.3
  Mbit/s), final receive windows 6 / 15 MiB before, now 2–4 / 3–6 MiB on the clean link and 0.5–2 / 0.75–3 MiB at 1 %
  loss. Lost `MAX_DATA` / `MAX_STREAM_DATA` / `RESET_STREAM` / `STOP_SENDING` are queued once per stream instead of
  once per loss report.

QUIC TLS, key update and versions (`kuicksilver-quic`, `kuicksilver-native`; conformance review of 2026-10-14):

- Key update (RFC 9001 §6.1): after our own update the previous read key now stays until a packet of the new phase
  authenticated, then 3 x PTO; it used to go 3 x PTO after the update, so on an idle connection the peer's later
  old-phase packets failed authentication. A further update waits 3 x PTO after the ACK that confirmed the previous
  one (§6.5), and `QuicConnection.keyUpdate()` is woken when that wait ends.
- A peer without the quic_transport_parameters extension is closed with 0x016d (RFC 9001 §8.2); the handshake used to
  complete without the RFC 9000 §7.3 connection ID checks. A ClientHello with a legacy_session_id is a
  PROTOCOL_VIOLATION (§8.4), and so is a NewSessionTicket with a max_early_data_size other than 0xffffffff (§4.6.1;
  OpenSSL's illegal_parameter is mapped). No packet is processed after closing at the AEAD integrity limit (§6.6).
- 0-RTT and QUIC v2 (RFC 9369 §4.1, §5): across a compatible v1 -> v2 upgrade the client keeps 0-RTT in its original
  version and the server takes it with original-version keys (it never decrypted before); tickets carry the
  negotiated version of their connection and are not resumed for a connection started in another version, by the
  client nor by `ksl`. A Retry in another version than the client's Initial is ignored.
- 0-RTT packets use only the remembered transport parameters until 1-RTT (RFC 9000 §7.4.1); a smaller
  max_datagram_frame_size on acceptance is a PROTOCOL_VIOLATION (RFC 9221 §3).
- version_information (RFC 9368 §4): an Available Version of zero and a client Chosen Version missing from its
  Available Versions are parsing failures; an empty server list after Version Negotiation is VERSION_NEGOTIATION_ERROR.

QUIC congestion control and loss recovery (conformance review of 2026-10-14):

- Persistent congestion (RFC 9002 §7.6.2) needs two lost ack-eliciting packets sent after the first RTT sample, with no
  packet between them acknowledged, and is judged per path. A lost first Initial and two lost PTO probes used to drop
  every such handshake to the 2-datagram window; ACK-only and skipped packet numbers no longer break the period, and
  padding-only packets no longer end it. After persistent congestion min_rtt restarts from the newest sample (§5.2).
- The window grows only when the sender used it before the ACK frame (RFC 9002 §7.8): an ACK of a whole window in slow
  start counted half of it as application-limited, and in congestion avoidance a sender using 55 % of its window
  still grew it. The margins are quic-go's: at most 3 datagrams unused, or more than half in flight in slow start.
- CUBIC: the time since the epoch no longer includes application-limited ACKs or time with nothing in flight (RFC 9438
  §4.2; after 30 s idle the window grew 1.5x per RTT past W_max); the Reno-friendly alpha becomes 1 once W_est reaches
  the window before the last reduction (§4.3). HyStart++ takes every RTT sample of a round, checks on each ACK from the
  8th sample, and uses the minimum of the round that entered Conservative Slow Start as baseline (RFC 9406 §4.2).
- NewReno (not the default) kept the remainder of max_datagram_size x acked / cwnd: congestion avoidance stalled above
  a 1.44 MB window.
- BBR: CE reports count toward the Startup exit like lost ranges (draft-ietf-ccwg-bbr-06 §3.7); a larger datagram size
  from PMTUD no longer raises the window (RFC 8899 §3), the 4-datagram floor applies when the window is next set.
- ECN: after the ten test packets nothing is marked until an ACK validates the path (RFC 9000 appendix A.4), so a path
  that drops marked datagrams costs those ten packets instead of everything sent until a PTO; only packets loss
  detection tracks count as test packets. CE-marked ack-eliciting packets are acknowledged at once (§13.2.1).

QUIC runtime and sockets:

- A client whose only socket was lost between handshake completion and confirmation ends at once with
  `ConnectionLost.NoViablePath`: it may not migrate yet (RFC 9000 §9) and can neither send its Finished nor receive
  HANDSHAKE_DONE, so `migrate()` used to wait for the 30 s idle timeout.
- The `UnsupportedOperationException` of a Kotlin/Native QUIC server without the accelerated socket named Linux and
  Apple only; Windows has the socket too. `ConnectionLost.Timeout`'s KDoc no longer lists the removed path-validation
  and disconnect timers, and the Ktor server's `udpSocketCount` KDoc says Linux and Android (it said Linux).
- The fallback to the portable socket when the accelerated socket's one-time loopback probe fails (a sandbox that
  refuses every bind) was silent; it is now logged once per process at `Warn`, like a refused bind: "accelerated UDP
  socket unavailable (<reason>); using the portable socket".
- Windows: a datagram sent with the CE codepoint no longer turns ECN off for its socket. Windows 11 refuses CE in the
  `IP_ECN` / `IPV6_ECN` control message (`WSAEINVAL`); `ksl` took that for a refusal of ECN itself, so every later
  ECT(0) datagram of the socket left unmarked. CE is now sent unmarked and ECT stays on. The QUIC core never sends CE
  (RFC 9000 section 13.4.1), so connections were not affected; a `DatagramIo` user sending CE was, and so was the JVM
  test that does (`KslDatagramIoTest.ecnSurvivesLoopback`, which failed on Windows).
- A lost path socket (`PathEvent.SocketLost`) is forgotten when its connection ends: the loop's list of lost sockets,
  which keeps them from being written again, dropped an entry only when the path itself was closed, so every connection
  that ended on a lost migrated socket left one behind for the life of the endpoint.
- Windows: `0.0.0.0:P` binds port P again. The dual-stack socket that `0.0.0.0` opens since the Windows fixes was bound to
  `::` on port 0, so an explicit port was silently replaced by a random one (a server on `0.0.0.0:4433` listened elsewhere,
  and a port an IPv4 socket held was not refused). Found by the port guard tests in the Windows 11 VM
  (`udp_win_wildcard_explicit_port_kept`, ADR-0006).
- macOS and iOS: a socket bound to a wildcard address (the Ktor client's endpoint, `0.0.0.0:0`) no longer gets a port an IPv4
  socket of another process or endpoint already holds. Darwin picks a dual-stack socket's port among the IPv6 ports only and
  bound an explicit `::` port beside `0.0.0.0` on it; that IPv4 socket then kept every IPv4 datagram for the port, so a client's
  handshake replies went elsewhere and the connection timed out (about one connect in five with 4000 IPv4 ports in use on the
  host; the rare 10 s `ConnectTimeoutException` of the contract suite on busy hosts). `ksl_udp` now takes a port free on the
  IPv4 side for a dual-stack socket and refuses an explicit one an IPv4 socket holds (ADR-0006).
- The endpoint's receive loop yields after 16 rounds or 2 ms of continuous traffic, so a socket that never runs dry (a
  flood) no longer starves the connection timers and queued application commands.
- No resolver call on the endpoint loop: on Kotlin/Native the address bytes of a datagram's source are parsed from its IP
  literal instead of `getaddrinfo`, and Stateless Reset candidates are keyed by address bytes and port, so a reset from
  `0:0:0:0:0:0:0:1` matches a connection to `::1`.
- A server whose peer keeps moving no longer keeps a path object per address it ever saw: paths the connection evicts (at
  most four) leave `QuicConnection.paths` and their sockets are closed.
- Datagrams the socket did not take (a failed send, or a full buffer that took part of a batch) are counted in the new
  `ConnectionStats.datagramsDroppedSocket` (`@ExperimentalKuicksilverApi`); the portable JVM socket waits once, briefly,
  for room instead of treating a refused datagram as sent.
- A socket whose `capabilities` lose ECN marking or DF (for example the portable socket clearing IP_TOS after a failed
  ECN validation) downgrades the connections already on it, the endpoint's socket and a migrating client's extra sockets
  alike, instead of only the connections that start afterwards.
- The accept queue never holds more than `acceptQueue` connections: a handshake that completes while the queue is full is
  closed with CONNECTION_REFUSED. Admission counts only the connections waiting for `accept()`, so half-open handshakes
  from spoofed sources cannot lock real clients out.
- An `accept()` cancelled just as the queue handed it a connection no longer keeps that queue slot and leaves the
  connection open: the connection is closed and the slot released.
- `KslUdpSocket.supported` answers false when its loopback probe fails for any reason (for example `bind` refused by the
  App Sandbox) instead of throwing, and `DatagramIo.open` falls back to the portable socket when the accelerated one is
  refused at bind time, with one line on standard error.
- The accelerated UDP socket (Linux, Apple) opens a dual-stack IPv6 socket for a wildcard address (`0.0.0.0` or `::`), as
  NIO did: the Ktor client (whose endpoint binds `0.0.0.0:0`) reaches IPv6 HTTP/3 servers, and a Ktor server on the
  default host serves HTTP/3 to IPv6 clients. Before, `0.0.0.0` gave an IPv4-only socket, so datagrams to IPv6 peers were
  dropped and the handshake timed out. ECN and DF cover both address families; IPv4 peers are reported as IPv4.
- Windows: the accelerated UDP socket opens a dual-stack IPv6 socket for `0.0.0.0` too, as on Linux and Apple, so the
  Ktor client (which binds `0.0.0.0:0`) reaches IPv6 HTTP/3 servers on Windows; without IPv6 it falls back to IPv4. DF
  stays on where Windows refuses `IP_MTU_DISCOVER = PROBE` (some Windows 11 builds), as msquic runs.
- Windows (JVM and Native): HTTP/3 and QUIC no longer stall up to 100 ms per flight. `ksl_udp_win.c` created its
  sockets without `WSA_FLAG_OVERLAPPED`, so Windows serialised a send behind the receiving thread's `WSAPoll` on the
  same socket; a small request took ~500 ms, an 8 MiB upload timed out after 60 s, and Ktor's redirect test with a 1 s
  budget failed. Sockets are now overlapped, as `socket()` and msquic create them.
- QUIC: a stateless Initial CONNECTION_CLOSE (INVALID_TOKEN, or CONNECTION_REFUSED at a full accept queue) leaked one
  native packet key per answer — a peer could grow the server's native memory without bound within the stateless rate
  limits; both Initial keys are freed now (found by the soak harness).
- QUIC: a client that closed after a migration closed its new socket before the CONNECTION_CLOSE was sent on it, so the
  server kept the connection (its streams, CIDs and memory) until its idle timeout; a closing connection now keeps its
  path sockets until it reaches the closed state (found by the soak harness).
- QUIC: a sender could stop for good once pacing switched on. The pacer refilled its bucket with rate x elapsed time,
  which overflowed after a long gap (about 80 s at 115 MB/s): a connection whose smoothed RTT stayed below 1 ms
  (unpaced) for minutes and then reached it got a negative refill, which was dropped without moving the refill time, so
  the pacer answered "a moment later" forever and the connection sent nothing until its idle timeout. On Linux loopback,
  where the RTT hovers around 1 ms, the Ktor client's pooled HTTP/3 connection hit it about twice per 30 min soak (every
  request in flight failed with "Idle timeout after 30s"). The same overflow stalled any controller after a short idle
  gap on a fast path (10 Gbit/s for 7.4 s, 1 Gbit/s for 74 s). A bucket whose fill time has passed is now simply full
  (found by the soak harness and by the review of BBR).
- A client endpoint starts a new connection to a server address it already measured from that address's last smoothed
  RTT (RFC 9002 section 6.2.2) instead of `QuicConfig.initialRtt`, so a lost first flight is probed after about three
  RTTs rather than after 1 s, 2 s, 4 s. Under heavy loss the old schedule left quic-go servers more than their 5 s
  handshake idle timeout without a packet, and they restarted the half-open connection (interop `handshakecorruption`).
  At most 256 addresses are kept (the least recently stored is dropped), only from connections that ended on the
  endpoint's own socket, and only on client endpoints.
- `QuicStream.output.flushAndClose()` hands the data still buffered in the channel to the core together with the FIN, so
  they leave in one STREAM frame when they fit a packet; before, it flushed the data first and sent the FIN in a packet
  of its own. Found by the interop case `zerortt` against quiche, whose hq server left 0-RTT requests whose FIN came
  alone unanswered; the interop client now writes its request into the channel's buffer and closes it in one step.
  `flushAndClose` also yields to the closes already queued on the endpoint loop before the packet is built, so requests
  closed concurrently share packets instead of taking one each (the interop `zerortt` client spent its initial window on
  one 303-byte packet per request and sent the last 0-RTT requests in 1-RTT).

TLS and native layer (`kuicksilver-tls`, `kuicksilver-native`):

- A client resuming under the OpenSSL verifier (`AnchoredCa`, `Platform` on Linux, and `Pinned`/`ExpectedName` over them)
  re-checked only the pins, so a chain that expired after the full handshake kept resuming, and sending 0-RTT, for the
  ticket's lifetime (ADR-0011). The cached chain is now verified again (`ksl_ctx_verify_chain`: trust store, time, name,
  purpose) before the ticket is offered; a chain that no longer passes runs a full handshake
  (`negative_resumptionRechecksCachedChainOnOpenSslPath`, `negative_resumeRechecksCachedChain`, C `verify_cached_chain_again`).
- `TrustConfig.AnchoredCa` with an intermediate CA among its roots rejected the chains through it with `UnknownIssuer`,
  although each listed certificate is documented as trusted as a root: OpenSSL accepted only chains up to a self-signed
  certificate. Every anchor now ends a chain (`X509_V_FLAG_PARTIAL_CHAIN`) (`anchoredAtIntermediateAccepts`, C
  `verify_openssl_verifier`).
- QUIC handshakes without ALPN completed: a server accepted a ClientHello without the extension and a client a server
  that negotiated none. Both now close with `no_application_protocol` (CRYPTO_ERROR 0x0178, RFC 9001 section 8.1), and
  `Http3Endpoint.connect`/`connectEarly` fail with H3_GENERAL_PROTOCOL_ERROR when a client that offered more than `h3`
  ends on another protocol (C `quic_no_alpn_is_no_application_protocol`,
  `Http3EndpointAlpnTest.negative_clientRefusesServerThatChoseAnotherProtocol`).
- A server with `ClientAuth.Optional` and `TrustConfig.Pinned` rejected every client that sent no certificate (TCP and
  QUIC); such a client is now accepted, as documented, and a presented certificate must still match a pin
  (`clientAuthOptionalPinnedAcceptsClientWithoutCertificate`, `quicServerOptionalPinnedAcceptsClientWithoutCertificate`).
- `TlsException.Verify` printed `VerifyReason.Expired` and the other object reasons as `ClassName@hash`; they are
  `data object`s now, so the message reads "certificate verification failed: Expired".
- `TrustConfig.Platform` works on Windows Native (mingwX64): it rejected every peer, so the default
  `HttpClient(Kuicksilver)` could not open any public HTTPS site. It now verifies with CryptoAPI
  (`CertGetCertificateChain` with the presented intermediates and AIA, `CertVerifyCertificateChainPolicy` with the SSL
  policy and the host name) and maps Windows errors to `VerifyReason` (`UnknownIssuer`, `Expired`, `NotYetValid`,
  `HostnameMismatch`, `Revoked`, `InvalidPurpose`, `BadSignature`); pins and `ExpectedName` apply as on the other
  platforms. Revocation of the leaf is checked, soft fail; verification runs on `Dispatchers.IO`.
- Linux Native: a host without a CA store (distroless, `scratch`) fails when a `TrustConfig.Platform` client
  configuration is built, with a `TlsException.Config` that names every path searched and `SSL_CERT_FILE`/
  `SSL_CERT_DIR`; before, a missing `/etc/ssl/certs` was accepted and every handshake failed with `UnknownIssuer`. When
  `SSL_CERT_FILE` or `SSL_CERT_DIR` is set, only they are used (as in Go), instead of falling back to the distribution
  paths. The search order is documented in the TLS guide.
- Platform trust reports `VerifyReason.UnknownRevocationStatus` when the JVM PKIX validator
  (`UNDETERMINED_REVOCATION_STATUS`) or Apple (`errSecIncompleteCertRevocationCheck`) could not determine revocation, and
  `VerifyReason.CertificateTransparency` when Android's CT policy rejects a chain, instead of `UnknownIssuer`.
- `QuicTlsSession` (`setTransportParameters`, `provide`, `resumeVerify`, `exportKeyingMaterial`) and
  `TlsConnection.exportKeyingMaterial` no longer leak the native `KslException.Internal`: a call in the wrong state throws
  `IllegalStateException`, other TLS errors `TlsException.Protocol`.
- `TlsConfig` counts ALPN names in UTF-8 bytes (a 200-character `é` name passed as 200) and refuses a list longer than 255
  bytes on the wire; a server's `ServerTlsOverride` passes the same ALPN and client-certificate trust checks as `build()`
  instead of none. Both copy the ALPN list before validating it, so the stored list is the one that was checked.
- The TCP client session cache holds at most 256 sessions (the least recently stored one is evicted and its native
  session freed) and each Ktor client engine owns its own cache, which it clears when it closes; before, one process-wide
  cache grew without bound and outlived every engine.
- A TCP session ticket is cached before the application data that followed it is delivered, so a client that reads one
  response and closes keeps the ticket for its next connection.
- `ksl`: setting the verify name a second time with the other identifier type (host after IP literal or the reverse)
  clears the previous one instead of checking both.
- `keylogFile` (and `keylogFile(context)`) on Android below API 26 throws `IllegalArgumentException` (the file cannot be
  checked without `java.nio.file`) instead of `NoClassDefFoundError`.
- TLS over TCP: the reader and the writer pump could drain ciphertext to the transport at the same time, reordering
  records (the peer failed with bad_record_mac) or failing the transport with "Concurrent write attempts" under
  full-duplex traffic; drains are serialized now (found by the soak harness).
- TLS over TCP: with both peers writing at once over full transports, a connection could stop for good. The reader pump
  drained ciphertext too, including the application data the writer pump had just encrypted, and while it waited for
  room on the transport it read nothing; when both peers' reader pumps did, neither transport emptied again. Only the
  writer pump and a separate drainer write to the transport now, and the reader pump never waits on it (found while
  chasing a hang of `AbandonedBodyTest`; `TlsConnectionTest.fullDuplexOverFullTransportsNeverStalls`).
- A TLS connection whose transport failed while the application was writing (a peer gone mid-response) left the
  application's writer waiting forever on a full output buffer; the output channel is now cancelled with the failure, so
  a Ktor server handler writing a long body to a client that left ends and releases its connection.

HTTP/3 (`kuicksilver-http3`):

- `Http3Settings` KDoc gave the defaults of `encoderMaxTableCapacity`, `maxFieldSectionSize`,
  `maxInformationalResponses` and `maxEarlyPriorityUpdates` in a form that read as ceilings ("32 at most"); it now
  states default and range, and a negative `maxInformationalResponses` or `maxEarlyPriorityUpdates` is refused with a
  message naming it.
- A QPACK encoder-stream instruction cut into many fragments by the transport was re-copied and re-parsed per fragment
  (quadratic in its length); it is now appended to once and parsed when its known length has arrived (RFC 9204 section
  7.4).
- Request-stream frame hygiene: a flood of unknown frames on a request stream (reserved GREASE types excepted) spends
  glitch tokens and closes the connection with `H3_EXCESSIVE_LOAD` like one on the control stream (RFC 9114 section
  7.2.8); DATA on a response to HEAD or with status 204 or 304 is a malformed message (`Http3Exception.MessageError`)
  instead of a body; `te` is accepted in requests only — a response or trailers carrying it are malformed, the server
  engine drops it from application responses (RFC 9110 section 10.1.4).
- Server: a request whose HEADERS were still arriving when the final GOAWAY went out counted as idle, so the connection
  could close under it; a request stream now counts as in flight from its first byte (RFC 9114 section 5.2), and is
  rejected with `H3_REQUEST_REJECTED` if its HEADERS are still incomplete 10 seconds after the final GOAWAY.
- Server: a body the application wrote to a response to HEAD, or with status 204 or 304, went out as DATA (Ktor's
  `respondText` on a HEAD route did that), which a conforming client treats as a malformed message; it is now dropped and
  `content-length` is kept (RFC 9110 sections 9.3.2, 15.3.5, 15.4.5).
- Client: the `Http3Request.onInformational` and `trailers` callbacks ran on the connection's single-threaded dispatcher,
  so a slow callback stalled every stream of the connection; they now run on the caller's dispatcher.
- The peer's `SETTINGS_MAX_FIELD_SECTION_SIZE` is honoured when sending (RFC 9114 section 4.2.2): a request above it fails
  with `Http3Exception.FieldSectionTooLarge` before a stream is opened, response headers and trailers above it fail
  `respond`/`finish` (refused trailers reset the stream with `H3_INTERNAL_ERROR` rather than leaving it without FIN),
  request trailers reset the stream and fail the request or its response body with `FieldSectionTooLarge` — instead of
  being sent for the peer to refuse.
- QPACK: a prefixed integer whose 10th continuation byte carried bits above bit 62 lost them silently (an even byte
  read 2^64 + n as n); such an encoding is now a decoding error (RFC 7541 section 5.1, RFC 9204 section 4.1.1).
- QPACK: one field longer than 64 KiB closed the whole connection with `QPACK_DECOMPRESSION_FAILED` (the decoder's
  string ceiling was fixed), even below a raised `maxFieldSectionSize`; the ceiling in field sections is now
  `maxFieldSectionSize`, and a longer string makes the section too large — the server answers 431 with
  `STOP_SENDING H3_EXCESSIVE_LOAD`, the client fails that request with `FieldSectionTooLarge`, other requests on the
  connection go on (RFC 9204 section 7.4). Encoder-stream strings keep the 64 KiB ceiling and the connection error.
- QPACK with the dynamic table on: a request or response stream that the peer reset, or whose body the reader
  abandoned, after its first HEADERS sent no Stream Cancellation, so the peer's encoder kept references to entries
  that trailers still in flight might use (they could never be evicted); one is now sent (RFC 9204 section 2.2.2.2).
- Request pseudo-headers are validated like quic-go does (RFC 9114 section 4.3.1): a `:method` that is not a token
  (`GET /admin X`), a `:path` that does not start with `/` (or is `*` for OPTIONS) or holds whitespace, userinfo in
  `:authority` (or in the `host` standing in for it) and a second `host` field make the request malformed
  (`H3_MESSAGE_ERROR`); before, such values reached the application, and a proxy could copy them into an HTTP/1.1
  request line.
- What we send is checked the same way: `Http3Connection.request` throws `IllegalArgumentException` for a request the
  peer would reject (`te` other than `trailers`, a bad method, path or authority, a `host` differing from the
  authority) before it opens a stream, and request trailers or response trailers (`finish`) with a pseudo-header, a
  connection-specific field or `te` throw it too and reset the stream — instead of being sent for the peer to reset.
- A HEADERS frame on an established CONNECT tunnel (a 2xx was sent or received, Extended CONNECT and WebSockets
  included) was taken as trailers and silently ended the tunnel's input; it is now a connection error
  `H3_FRAME_UNEXPECTED`, on the server and on the client (RFC 9114 section 4.4).
- HTTP datagrams follow the stream's state (RFC 9297 section 2.1): datagrams that arrived after the stream's receive
  side closed were still delivered (the registration lasted until both directions ended) and are now dropped, the
  `Http3Stream.datagrams` flow ending with the receive side; after our send side closed (`output` closed or `reset`)
  `trySendDatagram` still sent, and now answers `DatagramSendResult.Closed` (`sendDatagram` throws
  `IllegalStateException`).

Ktor client (`kuicksilver-ktor-client`):

- An `engine { tls { } }` block that set `alpn` or `serverName` replaced the request's: every HTTP/3 handshake failed on
  ALPN, or the certificate was verified against another name. Both are now set from the request after the block.
- Setting `quic = quicConfig { connectionIdLength = … }` alone made every HTTP/3 connect fail: the engine's endpoint
  kept its default length of 8. The endpoint and the connections now share one length (the one left at the default
  follows the other); two different explicit values fail the engine's creation with `IllegalArgumentException`.
- A non-idempotent request that failed on a pooled HTTP/1.1 connection the server had closed is no longer sent again
  (RFC 9112 section 9.3.1); only idempotent requests get the transparent retry, and connections already closed for
  reading are dropped when taken from the pool.
- The h3/h1 connection race makes one HTTP/1.1 attempt (a second TCP connection was opened when both setups failed),
  closes an HTTP/1.1 connection that lost the race instead of leaking it (also when the caller is cancelled), and marks
  the alternative broken when a request fell back to HTTP/1.1 after its HTTP/3 connection failed — not for a single
  stream error (RFC 7838 section 2.4, RFC 8305 section 5).
- The Alt-Svc stores, broken-alternative marks and per-origin RTTs are bounded — 8 alternatives per origin (the first
  ones of the header), 1000 origins with the least recently used dropped — so a server, or many origins, can no longer
  grow them without limit. `FileAltSvcStore` reads at most that many records, skips the rewrite when a repeated header
  only moves the expiry later by less than half its lifetime (a shorter `ma` always replaces the cached expiry), writes
  through a uniquely named temporary file, and, when used by the engine, writes after the engine's lock is released
  instead of blocking every request on disk I/O (a write is not lost when its request is cancelled, and a pending one is
  flushed when the engine closes). `AltSvcEntry` equality compares the alternative, not its expiry (RFC 7838 sections
  2.2, 3, 9.4).
- `FileAltSvcStore` persists on Android API 24-25: kotlinx-io's `atomicMove` needs `java.nio.file` (API 26), so every
  write failed and the store silently kept alternatives in memory only; it now falls back to `java.io.File.renameTo`,
  and a store that cannot be written logs one warning.
- IPv6 literal URLs (`https://[::1]:8443/`) connect on Kotlin/Native (the brackets reached `getaddrinfo`) and over
  HTTP/1.1 (the JVM connected to the reverse-resolved host name); `Alt-Used` brackets an IPv6 alternative (RFC 7838
  section 5).
- `HttpClient()` without an explicit engine finds the Kuicksilver engine on Android: the engine container and its
  `META-INF/services` entry were missing from the AAR.
- An HTTP/3 WebSocket on Kotlin/Native ends once Close frames were exchanged, as on the JVM, instead of waiting for the
  peer's FIN: Ktor's common WebSocket reader reads to the end of the stream, so a peer whose FIN trailed its Close frame
  delayed `webSocket {}` and one that never sent it kept the session open until the caller gave up. The engine now ends
  the input it hands to that reader after the peer's Close frame and abandons the rest of the stream with STOP_SENDING
  (RFC 6455 §7.1.1, RFC 9220).
- HTTP/1.1: a response body left halfway returned its connection to the idle pool with the rest of the body still on the
  wire (the server's handler blocked for the life of the client, and a later request on that connection would have read
  the old body); the connection is reused only after the whole body was read (found by the soak harness).
- `HttpStatement.execute {}` could hang forever when the block left a `bodyAsChannel()` body unread: Ktor's default
  transformer copies the raw body into the application's channel, and once a megabyte waited there unread its copier
  suspended on that channel; `execute` cancels the raw body (which does not wake a copier waiting on its destination)
  and joins the call, which waits for the copier. A body cancelled while still open now cancels its call, over HTTP/1.1
  and HTTP/3, so `execute` returns. The suspended copier itself belongs to Ktor's client scope and is released only when
  the `HttpClient` closes (found as a 60 s hang of `AbandonedBodyTest` under load).
- Over HTTP/3 a URL with a query but no path (`https://host?a=1`) went out as `:path ?a=1`, which RFC 9114 section 4.3.1
  makes malformed (strict servers such as quic-go reset it, and the HTTP/3 layer now refuses it); it is sent as `/?a=1`.
- HTTP/1.1 connection pool: a request waiting for a connection is resumed after the pool's lock is released. With
  `engine { dispatcher = Dispatchers.Unconfined }` the waiter resumed inside the lock, and one whose connection failed at
  once (or whose connect failed before suspending) spun forever on the lock its own thread held. A waiter cancelled
  while the engine closes now ends with `CancellationException`, not `IllegalStateException`.
- HTTPS through an HTTP proxy failed on every platform with `ClassCastException`: the proxy's address was cast to
  `ktor-network`'s `InetSocketAddress`, which `ProxyConfig.resolveAddress()` never returns. A `2xx` answer to the CONNECT
  that carried `Content-Length` made the client wait for that many bytes before its ClientHello, until the connect
  timeout; Content-Length and Transfer-Encoding of a successful CONNECT response are now ignored (RFC 9110 §9.3.6).
- HTTP/1.1 responses are framed as RFC 9112 §6.3 says, where the vendored Ktor CIO code did not: a response without
  Content-Length or Transfer-Encoding is read until the server closes the connection (it failed with "Failed to parse
  request body"); a chunked body with a trailer section is accepted (the trailer fields, at most 16 KiB, are discarded;
  it failed with "Expected CR"), and one cut before its last chunk fails instead of arriving short; a transfer coding
  other than a final `chunked` is read until close. A request that sends `Connection: close` is the last one on its
  connection even when the server does not echo the option (§9.6).
- An idle pooled HTTP/1.1 connection that won the h3/h1 race was treated as a new one, so an idempotent request on it
  failed when the server had closed it, without the one transparent retry the plain HTTP/1.1 path gives (RFC 9112 §9.3.1).
- Client 0-RTT (`http3 { earlyData = true }`) no longer defeats the h3/h1 race and the fallback: a connection that
  merely had 0-RTT keys won every race, confirmed QUIC on the network, marked the alternative working and stored its
  initial RTT estimate as the origin's; on a path that dropped UDP a GET waited for the 10 s handshake timeout instead
  of the connect timeout, and a POST (which waits for the handshake) failed without falling back although it was never
  sent. Now a 0-RTT connection wins before its handshake only where QUIC was confirmed, the bookkeeping waits for the
  handshake, the connect timeout bounds the handshake, and a request that waited for a failed handshake falls back to
  HTTP/1.1.
- `Alt-Svc` on HTTP/3 responses is processed (RFC 7838 §3): a `clear`, or a new list, sent over the alternative in use
  replaced nothing, so clients already on HTTP/3 kept a retired alternative until its `ma` ran out (24 h by default).
  The `Alt-Svc` parser resolves quoted-pairs (`\"` no longer ends a quoted string or lets a comma inside it split the
  list).

Ktor server (`kuicksilver-ktor-server`):

- `quicMaxIdleTimeout` applied whenever `quic` was the `QuicConfig.Default` instance, so `quic = QuicConfig.Default`
  counted as unset; it now applies only while `quic` was never assigned, whatever the value assigned.
- With `port = 0` the HTTP/3 endpoint bound the UDP twin of the port the OS gave TCP, and the start failed with
  `BindException` when that UDP port was taken; the TCP + UDP pair is now retried on a new port up to 16 times, then
  HTTP/3 is skipped with a warning and HTTP/1.1 is served alone.
- A `tlsConnector` with a `sniSelector` and HTTP/3 on failed to start with `TlsException.Config`; it now serves HTTP/1.1
  and skips HTTP/3 with a warning (no `Alt-Svc`), as on a platform without a QUIC server.
- A failed HTTP/3 request (for example a client resetting a WebSocket CONNECT stream) no longer cancels the
  connection's handler and aborts the Kotlin/Native process; each request contains its own failure.
- HTTP/1.1 request framing follows RFC 9112 §6: a request without Content-Length or Transfer-Encoding has no body, also
  a POST with `Connection: close` (Ktor CIO's pipeline read the connection to its end, so `receiveText()` waited for a
  half-close the client never sends); a chunked body with a trailer section is accepted (it failed with "Expected CR"),
  the trailer fields discarded. The connection pipeline is now a copy of Ktor CIO's in `h1/ServerPipeline.kt`, and
  `ktor-server-cio` is no longer a dependency.
- A request a gateway forwarded from early data, marked `Early-Data: 1` (RFC 8470 §5.1), was processed as an ordinary
  request: `receivedEarly` was false and an unsafe method ran although it may be a replay. Over HTTP/1.1 and HTTP/3,
  such a request now has `receivedEarly` true, and one the early-data policy does not declare replayable gets
  `425 Too Early` without reaching the application.
- The startup Ktor version check also covers `ktor-network`, `ktor-io` and (client) `ktor-websockets`, whose internals
  the engines use: a build that pinned one of them to another minor passed the check and failed later with
  `NoSuchMethodError`.

Both Ktor engines on Kotlin/Native (`kuicksilver-ktor-network`, `kuicksilver-ktor-client`, `kuicksilver-ktor-server`):

- HTTP/1.1 over IPv6 binds and connects the address it is given on Linux, Apple and Windows Native. The engines opened
  their TCP sockets with Ktor 3.6.0's `ktor-network`, whose native sockets never copy the IPv6 address into
  `sockaddr_in6` and so use `::` for every IPv6 bind and connect: a server connector on `::1` listened on every interface
  (and on IPv4), a request to an IPv6 address went to the local host on Linux and Apple, and Windows Native refused it
  with `WSAEADDRNOTAVAIL` (10049). The engines now use `kuicksilver-ktor-network`'s own native TCP sockets (`bindTcp`,
  `connectTcp`; `ktor-network` as before on the JVM and Android). The portable Native UDP socket, which still uses
  `ktor-network`, refuses a specific IPv6 bind address and IPv6 destinations instead. An upstream report is drafted in
  `docs/upstream/ktor-native-ipv6.md`.

Samples and testing:

- `samples/realtime-telemetry` reads control lines with a 1024-byte limit; a longer line closes the connection (code 2)
  instead of growing the server's buffer.
- The `NullCryptoProvider` test protection binds the packet number into its tag, so a misdecoded packet number fails to
  open as with real keys instead of being acknowledged.

### Security

- CRYPTO data at an encryption level TLS has left was buffered without bound (RFC 9001 §4.1.3): after one valid
  ClientHello, in-order Initial CRYPTO went to a `ksl` buffer OpenSSL never reads again, so a client could grow a
  server's memory at its own bandwidth until the handshake timeout, uncounted by admission. Such data is now a
  PROTOCOL_VIOLATION (the Initial stream is sealed when TLS reads Handshake, the Handshake stream at completion), the
  Initial stream ends at 64 KiB and the Handshake stream at 256 KiB (CRYPTO_BUFFER_EXCEEDED, as ngtcp2), `ksl` refuses
  data below its read level and holds at most 256 KiB unread per level, and that data counts toward admission's
  handshake buffer bytes.
- Findings of the local fuzzing campaigns (`tools/fuzz/campaign.sh`, threat model §3.10), each with a regression input
  and a test: a server endpoint answering a short-header datagram over 1500 bytes to an unknown connection ID with a
  stateless reset overflowed its answer buffer and threw out of `EndpointCore.handleDatagram`; a client that received a
  Retry with a token too large for its next Initial (Retry integrity keys are public, so an on-path attacker can forge
  one) threw out of `poll` — such a Retry is now dropped (tokens up to 1024 bytes are taken); a peer's RESET_STREAM final
  size was checked against the connection window only, so it could exceed the stream window without FLOW_CONTROL_ERROR
  (RFC 9000 §4.1, §4.5, §19.10); every PATH_CHALLENGE a connection sent was appended to a test-only record that was never
  trimmed (as was every MTU update), so an attacker who forged copies of a peer's packets from ever new addresses grew the
  connection's memory without bound — the records now keep their latest 64 entries; a connection ID the peer retired
  keeps routing for 3 × PTO and is replaced at once, so a peer that retired every new ID grew the retired set and the
  endpoint's routing table without a fixed bound — at most 32 retired IDs route at once, the oldest stops early.
- Kotlin/Native: a Ktor server connector bound to a specific IPv6 address (for example a loopback-only `::1` endpoint) no
  longer listens on every interface and on IPv4, and a client request to an IPv6 address no longer reaches a local
  process on the same port instead of the intended host (threat model section 3.19,
  `negative_ipv6ConnectorListensOnItsAddressOnly`, `negative_h1ToIpv6LiteralReachesThatAddressOnly`).
- `ksl`: `KSL_OPT_CLIENT_CERT` is refused on a client context (it rewrote `SSL_CTX_set_verify` and switched server
  verification off); `KSL_OPT_VERIFY_MODE` and `KSL_OPT_CLIENT_CERT` reject values outside 0..2.
- `TrustConfig.Pinned` refuses a `Custom` base wrapped in `ExpectedName` as it already refused a bare `Custom` (the spec:
  pins are checked against a chain the library validated, a custom verifier decides alone).
- `keylogFile(path)` refuses a symlink, a non-regular file, a file with more than one hard link, a file of another user or
  a file system without POSIX permissions, tightens an existing file to 0600 and reopens it without following links for
  every line (threat model section 3.7). On the JVM the sink keeps the one descriptor it checked for its lifetime (it is
  `java.io.Closeable`) instead of reopening the path for every line without re-checking the owner, so a file recreated
  at the path by another local user receives no secrets.
- `KslLoader` (JVM) refuses a work directory that is a symbolic link, not a directory, owned by another user or not
  private to it (`IntegrityMismatch`), and no longer deletes the extracted, verified library on exit, so a second JVM that
  shares the directory is not pulled from under its own `System.load`. It creates the work directory owner-only in one
  call (not under the umask), reuses an extracted library only when this user owns it (otherwise it reinstalls it
  atomically) and refuses to load when the user of the process cannot be determined on a POSIX file system.
- `TlsIdentity.fromPem` decodes the key straight from its `CharArray` instead of turning it into `String`s (which stayed
  on the heap) and wipes every decoded key block, also when the import fails.
- 0-RTT replay protection, hardened before its first release (threat model section 3.8): one replay register per process,
  shared by every endpoint, loop and configuration that can decrypt the process's tickets; forged ClientHellos no longer
  fill it; a wall clock stepped back cannot reopen a replay; an idle register stripe keeps a full half of history.
- TLS server with an `sniSelector`: the override's settings are now fully in effect. OpenSSL copies per-connection
  settings out of the base context when the session is created and an SNI context switch moved only the certificate, so
  an override that pins client certificates over a base that does not still sent a TLS 1.3 ticket before its pin verdict,
  and the client resumed with it past the pin (ADR-0011 rule 2). `ksl` now applies the override's ticket count, version
  range, options, verify mode and parameters, suites, groups, session context and early-data settings; a ticket is issued
  under such a configuration only after the pin verdict, and only such tickets resume there (`ksl` stamps each ticket)
  (`negative_sniOverridePinnedClientsNoTicketBeforeVerdict`, C `tcp_sni_override_settings_effective`).
- Ktor client: `Proxy-Authorization` (and `Proxy-Connection`) set on a request went to the proxy on the CONNECT and then,
  inside the TLS tunnel, to the origin server as well, which received the proxy credentials; they now stay on the
  CONNECT (RFC 9110 §11.7.2, threat model section 3.20, `negative_proxyCredentialsStayOnTheConnect`).
- Ktor client: a response with conflicting or invalid Content-Length values (`5` and `42`, `+5`) was framed by the first
  one and its connection returned to the pool, so the rest of its bytes became the response to the next request on it
  (response splitting); it now fails and the connection is closed (RFC 9112 §6.3 item 5). A response with both
  Content-Length and Transfer-Encoding is framed by the coding and its connection is not reused (item 3)
  (`negative_conflictingContentLengthFailsAndClosesConnection`, `negative_contentLengthWithTransferEncodingIsNotReused`).
- Ktor server: a request with both Content-Length and Transfer-Encoding was framed by the chunked coding and the
  connection kept open, so behind a front proxy that frames by Content-Length the rest of the bytes became a second,
  smuggled request; such a request is now refused with 400 and the connection closed (RFC 9112 §6.1, threat model
  section 3.20, `negative_contentLengthWithTransferEncodingIsRejectedAndClosed`).
- Session ticket keys no longer live on the Kotlin heap (security review 2026-10-14, threat model sections 1 and 3.7): the
  process-wide keys are generated and rotated inside `ksl`, and explicit `SessionTicketConfig(keys = …)` are copied into
  native memory when the configuration is built. **Breaking:** the arrays passed as `keys` are zeroed by the constructor
  (also when it throws), and the `SessionTicketConfig.keys` property is removed (the keys cannot be read back).
- `DirectoryQlogSink` no longer trusts the client-chosen connection ID it names files after (security review 2026-10-14,
  threat model section 3.2): files are created exclusively and never through a symbolic link (a planted link, FIFO or
  file is never followed, truncated or blocked on), named `<odcid>_<role>_<random>.sqlog`; the directory is created
  owner-only and refused when it is a link, another user's, or writable by others without the sticky bit; at most 256
  traces are open at once and 1 GiB is written over the sink's lifetime (experimental constructor
  `DirectoryQlogSink(directory, maxOpenTraces, maxTotalBytes)`).
- `keylogFile(path)` refuses a FIFO at the path instead of blocking until a reader appears (on Native that stalled the
  endpoint loop at the first secret line): Native opens with `O_NONBLOCK` and checks the descriptor, the JVM checks the
  path before opening it, Windows refuses anything but a regular file (security review 2026-10-14, threat model 3.7).
- Ktor client: an `Alt-Svc` alternative on a loopback, link-local or private address (or a `localhost` name) is ignored
  unless the origin itself is on such an address, and one on an unspecified, multicast or broadcast address always, so a
  verified origin cannot aim clients' QUIC Initials at their own network (RFC 9000 section 21.5, threat model 3.14).
- Kotlin/Native Linux clients with `TrustConfig.Platform` parse the system CA bundle once per process instead of once per
  connection (3.6 ms each, seven handshakes' worth); the shared store is reloaded when the bundle or `SSL_CERT_FILE` /
  `SSL_CERT_DIR` change (threat model 3.2, `tools/bench/ksl-ctx-bench.sh`).
- Supply chain (threat model 3.11): every Gradle dependency and plugin is verified by signature or SHA-256
  (`gradle/verification-metadata.xml`); a release rebuilds all twelve OpenSSL targets from the verified tarball instead of
  reusing `build/openssl`, and checks the Android `.so` files and the Kotlin/Native archives, as it did the JVM libraries,
  for the pinned OpenSSL, sanitizer or debug builds and the export whitelist or symbol prefix.

## 0.1.0 candidate (never published)

The first 0.x candidate: the code frozen on 2026-10-09 for the first public release. It was never published: on
2026-10-14 the owner made 0.2.0 the first Maven Central publication, and 0.2.0 contains everything below.

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
  Extended CONNECT (RFC 9220), HTTP datagrams (RFC 9297; the Capsule Protocol of its section 3 is not implemented, a correction of the 0.2.0 review), trailers, 1xx responses, GOAWAY.
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

### Security

- Connection IDs, tokens, path challenges and packet-number skips come from OpenSSL's `RAND_bytes` through a
  thread-safe per-loop source; a non-cryptographic generator is no longer used on production paths.
- HTTP/3 header frames are read incrementally instead of allocating their declared length up front.
- TLS-over-TCP session tickets are bound to the server's client-authentication and trust configuration, so a ticket
  only resumes under the configuration that issued it.
- Bounds checks on every buffer copy in the JNI and cinterop bindings.
