<!-- Copyright 2026 The Kuicksilver Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Roadmap

Owner decisions of 2026-10-09, with the 0.2.0 scope widened on 2026-10-12 (0-RTT, the Windows QUIC server and the
interop throughput thresholds moved in while the 0.1.0 publication waits on Maven Central). The compliance status per
RFC section is in `spec/rfc-compliance.md`; the design in `spec/2026-10-02-kuicksilver-design.md`; the changes in
`../CHANGELOG.md`.

## 0.1.0 — first public release

Frozen on 2026-10-09, not yet published (the Maven Central quota is pending). What ships: QUIC v1 (RFC 9000/9001/9002,
v2 by RFC 9369), HTTP/3 with QPACK, the Ktor client engine (HTTP/1.1 + HTTP/3 with Alt-Svc discovery) and the Ktor
server engine, TLS 1.3 over OpenSSL 3.5 through the `ksl` shim.

| Platform | Client | Server | UDP path |
|---|---|---|---|
| JVM (Linux, macOS) | yes | yes | NIO; accelerated `KslDatagramIo` on Linux |
| Android (arm64-v8a, armeabi-v7a, x86_64) | yes | yes | accelerated |
| Kotlin/Native Linux x64 / arm64 | yes | yes | accelerated |
| Kotlin/Native macOS arm64, iOS | yes | no (ADR-0006) | portable |
| Kotlin/Native Windows (mingw x64) | yes | no | portable |

Known limits of 0.1.0, stated on purpose:
- A handshake under heavy loss with an ML-KEM peer: both flights span two datagrams and the RFC 9002 initial PTO
  (1 s, 2 s, 4 s before an RTT sample) gives three retransmissions before a 10 s peer timeout
  (`spec/rfc-compliance.md`, interop `handshakecorruption`).
- No 0-RTT (ADR-0008), no HTTP/2 in the client engine (ADR-0009), no HTTP/3 server push, no certificate
  compression (RFC 8879), no OCSP/CRL checks of our own (the platform verifier decides under `TrustConfig.Platform`).
- No macosX64 target.
- The `kuicksilver-testing` module is not published.
- The deferred review findings listed under 0.2.0 (none affects correctness on a healthy network).

## 0.2.0

Implemented on the integration branch (2026-10-12/13); released after 0.1.0.

| Platform | Client | Server | UDP path |
|---|---|---|---|
| JVM (Linux, macOS, Windows) | yes | yes | accelerated `KslDatagramIo` (GSO/GRO on Linux, USO/URO on Windows where granted); NIO as fallback |
| Android (arm64-v8a, armeabi-v7a, x86_64) | yes | yes | accelerated |
| Kotlin/Native Linux x64 / arm64 | yes | yes | accelerated |
| Kotlin/Native macOS arm64, iOS | yes | yes (macOS arm64 tested; iOS compiled and linked) | accelerated, without GSO/GRO (ADR-0006) |
| Kotlin/Native Windows (mingw x64) | yes | yes | accelerated (Winsock) |

Windows (Kotlin/Native and the JVM) is implemented and cross-built, but no CI run on Windows has passed on this code
(GitHub Actions is paused); the owner's verification in a local Windows VM is pending for the release.

What 0.2.0 brings:
- Hardening from the 2026-10-08 full review (`docs/plans` F1–F4 in the owner's notes): PATH_CHALLENGE backoff
  (RFC 9000 §8.2.4), NEW_CONNECTION_ID retransmission against a retired sequence, Retry token bound to the SCID,
  ECN accounting per space with out-of-order ACKs, the O(n) hot spots in `onAck`, `onMaxData` and
  `StreamScheduler.add`, NIO timer starvation, server path-list growth, `AltSvcCache`/`FileAltSvcStore` limits,
  idle close after GOAWAY with unfinished requests, QPACK on fragmented input, `te`/HEAD/204/304 edge cases,
  `keylogFile` O_NOFOLLOW, `KslLoader` directory ownership, `SessionCache` across engines; a full reassembly range
  table drops the packet instead of closing the connection (RFC 9000 §21.7).
- `QuicConfig.initialRtt` (default 333 ms per RFC 9002; a lower value trades spurious retransmissions for a faster
  handshake under loss) validated in (0, 10 s] and the lossy-handshake behaviour documented in the guide.
- The accept queue: `acceptQueue` 128 by default, and an Initial that arrives while it is full is refused statelessly
  with CONNECTION_REFUSED (RFC 9000 §5.2.2).
- Automatic migration on network changes: `NetworkMigrator` in common code and `followDefaultNetwork` on Android
  (requested by the first external consumer).
- QUIC server on Kotlin/Native macOS: `ksl_udp` over `sendmsg`/`recvmsg` and `poll` (kqueue not needed, ADR-0006), the
  server test suites on `macosArm64`; the JVM on macOS moves from NIO to the accelerated socket.
- QUIC server on Kotlin/Native Windows (`ksl_udp` over Winsock, `WSAPoll`), also used by the JVM on Windows.
- Dual-stack wildcard binds on the accelerated socket (Linux, Apple), IPv6 literal URLs in the Ktor client.
- 0-RTT (RFC 9001 §4.6), opt-in and experimental (ADR-0015): the ADR-0013 review (2026-10) keeps its three layers and
  puts freshness on OpenSSL's check (the ticket lifetime and the 10 s allowance between reported and computed ticket
  age, which is the replay window). It adds a per-process replay register keyed by ticket, single-use client tickets in
  the per-engine session cache, and HTTP/3 safe-method gating with RFC 8470 `425`.
- The Ktor engines' HTTP/3 tests and the vendored contract suites on every target.
- Coverage reports of the JVM tests with Kover (`-Pkuicksilver.coverage :koverHtmlReportJvmTests`, no threshold).
- The interop runner's `perf` protocol and throughput thresholds (`.github/workflows/perf.yml`; the floors warn until
  re-measured on GitHub-hosted runners).
- BBR congestion control (draft-ietf-ccwg-bbr-06, BBRv3), owner decision to ship it in 0.2.0: opt-in and experimental
  (`Bbr`; CUBIC stays the default), with spurious-loss undo, restart from idle, PMTU changes, property tests, a Jazzer
  target and harsh simulator scenarios against CUBIC (`guide/quic.md` "Choosing a congestion controller").

Known limits of 0.2.0, stated on purpose:
- A handshake under heavy loss with an ML-KEM peer, as in 0.1.0; mitigated by `QuicConfig.initialRtt`
  (`guide/quic.md`).
- 0-RTT is opt-in and experimental (ADR-0015); a replay into another server process that shares explicit ticket keys
  passes the freshness check only (threat model 3.8).
- No HTTP/2 in the client engine (ADR-0009), no HTTP/3 server push, no certificate compression (RFC 8879), no OCSP/CRL
  checks of our own (the platform verifier decides under `TrustConfig.Platform`).
- `loops > 1` only on Linux and Android (kernel `SO_REUSEPORT` flow hashing); macOS and Windows run one loop per port.
- Windows: verification pending (above); `TrustConfig.Platform` is not available on Kotlin/Native Windows (use
  `AnchoredCa`); a `0.0.0.0` bind there is IPv4-only (bind `::` for both families).
- iOS is compiled and linked; its tests have not run on a device or simulator.
- No macosX64 target. The `kuicksilver-testing` module is not published.

## After 0.2.0

- RFC 9460 HTTPS records as a source of h3.
- WebTransport.
- Multipath.
- QUIC-LB (`PathId` and the CID layout are prepared).
