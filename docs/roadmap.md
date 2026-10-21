<!-- Copyright 2026 The Kuicksilver Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Roadmap

Decisions of 2026-10-09, with the 0.2.0 scope widened on 2026-10-12 (0-RTT, the Windows QUIC server and the
interop throughput thresholds moved in) and, on 2026-10-14, 0.2.0 made the first public release: the 0.1.0 candidate
is never published. 0.2.0 was released on 2026-10-18. The compliance status per RFC section is in
[rfc-compliance.md](spec/rfc-compliance.md); the design in [architecture.md](architecture.md) and the
[ADRs](adr/README.md); the changes in [CHANGELOG.md](../CHANGELOG.md).

## 0.1.0 — candidate, never published

Frozen on 2026-10-09 as the first public release, then superseded by 0.2.0 before it was published; it has no tag and
no Maven Central deployment. What it contains ships with 0.2.0: QUIC v1 (RFC 9000/9001/9002,
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
  ([rfc-compliance.md](spec/rfc-compliance.md), interop `handshakecorruption`).
- No 0-RTT (ADR-0008), no HTTP/2 in the client engine (ADR-0009), no HTTP/3 server push, no certificate
  compression (RFC 8879), no OCSP/CRL checks of our own (the platform verifier decides under `TrustConfig.Platform`).
- No macosX64 target.
- The `kuicksilver-testing` module is not published.
- The deferred review findings listed under 0.2.0 (none affects correctness on a healthy network).

## 0.2.0 — first public release

Implemented 2026-10-12/13 and released on 2026-10-18; the first version published on Maven Central, released from a
maintainer's macOS host with `tools/release/local-release.sh` ([release.md](release.md)). It contains the 0.1.0
candidate above.

| Platform | Client | Server | UDP path |
|---|---|---|---|
| JVM (Linux, macOS, Windows) | yes | yes | accelerated `KslDatagramIo` (GSO/GRO on Linux, USO/URO on Windows where granted); NIO as fallback |
| Android (arm64-v8a, armeabi-v7a, x86_64) | yes | yes | accelerated |
| Kotlin/Native Linux x64 / arm64 | yes | yes | accelerated |
| Kotlin/Native macOS arm64, iOS | yes | yes (macOS arm64 tested; iOS on the simulator, also against a host peer) | accelerated, without GSO/GRO (ADR-0006) |
| Kotlin/Native Windows (mingw x64) | yes | yes | accelerated (Winsock) |

Windows (Kotlin/Native and the JVM) is cross-built and was verified in a local Windows 11 VM (Parallels). The GitHub
Actions workflows are disabled; the gate is `tools/ci/local-matrix.sh` (with `--with-windows` for the Windows VM).

What 0.2.0 brings:
- Hardening from the 2026-10-08 full review: PATH_CHALLENGE backoff
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
- The interop runner's `perf` protocol and throughput thresholds (`tools/interop/perf-thresholds.json`, checked by
  `tools/interop/run-local.sh --perf`; the floors warn until they are measured on more than one host, and the weekly
  `perf` workflow that would run them is disabled like the other workflows).
- BBR congestion control (draft-ietf-ccwg-bbr-06, BBRv3), shipped in 0.2.0 by decision: opt-in and experimental
  (`Bbr`; CUBIC stays the default), with spurious-loss undo, restart from idle, PMTU changes, property tests, a Jazzer
  target and harsh simulator scenarios against CUBIC ([Choosing a congestion controller](guide/quic.md#choosing-a-congestion-controller)).

Known limits of 0.2.0, stated on purpose:
- A handshake under heavy loss with an ML-KEM peer, as in 0.1.0; mitigated by `QuicConfig.initialRtt`
  ([quic.md](guide/quic.md)).
- 0-RTT is opt-in and experimental (ADR-0015); a replay into another server process that shares explicit ticket keys
  passes the freshness check only (threat model 3.8).
- No HTTP/2 in the client engine (ADR-0009), no HTTP/3 server push, no certificate compression (RFC 8879), no OCSP/CRL
  checks of our own (the platform verifier decides under `TrustConfig.Platform`).
- `loops > 1` only on Linux and Android (kernel `SO_REUSEPORT` flow hashing); macOS and Windows run one loop per port.
- Windows: verified in a local VM only, no hosted CI run (above).
- iOS: the test suites run on the simulator, also against a peer on the host; not yet verified on a physical device.
- No macosX64 target. The `kuicksilver-testing` module is not published.

## After 0.2.0

The 0.3.0 scope was decided on 2026-10-21, with a release planned for December 2026; what comes after it is a
proposal, not a commitment. The order may change with user feedback, and every item still follows the release bar (each
bug fixed with a test before a release).

### 0.2.x — patch releases

0.2.1 is a bug-fix release, prepared on the `release/0.2.x` branch for November 2026.

- Fixes from early user reports.
- A run of the iOS device checklist on a physical iPhone ([Device checklist](guide/ios.md#device-checklist)).
- A published benchmark table: goodput, CPU per GB and handshakes per second against quiche, quinn and msquic (done for
  0.2.1, [benchmarks.md](benchmarks.md)).
- Supply chain: an SBOM (CycloneDX) and build provenance for the published artifacts (done for 0.2.1,
  [release.md](release.md)).
- Hosted CI (GitHub Actions) when the workflows are enabled again; until then the local gate (`tools/ci/local-matrix.sh`).
- Longer soak (24–72 h) and fuzzing campaigns (at least 2 h per target).
- A statement in [stability.md](stability.md) that the library is not FIPS-certified (done for 0.2.1).
- Server CPU ([Where the time went](benchmarks.md#where-the-time-went)), each measured with `tools/bench` before and after:
  - one `SSL_CTX` per server configuration, shared by its QUIC sessions, instead of one per session: 53 µs of the
    server's ~180 µs of OpenSSL work per handshake (the context is frozen after configuration; what needs care is the
    per-context state `ksl` keeps: the last error, the SNI override, the ticket-key reference);
  - stream writes: every write through `QuicStream.output` is a flush that ends in a packet of its own, so a server
    writing a file in 8 KiB pieces costs two to four times the CPU per GB of one large write, on both ends (a short
    packet per write, about 2.8 times the ACKs). Coalesce: hand writes to the core without sending while more is queued
    and in flight (Linux TCP's autocorking), keeping a lone write's latency;
  - the Kotlin/Native core: 3.2 times the JVM's time in the core benchmark with the Null crypto, 1.5 times with AES-GCM,
    after the `PacketBuffer` fix (`CoreThroughputBenchmark`); next in its profile are `Duration` arithmetic on the
    per-packet paths (pacer, PTO, ACK delay; nanoseconds as `Long` instead), enum `==` compiled to a virtual `equals`,
    list index checks in `ConnectionIdManager`, and varints read and written byte by byte;
  - per connection, about 80 KiB of buffers allocated up front (16 KiB in each direction per stream, the crypto streams'
    16 KiB scratch and four 4 KiB send rings): allocate on first use.

### 0.3.0 — client and server completeness (planned for December 2026)

- WebTransport over HTTP/3 (draft-ietf-webtrans-http3), experimental.
- RFC 9460 HTTPS records as a source of h3, off by default.
- QUIC server, rebind during the handshake: keep both candidate addresses as separate paths and challenge both, so that
  a client that really rebinds while an observer races copies of its packets from the old address is not held on the
  dead one until the handshake timeout (the known limit in [rfc-compliance.md](spec/rfc-compliance.md), RFC 9000 §9
  rebind row; the reference implementations lose that handshake as well).
- The client follows a server's preferred address (RFC 9000 §9.6).
- NEW_TOKEN: the server issues tokens, the client stores and returns them (RFC 9000 §8.1.3).
- The Capsule Protocol on CONNECT streams (RFC 9297 §3).
- HTTP/3 priorities exposed in the Ktor engines (RFC 9218).
- PMTUD from ICMP Packet Too Big as a hint (RFC 8899 §4.6).
- Clients: SOCKS and system proxy settings, Happy Eyeballs on TCP (RFC 8305), WebSocket permessage-deflate (RFC 7692).
  The Ktor client gets a `proxyResolver` setting whose default is the system proxy (HTTP/3 is not used through a proxy).
- Server: certificate hot reload and a limit on TCP connections.
- `loops > 1` on macOS and Windows.

### 0.3.x

- QUIC-LB (`PathId` and the CID layout are prepared).

### Later

- Multipath.
