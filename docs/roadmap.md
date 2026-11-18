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
  ([interop.md](spec/interop.md), interop `handshakecorruption`).
- No 0-RTT (ADR-0008), no HTTP/2 in the client engine (ADR-0009; superseded by ADR-0017 for 0.3.0), no HTTP/3 server push, no certificate
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

Windows (Kotlin/Native and the JVM) is cross-built and was verified in a local Windows 11 VM (Parallels). At the time
of 0.2.0 the GitHub Actions workflows were disabled; the gate was `tools/ci/local-matrix.sh` (with `--with-windows` for
the Windows VM).

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
  `perf` workflow that would run them was disabled like the other workflows then).
- BBR congestion control (draft-ietf-ccwg-bbr-06, BBRv3), shipped in 0.2.0 by decision: opt-in and experimental
  (`Bbr`; CUBIC stays the default), with spurious-loss undo, restart from idle, PMTU changes, property tests, a Jazzer
  target and harsh simulator scenarios against CUBIC ([Choosing a congestion controller](guide/quic.md#choosing-a-congestion-controller)).

Known limits of 0.2.0, stated on purpose:
- A handshake under heavy loss with an ML-KEM peer, as in 0.1.0; mitigated by `QuicConfig.initialRtt`
  ([quic.md](guide/quic.md)).
- 0-RTT is opt-in and experimental (ADR-0015); a replay into another server process that shares explicit ticket keys
  passes the freshness check only (threat model 3.8).
- No HTTP/2 in the client engine (ADR-0009; superseded by ADR-0017 for 0.3.0), no HTTP/3 server push, no certificate compression (RFC 8879), no OCSP/CRL
  checks of our own (the platform verifier decides under `TrustConfig.Platform`).
- `loops > 1` only on Linux and Android (kernel `SO_REUSEPORT` flow hashing); macOS and Windows run one loop per port.
- Windows: verified in a local VM only, no hosted CI run at the time (above).
- iOS: the test suites run on the simulator, also against a peer on the host; not yet verified on a physical device.
- No macosX64 target. The `kuicksilver-testing` module is not published.

## After 0.2.0

The 0.3.0 scope was decided on 2026-10-21 and widened on 2026-11-16 to feature parity with the established QUIC and
HTTP stacks in other languages (quic-go, quiche, OkHttp, Netty, Cronet). Releases are planned, not dated: a release
ships when its gate passes ([process.md](process.md)). What comes after 0.3.0 is a proposal, not a commitment; the order
may change with user feedback, and every item still follows the release bar (each bug fixed with a test before a
release). The [Not planned](#not-planned) list says what the project will not do, and why.

### 0.2.x — patch releases

0.2.1, a bug-fix release from the `release/0.2.x` branch, was released on 2026-11-04.

- Fixes from early user reports and from the reviews against the RFCs ([CHANGELOG](../CHANGELOG.md)).
- A published benchmark table: goodput, CPU per GB and handshakes per second against quiche, quinn and msquic (done for
  0.2.1, [benchmarks.md](benchmarks.md)).
- Supply chain: an SBOM (CycloneDX) and build provenance for the published artifacts (done for 0.2.1,
  [release.md](release.md)).
- Longer soak and fuzzing campaigns (done for 0.2.1: a 24-hour Kotlin/Native soak and a 37-hour JVM soak, both flat, and
  2 hours per fuzz target).
- A statement in [stability.md](stability.md) that the library is not FIPS-certified (done for 0.2.1).
- Hosted CI: the `build` workflow runs on GitHub Actions on every push to `main` and `release/**`, every pull request to
  them, weekly and by hand (restored on `main` for 0.3.0). The local gate (`tools/ci/local-matrix.sh`) stays the
  release gate.

Moved to 0.3.0: a run of the iOS device checklist on a physical iPhone
([Device checklist](guide/ios.md#device-checklist)), and the server CPU work below.

### 0.3.0 — client and server completeness, feature parity (planned)

- WebTransport over HTTP/3 (draft-ietf-webtrans-http3), experimental.
- HTTP/2 (RFC 9113, HPACK RFC 7541) in a new module `kuicksilver-http2` (ADR-0017): the client offers `h2` next to
  `http/1.1` over TLS, the server serves it opt-in, WebSocket over HTTP/2 (RFC 8441, done in both engines); no
  server push, h2c under [Feature parity](#feature-parity-decided-2026-11-16).
- RFC 9460 HTTPS records as a source of h3, off by default (done: `http3 { httpsRecords }`).
- QUIC server, rebind during the handshake: keep both candidate addresses as separate paths and challenge both, so that
  a client that really rebinds while an observer races copies of its packets from the old address is not held on the
  dead one until the handshake timeout (the known limit in
  [RFC 9000 §9, rebind during the handshake](spec/rfc/9000.md#s9-rebind-during-the-handshake); the reference
  implementations lose that handshake as well).
- The client follows a server's preferred address (RFC 9000 §9.6).
- NEW_TOKEN: the server issues tokens, the client stores and returns them (RFC 9000 §8.1.3).
- The Capsule Protocol on CONNECT streams (RFC 9297 §3).
- HTTP/3 priorities exposed in the Ktor engines (RFC 9218) (done; the HTTP/2 server schedules its responses by them too).
- PMTUD from ICMP Packet Too Big as a hint (RFC 8899 §4.6).
- Clients: SOCKS5 (CONNECT; no GSSAPI method, see [RFC 1928 §3](spec/rfc/1928-1929.md#s3-gssapi)) and system proxy
  settings, Happy Eyeballs on TCP (RFC 8305), WebSocket permessage-deflate (RFC 7692). The Ktor client gets a `proxyResolver` setting whose default is the system proxy (HTTP/3 is not used through a proxy).
- Server: certificate hot reload and a limit on TCP connections.
- `loops > 1` on macOS, iOS and Windows: one socket routed in process by connection ID (done; the benchmark of what it buys is still to come).
- A run of the iOS device checklist on a physical iPhone ([Device checklist](guide/ios.md#device-checklist)).
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
  - per connection, buffers allocated up front: the CRYPTO send rings and scratch grow on first use (the Initial and
    Handshake rings, 2 KiB each, are kept after the handshake), and the stream halves' 16 KiB and the datagram flow's
    64 KiB are one scratch per endpoint loop (0.3.0); what is left is listed in
    [docs/benchmarks.md](benchmarks.md#memory-p5-2026-11-06).

#### Feature parity (decided 2026-11-16)

Each item starts with a check of the RFC or draft it implements (every MUST and SHOULD, prerequisites included) and of
what the peers really do, and is delivered whole or not at all.

- Certificate selection by SNI for QUIC and HTTP/3 (today `sniSelector` works on TCP only, and HTTP/3 does not start with
  it).
- h2c (HTTP/2 with prior knowledge over cleartext TCP), opt-in on the client and the server, for deployments behind
  TLS-terminating proxies, service meshes and gRPC; it supersedes ADR-0017's "no h2c" ([ADR-0018](adr/0018-h2c-and-coalescing-in-030.md))
  ([RFC 9113 §3.1, §3.3](spec/rfc/9113.md#s3-1-h2c)).
- Connection coalescing across origins for HTTP/2 and HTTP/3, off by default and opt-in ([ADR-0018](adr/0018-h2c-and-coalescing-in-030.md)): the address matches and the certificate covers the name,
  with a retry on 421 ([RFC 9113 §9.1.1](spec/rfc/9113.md#s9-1-1-connection-reuse)).
- CONNECT-UDP (RFC 9298), client and server, over the capsules, datagrams and extended CONNECT already in place:
  HTTP/3 through a MASQUE proxy.
- PROXY protocol v1 and v2 on the TCP connectors, with a list of trusted sources.
- A pluggable DNS resolver in the Ktor client, used by TCP, QUIC and Happy Eyeballs alike.
- HTTPS proxies (TLS to the proxy).
- ACK frequency (draft-ietf-quic-ack-frequency), experimental and off by default.
- TLS certificate compression (RFC 8879) through OpenSSL, which keeps a server's first flight within QUIC's
  amplification limit ([RFC 8879](spec/rfc/8879.md#certificate-compression)) (done: on by default on both sides, brotli
  then zlib, built into libcrypto from pinned and verified releases, [ADR-0025](adr/0025-zlib-and-brotli-in-libcrypto.md)).
- Configurable key exchange groups.
- qlog: HTTP/3 events, checked against qvis.
- h3spec and the Autobahn WebSocket suite in the gate.
- OpenSSL 4.1.x instead of the 3.5 LTS, and 4.2 LTS once it is released (planned by OpenSSL for April 2027): the 3.5
  branch has no ECH ([ADR-0019](adr/0019-openssl-4-and-ech.md), decided 2026-11-18).
- TLS Encrypted Client Hello ([RFC 9849](spec/rfc/9849.md#ech), and its HTTPS record parameter,
  [RFC 9848](spec/rfc/9848.md#ech-https-records)), decided 2026-11-18: a client that takes the configuration from the
  HTTPS record or the application and retries once with the server's retry configurations, GREASE ECH on by default,
  and a server in shared mode with key rotation and retry configurations; no split mode. The spike of ECH through the
  QUIC TLS callbacks `ksl` uses is done (2026-11-18): ECH works through them apart from two OpenSSL 4.1.0 bugs and the
  name check on rejection, and the move to 4.1.x has its own prerequisites; both are listed in
  [ADR-0019](adr/0019-openssl-4-and-ech.md).

### 0.3.x — multipath QUIC

Multipath QUIC ([RFC 10069](spec/rfc/draft-ietf-quic-multipath.md#multipath), published 2026-11 from
draft-ietf-quic-multipath) moved from 0.3.0 to a 0.3.x release on 2026-11-18: experimental and off by default, but with
every MUST and SHOULD of the RFC. It starts with the refactoring to one packet number space per path.

### After 0.3.0, until 1.0

Fixes and hardening, and multipath QUIC in 0.3.x (above); no other new features after 0.3.0. The public API is frozen before 1.0.0 ([stability.md](stability.md)).

### After 1.0

Proposals, in no fixed order:

- CONNECT-IP (RFC 9484).
- A built-in DNS-over-HTTPS client.
- Happy Eyeballs version 3.
- brotli and zstd content coding.
- Certificate Transparency checks.
- Micrometer and OpenTelemetry modules.
- Unix domain sockets.
- Restarting a server without dropping connections.
- The ORIGIN frame.
- Kotlin/Native for Linux with musl, Windows on arm64, tvOS and watchOS.

### Not planned

Decided against, with the reason; a change of mind needs a new decision (an ADR, see [GOVERNANCE.md](../GOVERNANCE.md)).

- **Server push, on HTTP/2 and HTTP/3.** Browsers have dropped HTTP/2 push and none implements HTTP/3 push, and 103 Early Hints does its job
  without pushing bytes the client may already have; the client refuses it and the server never pushes
  ([RFC 9113 §8.4](spec/rfc/9113.md#s8-4-server-push), [RFC 9114 §4.6](spec/rfc/9114.md#s4-6-server-push)).
- **WebTransport over HTTP/2.** WebTransport is served over HTTP/3; where UDP is blocked, WebSocket (over HTTP/1.1 or
  HTTP/2) is the fallback a client already has, and a second WebTransport transport would double the surface for a
  rare case.
- **SOCKS4, and the GSSAPI method of SOCKS5.** SOCKS4 has no IPv6, no host names (only the SOCKS4a extension) and no
  authentication; GSSAPI would need a Kerberos stack on every platform ([RFC 1928 §3](spec/rfc/1928-1929.md#s3-gssapi)).
- **TLS early data over TCP.** 0-RTT exists for QUIC and HTTP/3, where the replay protections of ADR-0015 apply
  (single-use tickets, a replay register, safe-method gating with 425); over TCP the gain is smaller and the same
  protections would have to be built a second time.
- **Raw public keys (RFC 7250) and external pre-shared keys.** Trust is an X.509 chain with the host name always
  checked (ADR-0011); a second trust model would weaken that rule for uses the web does not have.
- **A Kotlin/Native target for Intel Macs (`macosX64`).** Intel Macs are served by the JVM and its `osx-x86_64` JNI
  library ([stability.md](stability.md)).
- **JavaScript and WebAssembly targets.** Browsers give a library neither UDP sockets nor its own TLS, and the
  transport depends on the native OpenSSL through `ksl` (ADR-0001, ADR-0002).
