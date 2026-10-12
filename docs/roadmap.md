<!-- Copyright 2026 The Kuicksilver Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Roadmap

Owner decisions of 2026-10-09. The compliance status per RFC section is in `spec/rfc-compliance.md`; the design in
`spec/2026-10-02-kuicksilver-design.md`.

## 0.1.0 — first public release

What ships: QUIC v1 (RFC 9000/9001/9002, v2 by RFC 9369), HTTP/3 with QPACK, the Ktor client engine (HTTP/1.1 + HTTP/3
with Alt-Svc discovery) and the Ktor server engine, TLS 1.3 over OpenSSL 3.5 through the `ksl` shim.

| Platform | Client | Server | UDP path |
|---|---|---|---|
| JVM (Linux, macOS) | yes | yes | NIO; accelerated `KslDatagramIo` on Linux |
| Android (arm64-v8a, armeabi-v7a, x86_64) | yes | yes | accelerated |
| Kotlin/Native Linux x64 / arm64 | yes | yes | accelerated |
| Kotlin/Native macOS arm64, iOS | yes | no (ADR-0006) | portable |
| Kotlin/Native Windows (mingw x64) | yes | no | portable |

Known limits, stated on purpose:
- A handshake under heavy loss with an ML-KEM peer: both flights span two datagrams and the RFC 9002 initial PTO
  (1 s, 2 s, 4 s before an RTT sample) gives three retransmissions before a 10 s peer timeout
  (`spec/rfc-compliance.md`, interop `handshakecorruption`); mitigated by `QuicConfig.initialRtt` (0.2.0, `guide/quic.md`).
- No 0-RTT (ADR-0008), no HTTP/2 in the client engine (ADR-0009), no HTTP/3 server push, no certificate
  compression (RFC 8879), no OCSP/CRL checks of our own (the platform verifier decides under `TrustConfig.Platform`).
- No macosX64 target.
- The `kuicksilver-testing` module is not published.
- The deferred review findings listed under 0.2.0 (none affects correctness on a healthy network).

## 0.2.0

- Hardening from the 2026-10-08 full review (`docs/plans` F1–F4 in the owner's notes): PATH_CHALLENGE backoff
  (RFC 9000 §8.2.4), NEW_CONNECTION_ID retransmission against a retired sequence, Retry token bound to the SCID,
  ECN accounting per space with out-of-order ACKs, the O(n) hot spots in `onAck`, `onMaxData` and
  `StreamScheduler.add`, NIO timer starvation, server path-list growth, `AltSvcCache`/`FileAltSvcStore` limits,
  idle close after GOAWAY with unfinished requests, QPACK on fragmented input, `te`/HEAD/204/304 edge cases,
  `keylogFile` O_NOFOLLOW, `KslLoader` directory ownership, `SessionCache` across engines.
- `QuicConfig.initialRtt` (default 333 ms per RFC 9002; a lower value trades spurious retransmissions for a faster
  handshake under loss) validated in (0, 10 s] and the lossy-handshake behaviour documented in the guide (done on
  `k7/f1-core`).
- QUIC server on Kotlin/Native macOS: `ksl_udp` over `sendmsg`/`recvmsg` and kqueue, the server test suites on
  `macosArm64`.
- Coverage reports of the JVM tests with Kover (`-Pkuicksilver.coverage :koverHtmlReportJvmTests`, no threshold).
- 0-RTT (RFC 9001 §4.6), owner decision to ship it in 0.2.0: the ADR-0013 review (2026-10) keeps its three layers and
  puts freshness on OpenSSL's check (the ticket lifetime and the 10 s allowance between reported and computed ticket
  age, which is the replay window). It adds a per-server replay register keyed by ticket, single-use client tickets in
  the per-engine session cache, and HTTP/3 safe-method gating with RFC 8470 `425`. About 14 tasks.
- QUIC server on Kotlin/Native Windows (`ksl_udp` over Winsock).
- The interop runner's `perf` protocol and throughput thresholds in CI.

## After 0.2.0

- RFC 9460 HTTPS records as a source of h3, WebTransport, multipath and QUIC-LB (`PathId` and the CID layout are
  prepared), BBR.
