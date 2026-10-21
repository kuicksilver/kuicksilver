# Architecture

This document describes the high-level architecture of Kuicksilver. If you want to find your way around the code, read
it first. Decisions and their reasons live in the ADRs (`docs/adr/`, one decision per file); the RFC coverage is in
`docs/spec/rfc-compliance.md`, the threat model in `docs/spec/threat-model.md`, the user guides in `docs/guide/`.

## Bird's Eye View

Kuicksilver is a Kotlin Multiplatform network stack: QUIC v1 and v2 (RFC 9000/9001/9002/9369, datagrams of RFC 9221,
path MTU discovery of RFC 8899), HTTP/3 with QPACK (RFC 9114/9204, priorities of RFC 9218, Extended CONNECT of
RFC 9220, HTTP datagrams of RFC 9297), Ktor client and server engines over it, and TLS 1.3 over OpenSSL 3.5, on the
JVM, Android and Kotlin/Native (Linux, Apple, Windows).

On input, the stack gets UDP datagrams (QUIC) or TCP bytes (TLS) and calls from the application; on output, it sends
datagrams or bytes and hands the application streams, datagrams and events. Everything that can be Kotlin is Kotlin:
the QUIC state machine, loss recovery, congestion control, streams, paths, the coroutine API. Native code is limited
to what cannot be done safely or fast in Kotlin: OpenSSL (TLS handshake, AEAD, header protection, certificate chains)
and batched UDP. It sits behind one small C shim, `ksl`, used both through JNI and through cinterop (ADR-0001,
ADR-0003).

Two properties shape the code more than anything else:

- **The QUIC core is sans-IO** (ADR-0004). `ConnectionCore` and `EndpointCore` never touch a socket, a clock or a
  coroutine: datagrams come in through `handleDatagram`, go out through `poll`, time is a parameter, randomness is
  injected. That makes the core deterministic, which the network simulator and the fuzzers rely on.
- **Every layer sees only the layer directly below it** (ADR-0005): `kuicksilver-ktor-client` / `kuicksilver-ktor-server`
  → `kuicksilver-http3` → `kuicksilver-quic` → `kuicksilver-tls` → `kuicksilver-native` (the Ktor engines also use
  `kuicksilver-ktor-network` for HTTP/1.1 over TLS). The transport depends on the `QuicCrypto` interface, not on
  OpenSSL (ADR-0002); the engines see the transport only through `Http3Endpoint` (ADR-0014).

## Entry Points

- `QuicEndpoint.bind(local, config)` (`kuicksilver-quic`, `QuicEndpoint.kt`) — the coroutine API: an endpoint loop that
  owns a socket and its connections; `connect`, `accept`, then `QuicConnection` and `QuicStream`.
- `ConnectionCore.client(...)` / `EndpointCore` (`ConnectionCore.kt`, `EndpointCore.kt`) — the sans-IO level for callers
  with their own event loop (`@ExperimentalKuicksilverApi`).
- `TlsConnection.client/server(transportIn, transportOut, config)` (`kuicksilver-tls`, `TlsConnection.kt`) — TLS over
  any pair of ktor-io channels; `Socket.tls(config)` (`kuicksilver-ktor-network`) wraps a ktor-network socket.
- `tlsConfig(role) { }` (`TlsConfig.kt`) and `quicConfig { }`, `quicClientConfig`, `quicServerConfig`,
  `quicEndpointConfig` (`QuicConfig.kt`, `QuicDsl.kt`) — all configuration is immutable and validated when built.
- `Http3Endpoint.bind/connect` (`kuicksilver-http3`, `Http3Endpoint.kt`) — HTTP/3 connections: `Http3Connection.request`
  on the client, `acceptRequest` on the server, Extended CONNECT streams, HTTP datagrams.
- `HttpClient(Kuicksilver)` (`kuicksilver-ktor-client`, `KuicksilverEngine.kt`) and `embeddedServer(Kuicksilver)`
  (`kuicksilver-ktor-server`, `KuicksilverApplicationEngine.kt`, with `TcpListener.kt` and `Http3Listener.kt`) — the
  Ktor engines: HTTP/1.1 over TLS and HTTP/3 on one port, Alt-Svc discovery, racing and fallback on the client.
- `ksl.h` (`kuicksilver-native/src/c`) — the whole native surface, with `KSL_ABI_VERSION`.

## Code Map

### `kuicksilver-native`

The C shim `ksl` (`src/c/ksl_*.c`, one header `ksl.h`), its JNI binding (`src/jni`), its cinterop definition
(`src/nativeInterop/cinterop/ksl.def`) and the Kotlin facade `Ksl` (`src/commonMain/.../native/Ksl.kt`, with `actual`s
per platform). Also `PacketBuffer` (a native-memory buffer: direct `ByteBuffer` on the JVM, `nativeHeap` on Native),
`KslLoader` and the opt-in annotations (`io.kuicksilver.annotations`). OpenSSL is built from a pinned, signature-checked
tarball by `tools/openssl` and its symbols are prefixed on Kotlin/Native (`tools/prefix`, ADR-0007).

**Architecture Invariant:** no upcalls from C into Kotlin. When OpenSSL needs a decision (a certificate verdict), `ksl`
pauses the handshake and returns; Kotlin resumes it later (ADR-0012). Packet keys and the endpoint's Retry and reset keys
never leave native memory; Kotlin holds handles.

**Architecture Invariant:** errors are kept in the object that failed, not in thread-local state, because coroutines
move between OS threads.

**API Boundary:** `Ksl` is `@InternalKuicksilverApi`; applications never call it.

### `kuicksilver-tls`

TLS 1.3 configuration and sessions (`io.kuicksilver.tls`): `TlsConfig`, `TlsIdentity`, `Certificate`, `TrustConfig`
and verification (`Verification.kt`, `PlatformVerifier.*.kt` per platform), `TlsConnection` (TLS over TCP), `KslCrypto`,
keylog sinks; and the interfaces QUIC needs: `QuicCrypto`, `QuicTlsSession`, `PacketProtector`, with the OpenSSL
implementation `KslQuicCrypto`.

**Architecture Invariant:** the host name is always checked by one matcher (RFC 9525) on every platform; it can be
replaced (`TrustConfig.ExpectedName`) but never disabled, and a pin is checked in addition to the base trust, never
instead of it (ADR-0011).

**Architecture Invariant:** `SSLKEYLOGFILE` is never read implicitly; secrets leave the process only through an explicit
`KeylogSink`.

**API Boundary:** `TlsConfig`, `TrustConfig`, `TlsIdentity`, `Certificate`, `TlsConnection` and `TlsException` are for
applications; `QuicTlsSession`, `PacketProtector` and the key types serve the transport.

### `kuicksilver-quic`

The QUIC transport (`io.kuicksilver.quic`). The core packages are `wire` (packet and frame codecs, transport
parameters, version profiles), `crypto` (packet protection), `recovery` (ACK tracking, loss detection, RTT, pacing, BBR's delivery-rate sampling),
`flow` (flow control), `stream` (stream state and reassembly), `core` (handshake driver, packet builder and receiver,
paths, key phases, ECN, PMTUD, the glitch bucket) and `endpoint` (connection-ID routing, Retry tokens, stateless reset,
admission). `ConnectionCore` and `EndpointCore` sit on top of them: `ConnectionCore.kt` holds the connection's state
and public API, its internal transitions are extension functions in `core/ConnectionCore.handshake.kt`,
`ConnectionCore.paths.kt`, `ConnectionCore.close.kt` and `ConnectionCore.timers.kt`; the receive path is
`core/PacketReceiver.kt` (headers, keys, decryption) plus `core/FrameDispatcher.kt` (frames to the connection);
`EndpointCore.admission.kt` decides queued Initials. `runtime` turns the core into the coroutine API:
`EndpointLoop` (one loop, one socket, a timer heap), `LoopGroup` (several loops on one port), `ConnectionRuntime`
(`QuicConnection`: lifecycle, paths, datagrams), `StreamRuntime` with its ktor-io channels (`StreamChannels.kt`)
and datagram queues. `DatagramIo` is the socket abstraction, with the accelerated `KslDatagramIo` (batched UDP with ECN and DF
through `ksl`, GSO/GRO on Linux, USO/URO on Windows where granted; Linux, Android, Apple, Windows) and the portable NIO or
ktor-network sockets as the fallback (ADR-0006).

**Architecture Invariant:** the core packages import no coroutines, no sockets, no clocks and no default randomness;
`tools/check/sans-io.sh` enforces it. Only `runtime` and the coroutine-level files know about them.

**Architecture Invariant:** a connection is touched only by the endpoint loop that owns it (a single-threaded
dispatcher). Application calls become commands queued to the loop; there are no locks on connection state. Nothing
blocks on the loop's thread except a socket wait of at most 1 ms (and never past its next timer) while datagrams keep
coming (`runtime/BatchReceiver.kt`; not on Windows; datagrams the socket drops, such as empty ones, do not extend it),
and only on the loop's own dispatcher: on one the caller supplies (a UI one, or one shared by two endpoints) the loop takes
what is queued and never waits.

**Architecture Invariant:** memory per connection is bounded by explicit ceilings (windows, queues, ranges), each refused
before allocation; there is no separate byte budget.

**API Boundary:** `QuicEndpoint`, `QuicConnection`, `QuicStream`, `QuicPath`, the configs and `QuicException` are the
stable surface; `ConnectionCore`, `EndpointCore`, `CongestionController` and `DatagramSender` are
`@ExperimentalKuicksilverApi`; implementing `DatagramIo` needs the same opt-in.

### `kuicksilver-ktor-network`

`Socket.tls(config)` and `Socket.tlsServer(config)` for ktor-network sockets. It depends on `kuicksilver-tls` only.
`connectTcp`/`bindTcp` (`@InternalKuicksilverApi`) open the engines' TCP sockets: ktor-network's on the JVM and Android, on
Kotlin/Native a socket of this module on ktor-network's selector (`TcpSockets.native.kt` over the system calls of
`TcpSys.kt`: `posixMain` for Linux and Apple, `mingwMain`), because Ktor 3.6.0's native sockets bind and connect every
IPv6 address as `::` (reported to Ktor as [KTOR-10017](https://youtrack.jetbrains.com/issue/KTOR-10017)).

### `kuicksilver-http3`

HTTP/3 and QPACK (`io.kuicksilver.http3`). `frame` holds the sans-IO frame and SETTINGS codecs, `qpack` the encoder and
decoder with the dynamic table (blocked streams, Section Acknowledgment and Stream Cancellation, Insert Count
Increment), `message` the field and pseudo-header rules (RFC 9114 section 4) and the `Priority` field, `runtime` the
connection (`H3Session`: control and QPACK streams, GOAWAY, PRIORITY_UPDATE, datagram demultiplexing) and the request
streams (HEADERS/DATA/trailers with backpressure, 1xx, Extended CONNECT: `ServerRequestStream.kt` reads requests and
writes responses, `ClientRequestStream.kt` writes requests and reads responses, `RequestStream.kt` holds the body pump
both share). The public API is
`Http3Endpoint`, `Http3Connection`, `Http3Request`/`Http3Response`, `Http3ServerRequest`, `Http3Stream`, `Http3Settings`
and `Http3Exception`. Every HTTP/3 resource bound (field section size, blocked streams, buffered PRIORITY_UPDATEs, frame
length never pre-allocated) lives here.

### `kuicksilver-ktor-client`, `kuicksilver-ktor-server`

The Ktor engines (`io.kuicksilver.ktor.client`, `io.kuicksilver.ktor.server`). The client runs HTTP/1.1 over
`TlsConnection` (`h1`: a vendored CIO parser, a connection pool) and HTTP/3 over `Http3Endpoint` (`h3`: `H3Pool`), with
`Http3DiscoveryMode` (`Auto` learns `Alt-Svc`, `Preferred`, `H3Only`, `H1Only`), a connection race (`ProtocolRace`), a
broken-alternative memory (`BrokenAltSvc`) and fallback rules that never replay a consumed body. The server serves
HTTP/1.1 over TLS on TCP and HTTP/3 on UDP on the same port (`KuicksilverApplicationEngine` starts and stops the
listeners, `TcpListener.kt` (`TcpServer`, started by `startTcp`) holds the TCP/TLS accept loop, `Http3Listener.kt` the HTTP/3 one; `H3Call` maps requests into Ktor's model, `WebSocketOverH3`
implements RFC 9220), advertises `Alt-Svc`, and stops gracefully with GOAWAY. Neither engine sees `kuicksilver-quic`
directly (ADR-0014).

### `kuicksilver-testing`

The deterministic network simulator for the sans-IO core (`Simulator`, `SimLink`, `LinkParams`, invariants checked
after every step) and `MemoryNetwork`, an in-memory UDP network with bounded per-socket receive buffers that runs whole
applications without sockets. Not published yet.

### `kuicksilver-interop`, `kuicksilver-bench`, `samples/`

The QUIC Interop Runner endpoint (`kuicksilver-interop`, Docker image in `tools/interop`), benchmarks and allocation
gates (`kuicksilver-bench`), `samples/realtime-telemetry`, a separate Gradle build that consumes the library as an
outside project would, and `samples/ios`, an Xcode app over the library's XCFramework ([iOS guide](guide/ios.md)).

## Cross-Cutting Concerns

**Errors.** Every QUIC failure an application sees is a `QuicException` (a `kotlinx.io.IOException`, copyable for
coroutines); a lost connection is one `ConnectionLost` reason that every waiter of that connection receives. TLS failures
are `TlsException` (on the JVM an `SSLException`). Configuration errors are thrown when a config is built, not at the
first packet. `CancellationException` is never wrapped.

**Threads.** Coroutines guarantee sequential execution, not one OS thread; every rule is phrased as "one owner at a
time". OpenSSL objects are owned by one loop; immutable contexts are shared.

**Buffers.** On the hot path (receive → decrypt → frames → ACK → send) the steady state allocates nothing;
`kuicksilver-bench` holds the gate. Native code receives addresses and lengths, never copies of Kotlin arrays.

**Testing.** Unit and property tests per package; RFC test vectors; the simulator (seeded, reproducible) for loss,
reordering, MTU black holes, NAT rebinding and migration; Jazzer fuzz targets for every parser; the QUIC Interop Runner
against other implementations; negative security controls named `negative_*` after the threat model.

**Architecture checks.** `checkLayerDependencies` (module dependencies), `tools/check/sans-io.sh` and
`tools/check/quic-imports.sh` (QUIC core rules), `checkKotlinAbi` (public ABI dumps in each module's `api/`),
`checkSpdxHeaders`, and the native checks in `tools/check` (exported symbols, glibc floor, keylog disabled, page alignment,
size).
