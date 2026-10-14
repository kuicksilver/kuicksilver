<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Configuration reference

Every option of Kuicksilver 0.2.0 in one place: its type, its default as the code sets it, the range the builder
accepts and what it does. The guides explain how the options work together; each section links its guide. Options
marked *experimental* need `@OptIn(ExperimentalKuicksilverApi::class)`, *delicate* ones
`@OptIn(DelicateKuicksilverApi::class)` ([stability](../stability.md)).

All configuration objects are immutable and validated when built: a builder's `build()` (or the DSL function around
it) throws `IllegalArgumentException` naming the first value out of range, or `TlsException.Config` for a TLS setting.
Problems that only show at run time are in [troubleshooting](troubleshooting.md).

Contents: [QUIC transport](#quicconfig) · [QUIC client and server](#quicclientconfig-and-quicserverconfig) ·
[QUIC endpoint](#quicendpointconfig) · [other QUIC options](#other-quic-options) · [TLS](#tlsconfig) ·
[trust](#trustconfig) · [identities and key logging](#identities-and-key-logging) · [HTTP/3](#http3settings) ·
[Ktor client](#ktor-client-engine) · [Ktor server](#ktor-server-engine) · [system properties and environment
variables](#system-properties-and-environment-variables) · [fixed limits](#fixed-limits)

## QuicConfig

Transport settings of a connection: `quicConfig { }` (`QuicConfig.Builder`), `QuicConfig.Default` for all defaults,
`toBuilder()` (*experimental*) to change one value of an existing config. Guide: [QUIC](quic.md#configuration).

| Option | Type | Default | Range | What it does |
|---|---|---|---|---|
| `maxIdleTimeout` | `Duration` | 30 s | zero or positive and finite | our `max_idle_timeout`; the connection closes silently after the smaller of both peers' values (never below 3 x PTO) without traffic, with `ConnectionLost.Timeout(TimeoutKind.Idle)`. `Duration.ZERO` advertises none and leaves the timeout to the peer |
| `handshakeTimeout` | `Duration` | 10 s | positive (`Duration.INFINITE` leaves only the idle timeout) | a connection whose handshake has not completed by then closes with `TimeoutKind.Handshake` |
| `keepAlive` | `Duration?` | `null` (off) | positive and finite; at most 3/4 of `maxIdleTimeout` unless that is `ZERO` | PING interval while the application is quiet; PINGs go out at least every half of the effective idle timeout, so a peer with a shorter timeout does not close the connection (as quic-go). With `maxIdleTimeout = ZERO` it holds the connection against the peer's timeout |
| `initialStreamWindow` | `Long` (bytes) | 524 288 (512 KiB) | 1..`maxStreamWindow` | receive window of each stream at its start (`initial_max_stream_data_*`); doubles while the application reads a whole window in under four RTTs |
| `initialConnectionWindow` | `Long` (bytes) | 786 432 (768 KiB) | 1..`maxConnectionWindow` | receive window of the connection at its start (`initial_max_data`); kept at least 1.5 x the largest stream window |
| `maxStreamWindow` | `Long` (bytes) | 6 291 456 (6 MiB) | at least `initialStreamWindow` | ceiling of a stream's receive window: the most unread data one stream holds |
| `maxConnectionWindow` | `Long` (bytes) | 15 728 640 (15 MiB) | at least `initialConnectionWindow` | ceiling of the connection's receive window |
| `maxBidiStreams` | `Long` | 100 | 0..2^60 | bidirectional streams the peer may have open at once (`initial_max_streams_bidi`); raised by MAX_STREAMS as streams close |
| `maxUniStreams` | `Long` | 100 | 0..2^60 | the same for unidirectional streams |
| `maxSendBuffer` | `Long` (bytes) | 4 194 304 (4 MiB) | 1..2^62 | unacknowledged send data the connection buffers over all streams; writers wait beyond it |
| `maxAckDelay` | `Duration` | 25 ms | below 2^14 ms | our `max_ack_delay` |
| `ackDelayExponent` | `Int` | 3 | 0..20 | our `ack_delay_exponent` |
| `activeConnectionIdLimit` | `Int` | 4 | at least 2 | our `active_connection_id_limit`: connection IDs of the peer kept for migration and rotation |
| `connectionIdLength` | `Int` (bytes) | 8 | 4..20; must equal `QuicEndpointConfig.connectionIdLength` | length of the connection IDs we issue |
| `maxUdpPayloadSize` | `Int` (bytes) | 1452 | 1200..65 527; a `QuicEndpoint` refuses more than 1500 at `bind`/`connect` | advertised `max_udp_payload_size` and the upper bound of PMTUD ([Path MTU](quic.md#path-mtu)) |
| `versions` | `List<VersionProfile>` | `listOf(VersionProfile.V1)` | non-empty, no duplicates | versions in preference order; `listOf(V2, V1)` opts into QUIC v2 (RFC 9368/9369) |
| `initialVersion` | `VersionProfile?` | `null` (first of `versions`) | one of `versions` | the version of a client's first flight |
| `initialRtt` | `Duration` | 333 ms | (0, 10 s] | RTT assumed before the first sample: the first PTO is 3 x this (1 s, 2 s, 4 s at the default) and a path validation lasts at least 6 x this. A client endpoint replaces it with the last smoothed RTT to the same server address (see [fixed limits](#fixed-limits)) |
| `defaultStreamErrorCode` | `Long` | 0 | 0..2^62-1 | code of the STOP_SENDING / RESET_STREAM sent when a stream channel is cancelled |
| `qlog` | `QlogSink?` | `null` | | a qlog trace per connection ([qlog](quic.md#qlog)); a failing sink stops tracing for that connection only |
| `congestionController` | `() -> CongestionController` | `{ Cubic() }` | return a fresh instance per call | controller of each path: `Cubic` (CUBIC with HyStart++), `NewReno`, `Bbr` (*experimental*) ([Congestion control](quic.md#congestion-control)) |
| `greaseQuicBit` | `Boolean` | `true` | | send the fixed bit randomly when the peer allows it (RFC 9287) |
| `glitchProtection` | `Boolean` | `true` | | close a connection whose peer keeps making us do useless work ([Glitch protection](quic.md#glitch-protection)) |
| `allowMigration` | `Boolean` | `true` | | server: follow a client to a new address; `false` advertises `disable_active_migration` and drops datagrams from other addresses |
| `allowMigrationToLoopback` | `Boolean` | `false` | | server: accept a move to a loopback or link-local address from a connection that did not start on one |
| `pmtud` | `Boolean` | `true` | | DPLPMTUD (RFC 8899) on sockets that set DF; `false` keeps 1200 bytes |
| `maxDatagramFrameSize` | `Long` | 65 535 | 0..65 535 | our `max_datagram_frame_size` (RFC 9221); 0 turns datagrams off |
| `datagramReceiveQueue` | `Int` | 128 | at least 1 | received datagrams held for the application; a full queue drops the oldest |
| `datagramSendQueue` | `Int` | 32 | at least 1 | datagrams queued for sending ([Datagrams](quic.md#datagrams-rfc-9221)) |
| `datagramSendQueueBytes` | `Long` | 1 048 576 (1 MiB) | at least 1 | byte ceiling of the same queue |

## QuicClientConfig and QuicServerConfig

`quicClientConfig(tls) { }` and `quicServerConfig(tls) { }` pair a `TlsConfig` with a `QuicConfig`. `build()` throws
`IllegalArgumentException` for a `TlsConfig` of the wrong role ("client config needs a client TlsConfig") and
`TlsException.Config` for one QUIC cannot use: TLS 1.2 allowed, an empty `alpn`, `TLS_AES_128_CCM_8_SHA256`, or an
`sniSelector`.

| Option | Type | Default | Range | What it does |
|---|---|---|---|---|
| `tls` (constructor) | `TlsConfig` | | client or server role | name to verify, trust, ALPN; identity on a server |
| `quic` | `QuicConfig` | `QuicConfig.Default` | on a server, its `connectionIdLength` must equal the endpoint's | transport settings |
| client `earlyData` (*experimental*) | `EarlyDataState` | `Disabled` | `Disabled`, `Allowed`, `Required` | keep the server's session tickets (per endpoint, single use) and send 0-RTT through `QuicEndpoint.connectEarly`; `Required` fails the connection with `ZeroRttRejected` when 0-RTT is refused or impossible ([0-RTT](quic.md#0-rtt-opt-in-experimental)) |
| server `earlyData` (*experimental*) | `Boolean` | `false` | not with client certificates | accept 0-RTT: fresh tickets only (±10 s ticket age), once per ticket, only for the configuration that issued it |
| server `earlyDataContext` (*experimental*) | `ByteArray?` | `null` | at most 256 bytes | application settings bound into tickets (`Http3Endpoint` puts its SETTINGS here) |

## QuicEndpointConfig

The endpoint that owns a socket and its connections: `quicEndpointConfig { }`, `QuicEndpointConfig.Default` (a
client-only endpoint), `toBuilder()` (*experimental*). Guide: [Admission and endpoint limits](quic.md#admission-and-endpoint-limits).

| Option | Type | Default | Range | What it does |
|---|---|---|---|---|
| `server` | `QuicServerConfig?` | `null` | | the server side; `null` is a client-only endpoint, which admits no connection |
| `crypto` | `QuicCrypto` | `KslQuicCrypto` | | TLS and packet protection (OpenSSL through `ksl`) |
| `maxConnections` | `Int` | 10 000 | at least 1 | beyond this many connections new Initials are dropped silently |
| `acceptQueue` | `Int` | 128 | at least 1 | handshaken connections waiting for `accept()`, over all loops; while full, a new client is refused statelessly with CONNECTION_REFUSED (0x02). Handshakes in flight do not count |
| `dispatcher` | `CoroutineDispatcher?` | `null` (`Dispatchers.Default.limitedParallelism(1)`) | must stay `null` with `loops > 1` | the single-threaded dispatcher of the endpoint loop |
| `io` | `(suspend (InetSocketAddress) -> DatagramIo)?` | `null` (`DatagramIo.open` with `IoPreference.Accelerated`) | | how the loop opens its socket; `MemoryNetwork.open` runs the endpoint in memory ([Testing](quic.md#testing-your-application)) |
| `connectionIdLength` | `Int` (bytes) | 8 | 4..20; must equal the `QuicConfig.connectionIdLength` of the server and of every client connection | length used to parse short headers |
| `admission` | `ConnectionAdmission` | `ConnectionAdmission.default()` | | decides per new client Initial: `Allow`, `Retry`, `Drop` or `Close(code)`. `default(maxInflightHandshakes = 256, maxHandshakeBufferBytes = 8 MiB)` asks for a Retry above either; `ConnectionAdmission.AlwaysRetry` validates every address first |
| `initialQueueCap` | `Int` | 1024 | at least 1 | new Initials queued for admission per receive batch; more are dropped |
| `maxConnectionsPerIp` | `Int?` | 256 | positive or `null` (no limit) | connections one client IP may hold, ports ignored; the excess is dropped silently |
| `maxConnectionLifetime` | `Duration?` | `null` (none) | positive or `null` | server connections older than this close with NO_ERROR ("connection lifetime reached") |
| `rejectInitialFromReflectivePorts` | `Boolean` | `true` | | drop Initials from source ports 53, 123, 1900, 5353 and 11211 (reflection attacks) |
| `statelessPerAddressPerSecond` | `Int` | 8 | at least 1 | stateless answers (Retry, Version Negotiation, Stateless Reset, refusals) per client address per second |
| `statelessTotalPerSecond` | `Int` | 1000 | at least 1 | stateless answers per second over all addresses |
| `loops` | `Int` | 1 | 1..255; more than 1 needs a `server`, no `dispatcher`, and Linux or Android (`UnsupportedOperationException` at `bind` elsewhere) | endpoint loops sharing the port with `SO_REUSEPORT` ([Several loops on one port](quic.md#several-loops-on-one-port)) |
| `logger` (*experimental*) | `KuicksilverLogger` | `KuicksilverLogger.Stderr` (warnings and errors on standard error) | | the endpoint's diagnostics; `KuicksilverLogger.None`, `KuicksilverLogger.stderr(LogLevel.Debug)` or your own ([Observability](quic.md#observability)) |
| `listener` (*experimental*) | `ConnectionListener?` | `null` | | lifecycle callbacks of every connection, on the loop |

## Other QUIC options

| Where | Option | Default | What it does |
|---|---|---|---|
| `QuicConnection.openBidi`, `openUni` | `priority: StreamPriority` | `StreamPriority.Default` (`urgency = 3`, `incremental = false`; urgency 0..7) | send order between streams (RFC 9218 levels) |
| `QuicConnection.sendDatagram`, `trySendDatagram` | `policy: DatagramPolicy` | `DropOldest` | `DropOldest`, `LatestWins(key)` or `Reject` when the send queue is full |
| `DatagramIo.open(local, prefer)` | `prefer: IoPreference` | `Accelerated` | `Accelerated`: the `ksl` socket where it exists, `Portable`: NIO on the JVM, `ktor-network` on Kotlin/Native |
| `Cubic(maxDatagramSize, hystart)`, `NewReno(maxDatagramSize)` | | 1200, `true` | the stable congestion controllers |
| `Bbr(maxDatagramSize, random)` (*experimental*) | | 1200, `null` (jitter from send and ACK times) | BBRv3 ([Choosing a congestion controller](quic.md#choosing-a-congestion-controller)) |
| `DirectoryQlogSink(directory)` | | | one `<odcid>_<client\|server>.sqlog` file per connection; creates the directory |
| `AsyncQlogSink(delegate, queueCapacity, sampleEvery, dispatcher)` (*experimental*) | | 8192 records, 1 (every connection), `Dispatchers.IO.limitedParallelism(1)` | runs a sink off the endpoint loop; a full queue drops records (`dropped`) |
| `NetworkMigrator(connection, networks, openIo, scope)` (*experimental*) | | no defaults; client connections only | follows a `Flow` of networks ([Network changes](quic.md#network-changes)) |
| `QuicConnection.rebind(local, prefer)` (*experimental*) | | `null` (wildcard of the peer's family), `Accelerated` | moves the connection to a fresh socket |
| `followDefaultNetwork(connectivity, scope, local, prefer)` (Android), `followDefaultNetwork(scope, local, prefer)` (Apple) (*experimental*) | | `null`, `Accelerated` | a started `NetworkMigrator` on the default network |
| `QuicEndpoint.shutdown(grace, code, reason)` (*experimental*) | | `code = 0`, `reason = "shutdown"` | graceful shutdown ([Graceful shutdown](quic.md#graceful-shutdown)) |

## TlsConfig

`tlsConfig(TlsRole.Client / TlsRole.Server) { }` (`TlsConfig.Builder`); errors are `TlsException.Config`. One
`TlsConfig` drives QUIC, TLS over TCP and `Socket.tls()`. Guide: [TLS](tls.md#configuration).

| Option | Type | Default | Range | What it does |
|---|---|---|---|---|
| `alpn` | `List<String>` | empty | each name 1..255 UTF-8 bytes, the list at most 255 bytes on the wire; QUIC needs at least one | ALPN protocol IDs in preference order |
| `serverName` | `String?` | `null` | a client needs it (or `TrustConfig.ExpectedName`) | SNI and the name the certificate must match; an IP literal is verified but never sent as SNI. Servers ignore it |
| `versions` | `TlsVersions` | `Tls13` | QUIC: `Tls13` only | `Tls12And13` allows the RFC 9325 profile of TLS 1.2 over TCP |
| `cipherSuites` | `CipherSuites` | `CipherSuites.Default` (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305) | at least one; QUIC refuses `TLS_AES_128_CCM_8_SHA256` | TLS 1.3 suites in preference order |
| `identity` | `TlsIdentity?` | `null` | a server needs an identity or an `sniSelector` | certificate chain and key |
| `trust` | `TrustConfig` | `TrustConfig.Platform` | with `clientAuth` other than `None`: `AnchoredCa`, optionally under `Pinned` | how the peer is verified ([below](#trustconfig)) |
| `clientAuth` | `ClientAuth` | `None` | servers only | `None`, `Optional` or `Required` client certificates |
| `sniSelector` | `(suspend (ClientHelloInfo) -> ServerTlsOverride?)?` | `null` | servers, TCP only (QUIC refuses it) | picks a `ServerTlsOverride(identity, alpn, clientAuth, trust)` per ClientHello |
| `sessionTickets` | `SessionTicketConfig` | `SessionTicketConfig.Default` | see below | the keys and lifetime of a TLS-over-TCP server's tickets and of a QUIC server with `earlyData` (the only QUIC servers that issue tickets) |
| `keylog` (*delicate*) | `KeylogSink?` | `null` | | TLS secrets as RFC 9850 key log lines ([Key logging](tls.md#key-logging)) |
| `handshakeTimeout` | `Duration` | 10 s | positive (`Duration.INFINITE`: no deadline) | TLS over TCP only (QUIC uses `QuicConfig.handshakeTimeout`) |
| `genericAlerts` | `Boolean` | `false` | | send `handshake_failure` instead of the specific alert |

`SessionTicketConfig(keys, rotateEvery, ticketLifetime)`: `keys = null` (generated in the process), `rotateEvery = 1
day` (positive, at most 7 days), `ticketLifetime = 12 hours` (at least 1 s, at most `rotateEvery / 2`); explicit keys
are 80-byte entries.

Key exchange groups are not configurable: `X25519MLKEM768`, `X25519`, `secp256r1`, `X448`, `secp384r1`, `secp521r1`
([Key exchange groups](tls.md#key-exchange-groups)).

## TrustConfig

Guide: [TLS: Trust](tls.md#trust).

| Variant | Parameters (defaults) | Checks | What it does |
|---|---|---|---|
| `TrustConfig.Platform` | | Linux Native: a CA store must exist when the client config is built | the operating system's verifier ([Platform trust](tls.md#platform-trust)) |
| `TrustConfig.AnchoredCa(roots)` | `roots: List<Certificate>` | at least one root | only these roots, verified inside `ksl`; the only trust for client certificates in v1 |
| `TrustConfig.ExpectedName(name, base)` | `base = Platform` | non-blank `name`; `base` is `Platform`, `AnchoredCa` or `Custom` | verify another name than the one connected to (proxies) |
| `TrustConfig.Pinned(pins, scope, base)` | `scope = PinScope.Leaf`, `base = Platform` | at least one pin; not around `Tofu`, `Custom` or another `Pinned` | SPKI pins checked on top of `base`; `PinScope.AnyInValidatedChain` matches any certificate of the validated chain |
| `TrustConfig.Tofu(store)` | `store: TofuStore` | clients only | trust on first use |
| `TrustConfig.Custom(verifier)` (*delicate*) | `verifier: CertificateVerifier` | clients only | your verifier decides; the name check still runs |
| `TrustConfig.fromTrustManager(trustManager)` | | JVM only | a `javax.net.ssl.X509TrustManager` as a verifier |

Pins are written `SpkiSha256.parse("sha256/<base64>")` (32 bytes). Certificates come from `Certificate.parsePem` or
DER.

## Identities and key logging

| API | Parameters (defaults) | What it does |
|---|---|---|
| `TlsIdentity.fromPem(chainPem, keyPem, password)` | `password = null` (encrypted keys are refused) | chain plus one PKCS#8 key; `keyPem` is zeroed and the key lives in OpenSSL only |
| `TlsIdentity.fromDer(chain, keyDer)` | | the same from DER; `keyDer` is zeroed |
| `TlsIdentity.fromKeyStore(keyStore, alias, password)`, `fromPkcs12(bytes, password)` | | JVM only |
| `keylogFile(path)` (*delicate*) | | a 0600 key log file, refused for links, foreign owners and file systems without POSIX permissions |
| `keylogFile(context, name)` (Android, *delicate*) | `name = "kuicksilver-keylog.txt"` | in the app's files; `null` in a non-debuggable build |
| `keylogFromEnvironment()` (*delicate*) | | `SSLKEYLOGFILE`, read only when called |

## Http3Settings

`http3Settings { }` (`Http3Settings.Builder`), `Http3Settings.Default`, `toBuilder()`. Guide: [HTTP/3](http3.md).

| Option | Type | Default | Range | What it does |
|---|---|---|---|---|
| `qpackMaxTableCapacity` | `Long` | 0 | 0..2^30 | `SETTINGS_QPACK_MAX_TABLE_CAPACITY` we advertise: the dynamic table the peer's encoder may use |
| `qpackBlockedStreams` | `Long` | 0 | 0..65 535 | `SETTINGS_QPACK_BLOCKED_STREAMS` we advertise |
| `encoderMaxTableCapacity` | `Long` | 4096 | 0..2^30 | ceiling of our own encoder's dynamic table, under what the peer allows |
| `maxFieldSectionSize` | `Long` | 65 536 (64 KiB) | 1..2^30 | largest decoded header or trailer section we accept, advertised as `SETTINGS_MAX_FIELD_SECTION_SIZE` |
| `enableConnectProtocol` | `Boolean` | `false` | | advertise Extended CONNECT (RFC 9220) |
| `h3Datagram` | `Boolean` | `true` | | `SETTINGS_H3_DATAGRAM` (always sent); `Http3Endpoint` sends 0 when `QuicConfig.maxDatagramFrameSize` is 0 |
| `grease` | `Boolean` | `true` | | send a reserved setting, frame and stream type |
| `maxInformationalResponses` | `Int` | 5 | at least 0 | 1xx responses a client accepts per request; one more fails it with `H3_EXCESSIVE_LOAD` |
| `maxEarlyPriorityUpdates` | `Int` | 32 | at least 0 | PRIORITY_UPDATE frames remembered for streams not yet open |
| `glitchProtection` | `Boolean` | `true` | | close with `H3_EXCESSIVE_LOAD` a peer that floods useless frames |
| `earlyData` (*experimental*) | `Http3EarlyDataPolicy` | `WaitForHandshake()` | `WaitForHandshake(replayable)`, `Reject425(replayable)`; `replayable` admits GET, HEAD and OPTIONS by default | server: what happens to requests that arrive in 0-RTT ([HTTP/3 0-RTT](http3.md#0-rtt-opt-in-experimental)) |

`enableQpackDynamicTable()` sets `qpackMaxTableCapacity = 4096` and `qpackBlockedStreams = 16`.

Endpoint and request parameters:

| API | Parameters (defaults) |
|---|---|
| `Http3Endpoint.bind(local, config, settings)` | `config = QuicEndpointConfig.Default`, `settings = Http3Settings.Default`; the server's TLS must offer ALPN `h3` |
| `Http3Endpoint.connect(remote, tls, quic, settings)` | `quic = QuicConfig.Default`, `settings = Http3Settings.Default`; `tls` must offer ALPN `h3` |
| `Http3Endpoint.connectEarly(remote, tls, quic, settings, earlyData)` (*experimental*) | as `connect`, `earlyData = EarlyDataState.Allowed` (not `Disabled`) |
| `Http3Endpoint.shutdown(grace, code, reason)` (*experimental*) | `code = H3_NO_ERROR`, `reason = "shutdown"` |
| `http3Request(method, authority, path) { ... }` (`Http3Request.Builder`) | `scheme = "https"`, `headers = Http3Headers.Empty`, `body = null` (no body), `trailers = null`, `priority = null` (the default `u=3`), `protocol = null`, `onInformational = null`, `allowEarlyData = false` (*experimental*; GET, HEAD and OPTIONS without a body only) |

## Ktor client engine

`HttpClient(Kuicksilver) { engine { … } }` (`KuicksilverEngineConfig`). Values are checked when the engine is created.
Guide: [Ktor: Client](ktor.md#client).

| Option | Type | Default | Range | What it does |
|---|---|---|---|---|
| `trust` | `TrustConfig` | `TrustConfig.Platform` | | server verification for HTTP/3 and HTTP/1.1 alike |
| `identity` | `TlsIdentity?` | `null` | | client certificate |
| `tls` | `TlsConfig.Builder.() -> Unit` | `{}` | | further TLS settings, applied after `trust` and `identity` (which it can therefore replace); `alpn` and `serverName` come from the request and are set after it, so the block cannot change them (use `TrustConfig.ExpectedName` to verify another name) |
| `quic` | `QuicConfig` | `QuicConfig.Default` | its `connectionIdLength` and `http3.endpoint.connectionIdLength` agree: the one left at 8 follows the other; two different explicit values fail the engine's creation | QUIC transport of HTTP/3 connections |
| `maxIdleConnectionsPerRoute` | `Int` | 4 | at least 0 | idle HTTP/1.1 keep-alive connections kept per route; not a connection limit |
| `maxConnectionsCount` (*experimental*) | `Int` | 1000 | at least 1 | HTTP/1.1 connections of the engine, idle ones included; requests beyond it wait (FIFO, within the connect timeout) |
| `maxConnectionsPerRoute` (*experimental*) | `Int` | 100 | at least 1 | HTTP/1.1 connections to one route (scheme, host, port, proxy) |
| `idleTimeout` (*experimental*) | `Duration` | 5 min | positive | idle HTTP/1.1 connections, and HTTP/3 connections without requests, are closed after this |
| `maxConnectionLifetime` (*experimental*) | `Duration` | infinite | positive | age after which a connection takes no new requests |
| `connectTimeout` | `Duration` | 10 s | | connect timeout (TCP + TLS, or the QUIC handshake) when `HttpTimeout` sets none |
| `logger` (*experimental*) | `KuicksilverLogger?` | `null` (keeps `http3.endpoint.logger`) | | the engine's and its QUIC endpoint's diagnostics |
| `eventListener` (*experimental*) | `KuicksilverEventListener?` | `null` | | call, protocol, race, Alt-Svc and pool events ([Ktor: Observability](ktor.md#observability-experimental)) |
| `proxy` (Ktor) | `ProxyConfig?` | `null` | HTTP proxies only | HTTP/1.1 through the proxy; HTTP/3 is never proxied |

`pipelining` (from Ktor's `HttpClientEngineConfig`) is not used.

`http3 { … }` (`Http3ClientConfig`; guide: [HTTP/3 on the client](ktor.md#http3-on-the-client)):

| Option | Type | Default | What it does |
|---|---|---|---|
| `discovery` | `Http3DiscoveryMode` | `Auto` | `Auto` (HTTP/1.1 first, HTTP/3 after `Alt-Svc`), `Preferred` (HTTP/3 first, HTTP/1.1 fallback), `H3Only`, `H1Only` |
| `quicHints` | `Set<HostPort>` | empty | origins treated as `Preferred` in `Auto` mode; `HostPort(host, port)` compares the host exactly as in URLs |
| `altSvcStore` | `AltSvcStore` | `InMemoryAltSvcStore()` | where alternatives live; `FileAltSvcStore(path)` keeps them across restarts |
| `clearOnNetworkChange` | `Boolean` | `false` | drop alternatives without `persist=1` when `networkId` changes |
| `hardDelay` | `Duration?` | `null` (1.5 x the origin's smoothed RTT, 250 ms without history, clamped to 100 ms..2 s) | head start of HTTP/3 over HTTP/1.1 in a race; an explicit value is used as is |
| `networkId` | `() -> String?` | `{ null }` (one network) | identifies the current network; a change forgets broken marks and QUIC confirmation |
| `settings` | `Http3Settings` | `Http3Settings.Default` | HTTP/3 settings of the engine's connections |
| `endpoint` | `QuicEndpointConfig` | `QuicEndpointConfig.Default` | the client QUIC endpoint (bound to `0.0.0.0:0`, a dual-stack socket on the accelerated transport) |
| `earlyData` (*experimental*) | `Boolean` | `false` | 0-RTT for GET, HEAD and OPTIONS without a body on resumed connections |
| `qlog` (*experimental*) | `QlogSink?` | `null` (keeps `quic.qlog`) | a qlog trace per HTTP/3 connection |
| `connectionListener` (*experimental*) | `ConnectionListener?` | `null` (keeps `endpoint.listener`) | lifecycle of every QUIC connection |

## Ktor server engine

`embeddedServer(Kuicksilver, configure = { … })` (`KuicksilverApplicationEngine.Configuration`). Guide:
[Ktor: Server](ktor.md#server).

| Option | Type | Default | What it does |
|---|---|---|---|
| `tlsConnector(identity) { … }` | | | a TLS connector: HTTP/1.1 over TLS on TCP and HTTP/3 on UDP on the same port (below) |
| `identity` | `TlsIdentity?` | `null` | turns every plain connector (`port = …`, `connector { }`) into a TLS connector |
| `connectionIdleTimeoutSeconds` | `Int` | 45 | idle HTTP/1.1 keep-alive timeout |
| `http3` | `Boolean` | `true` | serve HTTP/3 on every TLS connector |
| `altSvc` | `Boolean` | `true` | add `Alt-Svc: h3=":<port>"; ma=86400` to HTTP/1.1 responses over TLS (not when the application set its own, not on 421) |
| `quic` | `QuicConfig` | `QuicConfig.Default` | QUIC transport of the HTTP/3 listeners |
| `quicMaxIdleTimeout` | `Duration?` | `null` | `quic.maxIdleTimeout`, applied only while `quic` is not assigned (assigning any `QuicConfig`, `QuicConfig.Default` included, uses that config's own timeout) |
| `udpSocketCount` | `Int` | 1 | endpoint loops per UDP port (`QuicEndpointConfig.loops`; more than 1 needs Linux or Android) |
| `quicAdmission` | `ConnectionAdmission?` | `null` (`ConnectionAdmission.default()`) | Retry policy |
| `http3Settings` | `Http3Settings` | `Http3Settings.Default` | HTTP/3 settings |
| `webSocketsOverHttp3` | `Boolean` | `true` | accept RFC 9220 WebSockets (turns `enableConnectProtocol` on) |
| `quicEarlyData` (*experimental*) | `Boolean` | `false` | accept 0-RTT; requests are handled by `http3Settings.earlyData` |
| `logger` (*experimental*) | `KuicksilverLogger?` | `null` (the endpoint default, `KuicksilverLogger.Stderr`) | the HTTP/3 endpoints' diagnostics |
| `qlog` (*experimental*) | `QlogSink?` | `null` | added to `quic` |
| `connectionListener` (*experimental*) | `ConnectionListener?` | `null` | lifecycle of every QUIC connection |
| `eventListener` (*experimental*) | `KuicksilverServerEventListener?` | `null` | connection and request events over both protocols |
| `shutdownGracePeriod`, `shutdownTimeout` (Ktor) | | Ktor's | `stop` sends GOAWAY and shuts the HTTP/3 endpoints down with the grace period ([Graceful stop](ktor.md#graceful-stop)) |

The other `QuicEndpointConfig` limits of the HTTP/3 listener (`maxConnections`, `acceptQueue`, `maxConnectionsPerIp`, …)
keep their defaults and are not configurable from the engine in 0.2.0. Ktor's `connectionGroupSize`,
`workerGroupSize` and `callGroupSize` are not used (the engine runs on `Dispatchers.IO`).

`tlsConnector(identity) { … }` (`KuicksilverTlsConnector.Builder`):

| Option | Type | Default | Range | What it does |
|---|---|---|---|---|
| `identity` | `TlsIdentity` | the argument | | certificate chain and key for TCP and QUIC |
| `host` | `String` | `"0.0.0.0"` | | bind address for TCP and UDP |
| `port` | `Int` | 443 | 0..65 535 | TCP port and UDP port of HTTP/3; 0 picks a free pair (`resolvedConnectors()`) |
| `clientAuth` | `ClientAuth` | `None` | | ask for or require client certificates |
| `trust` | `TrustConfig?` | `null` | `AnchoredCa` (optionally under `Pinned`) when `clientAuth` is not `None` | verifies client certificates |
| `cipherSuites` | `CipherSuites` | `CipherSuites.Default` | | TLS 1.3 suites |
| `sniSelector` | `(suspend (ClientHelloInfo) -> ServerTlsOverride?)?` | `null` | | identity per SNI name over TCP; the connector then serves no HTTP/3 (warning) |

`EngineMain` keys ([EngineMain and configuration keys](ktor.md#enginemain-and-configuration-keys)):
`kuicksilver.tls.certificateChain` and `kuicksilver.tls.privateKey` (PEM files, set together), `kuicksilver.http3`,
`kuicksilver.altSvc`, `kuicksilver.webSocketsOverHttp3` (`true`/`false`), `kuicksilver.udpSocketCount`, and
`ktor.deployment.connectionIdleTimeoutSeconds`.

## ktor-network

`Socket.tls(config, context)` and `Socket.tlsServer(config, context)` take a `TlsConfig` of the matching role (and a
`CoroutineContext`, empty by default); everything else comes from the `TlsConfig`.

## System properties and environment variables

| Name | Kind | Default | What it does |
|---|---|---|---|
| `kuicksilver.ktor.versionCheck` | JVM / Android system property | checked | `false` skips the Ktor 3.6.x check of the engines ([stability](../stability.md#ktor-versions)) |
| `kuicksilver.native.workdir` | JVM system property | `<java.io.tmpdir>/kuicksilver-native-<user>` | where `libksl` is extracted; must be a private directory of this user |
| `kuicksilver.native.path` | JVM system property | unset | load `libksl` from this file, without the hash check |
| `kuicksilver.native.system` | JVM system property | unset | `true` loads `ksl` with `System.loadLibrary`, without the hash check |
| `SSL_CERT_FILE`, `SSL_CERT_DIR` | environment, Linux Kotlin/Native | unset | the CA store of `TrustConfig.Platform`; when set, they replace the distribution paths ([Linux trust store](tls.md#linux-trust-store)) |
| `SSLKEYLOGFILE` | environment | | never read implicitly; `keylogFromEnvironment()` reads it on request. A `libksl` built against the system OpenSSL (Linux) refuses to load while it is set |

## Fixed limits

Not configurable in 0.2.0, listed so you can plan around them:

| Limit | Value |
|---|---|
| Client endpoint's RTT memory | the last smoothed RTT (1 ms..10 s) of connections that ended on the endpoint's own socket, per server address and port, at most 256 addresses (least recently stored dropped); replaces `initialRtt` for the next connection to that address |
| PMTUD | base 1200 bytes, 20-byte steps, 3 probes per size, a new search every 10 minutes, a 60 s pause after a black hole |
| Retry tokens | valid for 10 s |
| Glitch bucket | 1000 tokens, 33 back per second (QUIC and HTTP/3) |
| Connection ID rotation | every migration and every 10 000 1-RTT packets |
| Reassembly | 256 gaps per stream, 4096 per connection |
| TCP client session cache | 256 sessions per Ktor client engine (one process-wide cache for `Socket.tls` and `TlsConnection.client`) |
| Alt-Svc | 8 alternatives per origin, 1000 origins; default `ma` 86 400 s; broken marks 5 min doubling up to 2 days |
| Ktor client race head start | 100 ms..2 s when derived from the RTT |
| Datagram slots of `QuicEndpoint` | 1500 bytes (hence the `maxUdpPayloadSize` ceiling) |
| Portable JVM socket buffers | 8 MiB send and receive |
