<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Configuration reference

**What this page is for.** It is the reference for every Kuicksilver option: type, default, accepted range, the release
that introduced it and what it does. Use it to look up one option; the guides explain how options work together.

**Before you start**

- Options belong to the modules `io.kuicksilver:kuicksilver-quic`, `-tls`, `-http3`, `-http2`, `-ktor-client` and
  `-ktor-server` (version `0.3.0` or newer; the *Since* column names the release of each option;
  `io.kuicksilver:kuicksilver-bom` pins the modules to one version). A module brings along the modules it is built on,
  so you add the highest one you use.
- Built with Kotlin 2.4.20: JVM and Android need Kotlin 2.3 or newer, Kotlin/Native 2.4.x
  ([Kotlin version](../stability.md#kotlin-version)). The engine options need Ktor 3.6.x
  ([Ktor: Supported Ktor versions](ktor.md#supported-ktor-versions)).
- Know which object you configure: the table in [Where each option is set](#where-each-option-is-set) maps each one to
  its Kotlin, Ktor client, Ktor server and `EngineMain` spelling.

**How to use this page.** Find the object in the contents line or search the page for the option name; each section
links the guide that explains it. A minimal working setup is in [Ktor: Server](ktor.md#server) and
[Ktor: Client](ktor.md#client).

Every option of Kuicksilver in one place: its type, its default as the code sets it, the range the builder
accepts and what it does. The guides explain how the options work together; each section links its guide. Options
marked *experimental* need `@OptIn(ExperimentalKuicksilverApi::class)`, *delicate* ones
`@OptIn(DelicateKuicksilverApi::class)` ([stability](../stability.md)).

All configuration objects are immutable and validated when built: a builder's `build()` (or the DSL function around
it) throws `IllegalArgumentException` naming the first value out of range, or `TlsException.Config` for a TLS setting.
Problems that only show at run time are in [troubleshooting](troubleshooting.md). The *Since* column names the release
that introduced the option (`0.3.0`: the release in preparation); `tools/check/config-table.sh` checks every public
option of the configuration classes against these tables, defaults and releases included.

Contents: [where options are set](#where-each-option-is-set) · [QUIC transport](#quicconfig) · [QUIC client and server](#quicclientconfig-and-quicserverconfig) ·
[QUIC endpoint](#quicendpointconfig) · [other QUIC options](#other-quic-options) · [TLS](#tlsconfig) ·
[trust](#trustconfig) · [identities and key logging](#identities-and-key-logging) · [HTTP/3](#http3settings) · [HTTP/2](#http2settings) ·
[Ktor client](#ktor-client-engine) · [Ktor server](#ktor-server-engine) · [system properties and environment
variables](#system-properties-and-environment-variables) · [fixed limits](#fixed-limits)

## Where each option is set

| Object | Kotlin API | Ktor client | Ktor server | `EngineMain` key |
|---|---|---|---|---|
| [`QuicConfig`](#quicconfig) | `quicConfig { }` | `engine { quic = … }` | `quic = …` (`quicMaxIdleTimeout`) | |
| [`QuicEndpointConfig`](#quicendpointconfig) | `quicEndpointConfig { }` | `engine { http3 { endpoint = … } }` | only `quicMaxConnections`, `quicMaxConnectionsPerIp`, `quicAcceptQueue`, `quicAdmission`, `quicLoadBalancer`, `logger`, `qlog`, `connectionListener` and `udpSocketCount` (`loops`) reach it; the other limits keep their defaults | `kuicksilver.udpSocketCount`, `kuicksilver.quicMaxConnections`, `kuicksilver.quicMaxConnectionsPerIp`, `kuicksilver.quicAcceptQueue` |
| [`TlsConfig`](#tlsconfig) | `tlsConfig(role) { }` | `engine { trust = …; identity = …; tls { } }` | `tlsConnector(identity) { }` | `kuicksilver.tls.*` |
| [`Http3Settings`](#http3settings) | `http3Settings { }` | `engine { http3 { settings = … } }` | `http3Settings = …` | `kuicksilver.http3` (on/off) |
| [`Http2Settings`](#http2settings) | `Http2Settings(…)` | `engine { http2 { settings = … } }` | `http2Settings = …` | `kuicksilver.http2` (on/off) |
| [client engine](#ktor-client-engine) | | `HttpClient(Kuicksilver) { engine { … } }` | | |
| [server engine](#ktor-server-engine) | | | `embeddedServer(Kuicksilver) { … }` | `kuicksilver.*`, `ktor.deployment.*` |

## QuicConfig

Transport settings of a connection: `quicConfig { }` (`QuicConfig.Builder`), `QuicConfig.Default` for all defaults,
`toBuilder()` (*experimental*) to change one value of an existing config. Guide: [QUIC](quic.md#configuration).

| Option | Type | Default | Range | Since | What it does |
|---|---|---|---|---|---|
| `maxIdleTimeout` | `Duration` | 30 s | zero or positive and finite | 0.2.0 | our `max_idle_timeout`; the connection closes silently after the smaller of both peers' values (never below 3 x PTO) without traffic, with `ConnectionLost.Timeout(TimeoutKind.Idle)`. `Duration.ZERO` advertises none and leaves the timeout to the peer |
| `handshakeTimeout` | `Duration` | 10 s | positive (`Duration.INFINITE` leaves only the idle timeout) | 0.2.0 | a connection whose handshake has not completed by then closes with `TimeoutKind.Handshake` |
| `keepAlive` | `Duration?` | `null` (off) | positive and finite; at most 3/4 of `maxIdleTimeout` unless that is `ZERO` | 0.2.0 | PING interval while the application is quiet; PINGs go out at least every half of the effective idle timeout, so a peer with a shorter timeout does not close the connection (as quic-go). With `maxIdleTimeout = ZERO` it holds the connection against the peer's timeout |
| `initialStreamWindow` | `Long` (bytes) | 524 288 (512 KiB) | 1..`maxStreamWindow` | 0.2.0 | receive window of each stream at its start (`initial_max_stream_data_*`); doubles while the application reads a whole window in under four RTTs |
| `initialConnectionWindow` | `Long` (bytes) | 786 432 (768 KiB) | 1..`maxConnectionWindow` | 0.2.0 | receive window of the connection at its start (`initial_max_data`); kept at least 1.5 x the largest stream window |
| `maxStreamWindow` | `Long` (bytes) | 6 291 456 (6 MiB) | at least `initialStreamWindow` | 0.2.0 | ceiling of a stream's receive window: the most unread data one stream holds |
| `maxConnectionWindow` | `Long` (bytes) | 15 728 640 (15 MiB) | at least `initialConnectionWindow` | 0.2.0 | ceiling of the connection's receive window |
| `maxBidiStreams` | `Long` | 100 | 0..2^60 | 0.2.0 | bidirectional streams the peer may have open at once (`initial_max_streams_bidi`); raised by MAX_STREAMS as streams close. A stream counts as closed once the application took it from `acceptStream()` and consumed it (read to the end or saw its reset), so a peer cannot open more streams than this while the application accepts none |
| `maxUniStreams` | `Long` | 100 | 0..2^60 | 0.2.0 | the same for unidirectional streams; HTTP/3 needs at least 3 (RFC 9114 §6.2): `Http3Endpoint` and the Ktor engines with HTTP/3 refuse less |
| `maxSendBuffer` | `Long` (bytes) | 4 194 304 (4 MiB) | 1..2^62 | 0.2.0 | unacknowledged send data the connection buffers over all streams; writers wait beyond it |
| `maxAckDelay` | `Duration` | 25 ms | below 2^14 ms | 0.2.0 | our `max_ack_delay` |
| `ackDelayExponent` | `Int` | 3 | 0..20 | 0.2.0 | our `ack_delay_exponent` |
| `activeConnectionIdLimit` | `Int` | 4 | at least 2 | 0.2.0 | our `active_connection_id_limit`: connection IDs of the peer kept for migration and rotation |
| `connectionIdLength` | `Int` (bytes) | 8 | 4..20; must equal `QuicEndpointConfig.connectionIdLength` | 0.2.0 | length of the connection IDs we issue |
| `maxUdpPayloadSize` | `Int` (bytes) | 1452 | 1200..65 527; a `QuicEndpoint` refuses more than 1500 at `bind`/`connect` | 0.2.0 | advertised `max_udp_payload_size` and the upper bound of PMTUD ([Path MTU](quic.md#path-mtu)) |
| `versions` | `List<VersionProfile>` | `listOf(VersionProfile.V1)` | non-empty, no duplicates | 0.2.0 | versions in preference order; `listOf(V2, V1)` opts into QUIC v2 (RFC 9368/9369) |
| `initialVersion` | `VersionProfile?` | `null` (first of `versions`) | one of `versions` | 0.2.0 | the version of a client's first flight |
| `initialRtt` | `Duration` | 333 ms | (0, 10 s] | 0.2.0 | RTT assumed before the first sample: the first PTO is 3 x this (1 s, 2 s, 4 s at the default) and a path validation lasts at least 6 x this. A client endpoint replaces it with the last smoothed RTT to the same server address (see [fixed limits](#fixed-limits)) |
| `defaultStreamErrorCode` | `Long` | 0 | 0..2^62-1 | 0.2.0 | code of the STOP_SENDING / RESET_STREAM sent when a stream channel is cancelled, or when a peer stream is given up before the application accepted it (its `acceptStream()` caller cancelled). An HTTP/3 server (`Http3Endpoint`, the Ktor engine) left at 0, which is no HTTP/3 code, uses H3_REQUEST_REJECTED (0x10b, RFC 9114 §4.1.1: not processed, safe to retry); a code set explicitly is kept |
| `qlog` | `QlogSink?` | `null` |  | 0.2.0 | a qlog trace per connection ([qlog](quic.md#qlog)); a failing sink stops tracing for that connection only |
| `congestionController` | `() -> CongestionController` | `{ Cubic() }` | return a fresh instance per call | 0.2.0 | controller of each path: `Cubic` (CUBIC with HyStart++), `NewReno`, `Bbr` (*experimental*) ([Congestion control](quic.md#congestion-control)) |
| `greaseQuicBit` | `Boolean` | `true` |  | 0.2.0 | send the fixed bit randomly when the peer allows it (RFC 9287) |
| `glitchProtection` | `Boolean` | `true` |  | 0.2.0 | close a connection whose peer keeps making us do useless work ([Glitch protection](quic.md#glitch-protection)) |
| `allowMigration` | `Boolean` | `true` |  | 0.2.0 | server: follow a client to a new address; `false` advertises `disable_active_migration` and drops datagrams from other addresses |
| `allowMigrationToLoopback` | `Boolean` | `false` |  | 0.2.0 | server: accept a move to a loopback or link-local address from a connection that did not start on one |
| `pmtud` | `Boolean` | `true` |  | 0.2.0 | DPLPMTUD (RFC 8899) on sockets that set DF; `false` keeps 1200 bytes |
| `followPreferredAddress` (*experimental*) | `Boolean` | `true` |  | 0.3.0 | client: move to the server's preferred address after the handshake, once the path there is validated ([Migration and paths](quic.md#migration-and-paths)) |
| `pmtudIcmpHints` (*experimental*) | `Boolean` | `true` |  | 0.3.0 | validated ICMP Packet Too Big (Linux, Android) and EMSGSIZE speed up DPLPMTUD as hints, never lowering the MTU without lost probes ([Path MTU](quic.md#path-mtu)) |
| `maxDatagramFrameSize` | `Long` | 65 535 | 0..65 535 | 0.2.0 | our `max_datagram_frame_size` (RFC 9221); 0 turns datagrams off |
| `resetStreamAt` (*experimental*) | `Boolean` | `false` |  | 0.3.0 | advertise `reset_stream_at`: `QuicStream.resetAt` keeps a stream's first bytes when the peer advertised it too ([quic.md](quic.md#reliable-stream-reset-experimental)) |
| `datagramReceiveQueue` | `Int` | 128 | at least 1 | 0.2.0 | received datagrams held for the application; a full queue drops the oldest |
| `datagramSendQueue` | `Int` | 32 | at least 1 | 0.2.0 | datagrams queued for sending ([Datagrams](quic.md#datagrams-rfc-9221)) |
| `datagramSendQueueBytes` | `Long` | 1 048 576 (1 MiB) | at least 1 | 0.2.0 | byte ceiling of the same queue |

## QuicClientConfig and QuicServerConfig

`quicClientConfig(tls) { }` and `quicServerConfig(tls) { }` pair a `TlsConfig` with a `QuicConfig`. `build()` throws
`IllegalArgumentException` for a `TlsConfig` of the wrong role ("client config needs a client TlsConfig") and
`TlsException.Config` for one QUIC cannot use: TLS 1.2 allowed, an empty `alpn`, `TLS_AES_128_CCM_8_SHA256`, or an
`sniSelector`.

| Option | Type | Default | Range | Since | What it does |
|---|---|---|---|---|---|
| `tls` (constructor) | `TlsConfig` |  | client or server role | 0.3.0 | name to verify, trust, ALPN; identity on a server |
| `quic` | `QuicConfig` | `QuicConfig.Default` | on a server, its `connectionIdLength` must equal the endpoint's | 0.2.0 | transport settings |
| client `earlyData` (*experimental*) | `EarlyDataState` | `Disabled` | `Disabled`, `Allowed`, `Required` | 0.2.0 | keep the server's session tickets (per endpoint, single use) and send 0-RTT through `QuicEndpoint.connectEarly`; `Required` fails the connection with `ZeroRttRejected` when 0-RTT is refused or impossible ([0-RTT](quic.md#0-rtt-opt-in-experimental)) |
| server `earlyData` (*experimental*) | `Boolean` | `false` | not with client certificates | 0.2.0 | accept 0-RTT: fresh tickets only (the ticket's age within a 10 s window: [claimed − 1 s, claimed + 9 s]), once per ticket, only for the configuration that issued it |
| server `earlyDataContext` (*experimental*) | `ByteArray?` | `null` | at most 256 bytes | 0.2.0 | application settings bound into tickets (`Http3Endpoint` puts its SETTINGS here) |
| client `tokenStore` (*experimental*) | `QuicTokenStore?` | `null` |  | 0.3.0 | keep the servers' NEW_TOKEN tokens and present one on the next connection to the same server name and port: no Retry round trip; links those connections ([Address tokens](quic.md#address-tokens-new_token)) |
| server `preferredAddress` (*experimental*) | `PreferredAddress?` | `null` | IP literals, ports 1..65535, not unspecified or multicast | 0.3.0 | also listen on these addresses (one per family) and offer them in `preferred_address`; clients that follow move there after validating the path ([Migration and paths](quic.md#migration-and-paths)) |
| server `newTokenReplayCapacity` (*experimental*) | `Int` | `1_048_576` | 1..16,777,216 | 0.3.0 | NEW_TOKEN tokens the replay register holds per lifetime (32 bytes each, 32 MiB at the default, allocated on the first token shown); once full a returning client's token counts as absent |
| server `newTokenLifetime` (*experimental*) | `Duration?` | 24 hours | positive, at most 7 days; `null` issues none | 0.3.0 | how long the NEW_TOKEN tokens this server issues validate a returning client's address ([Admission and endpoint limits](quic.md#admission-and-endpoint-limits)) |

## QuicEndpointConfig

The endpoint that owns a socket and its connections: `quicEndpointConfig { }`, `QuicEndpointConfig.Default` (a
client-only endpoint), `toBuilder()` (*experimental*). Guide: [Admission and endpoint limits](quic.md#admission-and-endpoint-limits).

| Option | Type | Default | Range | Since | What it does |
|---|---|---|---|---|---|
| `server` | `QuicServerConfig?` | `null` |  | 0.2.0 | the server side; `null` is a client-only endpoint, which admits no connection |
| `crypto` | `QuicCrypto` | `KslQuicCrypto` |  | 0.2.0 | TLS and packet protection (OpenSSL through `ksl`) |
| `maxConnections` | `Int` | 10 000 | at least 1 | 0.2.0 | beyond this many connections new Initials are dropped silently; counts the whole endpoint, all `loops` (since 0.3.0; before, each loop) |
| `acceptQueue` | `Int` | 128 | at least 1 | 0.2.0 | handshaken connections waiting for `accept()`, over all loops; while full, a new client is refused statelessly with CONNECTION_REFUSED (0x02). Handshakes in flight do not count |
| `dispatcher` | `CoroutineDispatcher?` | `null` (`Dispatchers.Default.limitedParallelism(1)`) | must stay `null` with `loops > 1` | 0.2.0 | the single-threaded dispatcher of the endpoint loop. While datagrams keep coming the loop reads the ones already queued on this thread; only on its own dispatcher (`null`) does it also wait there up to 1 ms for the next ones (not on Windows), so a dispatcher set here, shared with a UI or a second endpoint, is never held in a socket wait |
| `io` | `(suspend (InetSocketAddress) -> DatagramIo)?` | `null` (`DatagramIo.open` with `IoPreference.Accelerated`) |  | 0.2.0 | how the loop opens its socket; `MemoryNetwork.open` runs the endpoint in memory ([Testing](quic.md#testing-your-application)) |
| `connectionIdLength` | `Int` (bytes) | 8 | 4..20; must equal the `QuicConfig.connectionIdLength` of the server and of every client connection | 0.2.0 | length used to parse short headers |
| `admission` | `ConnectionAdmission` | `ConnectionAdmission.default()` |  | 0.2.0 | decides per new client Initial: `Allow`, `Retry`, `Drop` or `Close(code)`. `default(maxInflightHandshakes = 256, maxHandshakeBufferBytes = 8 MiB)` asks an unvalidated client for a Retry above either and lets in one a Retry or NEW_TOKEN token validated; `ConnectionAdmission.AlwaysRetry` validates every address first |
| `initialQueueCap` | `Int` | 1024 | at least 1 | 0.2.0 | new Initials queued for admission per receive batch; more are dropped |
| `maxConnectionsPerIp` | `Int?` | 256 | positive or `null` (no limit) | 0.2.0 | connections one client IP may hold, ports ignored, over the whole endpoint, all `loops` (since 0.3.0; before, each loop); the excess is dropped silently |
| `maxConnectionLifetime` | `Duration?` | `null` (none) | positive or `null` | 0.2.0 | server connections older than this close with NO_ERROR ("connection lifetime reached") |
| `rejectInitialFromReflectivePorts` | `Boolean` | `true` |  | 0.2.0 | drop Initials from source ports 53, 123, 1900, 5353 and 11211 (reflection attacks) |
| `statelessPerAddressPerSecond` | `Int` | 8 | at least 1 | 0.2.0 | stateless answers (Retry, Version Negotiation, Stateless Reset, refusals) per client address per second |
| `statelessTotalPerSecond` | `Int` | 1000 | at least 1 | 0.2.0 | stateless answers per second over all addresses |
| `loops` | `Int` | 1 | 1..255; more than 1 needs a `server` and no `dispatcher` | 0.2.0 | endpoint loops sharing the port: a socket each with `SO_REUSEPORT` on Linux and Android, one socket routed in process elsewhere (every platform since 0.3.0; [Several loops on one port](quic.md#several-loops-on-one-port)) |
| `logger` (*experimental*) | `KuicksilverLogger` | `KuicksilverLogger.Stderr` (warnings and errors on standard error) |  | 0.2.0 | the endpoint's diagnostics; `KuicksilverLogger.None`, `KuicksilverLogger.stderr(LogLevel.Debug)` or your own ([Observability](quic.md#observability)) |
| `listener` (*experimental*) | `ConnectionListener?` | `null` |  | 0.2.0 | lifecycle callbacks of every connection, on the loop |
| `loadBalancer` (*experimental*) | `QuicLbConfig?` | `null` | needs a `server`, `connectionIdLength` = 1 + server ID + nonce and at least 8, a key next to a `preferredAddress` | 0.3.0 | QUIC-LB server connection IDs (draft-ietf-quic-load-balancers-21); change with `QuicEndpoint.updateLoadBalancer` ([Behind a load balancer](quic.md#behind-a-load-balancer)) |

## Other QUIC options

| Where | Option | Default | What it does |
|---|---|---|---|
| `QuicConnection.openBidi`, `openUni` | `priority: StreamPriority` | `StreamPriority.Default` (`urgency = 3`, `incremental = false`; urgency 0..7) | send order between streams (RFC 9218 levels) |
| `QuicConnection.sendDatagram`, `trySendDatagram` | `policy: DatagramPolicy` | `DropOldest` | `DropOldest`, `LatestWins(key)` or `Reject` when the send queue is full |
| `DatagramIo.open(local, prefer)` | `prefer: IoPreference` | `Accelerated` | `Accelerated`: the `ksl` socket where it exists, `Portable`: NIO on the JVM, `ktor-network` on Kotlin/Native |
| `Cubic(maxDatagramSize, hystart)`, `NewReno(maxDatagramSize)` | | 1200, `true` | the stable congestion controllers |
| `Bbr(maxDatagramSize, random)` (*experimental*) | | 1200, `null` (jitter from send and ACK times) | BBRv3 ([Choosing a congestion controller](quic.md#choosing-a-congestion-controller)) |
| `DirectoryQlogSink(directory)`, `DirectoryQlogSink(directory, maxOpenTraces, maxTotalBytes)` (*experimental*) | | 256 open traces, 1 GiB in all | one `<odcid>_<client\|server>_<random>.sqlog` file per connection, created exclusively, never through a link; creates the directory owner-only and refuses one another user could change |
| `qlogDirectory(context, name)` (Android, *experimental*) | | `name = "kuicksilver-qlog"` | a `DirectoryQlogSink` in the app's cache directory, created owner-only at once; API 26 and up (refused below) |
| `AsyncQlogSink(delegate, queueCapacity, sampleEvery, dispatcher)` (*experimental*) | | 8192 records, 1 (every connection), `Dispatchers.IO.limitedParallelism(1)` | runs a sink off the endpoint loop; a full queue drops records (`dropped`) |
| `NetworkMigrator(connection, networks, openIo, scope)` (*experimental*) | | no defaults; client connections only | follows a `Flow` of networks ([Network changes](quic.md#network-changes)) |
| `QuicConnection.rebind(local, prefer)` (*experimental*) | | `null` (wildcard of the peer's family), `Accelerated` | moves the connection to a fresh socket |
| `followDefaultNetwork(connectivity, scope, local, prefer)` (Android), `followDefaultNetwork(scope, local, prefer)` (Apple) (*experimental*) | | `null`, `Accelerated` | a started `NetworkMigrator` on the default network |
| `QuicEndpoint.shutdown(grace, code, reason)` (*experimental*) | | `code = 0`, `reason = "shutdown"` | graceful shutdown ([Graceful shutdown](quic.md#graceful-shutdown)) |

## TlsConfig

`tlsConfig(TlsRole.Client / TlsRole.Server) { }` (`TlsConfig.Builder`); errors are `TlsException.Config`. One
`TlsConfig` drives QUIC, TLS over TCP and `Socket.tls()`. Guide: [TLS](tls.md#configuration).

| Option | Type | Default | Range | Since | What it does |
|---|---|---|---|---|---|
| `alpn` | `List<String>` | empty | each name 1..255 UTF-8 bytes, the list at most 255 bytes on the wire; QUIC needs at least one | 0.2.0 | ALPN protocol IDs in preference order |
| `serverName` | `String?` | `null` | a client needs it (or `TrustConfig.ExpectedName`) | 0.2.0 | SNI and the name the certificate must match; an IP literal is verified but never sent as SNI. Servers ignore it |
| `versions` | `TlsVersions` | `Tls13` | QUIC: `Tls13` only | 0.2.0 | TLS 1.3 is the default (RFC 9852); `Tls12And13` allows TLS 1.2 over TCP under the RFC 9325 profile as narrowed by RFC 10015 (ECDHE and AEAD only); renegotiation is always refused, and on an `h2` connection a peer's attempt ends it (RFC 9113 section 9.2.1) |
| `cipherSuites` | `CipherSuites` | `CipherSuites.Default` (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305) | at least one; QUIC refuses `TLS_AES_128_CCM_8_SHA256` | 0.2.0 | TLS 1.3 suites in preference order |
| `identity` | `TlsIdentity?` | `null` | a server needs an identity or an `sniSelector` | 0.2.0 | certificate chain and key; `TlsIdentity.reloadable(...)` for one replaced at run time ([TLS guide](tls.md#rotating-the-server-certificate)) |
| `trust` | `TrustConfig` | `TrustConfig.Platform` | with `clientAuth` other than `None`: `AnchoredCa` or `ReloadableCa`, optionally under `Pinned` | 0.2.0 | how the peer is verified ([TrustConfig](#trustconfig)) |
| `clientAuth` | `ClientAuth` | `None` | servers only | 0.2.0 | `None`, `Optional` or `Required` client certificates |
| `sniSelector` | `(suspend (ClientHelloInfo) -> ServerTlsOverride?)?` | `null` | servers, TCP only (QUIC refuses it) | 0.2.0 | picks a `ServerTlsOverride(identity, alpn, clientAuth, trust)` per ClientHello |
| `sessionTickets` | `SessionTicketConfig` | `SessionTicketConfig.Default` | see [SessionTicketConfig](#sessionticketconfig) | 0.2.0 | the keys and lifetime of a TLS-over-TCP server's tickets and of a QUIC server with `earlyData` (the only QUIC servers that issue tickets) |
| `keylog` (*delicate*) | `KeylogSink?` | `null` |  | 0.2.0 | TLS secrets as RFC 9850 key log lines ([Key logging](tls.md#key-logging)) |
| `handshakeTimeout` | `Duration` | 10 s | positive (`Duration.INFINITE`: no deadline) | 0.2.0 | TLS over TCP only (QUIC uses `QuicConfig.handshakeTimeout`) |
| `genericAlerts` | `Boolean` | `false` |  | 0.2.0 | send `handshake_failure` instead of the specific alert; a failed stapled OCSP check is still sent as `bad_certificate_status_response` (113) |
| `revocation` (*experimental*) | `RevocationPolicy` | `StapledIfPresent` | clients; `RequireStapled` only with a trust `ksl` verifies (`AnchoredCa`, `Platform` on Linux Native) | 0.3.0 | how the OCSP response the server staples is checked: `Off`, `StapledIfPresent` (soft-fail without one), `RequireStapled`; a must-staple certificate needs one under every policy but `Off`. Alerts: 113 for every failed staple check (also with `genericAlerts`); a configured CRL gives 44 (revoked), 45 (expired CRL), 42 (CRL not valid yet, bad time field, undecryptable signature), 51 (CRL signature does not verify), 48 (no usable CRL or CRL issuer) or 46 (another scope, no cRLSign, unknown critical extension) ([Certificate revocation](tls.md#certificate-revocation)) |
| `ocspStapling` (*experimental*) | `OcspStapling?` | `null` | servers | 0.3.0 | the OCSP response stapled when the client asks and it is for the leaf sent and fresh; `update` replaces it at run time ([Certificate revocation](tls.md#certificate-revocation)) |

### SessionTicketConfig

`SessionTicketConfig(keys, rotateEvery, ticketLifetime)`:

| Option | Type | Default | Range | Since | What it does |
|---|---|---|---|---|---|
| `keys` (constructor) | `List<ByteArray>?` | `null` (generated in the process) | 1 to 64 entries of 80 bytes | 0.2.0 | explicit ticket keys, shared by the servers of one fleet |
| `rotateEvery` | `Duration` | 1 day | positive, at most 7 days | 0.2.0 | how often the active ticket key is replaced |
| `ticketLifetime` | `Duration` | 12 hours | at least 1 s, at most `rotateEvery / 2` | 0.2.0 | how long a ticket stays valid |

The keys stay in native memory: generated keys never reach Kotlin, explicit keys are
copied there when the configuration is built and the given arrays are zeroed (keep the keys in your secret store, not
in the arrays).

Key exchange groups are not configurable: `X25519MLKEM768`, `X25519`, `secp256r1`, `X448`, `secp384r1`, `secp521r1`
([Key exchange groups](tls.md#key-exchange-groups)).

## TrustConfig

Guide: [TLS: Trust](tls.md#trust).

| Variant | Parameters (defaults) | Checks | What it does |
|---|---|---|---|
| `TrustConfig.Platform` | | Linux Native: a CA store must exist when the client config is built | the operating system's verifier ([Platform trust](tls.md#platform-trust)) |
| `TrustConfig.AnchoredCa(roots)` | `roots: List<Certificate>` | at least one root | only these roots, verified inside `ksl`; with `ReloadableCa`, the only trust for client certificates |
| `TrustConfig.reloadable(initial)` (*experimental*) | `initial: AnchoredCa` | servers only; `reload` refuses a bundle with no certificate valid now | a `ReloadableCa`: client certificates verified against the `AnchoredCa` current when the handshake starts; `reload(next)` rotates it ([Rotating the client CA](tls.md#rotating-the-client-ca)) |
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

| Option | Type | Default | Range | Since | What it does |
|---|---|---|---|---|---|
| `qpackMaxTableCapacity` | `Long` | 0 | 0..2^30 | 0.2.0 | `SETTINGS_QPACK_MAX_TABLE_CAPACITY` we advertise: the dynamic table the peer's encoder may use |
| `qpackBlockedStreams` | `Long` | 0 | 0..65 535 | 0.2.0 | `SETTINGS_QPACK_BLOCKED_STREAMS` we advertise |
| `encoderMaxTableCapacity` | `Long` | 4096 | 0..2^30 | 0.2.0 | ceiling of our own encoder's dynamic table, under what the peer allows |
| `maxFieldSectionSize` | `Long` | 65 536 (64 KiB) | 1..2^30 | 0.2.0 | largest decoded header or trailer section we accept (and so the longest single field; above it: 431, the connection lives), advertised as `SETTINGS_MAX_FIELD_SECTION_SIZE` |
| `enableConnectProtocol` | `Boolean` | `false` |  | 0.2.0 | advertise Extended CONNECT (RFC 9220) |
| `h3Datagram` | `Boolean` | `true` |  | 0.2.0 | `SETTINGS_H3_DATAGRAM` (always sent); `Http3Endpoint` sends 0 when `QuicConfig.maxDatagramFrameSize` is 0 |
| `webTransport` | `Boolean` | `false` | needs `enableConnectProtocol` and `h3Datagram` | 0.3.0 | experimental: WebTransport over HTTP/3 (draft-ietf-webtrans-http3-16, with the draft-02 and draft-14 SETTINGS browsers use); `Http3Endpoint.bind` refuses it when `QuicConfig.maxDatagramFrameSize` is 0 |
| `grease` | `Boolean` | `true` |  | 0.2.0 | send a reserved setting, frame and stream type |
| `maxInformationalResponses` | `Int` | 5 | at least 0 | 0.2.0 | deprecated and ignored since 0.2.1: a client accepts any number of 1xx responses (RFC 9110 section 15.2); their fields together are bounded by `maxFieldSectionSize`, past which the request fails with `H3_EXCESSIVE_LOAD` |
| `maxEarlyPriorityUpdates` | `Int` | 32 | at least 0 | 0.2.0 | PRIORITY_UPDATE frames remembered for streams not yet open |
| `glitchProtection` | `Boolean` | `true` |  | 0.2.0 | close with `H3_EXCESSIVE_LOAD` a peer that floods useless frames |
| `earlyData` (*experimental*) | `Http3EarlyDataPolicy` | `WaitForHandshake()` | `WaitForHandshake(replayable)`, `Reject425(replayable)`; `replayable` admits GET, HEAD and OPTIONS by default | 0.2.0 | server: what happens to requests that arrive in 0-RTT ([HTTP/3 0-RTT](http3.md#0-rtt-opt-in-experimental)) |

`enableQpackDynamicTable()` sets `qpackMaxTableCapacity = 4096` and `qpackBlockedStreams = 16`.

Endpoint and request parameters:

| API | Parameters (defaults) |
|---|---|
| `Http3Endpoint.bind(local, config, settings)` | `config = QuicEndpointConfig.Default`, `settings = Http3Settings.Default`; the server's TLS must offer ALPN `h3` |
| `Http3Endpoint.connect(remote, tls, quic, settings)` | `quic = QuicConfig.Default`, `settings = Http3Settings.Default`; `tls` must offer ALPN `h3` |
| `Http3Endpoint.connectEarly(remote, tls, quic, settings, earlyData)` (*experimental*) | as `connect`, `earlyData = EarlyDataState.Allowed` (not `Disabled`) |
| `Http3Endpoint.shutdown(grace, code, reason)` (*experimental*) | `code = H3_NO_ERROR`, `reason = "shutdown"` |
| `http3Request(method, authority, path) { ... }` (`Http3Request.Builder`) | `scheme = "https"`, `headers = Http3Headers.Empty`, `body = null` (no body), `trailers = null`, `priority = null` (the default `u=3`), `protocol = null`, `onInformational = null`, `allowEarlyData = false` (*experimental*; GET, HEAD and OPTIONS without a body only) |

### CapsuleConfig (*experimental*)

How an Extended CONNECT stream speaks the Capsule Protocol (RFC 9297 section 3) once
`Http3Stream.useCapsuleProtocol(config)` is called: the constructor, `capsuleConfig { }` (`CapsuleConfig.Builder`),
`toBuilder()`. Guide: [HTTP/3, capsules](http3.md#capsules-experimental).

| Option | Type | Default | Range | Since | What it does |
|---|---|---|---|---|---|
| `knownTypes` | `Set<Long>` | empty | each 0..2^62-1 | 0.3.0 | capsule types delivered in `CapsuleStream.capsules`; other types are skipped as their bytes arrive. DATAGRAM (0x00) always goes to `datagrams` |
| `maxCapsuleLength` | `Int` (bytes) | 65 536 (64 KiB) | 1..1 048 576 | 0.3.0 | longest capsule of a known type; a longer one resets and stops the stream with `H3_MESSAGE_ERROR` |
| `maxDatagramLength` | `Int` (bytes) | 65 536 (64 KiB) | 1..1 048 576 | 0.3.0 | longest DATAGRAM capsule; a longer one is dropped without being buffered |
| `datagramFallback` | `Boolean` | `true` |  | 0.3.0 | send datagrams as DATAGRAM capsules when HTTP/3 datagrams are unsupported (either side's `SETTINGS_H3_DATAGRAM` is 0, or the peer's SETTINGS have not arrived yet); a datagram too large for QUIC never falls back |
| `receiveQueue` | `Int` | 16 | 1..4096 | 0.3.0 | received capsules held for the collector; when full, reading the stream pauses (flow control holds the peer back) |
| `sendQueue` | `Int` | 32 | 1..4096 | 0.3.0 | capsules waiting to be written; when full, `send` suspends and a fallback `trySendDatagram` answers `QueueFull` |
| `terminalTypes` | `Set<Long>` | empty | among `knownTypes`, not DATAGRAM | 0.3.0 | a capsule of such a type must be the stream's last: it is delivered, and any byte after it resets the stream with `H3_MESSAGE_ERROR` (WebTransport's WT_CLOSE_SESSION) |

## Http2Settings

`Http2Settings(...)` (*experimental*, constructor parameters, immutable). Used by the Ktor client (`http2 { settings = … }`) and
server (`http2Settings = …`); a bad value throws `IllegalArgumentException` when the object is built. Guide: [Ktor: HTTP/2 on
the client](ktor.md#http2-on-the-client), [on the server](ktor.md#http2-on-the-server); limits against floods: threat model 3.23.

| Option | Type | Default | Range | Since | What it does |
|---|---|---|---|---|---|
| `headerTableSize` | `Int` | 4096 | 0..65 536 | 0.3.0 | `SETTINGS_HEADER_TABLE_SIZE`: the HPACK dynamic table the peer may use towards us |
| `maxConcurrentStreams` | `Int` | 100 | at least 0 | 0.3.0 | `SETTINGS_MAX_CONCURRENT_STREAMS`: streams the peer may have open towards us; a stream the peer reset still counts until its handler has finished |
| `initialStreamWindow` | `Int` (bytes) | 524 288 (512 KiB) | at least 0 | 0.3.0 | `SETTINGS_INITIAL_WINDOW_SIZE`: the receive window each stream starts with |
| `maxStreamWindow` | `Int` (bytes) | 6 291 456 (6 MiB) | at least `initialStreamWindow` | 0.3.0 | the largest a stream's receive window grows to while the application reads faster than the window |
| `initialConnectionWindow` | `Int` (bytes) | 786 432 (768 KiB) | at least 65 535 | 0.3.0 | the connection's receive window |
| `maxConnectionWindow` | `Int` (bytes) | 15 728 640 (15 MiB) | at least `initialConnectionWindow` | 0.3.0 | the largest the connection's receive window grows to |
| `maxFrameSize` | `Int` (bytes) | 16 384 | 16 384..16 777 215 | 0.3.0 | `SETTINGS_MAX_FRAME_SIZE`: the largest frame payload we accept |
| `maxHeaderListSize` | `Int` (bytes) | 65 536 (64 KiB) | 1..2^30 - 1 | 0.3.0 | `SETTINGS_MAX_HEADER_LIST_SIZE`: the largest field section we decode (name + value + 32 per field); a larger one fails only its stream, its compressed form is buffered up to twice this, beyond that the connection ends |
| `settingsAckTimeout` | `Duration` | 10 s | positive | 0.3.0 | how long our SETTINGS may go unacknowledged before the connection ends with `SETTINGS_TIMEOUT` |
| `maxContinuationFrames` | `Int` | 8 | at least 0 | 0.3.0 | CONTINUATION frames allowed in one field block; more ends the connection (`ENHANCE_YOUR_CALM`) |
| `maxControlFramesQueued` | `Int` | 10 000 | at least 1 | 0.3.0 | control frames (SETTINGS and PING acknowledgements, RST_STREAM, WINDOW_UPDATE) queued for the peer |
| `maxEmptyFrames` | `Int` | 100 | at least 0 | 0.3.0 | DATA frames in a row with no content and no END_STREAM; more ends the connection |
| `resetBurst` | `Int` | 1000 | at least 1 | 0.3.0 | a server's budget for the client's RST_STREAM frames (Rapid Reset), burst (as nghttp2) |
| `resetsPerSecond` | `Int` | 33 | at least 0 | 0.3.0 | refill rate of that budget per second; 0: it never refills |
| `maxHeaderBlockTime` | `Duration` | 10 s | positive | 0.3.0 | how long one field block (HEADERS and its CONTINUATION frames) may take to arrive |
| `glitchBurst` | `Int` | 10 000 | at least 1 | 0.3.0 | burst of the glitch budget (PRIORITY, unknown frame types, SETTINGS, empty DATA, an unanswered-data PING, every stream error the peer causes) |
| `glitchesPerSecond` | `Int` | 330 | at least 0 | 0.3.0 | refill rate of the glitch budget per second; 0: it never refills |

## Ktor client engine

`HttpClient(Kuicksilver) { engine { … } }` (`KuicksilverEngineConfig`). Values are checked when the engine is created.
Guide: [Ktor: Client](ktor.md#client).

| Option | Type | Default | Range | Since | What it does |
|---|---|---|---|---|---|
| `trust` | `TrustConfig` | `TrustConfig.Platform` |  | 0.2.0 | server verification for HTTP/3, HTTP/2 and HTTP/1.1 alike |
| `identity` | `TlsIdentity?` | `null` |  | 0.2.0 | client certificate |
| `tls` | `TlsConfig.Builder.() -> Unit` | `{}` |  | 0.2.0 | further TLS settings, applied after `trust` and `identity` (which it can therefore replace); `alpn` and `serverName` come from the request and are set after it, so the block cannot change them (use `TrustConfig.ExpectedName` to verify another name) |
| `quic` | `QuicConfig` | `QuicConfig.Default` | its `connectionIdLength` and `http3.endpoint.connectionIdLength` agree: the one left at 8 follows the other; two different explicit values fail the engine's creation | 0.2.0 | QUIC transport of HTTP/3 connections |
| `maxIdleConnectionsPerRoute` | `Int` | 4 | at least 0 | 0.2.0 | idle HTTP/1.1 keep-alive connections kept per route; not a connection limit |
| `maxConnectionsCount` (*experimental*) | `Int` | 1000 | at least 1 | 0.2.0 | TCP connections (HTTP/1.1 and HTTP/2) of the engine, idle ones included; requests beyond it wait (FIFO, within the connect timeout) |
| `maxConnectionsPerRoute` (*experimental*) | `Int` | 100 | at least 1 | 0.2.0 | TCP connections to one route (scheme, host, port, proxy); an HTTP/2 connection counts once however many requests it carries |
| `idleTimeout` (*experimental*) | `Duration` | 5 min | positive | 0.2.0 | idle HTTP/1.1 connections, and HTTP/2 and HTTP/3 connections without requests, are closed after this |
| `maxConnectionLifetime` (*experimental*) | `Duration` | infinite | positive | 0.2.0 | age after which a connection takes no new requests |
| `connectTimeout` | `Duration` | 10 s |  | 0.2.0 | connect timeout (TCP + TLS, or the QUIC handshake) when `HttpTimeout` sets none; a WebSocket over HTTP/1.1 also waits at most this long for the answer to its opening handshake (`ConnectTimeoutException`) |
| `connectionAttemptDelay` (*experimental*) | `Duration` | 250 ms | 10 ms..2 s, or `Duration.INFINITE`; anything else fails the engine's creation | 0.3.0 | Happy Eyeballs (RFC 8305) for HTTP/1.1's TCP connects: the delay before the next address is tried while earlier attempts are still pending; `INFINITE` tries one address after another ([Ktor: IPv6 over TCP](ktor.md#ipv6-over-tcp-on-kotlinnative)) |
| `logger` (*experimental*) | `KuicksilverLogger?` | `null` (keeps `http3.endpoint.logger`) |  | 0.2.0 | the engine's and its QUIC endpoint's diagnostics |
| `eventListener` (*experimental*) | `KuicksilverEventListener?` | `null` |  | 0.2.0 | call, protocol, race, Alt-Svc and pool events ([Ktor: Observability](ktor.md#observability-experimental)) |
| `proxy` (Ktor) | `ProxyConfig?` | `null` | HTTP (`http://` only) and SOCKS5 proxies; others, an `https://` proxy URL included, fail each request with `UnsupportedOperationException` | 0.2.0 | TCP through the proxy (HTTP/1.1, or HTTP/2 inside the tunnel) (CONNECT for `https` and WebSockets, absolute form for `http`; SOCKS5 CONNECT with the proxy resolving names); HTTP/3 is never proxied |
| `proxyResolver` (*experimental*) | `ProxyResolver` | `ProxyResolvers.System` | `System`, `Environment`, `None` or your own | 0.3.0 | the proxy for requests `proxy` does not cover, per scheme, host and port (kept 30 s); each lookup is bounded by the engine's `connectTimeout` (not a per-request `HttpTimeout`) and fails the request with `ProxyException` beyond it; loopback is always direct with the built-ins; docs/guide/ktor.md, "Proxies" |
| `proxyCredentials` (*experimental*) | `ProxyCredentials?` | `null` | SOCKS5: user 1–255 bytes, password up to 255 (RFC 1929) | 0.3.0 | for the explicit `proxy` only (a resolver's proxy carries its own `ResolvedProxy.credentials`); SOCKS5 username/password when the proxy picks it; `Proxy-Authorization: Basic` on an HTTP proxy's CONNECT and absolute-form requests unless the request has its own; off the JVM the proxy URL's user info wins |

`pipelining` (from Ktor's `HttpClientEngineConfig`) is not used.

### HTTP/2 client options

`http2 { … }` (`Http2ClientConfig`, *experimental*; guide: [HTTP/2 on the client](ktor.md#http2-on-the-client)):

| Option | Type | Default | Since | What it does |
|---|---|---|---|---|
| `enabled` | `Boolean` | `true` | 0.3.0 | offer `h2` and `http/1.1` in ALPN on every `https://` connection over TCP (not WebSockets), over TLS 1.3 and, when `tls` allows it, TLS 1.2 (a server's renegotiation request then ends the connection with PROTOCOL_ERROR, RFC 9113 section 9.2.1); `false` offers only `http/1.1`, as in 0.2 |
| `settings` | `Http2Settings` | `Http2Settings()` | 0.3.0 | our SETTINGS, windows (512 KiB per stream growing to 6 MiB, 768 KiB per connection growing to 15 MiB) and the limits held against the server (64 KiB field sections, 10 s for our SETTINGS to be acknowledged, the flood limits; threat model 3.23) |
| `pingInterval` | `Duration` | `Duration.INFINITE` | 0.3.0 | a PING this often on every HTTP/2 connection; one still unanswered at the next ends the connection and fails its calls; at least 100 ms, else the engine's creation fails with `IllegalArgumentException` |

### HTTP/3 client options

`http3 { … }` (`Http3ClientConfig`; guide: [HTTP/3 on the client](ktor.md#http3-on-the-client)):

| Option | Type | Default | Since | What it does |
|---|---|---|---|---|
| `discovery` | `Http3DiscoveryMode` | `Auto` | 0.2.0 | `Auto` (TCP first, HTTP/3 after `Alt-Svc`), `Preferred` (HTTP/3 first, TCP fallback), `H3Only`, `H1Only` (no HTTP/3; TCP is HTTP/1.1 or HTTP/2) |
| `quicHints` | `Set<HostPort>` | empty | 0.2.0 | origins treated as `Preferred` in `Auto` mode; `HostPort(host, port)` compares the host exactly as in URLs |
| `altSvcStore` | `AltSvcStore` | `InMemoryAltSvcStore()` | 0.2.0 | where alternatives live; `FileAltSvcStore(path)` keeps them across restarts (on the JVM and Android also `FileAltSvcStore(file)` with a `java.io.File`, which works from API 24) |
| `clearOnNetworkChange` | `Boolean` | `true` | 0.2.0 | drop alternatives without `persist=1` when `networkId` changes (RFC 7838 section 2.2); `false` keeps them |
| `httpsRecords` (*experimental*) | `HttpsRecordSource` | `HttpsRecordSource.Off` | 0.3.0 | HTTPS resource records (RFC 9460) as a source of HTTP/3 in `Auto`: `System` (the OS resolver) or `Exchange { query -> response }` (your DNS-over-HTTPS client) ([HTTPS records](ktor.md#https-records-experimental)) |
| `httpsRecordExtraWait` (*experimental*) | `Duration` | 50 ms | 0.3.0 | how long a request waits for the HTTPS records after the origin's addresses resolved; 50 ms (RFC 9460 section 5.1) to 1 s, else the engine's creation fails with `IllegalArgumentException` |
| `hardDelay` | `Duration?` | `null` (1.5 x the origin's smoothed RTT, 250 ms without history, clamped to 100 ms..2 s) | 0.2.0 | head start of HTTP/3 over HTTP/1.1 in a race on a network where QUIC was confirmed (10 ms elsewhere); an explicit value must be 10 ms..2 s or `Duration.INFINITE` (RFC 8305 section 5; INFINITE starts HTTP/1.1 only after HTTP/3 failed, on every network), else the engine's creation fails with `IllegalArgumentException` |
| `networkId` | `() -> String?` | `{ null }` (one network) | 0.2.0 | identifies the current network; a change forgets broken marks, QUIC confirmation and HTTPS records; the engine caches HTTPS records only when it is set |
| `settings` | `Http3Settings` | `Http3Settings.Default` | 0.2.0 | HTTP/3 settings of the engine's connections |
| `endpoint` | `QuicEndpointConfig` | `QuicEndpointConfig.Default` | 0.2.0 | the client QUIC endpoint (bound to `0.0.0.0:0`, a dual-stack socket on the accelerated transport) |
| `earlyData` (*experimental*) | `Boolean` | `false` | 0.2.0 | 0-RTT for GET, HEAD and OPTIONS without a body on resumed connections |
| `qlog` (*experimental*) | `QlogSink?` | `null` (keeps `quic.qlog`) | 0.2.0 | a qlog trace per HTTP/3 connection |
| `connectionListener` (*experimental*) | `ConnectionListener?` | `null` (keeps `endpoint.listener`) | 0.2.0 | lifecycle of every QUIC connection |
| `webTransportIgnoresProxy` (*experimental*) | `Boolean` | `false` | 0.3.0 | `HttpClient.webTransport` connects directly although a proxy applies to the URL; otherwise such a call fails with `UnsupportedOperationException` ([WebTransport on the client](ktor.md#webtransport-on-the-client-experimental)) |
| `maxWebTransportSessions` (*experimental*) | `Int` | 64 | 0.3.0 | WebTransport sessions open at once, each on its own QUIC connection; at least 1; one more fails at once with `IllegalStateException` |
| `http3Allowed` (*experimental*) | `() -> Boolean` | `{ true }` | 0.3.0 | kill switch read once per `https://` request and `webTransport` call (not with `H1Only`): false sends a request over TCP, HTTP/2 included (`H3Only` requests and `webTransport` fail with `UnsupportedOperationException`); a switch that throws an exception allows HTTP/3 and is logged at most once per 5 minutes ([Turning HTTP/3 off remotely](ktor.md#turning-http3-off-remotely)) |
| `diagnosticsLogLevel` (*experimental*) | `LogLevel?` | `Info` | 0.3.0 | level of the engine logger's line for a call HTTP/3 could have served but did not; calls over HTTP/3 or never meant for it are logged at `Debug`; `null` writes none ([Why did this request not use HTTP/3?](ktor.md#why-did-this-request-not-use-http3)) |
| `connectionMigration` (*experimental*) | `Http3ConnectionMigration?` | `null` (connections stay on the network they were opened on) | 0.3.0 | pooled HTTP/3 connections follow the network (RFC 9000 section 9); `Http3ConnectionMigration.followDefaultNetwork(connectivity)` on Android, `followDefaultNetwork()` on iOS and macOS, your own `NetworkMigrator` elsewhere; events go to `connectionMigrated` ([Connection migration](ktor.md#connection-migration)) |

## Ktor server engine

`embeddedServer(Kuicksilver, configure = { … })` (`KuicksilverApplicationEngine.Configuration`). Guide:
[Ktor: Server](ktor.md#server).

| Option | Type | Default | Since | What it does |
|---|---|---|---|---|
| `tlsConnector(identity) { … }` |  |  | 0.2.0 | a TLS connector: HTTP/1.1 (and HTTP/2 with `http2`) over TLS on TCP and HTTP/3 on UDP on the same port ([Ktor: HTTP/3 on the server](ktor.md#http3-on-the-server)) |
| `identity` | `TlsIdentity?` | `null` | 0.2.0 | turns every plain connector (`port = …`, `connector { }`) into a TLS connector; a `TlsIdentity.Reloadable` can be replaced at run time ([Certificate rotation](ktor.md#certificate-rotation)) |
| `identityReloadInterval` (*experimental*) | `Duration?` | `null` | 0.3.0 | at least 1 s; how often the PEM files `EngineMain` read (the identity and `kuicksilver.tls.clientCa`) are checked for a renewed certificate or CA bundle (key `kuicksilver.tls.reloadInterval`); set without those files, the start fails ([Certificate rotation](ktor.md#certificate-rotation)) |
| `connectionIdleTimeoutSeconds` | `Int` | 45 | 0.2.0 | an HTTP/1.1 connection without requests for this long is closed (both directions), a response the client's socket takes nothing of ends the connection after the longer of this and 5 minutes (progress shows about 1 MiB at a time: about 3.4 KiB/s at least), and a closing connection that sends nothing for as long is aborted; a request body that sends no byte for this long gets 408 and the connection closes |
| `requestHeaderTimeoutSeconds` (*experimental*) | `Int` | 30 | 0.2.1 | positive; the time to send a complete HTTP/1.1 request head, from the accepted connection (TLS handshake included) or the end of the previous response; then `408 Request Timeout` and close when part of a head arrived, a close without a response when nothing did ([Server](ktor.md#server)) |
| `maxTcpConnections` (*experimental*) | `Int` | 10,000 | 0.3.0 | at least 1; TCP connections (HTTP/1.1 and HTTP/2, TLS handshakes included) each connector holds at once; at the limit it stops accepting and the OS backlog holds new clients; keep it below `ulimit -n` ([Connection limits](ktor.md#connection-limits)) |
| `maxTcpConnectionsPerIp` (*experimental*) | `Int?` | `null` (off) | 0.3.0 | at least 1, or `null`; TCP connections of one client address (its bytes; IPv6 whole, so a /64 holder gets around it; IPv4-mapped as IPv4) on a connector; one over it is reset at accept, before TLS (a proxy in front answers 502/503), and reported to `connectionRefused`; behind a proxy, load balancer, SNAT or NAT every client shares one address: enable it (e.g. 256) only when the server faces clients directly ([Connection limits](ktor.md#connection-limits)) |
| `http3` | `Boolean` | `true` | 0.2.0 | serve HTTP/3 on every TLS connector |
| `http2` (*experimental*) | `Boolean` | `false` | 0.3.0 | offer `h2` before `http/1.1` in the ALPN of every TLS connector and serve HTTP/2 to clients that pick it (TLS 1.3; no h2c on plain connectors) ([HTTP/2 on the server](ktor.md#http2-on-the-server)) |
| `http2Settings` (*experimental*) | `Http2Settings` | `Http2Settings()` | 0.3.0 | windows, SETTINGS and flood limits of every HTTP/2 connection; its `maxHeaderBlockTime` is bounded by `requestHeaderTimeoutSeconds` |
| `http2RepeatOffenderPenalty` (*experimental*) | `Duration` | `Duration.ZERO` (off) | 0.3.0 | not negative; an address whose HTTP/2 connections end in a flood limit three times within a minute has its TCP connections closed at accept for this long (IPv6 by its /56); only for a server that sees real client addresses, never behind a NAT or a source-rewriting load balancer ([HTTP/2 on the server](ktor.md#http2-on-the-server)) |
| `altSvc` | `Boolean` | `true` | 0.2.0 | add `Alt-Svc: h3=":<port>"; ma=86400` to HTTP/1.1 responses over TLS (not when the application set its own, not on 421); `engine.http3Advertising` changes it at run time ([Turning HTTP/3 off on the server](ktor.md#turning-http3-off-on-the-server)) |
| `quic` | `QuicConfig` | `QuicConfig.Default` | 0.2.0 | QUIC transport of the HTTP/3 listeners |
| `quicMaxIdleTimeout` | `Duration?` | `null` | 0.2.0 | `quic.maxIdleTimeout`, applied only while `quic` is not assigned (assigning any `QuicConfig`, `QuicConfig.Default` included, uses that config's own timeout) |
| `udpSocketCount` | `Int` | 1 | 0.2.0 | endpoint loops per UDP port (`QuicEndpointConfig.loops`; every platform since 0.3.0) |
| `quicMaxConnections` (*experimental*) | `Int` | 10,000 | 0.3.0 | at least 1; QUIC connections each HTTP/3 listener holds over all its `udpSocketCount` loops, handshakes included (`QuicEndpointConfig.maxConnections`); beyond it new Initials are dropped silently (`EndpointStats.connectionsRefusedLimits`) |
| `quicMaxConnectionsPerIp` (*experimental*) | `Int?` | 256 | 0.3.0 | at least 1, or `null` (off); QUIC connections of one client IP on each HTTP/3 listener over all its loops, ports ignored (`QuicEndpointConfig.maxConnectionsPerIp`); beyond it new Initials are dropped silently and the client times out. Behind a NAT, `kube-proxy` with `externalTrafficPolicy: Cluster` or a UDP load balancer that does not keep client addresses every client shares one address: raise it or turn it off ([QUIC connection limits](deployment.md#quic-connection-limits)) |
| `quicAcceptQueue` (*experimental*) | `Int` | 128 | 0.3.0 | at least 1; handshaken QUIC connections waiting for the HTTP/3 accept loop on each listener (`QuicEndpointConfig.acceptQueue`); while full, a new client is refused with CONNECTION_REFUSED (`EndpointStats.connectionsRefusedAcceptQueue`) |
| `quicAdmission` | `ConnectionAdmission?` | `null` (`ConnectionAdmission.default()`) | 0.2.0 | Retry policy |
| `quicLoadBalancer` (*experimental*) | `QuicLbConfig?` | `null` | 0.3.0 | QUIC-LB connection IDs of every HTTP/3 listener (`QuicEndpointConfig.loadBalancer`; its length must equal `quic.connectionIdLength`); `engine.updateLoadBalancer(next)` changes it on the running engine ([Behind a load balancer](quic.md#behind-a-load-balancer)) |
| `http3Settings` | `Http3Settings` | `Http3Settings.Default` | 0.2.0 | HTTP/3 settings |
| `webSocketsOverHttp3` | `Boolean` | `true` | 0.2.0 | accept RFC 9220 WebSockets (turns `enableConnectProtocol` on); with `false` a WebSocket CONNECT gets 501 |
| `webTransport` (*experimental*) | `Boolean` | `false` | 0.3.0 | serve WebTransport to `webTransport(path) { }` routes (turns `http3Settings.webTransport` and `enableConnectProtocol` on; needs QUIC datagrams) ([WebTransport](ktor.md#webtransport-over-http3-experimental)) |
| `quicEarlyData` (*experimental*) | `Boolean` | `false` | 0.2.0 | accept 0-RTT; requests are handled by `http3Settings.earlyData` |
| `logger` (*experimental*) | `KuicksilverLogger?` | `null` (the endpoint default, `KuicksilverLogger.Stderr`) | 0.2.0 | the HTTP/3 endpoints' diagnostics |
| `qlog` (*experimental*) | `QlogSink?` | `null` | 0.2.0 | added to `quic` |
| `connectionListener` (*experimental*) | `ConnectionListener?` | `null` | 0.2.0 | lifecycle of every QUIC connection |
| `eventListener` (*experimental*) | `KuicksilverServerEventListener?` | `null` | 0.2.0 | connection and request events over every protocol |
| `engine.http3Stats` (*experimental*, on the running engine) | `List<EndpointStats>` | empty before the start | 0.3.0 | the QUIC endpoint counters of every HTTP/3 listener, one per connector serving HTTP/3: datagrams, drops, refusals by admission, limits and the accept queue, handshakes ([Observability](deployment.md#observability)) |
| `engine.http3Advertising` (*experimental*, on the running engine) | `Http3Advertising` | `On` | 0.3.0 | `On`; `Clear` (`Alt-Svc: clear` on HTTP/1.1 and HTTP/3 responses, HTTP/3 still served); `Drain` (`clear`, GOAWAY to live HTTP/3 connections, new QUIC connections refused with CONNECTION_REFUSED); read per response and per new client ([Turning HTTP/3 off on the server](ktor.md#turning-http3-off-on-the-server)) |
| `shutdownGracePeriod`, `shutdownTimeout` (Ktor) |  | Ktor's | 0.2.0 | `stop` sends GOAWAY and shuts the HTTP/3 endpoints down with the grace period ([Graceful stop](ktor.md#graceful-stop)) |

The other `QuicEndpointConfig` limits of the HTTP/3 listener (`initialQueueCap`, `maxConnectionLifetime`, the stateless
rate limits, …) keep their defaults and are not configurable from the engine. Ktor's `connectionGroupSize`,
`workerGroupSize` and `callGroupSize` are not used (the engine runs on `Dispatchers.IO`).

### TLS connector

`tlsConnector(identity) { … }` (`KuicksilverTlsConnector.Builder`):

| Option | Type | Default | Range | Since | What it does |
|---|---|---|---|---|---|
| `identity` | `TlsIdentity` | the argument |  | 0.2.0 | certificate chain and key for TCP and QUIC |
| `host` | `String` | `"0.0.0.0"` |  | 0.2.0 | bind address for TCP and UDP |
| `port` | `Int` | 443 | 0..65 535 | 0.2.0 | TCP port and UDP port of HTTP/3; 0 picks a free pair (`resolvedConnectors()`) |
| `clientAuth` | `ClientAuth` | `None` |  | 0.2.0 | ask for or require client certificates |
| `trust` | `TrustConfig?` | `null` | `AnchoredCa` or `ReloadableCa` (optionally under `Pinned`) when `clientAuth` is not `None` | 0.2.0 | verifies client certificates; a `ReloadableCa` rotates for TCP and QUIC alike |
| `cipherSuites` | `CipherSuites` | `CipherSuites.Default` |  | 0.2.0 | TLS 1.3 suites |
| `sniSelector` | `(suspend (ClientHelloInfo) -> ServerTlsOverride?)?` | `null` |  | 0.2.0 | identity per SNI name over TCP; the connector then serves no HTTP/3 (warning) |
| `ocspStapling` (*experimental*) | `OcspStapling?` | `null` |  | 0.3.0 | the OCSP response stapled on TCP and QUIC ([Certificate revocation](tls.md#certificate-revocation)) |

`EngineMain` keys ([EngineMain and configuration keys](ktor.md#enginemain-and-configuration-keys)):
`kuicksilver.tls.certificateChain` and `kuicksilver.tls.privateKey` (PEM files, set together),
`kuicksilver.tls.clientAuth` (`none`, `optional` or `required`) and `kuicksilver.tls.clientCa` (the PEM file of the CAs
client certificates are verified against; set together),
`kuicksilver.tls.reloadInterval` (how often those files are checked for a renewed certificate or CA bundle; off by default),
`kuicksilver.http3`, `kuicksilver.http2`, `kuicksilver.http2RepeatOffenderPenalty`,
`kuicksilver.maxTcpConnections`, `kuicksilver.maxTcpConnectionsPerIp` (`0` or absent is off),
`kuicksilver.quicMaxConnections`, `kuicksilver.quicMaxConnectionsPerIp` (`0` is off), `kuicksilver.quicAcceptQueue`, `kuicksilver.altSvc`, `kuicksilver.webSocketsOverHttp3` (`true`/`false`), `kuicksilver.udpSocketCount`, and
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

Not configurable, listed so you can plan around them:

| Limit | Value |
|---|---|
| Client endpoint's RTT memory | the last smoothed RTT (1 ms..10 s) of connections that ended on the endpoint's own socket, per server address and port, at most 256 addresses (least recently stored dropped); replaces `initialRtt` for the next connection to that address |
| PMTUD | base 1200 bytes, 20-byte steps, 3 probes per size, a new search every 10 minutes, a 60 s pause after a black hole |
| Retry tokens | valid for 10 s |
| Glitch bucket | 1000 tokens, 33 back per second (QUIC and HTTP/3) |
| Connection ID rotation | every migration and every 10 000 1-RTT packets |
| Reassembly | 256 gaps per stream, 4096 per connection |
| qlog per connection | 64 MiB; after that the connection is not traced further |
| TCP client session cache | 384 sessions (six tickets for each of 64 origins) per Ktor client engine (one process-wide cache for `Socket.tls` and `TlsConnection.client`) |
| Alt-Svc | 8 alternatives per origin, 1000 origins; default `ma` 86 400 s; broken marks 5 min doubling up to 2 days |
| Ktor client race head start | 100 ms..2 s when derived from the RTT |
| Datagram slots of `QuicEndpoint` | 1500 bytes (hence the `maxUdpPayloadSize` ceiling) |
| Portable JVM socket buffers | 8 MiB send and receive |
