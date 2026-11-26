<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Configuration reference

**What this page is for.** It is the reference for every Kuicksilver option: where it is set, its type, default, the
release that introduced it, its stability and whether a wrong value weakens security. Use it to look up one option; the
guides explain how options work together.

**Before you start**

- Options belong to the modules `io.kuicksilver:kuicksilver-quic`, `-tls`, `-http3`, `-http2`, `-ktor-client` and
  `-ktor-server` (version `0.3.0` or newer; `io.kuicksilver:kuicksilver-bom` pins the modules to one version). A module
  brings along the modules it is built on, so you add the highest one you use.
- Built with Kotlin 2.4.20: JVM and Android need Kotlin 2.3 or newer, Kotlin/Native 2.4.x
  ([Kotlin version](../stability.md#kotlin-version)). The engine options need Ktor 3.6.x
  ([Ktor: Supported Ktor versions](ktor.md#supported-ktor-versions)).
- Coming from 0.2.x or a 0.3.0 snapshot: [Migrating from 0.2.x](#migrating-from-02x) maps every old name to its new place.

**How to use this page.** Start with the [first screen](#first-screen): the few options most applications set, all
stable. Every other option sits in a block, and the heading of its section is the block's path in the DSL
(`engine { http3 { stall { } } }`): [Ktor client](#ktor-client), [Ktor server](#ktor-server), the
[configuration-file keys](#hocon-keys) of `EngineMain`, and the [low-level](#low-level) builders that the engines' `quic { }`
and `settings { }` blocks also take. A minimal working setup is in [Ktor: Server](ktor.md#server) and
[Ktor: Client](ktor.md#client).

**The columns.** *Since* names the release that introduced the option under this name and in this block (`0.3.0`: the
release in preparation; an option that moved to a block in 0.3.0 is `0.3.0`). *Status* is the option's stability
([stability](../stability.md)): `experimental` needs `@OptIn(ExperimentalKuicksilverApi::class)`, `delicate`
`@OptIn(DelicateKuicksilverApi::class)` (an option that can only weaken a default). Experimental status goes by block: an
experimental block makes everything in it experimental, `expert { }` is always experimental, and an experimental option
inside a stable block is one whose type is experimental or a feature with an ADR of its own (each such exception is listed in
`tools/check/config-table.spec`). 🔒 marks an option whose wrong value weakens security, opens a denial of service or leaks
data (`@SecuritySensitive`, [threat model](../spec/threat-model.md)): read its description before you change it.

All configuration objects are immutable and validated when built: a builder's `build()` (or the DSL function around it),
the creation of the client engine or the start of the server throws `IllegalArgumentException` naming the first value out
of range by its block path, or `TlsException.Config` for a TLS setting. What an engine derives from other options
(ALPN, the connection ID length, the HTTP/3 stream minimum, Extended CONNECT...) cannot be set in its blocks: an
assignment fails with `... is derived by the engine (<why>); remove it`. Problems that only show at run time are in
[troubleshooting](troubleshooting.md). `tools/check/config-table.sh` checks every public option of the configuration
classes against these tables: defaults, releases, status and 🔒 included.

Contents: [first screen](#first-screen) · [where options are set](#where-each-option-is-set) · [Ktor client](#ktor-client) ·
[Ktor server](#ktor-server) · [HOCON keys](#hocon-keys) · [low level](#low-level) (QUIC, TLS, HTTP/3, HTTP/2) ·
[system properties and environment variables](#system-properties-and-environment-variables) · [fixed limits](#fixed-limits) ·
[migrating from 0.2.x](#migrating-from-02x)

## First screen

The options most applications set, one table per engine. All of them are stable: none needs an opt-in. Everything else
keeps a sound default.

### First screen: Ktor client

`HttpClient(Kuicksilver) { engine { … } }`; with no options at all the first request to a host goes over TCP (HTTP/2 or
HTTP/1.1) and HTTP/3 follows once the server announced it with `Alt-Svc`.

| Option | Type | Default | Status | What it is for |
|---|---|---|---|---|
| `engine { connectTimeout }` | `Duration` | 10 s | stable | the connect timeout (TCP + TLS, or the QUIC handshake) when `HttpTimeout` sets none |
| `engine { http3 { hints } }` | `Set<HostPort>` | empty | stable | your own API's origins: HTTP/3 from their first request |
| `engine { http3 { altSvcStore } }` | `AltSvcStore` | in memory | stable | `FileAltSvcStore(File(context.cacheDir, "alt-svc"))` remembers HTTP/3 across restarts |
| `engine { http3 { allowed } }` | `() -> Boolean` | `{ true }` | stable | a remote kill switch for HTTP/3 |
| `engine { http3 { enabled } }` | `Boolean` | `true` | stable | `false`: TCP only |
| `engine { http3 { discovery } }` | `Http3Discovery` | `Auto` | stable | `Preferred` tries HTTP/3 first for every origin, `H3Only` never uses TCP |
| `engine { tls { trust } }` | `TrustConfig` | `Platform` | stable | a private CA (`TrustConfig.AnchoredCa`) or certificate pins (`TrustConfig.Pinned`) |
| `engine { tls { identity } }` | `TlsIdentity?` | `null` | stable | a client certificate (mTLS) |
| `engine { http2 { enabled } }` | `Boolean` | `true` | stable | `false` for a server or middlebox whose HTTP/2 is broken |
| `engine { observability { logger } }` | `KuicksilverLogger` | `KuicksilverLogger.Default` (the platform's, warnings and up) | stable | `KuicksilverLogger.platform(LogLevel.Info)` while you debug "why not HTTP/3" |

On a phone, `http3 { migration = Http3ConnectionMigration.followDefaultNetwork(connectivity) }` keeps HTTP/3 connections
across a switch between Wi-Fi and the mobile network; it is experimental (its type is), so it is not on this screen.

### First screen: Ktor server

`embeddedServer(Kuicksilver, configure = { … })`; one `tlsConnector { }` serves HTTP/2 and HTTP/1.1 on TCP and HTTP/3 on
UDP on the same port.

| Option | Type | Default | Status | What it is for |
|---|---|---|---|---|
| `configure { tls { pemFiles(certificateChain, privateKey) } }` | function | | stable | the certificate chain and the unencrypted PKCS#8 key, from files (certbot) |
| `configure { tls { reloadInterval } }` | `Duration?` | `null` | stable | picks up a renewed certificate (`1.hours`) |
| `configure { tls { identity } }` | `TlsIdentity?` | `null` | stable | the certificate from code instead of files |
| `configure { tls { versions } }` | `TlsVersions` | `Tls13` | stable | `Tls12And13` for old clients without TLS 1.3 |
| `configure { tlsConnector { port } }` | `Int` | 443 | stable | TCP and UDP port; open both in the firewall |
| `configure { tlsConnector { host } }` | `String?` | `null` (every interface, IPv6 and IPv4: `::`, logged by Ktor as `https://:::443`) | stable | one address only |
| `configure { http2 { enabled } }` | `Boolean` | `true` | stable | `false` for a middlebox that breaks HTTP/2 |
| `configure { http3 { endpoint { maxConnectionsPerIp } } }` | `Int?` | 256 | stable | `null` behind a NAT or kube-proxy, where clients share one address |
| `configure { tcp { maxConnectionsPerIp } }` | `Int?` | `null` | stable | 256 for a server that faces its clients directly |
| `configure { observability { logger } }` | `KuicksilverLogger` | `ServerObservability.ApplicationLog` (Ktor's `environment.log`) | stable | the engine's diagnostics elsewhere |

Behind an L4 load balancer that sends the PROXY protocol: `tlsConnector { proxyProtocol { trust("10.0.0.0/8") } }`. The
same server from `application.conf`: [HOCON keys](#hocon-keys).

## Where each option is set

The DSL path of an option and its configuration-file key are the same (`http3 { endpoint { maxConnections } }` is
`kuicksilver.http3.endpoint.maxConnections`); the low-level builders are the same in both engines.

| Object | Kotlin API | Ktor client | Ktor server | `EngineMain` keys |
|---|---|---|---|---|
| [`QuicConfig`](#low-level) | `quicConfig { }` | `engine { http3 { quic { } } }` | `http3 { quic { } }` | `kuicksilver.http3.quic.*` (some options) |
| [`QuicEndpointConfig`](#low-level) | `quicEndpointConfig { }` | `http3 { expert { connectionIdLength; dispatcher } }`, `observability { }` | `http3 { endpoint { } }` (with `expert { connectionIdLength; … }`), `observability { }` | `kuicksilver.http3.endpoint.*` |
| [`TlsConfig`](#low-level) | `tlsConfig(role) { }` | `engine { tls { } }`, `proxies { tls { } }` | `tls { }`, `tlsConnector { tls { } }` | `kuicksilver.tls.*` |
| [`Http3Settings`](#low-level) | `http3Settings { }` | `engine { http3 { settings { } } }` | `http3 { settings { } }` | |
| [`Http2Settings`](#low-level) | `http2Settings { }` | `engine { http2 { settings { } } }` | `http2 { settings { } }` | |

## Ktor client

`HttpClient(Kuicksilver) { engine { … } }` (`KuicksilverEngineConfig`): `connectTimeout` at the top, everything else in
the blocks `tls { ech { } }`, `http3 { earlyData { } stall { } webTransport { } quic { } settings { } expert { } }`,
`http2 { settings { } }`, `http1 { }`, `pool { }`, `network { }`, `proxies { tls { } }`, `webSockets { }` and
`observability { }`. Values are checked when the engine is created. Guide: [Ktor: Client](ktor.md#client).

### `engine { }`

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `connectTimeout` | `Duration` | 10 s | 0.2.0 | stable | | connect timeout (TCP + TLS, or the QUIC handshake; the name resolution and the wait for a pool slot share it) when `HttpTimeout` sets none; a WebSocket over HTTP/1.1 also waits at most this long for the answer to its opening handshake (`ConnectTimeoutException`). It is also the QUIC and TLS handshake deadline, which the engine derives from it |
| `proxy` (Ktor) | `ProxyConfig?` | `null` | 0.2.0 | stable | | an explicit proxy: TCP through it (HTTP/1.1, or HTTP/2 inside the tunnel; CONNECT for `https` and WebSockets, absolute form for `http`; SOCKS5 CONNECT with the proxy resolving names); off the JVM an `https://` proxy URL is TLS to the proxy; HTTP/3 is never proxied. Other proxies come from `proxies { resolver }` |

`pipelining` and `threadsCount` (from Ktor's `HttpClientEngineConfig`) are not used.

### `engine { tls { } }`

`ClientTlsConfig`: the TLS of every connection, HTTP/3 and TCP alike (the fallback keeps the same trust and pins), and the
base of `proxies { tls { } }`. The engine derives ALPN (`h3`, or `h2` and `http/1.1`), the server name (the URL's host;
verify another name with `TrustConfig.ExpectedName`) and the handshake deadline (`connectTimeout`).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `trust` | `TrustConfig` | `TrustConfig.Platform` | 0.3.0 | stable | 🔒 | how the server is verified ([TrustConfig](#trustconfig)) |
| `identity` | `TlsIdentity?` | `null` | 0.3.0 | stable | 🔒 | the client certificate, sent when a server asks for one ([Ktor: Mutual TLS](ktor.md#mutual-tls-client-certificates)) |
| `versions` | `TlsVersions` | `TlsVersions.Tls13` | 0.3.0 | stable | 🔒 | the TLS versions offered over TCP; `Tls12And13` keeps HTTP/2 on over TLS 1.2 (a server's renegotiation request then ends the connection, RFC 9113 section 9.2.1); QUIC is TLS 1.3 only |
| `cipherSuites` | `CipherSuites` | `CipherSuites.Default` | 0.3.0 | stable | 🔒 | TLS 1.3 suites in preference order |
| `keyExchangeGroups` | `KeyExchangeGroups` | `KeyExchangeGroups.Default` | 0.3.0 | experimental | 🔒 | key-exchange groups and the key shares sent ([`tlsConfig(role) { }`](#tlsconfigrole--)) |
| `revocation` | `RevocationPolicy` | `RevocationPolicy.StapledIfPresent` | 0.3.0 | experimental | 🔒 | how the OCSP response the server staples is checked ([Certificate revocation](tls.md#certificate-revocation)) |
| `certificateCompression` | `Boolean` | `true` | 0.3.0 | stable | | TLS certificate compression (RFC 8879) |
| `keylog` | `KeylogSink?` | `null` | 0.3.0 | delicate | 🔒 | the handshake secrets as RFC 9850 key log lines; keep it null in production: anyone who reads the sink can decrypt the traffic ([Key logging](tls.md#key-logging)) |

### `engine { tls { ech { } } }`

`EchClientConfig`, *experimental* (guide: [Encrypted Client Hello](ktor.md#encrypted-client-hello-experimental)). A
connection offers the `ech` of the HTTPS record of its endpoint, else the `configLists` entry of its host, else GREASE ECH;
over TCP and QUIC alike, TLS 1.3 only.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `configLists` | `Map<String, EchConfigList>` | empty | 0.3.0 | experimental | | ECHConfigLists given out of band, by request host: every connection for that origin offers it (directly, to an `Alt-Svc` alternative, inside a proxy tunnel) unless an HTTPS record's endpoint brings its own; with a `tls { versions }` that allows TLS 1.2 the engine's creation fails (RFC 9849 section 6.1) |
| `grease` | `Boolean` | `true` | 0.3.0 | experimental | | GREASE ECH on every TLS connection that offers no configuration (RFC 9849 section 6.2.1) |
| `fromHttpsRecords` | `Boolean` | `true` | 0.3.0 | experimental | | offer the `ech` parameter of the origin's HTTPS records (RFC 9848), which `network { httpsRecords }` must look up: no ClientHello before the records resolved (section 5.3), and no fallback to a connection without them when every endpoint has `ech` (section 5.1, SVCB-reliant); ignored when TLS 1.2 is allowed |

### `engine { http3 { } }`

`Http3ClientConfig` (guide: [HTTP/3 on the client](ktor.md#http3-on-the-client)). Its `quic { }` block is a
[`quicConfig { }`](#low-level) for the HTTP/3 connections: the engine derives and refuses `handshakeTimeout`
(`connectTimeout`), `expert { resetStreamAt }` and `expert { cancelErrorCode }`; `maxBidiStreams` and
`expert { maxUniStreams }` (at least 3, RFC 9114 section 6.2) stay settable, and left alone default to 100 raised to fit
`webTransport { maxSessionsPerConnection }` sessions at the limits of `settings { webTransport { } }`
(`max(100, sessions x (initialMaxStreamsBidi + 1))`, `max(100, 3 + sessions x initialMaxStreamsUni)`). Its
`settings { }` block is an [`http3Settings { }`](#low-level): the engine derives and refuses `enableConnectProtocol`,
`h3Datagram`, `webTransport { enabled; maxSessions }` and `earlyData` (a server's policy); the per-session WebTransport
limits `webTransport { initialMaxStreamsBidi; initialMaxStreamsUni; initialMaxData }` are the client's to set there.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `enabled` | `Boolean` | `true` | 0.3.0 | stable | | `false`: every request goes over TCP (HTTP/2 or HTTP/1.1); with `discovery = H3Only` the engine's creation fails |
| `discovery` | `Http3Discovery` | `Http3Discovery.Auto` | 0.2.0 | stable | | `Auto` (TCP first, HTTP/3 after `Alt-Svc`), `Preferred` (HTTP/3 first, TCP fallback), `H3Only` (no TCP); proxied requests never use HTTP/3 |
| `hints` | `Set<HostPort>` | empty | 0.3.0 | stable | | origins known to speak HTTP/3 (Cronet's `addQuicHint`): HTTP/3 from their first request, as `Preferred`; `HostPort(host, port)` compares the host exactly as in URLs |
| `altSvcStore` | `AltSvcStore` | `InMemoryAltSvcStore()` | 0.2.0 | stable | | where alternatives live; `FileAltSvcStore(path)` keeps them across restarts (on the JVM and Android also `FileAltSvcStore(file)` with a `java.io.File`, from API 24) |
| `allowed` | `() -> Boolean` | `{ true }` | 0.3.0 | stable | | kill switch read once per `https://` request and `webTransport` call: false sends a request over TCP, HTTP/2 included (`H3Only` requests and `webTransport` fail with `UnsupportedOperationException`); a switch that throws allows HTTP/3 and is logged at most once per 5 minutes ([Turning HTTP/3 off remotely](ktor.md#turning-http3-off-remotely)) |
| `migration` | `Http3ConnectionMigration?` | `null` (connections stay on the network they were opened on) | 0.3.0 | experimental | | pooled HTTP/3 connections follow the network (RFC 9000 section 9): `Http3ConnectionMigration.followDefaultNetwork(connectivity)` on Android, `followDefaultNetwork()` on iOS and macOS; while `network { networkId }` is not set, its networks are the engine's network ([Connection migration](ktor.md#connection-migration)) |

### `engine { http3 { earlyData { } } }`

`ClientEarlyDataConfig`, *experimental* ([0-RTT](ktor.md#0-rtt-opt-in-experimental), ADR-0015).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `enabled` | `Boolean` | `false` | 0.3.0 | experimental | 🔒 | 0-RTT for GET, HEAD and OPTIONS without a body on resumed HTTP/3 connections; a 425 Too Early is retried once. Early requests can be replayed by an attacker: only for servers whose safe methods have no side effects |

### `engine { http3 { stall { } } }`

`StallConfig`, *experimental*: stall detection on the HTTP/3 connections the engine chose over TCP
([Stalled HTTP/3 connections](ktor.md#stalled-http3-connections)).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `enabled` | `Boolean` | `true` | 0.3.0 | experimental | | a path that stopped carrying packets drains the connection, marks the alternative broken and sends the request over TCP when it may be repeated (`fallback = QuicStalled`), else lets it wait `abandonAfter` for the path to come back and then fails it with `QuicStalledException`; a quiet watched connection sends PINGs (at most every half of the idle timeout in force), which keep it open past `maxIdleTimeout` while a response is outstanding (RFC 9114 section 5.1) and wake a mobile radio; `false` waits for the QUIC idle timeout and sends no PING |
| `probeTimeouts` | `Int` | 3 | 0.3.0 | experimental | | probe timeouts in a row without an acknowledgement (RFC 9002 section 6.2) before a connection may count as stalled; 1..10 |
| `minSilence` | `Duration` | 2 s | 0.3.0 | experimental | | the least time without any packet from the server, from the first unanswered probe timeout (before the handshake: without any answer at all, after two probe timeouts); 100 ms..60 s |
| `abandonAfter` | `Duration` | 10 s | 0.3.0 | experimental | | how long work that may not be repeated waits on a stalled connection for the path to come back (a handover, Wi-Fi roaming) before it fails with `QuicStalledException`; 100 ms..10 min |

### `engine { http3 { webTransport { } } }`

`ClientWebTransportConfig`, *experimental* ([WebTransport on the client](ktor.md#webtransport-on-the-client-experimental)).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `maxSessions` | `Int` | 64 | 0.3.0 | experimental | | WebTransport sessions open at once on the client, over all its connections (they share the pooled ones); at least 1; one more fails at once with `IllegalStateException` |
| `maxSessionsPerConnection` | `Int` | 4 | 0.3.0 | experimental | | sessions on one connection when flow control is on (draft-ietf-webtrans-http3-17 section 5.1), 1..65 535: the client opens another connection instead of putting more on one |
| `proxyPolicy` | `WebTransportProxyPolicy` | `WebTransportProxyPolicy.Refuse` | 0.3.0 | experimental | 🔒 | what a `webTransport` call does when a proxy applies to its URL: `Refuse` (fails with `UnsupportedOperationException`), `BypassHttpProxy` (connects directly past an HTTP or SOCKS proxy), `BypassConnectUdpProxy` (directly past a CONNECT-UDP proxy, exposing the client's address to the origin), `BypassAll` |

### `engine { http3 { expert { } } }`

`Http3ClientExpert`, *experimental*: the HTTP/3 options few applications change.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `raceHeadStart` | `RaceHeadStart` | `RaceHeadStart.Adaptive` | 0.3.0 | experimental | | head start of HTTP/3 over TCP in a race on a network where QUIC was confirmed (10 ms elsewhere): `Adaptive` (1.5 x the origin's smoothed RTT, 250 ms without history, 100 ms..2 s), `Fixed(delay)` (10 ms..2 s, RFC 8305 section 5), `NoRace` (TCP only after HTTP/3 failed, on every network) |
| `clearAltSvcOnNetworkChange` | `Boolean` | `true` | 0.3.0 | experimental | | drop alternatives without `persist=1` when the network changes (`network { networkId }`, else the networks `http3 { migration }` follows; with `networkId` also across restarts, RFC 7838 section 2.2); `false` keeps them |
| `connectionIdLength` | `Int` (bytes) | 8 | 0.3.0 | experimental | | length (4..20) of the connection IDs the engine's QUIC endpoints issue |
| `dispatcher` | `CoroutineDispatcher?` | `null` (a one-thread view of `Dispatchers.Default` per endpoint) | 0.3.0 | experimental | | the single-threaded dispatcher of the engine's QUIC endpoint loops |

### `engine { http2 { } }`

`Http2ClientConfig` (guide: [HTTP/2 on the client](ktor.md#http2-on-the-client)). Its `settings { }` block
(*experimental*) is an [`http2Settings { }`](#low-level): our windows, SETTINGS and the limits held against the server
(its `maxConcurrentStreams` is what the server may open towards us, which a client never uses).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `enabled` | `Boolean` | `true` | 0.3.0 | stable | | offer `h2` and `http/1.1` in ALPN on every `https://` connection over TCP; `false` offers only `http/1.1`, as in 0.2 |
| `pingInterval` | `Duration?` | `null` (no PINGs) | 0.3.0 | stable | | a PING this often on every HTTP/2 connection; one still unanswered at the next ends the connection and fails its calls; at least 100 ms |
| `priorKnowledge` | `Set<HostPort>` | empty | 0.3.0 | experimental | 🔒 | the `http://` origins whose requests go over h2c, HTTP/2 over cleartext TCP with prior knowledge (RFC 9113 section 3.3): the preface at once, no fallback to HTTP/1.1, never for `https://`; cleartext, so only servers on a trusted network ([h2c on the client](ktor.md#h2c-on-the-client)) |

### `engine { http1 { } }`

`Http1ClientConfig`, *experimental*.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `knownServers` | `KnownServers` | `KnownServers.None` | 0.3.0 | experimental | | servers known to handle HTTP/1.1 (RFC 9112 section 6.1 user configuration): a chunked request body goes to them at once, without the first-contact `OPTIONS` probe; `All`, or `Listed(setOf(HostPort(...)))` (the origin, or for plain `http` through an HTTP proxy the proxy) |

### `engine { pool { } }`

`PoolConfig` (guide: [Connection pool](ktor.md#connection-pool)).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `maxConnections` | `Int` | 1000 | 0.3.0 | stable | | TCP connections (HTTP/1.1 and HTTP/2) of the engine, idle ones included; requests beyond it wait (FIFO, within the connect timeout), and the oldest idle connection of another route is closed to make room |
| `maxConnectionsPerRoute` | `Int` | 100 | 0.3.0 | stable | | TCP connections to one route (scheme, host, port, proxy); an HTTP/2 connection counts once however many requests it carries |
| `maxIdleConnectionsPerRoute` | `Int` | 4 | 0.3.0 | stable | | idle HTTP/1.1 keep-alive connections kept per route; not a connection limit; 0 keeps none |
| `idleTimeout` | `Duration` | 5 min | 0.3.0 | stable | | idle HTTP/1.1 connections, and HTTP/2 and HTTP/3 connections without requests, are closed after this; for HTTP/3 the effective value is the smaller of this and `http3 { quic { maxIdleTimeout } }` (30 s) unless `quic { keepAlive }` is set |
| `maxConnectionLifetime` | `Duration?` | `null` (no limit) | 0.3.0 | stable | | age after which a connection takes no new requests; a finite value spreads load after DNS or load-balancer changes |
| `coalescing` | `Boolean` | `false` | 0.3.0 | experimental | 🔒 | an `https` request may go on another origin's HTTP/2 or HTTP/3 connection whose certificate passes every check for its host and whose address and port its host resolves to (RFC 9113 section 9.1.1, RFC 9114 section 3.3; ADR-0018); a 421 sends it once more on a connection of its own; never through a proxy, for a WebSocket, over h2c, under `Tofu` or under `ExpectedName` ([Connection coalescing](ktor.md#connection-coalescing-experimental)) |

### `engine { network { } }`

`ClientNetworkConfig`: name resolution and connection racing.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `dns` | `Dns` | `Dns.System` | 0.3.0 | experimental | 🔒 | resolves host names (the origin's, an alternative's, an HTTPS record target's, a proxy's; never an IP literal, never the origin's behind an HTTP or `socks5h` proxy); the answer is sorted by RFC 6724 and raced with Happy Eyeballs; bounded by the connect timeout; SNI and certificate checks use the host name, never the answer ([Name resolution](ktor.md#name-resolution-experimental)) |
| `httpsRecords` | `HttpsRecordSource` | `HttpsRecordSource.Off` | 0.3.0 | experimental | | HTTPS resource records (RFC 9460) as a source of HTTP/3 and of ECH in `Auto`: `System` (the OS resolver) or `Exchange { query -> response }` (your DNS-over-HTTPS client); an `http://` request to an origin with usable records gets a `307` to its `https` URL ([HTTPS records](ktor.md#https-records-experimental)) |
| `httpsRecordWait` | `Duration` | 50 ms | 0.3.0 | experimental | | how long a request waits for the HTTPS records after the origin's addresses resolved; 50 ms (RFC 9460 section 5.1) to 1 s |
| `happyEyeballsDelay` | `Duration?` | 250 ms | 0.3.0 | stable | | Happy Eyeballs (RFC 8305) for the TCP and QUIC connects: the delay before the next address is tried while earlier attempts are pending; 100 ms..2 s, or `null` to try one address after another ([Happy Eyeballs](ktor.md#happy-eyeballs)) |
| `networkId` | `(() -> String?)?` | `null` (not set) | 0.3.0 | stable | | identifies the current network; a change forgets broken marks, QUIC confirmation, HTTPS records and alternatives without `persist=1`; while it is not set, the networks `http3 { migration }` follows take its place, and without either the engine sees no network change |

### `engine { proxies { } }`

`ProxiesConfig`, *experimental*; Ktor's `proxy` on the engine configuration names an explicit proxy, which always wins
(guide: [Proxies](ktor.md#proxies)).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `resolver` | `ProxyResolver` | `ProxyResolvers.System` | 0.3.0 | experimental | 🔒 | the proxy for requests `proxy` does not cover, per scheme, host and port (kept 30 s): `System` (the platform's settings), `Environment` (`https_proxy`, `no_proxy`...), `None` or your own; each lookup is bounded by `connectTimeout`; loopback is always direct with the built-ins |
| `credentials` | `ProxyCredentials?` | `null` | 0.3.0 | experimental | 🔒 | for the explicit `proxy` only (a resolver's proxy carries its own): SOCKS5 username/password (RFC 1929) or `Proxy-Authorization: Basic` on an HTTP proxy's CONNECT and absolute-form requests; in clear to an `http://` or SOCKS5 proxy, only inside TLS to an `https://` one |
| `tls { }` | `ClientTlsConfig` block | the engine's `tls { }` trust without what names the origin, no identity | 0.3.0 | experimental | 🔒 | the TLS of connections to an `https://` proxy and to a `connectUdp` proxy; the server name is the proxy's host and ALPN `http/1.1` (`h3` to a CONNECT-UDP proxy); an `ech { configLists }` entry for the proxy's host is offered to it |
| `connectUdp` | `ConnectUdpProxy?` | `null` | 0.3.0 | experimental | 🔒 | a CONNECT-UDP proxy (RFC 9298, MASQUE) for HTTP/3: the `https` requests it applies to go over HTTP/3 inside a UDP tunnel through it, never over TCP or directly ([HTTP/3 through a CONNECT-UDP proxy](ktor.md#http3-through-a-connect-udp-proxy-experimental)) |
| `pacFullWebSocketUrl` | `Boolean` | `false` | 0.3.0 | experimental, delicate | 🔒 | with `ProxyResolvers.System` on Apple platforms and Windows: the PAC script the system settings name gets a `wss://` URI whole, path and query included (RFC 6455 section 4.1); off, every script gets `wss://host[:port]/` only, as browsers give it (CVE-2016-3763, CVE-2016-5134) |

### `engine { webSockets { } }`

`ClientWebSocketsConfig`.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `maxMessageSize` | `Long` (bytes) | 16 777 216 (16 MiB) | 0.3.0 | stable | 🔒 | the largest WebSocket frame, and message once reassembled, the client takes (RFC 6455 section 10.4), over HTTP/1.1, HTTP/2 and HTTP/3; a frame whose header claims more, or that takes its message past it, closes the connection with 1009 before its payload is read; a compressed message is held to the smaller of this and `PerMessageDeflate`'s `maxInflatedMessageSize`, counted as it inflates; at least 1 |

### `engine { observability { } }`

`ClientObservability` (guide: [Ktor: Observability](ktor.md#observability-experimental)).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `logger` | `KuicksilverLogger` | `KuicksilverLogger.Default` | 0.3.0 | stable | | the engine's and its QUIC endpoints' diagnostics; `Default` is the platform's logger at warnings and up (SLF4J on the JVM, Logcat on Android, `NSLog` on Apple platforms, standard error elsewhere); `KuicksilverLogger.platform(LogLevel.Info)`, `KuicksilverLogger.Stderr`, `None` or your own |
| `protocolChoiceLogLevel` | `LogLevel?` | `LogLevel.Info` | 0.3.0 | stable | | level of the logger's line for a call HTTP/3 could have served but did not, which the default logger (warnings and up) leaves out; calls over HTTP/3 or never meant for it are logged at `Debug`; `null` writes none ([Why did this request not use HTTP/3?](ktor.md#why-did-this-request-not-use-http3)). The first alternative marked broken on a network is one warning line whatever this says |
| `qlog` | `QlogSink?` | `null` | 0.3.0 | stable | | a qlog trace per HTTP/3 connection; wrap a file sink in `AsyncQlogSink` |
| `eventListener` | `KuicksilverEventListener?` | `null` | 0.3.0 | experimental | | call, protocol, race, Alt-Svc, DNS and pool events |
| `connectionListener` | `ConnectionListener?` | `null` | 0.3.0 | experimental | | lifecycle of every QUIC connection of the engine |

## Ktor server

`embeddedServer(Kuicksilver, configure = { … })` (`KuicksilverApplicationEngine.Configuration`): `requestHeaderTimeout`
at the top, everything else in the blocks `tls { }`, `tlsConnector { tls { } proxyProtocol { } }`,
`plainConnector { proxyProtocol { } }`, `http1 { }`, `http2 { settings { } }`,
`http3 { earlyData { } webTransport { } quic { } settings { } endpoint { expert { } } }`, `webSockets { }`, `tcp { }`
and `observability { }`. Values are checked when the server starts. Guide: [Ktor: Server](ktor.md#server).

### `configure { }`

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `requestHeaderTimeout` | `Duration` | 30 s | 0.3.0 | stable | 🔒 | the time a client has to send a complete request head on every protocol: over HTTP/1.1 from the accepted connection (TLS handshake included) or the end of the previous response, then `408 Request Timeout` and close when part of a head arrived, a close without a response when nothing did; it also bounds `maxHeaderBlockTime` of `http2 { settings { } }` and `http3 { settings { } }` and the PROXY protocol header's wait (a connector with `proxyProtocol { }` needs at least 3 s) |
| `shutdownGracePeriod`, `shutdownTimeout` (Ktor) | | Ktor's | 0.2.0 | stable | | `stop` sends GOAWAY and shuts the HTTP/3 endpoints down with the grace period ([Graceful stop](ktor.md#graceful-stop)) |

Ktor's `connectionGroupSize`, `workerGroupSize` and `callGroupSize` are not used (the engine runs on `Dispatchers.IO`). Ktor's
own connectors (`port = …`, `connector { }`) serve TLS once `tls { }` has an identity, and bind as Ktor says (`0.0.0.0`
by default). The deployment port of `EngineMain` without `ktor.deployment.host` (or `-host`) binds every interface as a
`tlsConnector { }` without a `host` does ([HOCON keys](#hocon-keys)). A connector bound to `::` is reported with that
host, so Ktor logs `Responding at https://:::443` for `[::]:443`; `resolvedConnectors()` keeps the bare `::`, which
socket APIs take back.

On the running engine (*experimental*):

| API | Default | What it does |
|---|---|---|
| `engine.http3Advertising` | `On` | `On`; `Clear` (`Alt-Svc: clear` on HTTP/1.1, HTTP/2 and HTTP/3 responses and in HTTP/2 ALTSVC frames, HTTP/3 still served); `Drain` (`clear`, GOAWAY to live HTTP/3 connections, new QUIC connections refused); read per response and per new client ([Turning HTTP/3 off on the server](ktor.md#turning-http3-off-on-the-server)) |
| `engine.http3Stats` | empty before the start | the QUIC endpoint counters of every HTTP/3 listener: datagrams, drops, refusals by admission, limits and the accept queue, handshakes ([Observability](deployment.md#observability)) |
| `engine.updateLoadBalancer(next)` | | changes `http3 { endpoint { loadBalancer } }` on the running engine |

### `configure { tls { } }`

`ServerTlsConfig`: the TLS of every TLS connector and of Ktor's own connectors; HTTP/3 on the UDP twin of a port shares it
(QUIC is TLS 1.3 only). A connector's own `tlsConnector { tls { } }` block overrides any of it for that connector: what it
does not set is the engine's, and an identity or a trust set there replaces the engine's, whichever way either was given.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `identity` | `TlsIdentity?` | `null` | 0.3.0 | stable | 🔒 | the certificate chain and key, for TCP and QUIC; a `TlsIdentity.Reloadable` can be replaced at run time ([Certificate rotation](ktor.md#certificate-rotation)); setting it in a block that called `pemFiles` fails |
| `pemFiles(certificateChain, privateKey)` | function | | 0.3.0 | stable | 🔒 | reads the chain (PEM, leaf first) and the unencrypted PKCS#8 key (`-----BEGIN PRIVATE KEY-----`) now, as `identity`; with `reloadInterval` the engine watches both files; a file larger than 1 MiB, a damaged one, an encrypted key or a key that does not match the chain is refused |
| `reloadInterval` | `Duration?` | `null` (read once) | 0.3.0 | stable | | how often the files of `pemFiles`, `clientCaFile` and `ocspStaplingFile` are checked; a new chain is applied once two reads a second apart agree and the key matches it, a failure keeps what is in use and is retried; needs `pemFiles` (the start fails without); at least 1 s |
| `clientAuth` | `ClientAuth` | `ClientAuth.None` | 0.3.0 | stable | 🔒 | ask for (`Optional`) or require (`Required`) client certificates; other than `None` it needs `clientTrust` or `clientCaFile` ([Ktor: Mutual TLS](ktor.md#mutual-tls-client-certificates)) |
| `clientTrust` | `TrustConfig?` | `null` | 0.3.0 | stable | 🔒 | verifies client certificates: `AnchoredCa` or `ReloadableCa` (rotated for TCP and QUIC alike), optionally under `Pinned` |
| `clientCaFile(path)` | function | | 0.3.0 | stable | 🔒 | reads the CA certificates client certificates are verified against from a PEM file now, as `clientTrust`; watched with `reloadInterval`; a file that holds a private key is refused |
| `versions` | `TlsVersions` | `TlsVersions.Tls13` | 0.3.0 | stable | 🔒 | `Tls12And13` serves TLS 1.2 clients over TCP too, under the RFC 9325 profile (ECDHE and AEAD only, Extended Master Secret, no renegotiation); HTTP/3 stays TLS 1.3 ([TLS 1.2 on the server](ktor.md#tls-12-on-the-server)) |
| `cipherSuites` | `CipherSuites` | `CipherSuites.Default` | 0.3.0 | stable | 🔒 | TLS 1.3 suites in preference order |
| `sniSelector` | `(suspend (ClientHelloInfo) -> ServerTlsOverride?)?` | `null` | 0.3.0 | stable | | identity per SNI name over TCP and HTTP/3: an answer's `alpn` without `h3` keeps that name off HTTP/3 and out of `Alt-Svc`, one of `h3` alone keeps it off TCP ([Certificate per name](ktor.md#certificate-per-name-sni)) |
| `sessionTickets` | `SessionTicketConfig` | `SessionTicketConfig.Default` | 0.3.0 | stable | 🔒 | session ticket keys and lifetimes of TLS resumption on TCP and of the QUIC side's tickets ([`SessionTicketConfig(…)`](#low-level)) |
| `keyExchangeGroups` | `KeyExchangeGroups` | `KeyExchangeGroups.Default` | 0.3.0 | experimental | 🔒 | the server's key-exchange groups for TCP and HTTP/3, in its order of preference; no key shares; with `Tls12And13` at least one elliptic curve, and a TLS 1.2 client's P-256 certificate needs `secp256r1` ([Key exchange groups](tls.md#key-exchange-groups)) |
| `ocspStapling` | `OcspStapling?` | `null` | 0.3.0 | experimental | | the OCSP response stapled on TCP and QUIC; `update` replaces it at run time ([Certificate revocation](tls.md#certificate-revocation)) |
| `ocspStaplingFile(path)` | function | | 0.3.0 | experimental | | reads a DER `OCSPResponse` (at most 1 MiB) now, as `ocspStapling`; re-read every `reloadInterval`, or hourly without one; whether it is stapled is logged |
| `echKeys` | `EchServerKeys?` | `null` | 0.3.0 | experimental | 🔒 | Encrypted Client Hello keys (RFC 9849, shared mode) of TCP and HTTP/3; `rotate` replaces them for new handshakes; the identity must cover the keys' `public_name` ([Encrypted Client Hello on the server](ktor.md#encrypted-client-hello-on-the-server)) |
| `keylog` | `KeylogSink?` | `null` | 0.3.0 | delicate | 🔒 | the handshake secrets of TCP and QUIC connections as RFC 9850 key log lines; keep it null in production |

### `configure { tlsConnector { } }`

`KuicksilverTlsConnector.Builder`: a TLS connector, HTTP/2 and HTTP/1.1 over TLS on TCP and HTTP/3 on UDP on the same port
([Ktor: HTTP/3 on the server](ktor.md#http3-on-the-server)). It needs an identity, from the engine's `tls { }` or its own.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `host` | `String?` | `null` (every interface, IPv6 and IPv4) | 0.2.0 | stable | | the address to bind, for TCP and UDP alike; `null` binds `::` with one dual-stack socket per protocol (an IPv4 client arrives as an IPv4-mapped address, and `call.request.local` reports it as the IPv4 address it is), or `0.0.0.0` where the host has no IPv6 (logged at Info); `"0.0.0.0"` keeps IPv4 alone (0.2: `"0.0.0.0"` by default) |
| `port` | `Int` | 443 | 0.2.0 | stable | | TCP port and UDP port of HTTP/3, 0..65 535; 0 picks a free pair (`resolvedConnectors()`) |
| `proxyProtocol { }` | block | none | 0.3.0 | stable | 🔒 | the PROXY protocol on the TCP side ([below](#configure--tlsconnector--proxyprotocol----)) |
| `allowMisdirectedHosts` | `Boolean` | `false` | 0.3.0 | delicate | 🔒 | `true` turns off the `421 Misdirected Request` for hosts the connection's certificate does not name (RFC 9110 section 7.4), on HTTP/1.1, HTTP/2 and HTTP/3: only for connectors whose every client is a trusted gateway ([Misdirected requests](ktor.md#misdirected-requests)) |

`tls { }` on the connector takes the [`configure { tls { } }`](#ktor-server) options for this connector only.

### `configure { plainConnector { } }`

`KuicksilverPlainConnector.Builder`: Ktor's `connector { }` with the options below.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `host` | `String?` | `null` (every interface, IPv6 and IPv4) | 0.3.0 | stable | | the address to bind; `null` binds `::` dual-stack, or `0.0.0.0` where the host has no IPv6 |
| `port` | `Int` | 80 | 0.3.0 | stable | | TCP port, 0..65 535; 0 picks a free one |
| `allowMisdirectedHosts` | `Boolean` | `false` | 0.3.0 | delicate | 🔒 | `true` serves absolute-form `https://` targets, which a plain connection otherwise answers `421 Misdirected Request` (RFC 9110 section 7.4); only for connectors whose every client is a trusted gateway |
| `h2c` | `H2cMode` | `H2cMode.Off` | 0.3.0 | experimental | 🔒 | HTTP/2 over cleartext TCP with prior knowledge (RFC 9113 section 3.3, ADR-0018): `WithHttp11` serves HTTP/1.1 and h2c, told apart by the client preface; `Only` serves h2c alone; `Upgrade: h2c` is never taken; cleartext, so only behind a trusted network or proxy; a connector the engine's `tls { }` identity makes TLS refuses it at start ([h2c on the server](ktor.md#h2c-on-the-server)) |
| `proxyProtocol { }` | block | none | 0.3.0 | stable | 🔒 | the PROXY protocol on this connector ([below](#configure--tlsconnector--proxyprotocol----)) |

### `configure { tlsConnector { proxyProtocol { } } }`

`ProxyProtocolConfig.Builder`, on either connector (`plainConnector { proxyProtocol { } }` too): every TCP connection must
start with a PROXY protocol header (v1 or v2) from one of the trusted sources, before the ClientHello; its client becomes
`call.request.origin`, and `tcp { maxConnectionsPerIp }` then counts the proxy. HTTP/3 takes none
([PROXY protocol](ktor.md#proxy-protocol)).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `trust(vararg sources)` | function | | 0.3.0 | stable | | adds the TCP peers allowed to send the header: IPv4 or IPv6 addresses or CIDR blocks (`10.0.0.0/8`, `2001:db8::/32`) without bits past the prefix or zone IDs; at least one; any other peer is closed at accept. IPv4 peers match IPv4 blocks only, also when reported as IPv4-mapped IPv6 |
| `headerTimeout` | `Duration` | 5 s | 0.3.0 | stable | | the whole header must arrive within it, counted from accept; at least 3 s ("to cover a TCP retransmit"), and cut to what is left of `requestHeaderTimeout` |
| `maxHeaderSize` | `Int` (bytes) | 4096 | 0.3.0 | stable | | the longest version 2 header taken, 232..65 551 (its length field is checked before the rest is read); version 1 is at most 107 bytes |

### `configure { http1 { } }`

`Http1ServerConfig`.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `allowBareLf` | `Boolean` | `false` | 0.3.0 | delicate | 🔒 | let a bare LF (no CR before it) end a line of an HTTP/1.1 request head or trailer section (RFC 9112 section 2.2 MAY); by default such a request gets 400 and the connection closes, since a proxy in front that reads the LF as part of a line would frame the request otherwise (section 11.2) |

### `configure { http2 { } }`

`Http2ServerConfig` (guide: [HTTP/2 on the server](ktor.md#http2-on-the-server)). Its `settings { }` block
(*experimental*) is an [`http2Settings { }`](#low-level) for every HTTP/2 connection, `maxHeaderBlockTime` bounded by
`requestHeaderTimeout`.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `enabled` | `Boolean` | `true` | 0.3.0 | stable | | serve HTTP/2 on the TLS connectors: ALPN offers `h2`, then `http/1.1`, so a client that offers both gets HTTP/2 (TLS 1.3, and TLS 1.2 with `tls { versions = Tls12And13 }`); `false` keeps HTTP/1.1 alone, as in 0.2. Plain connectors serve h2c only with their own `h2c` |
| `repeatOffenderPenalty` | `Duration?` | `null` (off) | 0.3.0 | experimental | 🔒 | an address whose HTTP/2 connections end in a flood limit three times within a minute has its TCP connections closed at accept for this long (IPv6 by its /56); only for a server that sees real client addresses, never behind a NAT or a source-rewriting load balancer |

### `configure { http3 { } }`

`Http3ServerConfig` (guide: [HTTP/3 on the server](ktor.md#http3-on-the-server)): HTTP/3 on the UDP twin of every TLS
connector's port. Its `quic { }` block is a [`quicConfig { }`](#low-level): the engine derives and refuses
`expert { resetStreamAt }` (on with WebTransport) and `expert { cancelErrorCode }`; `maxBidiStreams` and
`expert { maxUniStreams }` (at least 3, RFC 9114 section 6.2) stay settable, and left alone default to 100 raised to fit
the `webTransport { }` sessions (`max(100, maxSessionsPerConnection x (initialMaxStreamsBidi + 1))`,
`max(100, 3 + maxSessionsPerConnection x initialMaxStreamsUni)`); an explicit value they do not fit in fails the start. Its
`settings { }` block is an [`http3Settings { }`](#low-level), `maxHeaderBlockTime` bounded by `requestHeaderTimeout`: the
engine derives and refuses `enableConnectProtocol` (from `webSockets { overHttp3 }`, `webTransport { enabled }` and
`connectUdp`), `h3Datagram`, `webTransport { }` and `earlyData`. The start logs at Info that an advertised HTTP/3 needs its
UDP port open.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `enabled` | `Boolean` | `true` | 0.3.0 | stable | | serve HTTP/3 on every TLS connector |
| `altSvc` | `Boolean` | `true` | 0.3.0 | stable | | add `Alt-Svc: h3=":<port>"; ma=86400` to HTTP/1.1 and HTTP/2 responses over TLS, and on HTTP/2 also send it as an ALTSVC frame per origin, refreshed every 12 hours (RFC 7838 sections 3, 4; not when the application set its own, not on 421); `engine.http3Advertising` changes it at run time |
| `connectUdp` | `Boolean` | `false` | 0.3.0 | experimental | 🔒 | take CONNECT-UDP requests (RFC 9298, ADR-0024) into the pipeline for `connectUdp(proxy)` routes; without it they are answered 501 ([CONNECT-UDP over HTTP/3](ktor.md#connect-udp-over-http3-experimental)) |

### `configure { http3 { earlyData { } } }`

`ServerEarlyDataConfig`, *experimental* ([0-RTT](ktor.md#0-rtt-opt-in-experimental), ADR-0015).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `enabled` | `Boolean` | `false` | 0.3.0 | experimental | 🔒 | accept 0-RTT on HTTP/3: only the requests `policy` declares replayable run before the handshake completes; not with client certificates |
| `policy` | `Http3EarlyDataPolicy` | `WaitForHandshake()` | 0.3.0 | experimental | 🔒 | `WaitForHandshake(replayable)` (the others wait for the handshake) or `Reject425(replayable)`; `replayable` admits GET, HEAD and OPTIONS by default |

### `configure { http3 { webTransport { } } }`

`ServerWebTransportConfig`, *experimental* ([WebTransport](ktor.md#webtransport-over-http3-experimental)): WebTransport over
HTTP/3 (draft-ietf-webtrans-http3-17) to `webTransport(path) { }` routes. It turns on Extended CONNECT, H3_DATAGRAM and
RESET_STREAM_AT and needs QUIC datagrams.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `enabled` | `Boolean` | `false` | 0.3.0 | experimental | | serve WebTransport |
| `maxSessionsPerConnection` | `Int` | 4 | 0.3.0 | experimental | | sessions a client may open on one connection (`SETTINGS_WT_MAX_SESSIONS`); one more is refused with `H3_REQUEST_REJECTED` |
| `initialMaxStreamsBidi` | `Long` | 24 | 0.3.0 | experimental | | bidirectional streams a client may open in one session at first (`SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI`) |
| `initialMaxStreamsUni` | `Long` | 24 | 0.3.0 | experimental | | unidirectional streams a client may open in one session at first |
| `initialMaxData` | `Long` (bytes) | 3 932 160 | 0.3.0 | experimental | | bytes a client may send in one session at first, over all its streams (`SETTINGS_WT_INITIAL_MAX_DATA`) |

### `configure { http3 { endpoint { } } }`

`ServerEndpointConfig`: the QUIC endpoint of each HTTP/3 listener (one per TLS connector). Its `expert { }` block
(*experimental*, below) holds the connection ID length and the endpoint's admission internals.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `loops` | `Int` | 1 | 0.3.0 | stable | | endpoint loops on the UDP port: a socket each with `SO_REUSEPORT` on Linux and Android, one socket routed in process elsewhere ([Several loops on one port](quic.md#several-loops-on-one-port)) |
| `maxConnections` | `Int` | 10 000 | 0.3.0 | stable | 🔒 | QUIC connections each listener holds over all its loops, handshakes included; beyond it new Initials are dropped silently (`EndpointStats.connectionsRefusedLimits`) |
| `maxConnectionsPerIp` | `Int?` | 256 | 0.3.0 | stable | 🔒 | QUIC connections of one client IP on each listener over all its loops, ports ignored; `null` turns the limit off. Beyond it new Initials are dropped silently and the client times out; the first refusal logs one warning, then at most one every 5 minutes. Behind a NAT, kube-proxy with `externalTrafficPolicy: Cluster` or a UDP load balancer that does not keep client addresses every client shares one address: raise it or set `null` ([QUIC connection limits](deployment.md#quic-connection-limits)). On by default, unlike `tcp { maxConnectionsPerIp }`: QUIC Initials come from unvalidated addresses and cost more state, and a proxy in front of QUIC is rare |
| `acceptQueue` | `Int` | 128 | 0.3.0 | stable | | handshaken QUIC connections waiting for the HTTP/3 accept loop on each listener; while full, a new client is refused with CONNECTION_REFUSED (`EndpointStats.connectionsRefusedAcceptQueue`) |
| `admission` | `ConnectionAdmission` | `ConnectionAdmission.default()` | 0.3.0 | stable | 🔒 | admission of new QUIC connections: the default asks for a Retry above 256 handshakes in flight or 8 MiB of their buffers; `ConnectionAdmission.AlwaysRetry` validates every address first |
| `maxConnectionLifetime` | `Duration?` | `null` (no limit) | 0.3.0 | stable | | a server connection older than this closes with NO_ERROR, whatever its activity |
| `loadBalancer` | `QuicLbConfig?` | `null` | 0.3.0 | experimental | | QUIC-LB connection IDs of every listener (draft-ietf-quic-load-balancers-21); `engine.updateLoadBalancer(next)` changes it on the running engine ([Behind a load balancer](quic.md#behind-a-load-balancer)) |

### `configure { http3 { endpoint { expert { } } } }`

`ServerEndpointExpert`, *experimental*: the connection ID length of the listeners, and the admission internals of
[`quicEndpointConfig { expert { } }`](#low-level), which these options set.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `connectionIdLength` | `Int` (bytes) | 8 | 0.3.0 | experimental | | length (4..20) of the connection IDs the listeners issue; with `loadBalancer` the QUIC-LB configuration's, and setting it fails the start (`... is derived by the engine`) |
| `initialAdmissionQueue` | `Int` | 1024 | 0.3.0 | experimental | | new Initials queued for admission per receive batch, at least 1; more are dropped |
| `rejectInitialFromReflectivePorts` | `Boolean` | `true` | 0.3.0 | experimental, delicate | 🔒 | drop Initials from source ports 53, 123, 1900, 5353 and 11211 (reflection attacks) |
| `statelessPerAddressPerSecond` | `Int` | 8 | 0.3.0 | experimental | 🔒 | stateless answers (Retry, Version Negotiation, Stateless Reset, refusals) per client address per second, at least 1 |
| `statelessTotalPerSecond` | `Int` | 1000 | 0.3.0 | experimental | 🔒 | stateless answers per second over all addresses, at least 1 |

### `configure { webSockets { } }`

`ServerWebSocketsConfig`.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `overHttp2` | `Boolean` | `true` | 0.3.0 | stable | | with HTTP/2 on: advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL` and serve RFC 8441 WebSockets (Extended CONNECT) to `webSocket {}` routes; browsers' `wss://` then comes over HTTP/2; `false` leaves WebSockets on HTTP/1.1 ([WebSockets over HTTP/2](ktor.md#websockets-over-http2)) |
| `overHttp3` | `Boolean` | `true` | 0.3.0 | stable | | accept RFC 9220 WebSockets over HTTP/3; with `false` a WebSocket CONNECT gets 501 |
| `maxMessageSize` | `Long` (bytes) | 16 777 216 (16 MiB) | 0.3.0 | stable | 🔒 | the largest WebSocket frame, and message once reassembled, the server takes from a client (RFC 6455 section 10.4), over HTTP/1.1, HTTP/2 and HTTP/3; a frame whose header claims more, or that takes its message past it, closes the connection with 1009 before its payload is read; at least 1 |

### `configure { tcp { } }`

`TcpLimitsConfig`: the TCP connections of every connector, HTTP/1.1 and HTTP/2 alike: their idle timeout and limits
([Connection limits](ktor.md#connection-limits)).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `idleTimeout` | `Duration` | 45 s | 0.3.0 | stable | | a TCP connection without requests for this long is closed: an HTTP/1.1 one both directions, an HTTP/2 one after GOAWAY; a response the client's socket takes nothing of ends the connection after the longer of this and 5 minutes; a request body that sends no byte for this long fails the handler's read (HTTP/1.1: 408 and close). `EngineMain` sets it from `ktor.deployment.connectionIdleTimeoutSeconds`; HTTP/3 has `http3 { quic { maxIdleTimeout } }` |
| `maxConnections` | `Int` | 10 000 | 0.3.0 | stable | 🔒 | TCP connections (TLS handshakes included) each connector holds at once; at the limit it stops accepting and the OS backlog holds new clients; keep it below `ulimit -n`; at least 1 |
| `maxConnectionsPerIp` | `Int?` | `null` (off) | 0.3.0 | stable | 🔒 | TCP connections of one client address (IPv6 whole; IPv4-mapped as IPv4) on a connector; one over it is reset at accept, before TLS, and reported to `connectionRefused`; behind a proxy, load balancer, SNAT or NAT every client shares one address, so turn it on (256, say) only when the server faces clients directly; with `proxyProtocol` the address is the proxy's. Off by default, unlike QUIC's (256): the TCP handshake proves the address before any state is kept, and proxies in front of TCP are common |

### `configure { observability { } }`

`ServerObservability`.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `logger` | `KuicksilverLogger` | `ServerObservability.ApplicationLog` | 0.3.0 | stable | | where the engine's diagnostics go: listeners, TCP, HTTP/1.1, HTTP/2 and HTTP/3 connections, the watched TLS files and the HTTP/3 endpoints ([Observability](quic.md#observability)); `ApplicationLog` is Ktor's `environment.log`; a warning about one call's answer goes to the application's log either way |
| `qlog` | `QlogSink?` | `null` | 0.3.0 | stable | | a qlog trace per HTTP/3 connection; wrap a file sink in `AsyncQlogSink` |
| `connectionListener` | `ConnectionListener?` | `null` | 0.3.0 | experimental | | lifecycle of every QUIC connection of the listeners |
| `eventListener` | `KuicksilverServerEventListener?` | `null` | 0.3.0 | experimental | | connection and request events over HTTP/1.1, HTTP/2 and HTTP/3 |

## HOCON keys

`EngineMain` (`mainClass = io.kuicksilver.ktor.server.EngineMain`) reads `application.conf`; the same keys work in
`application.yaml`. A key is the path of its option in the server's DSL under `kuicksilver.`, with three exceptions: the
TLS files (`kuicksilver.tls.certificateChain`, `privateKey`, `clientCa`, `ocspStapling`, `echKeys`), the
`kuicksilver.connector` block for the deployment port (a Ktor connector, which has no DSL block) and Ktor's own
`ktor.deployment.connectionIdleTimeoutSeconds`. Guide: [EngineMain and configuration keys](ktor.md#enginemain-and-configuration-keys).
Without `ktor.deployment.host` (and `-host`) the deployment port binds every interface of both families, as a
`tlsConnector { }` without a `host`: one dual-stack socket per protocol on `::`, or `0.0.0.0` where the host has no IPv6
(logged at Info); Ktor's own engines bind `0.0.0.0` there. An explicit `ktor.deployment.host = "0.0.0.0"` keeps IPv4 alone.

```hocon
ktor.deployment.port = 443                                               # no host: every interface, IPv6 and IPv4
ktor.application.modules = [ com.example.ApplicationKt.module ]
kuicksilver.tls {
    certificateChain = "/etc/letsencrypt/live/example.com/fullchain.pem"
    privateKey       = "/etc/letsencrypt/live/example.com/privkey.pem"   # unencrypted PKCS#8
    reloadInterval   = 1h
    # versions = tls12And13                                            # old clients without TLS 1.3
}
# kuicksilver.http3.endpoint.maxConnectionsPerIp = off                   # behind a NAT or kube-proxy
```

Values: `true` or `false` for a switch (nothing else); a duration as `Duration.parse` reads it (`30s`, `1h`, `PT30S`),
in whole milliseconds (`1.5ms` is refused); an enumeration's names in any case; `off` for "none" or "no limit" where an option has one, and `0` there is refused
(`kuicksilver.tcp.maxConnectionsPerIp: use off instead of 0`). A value goes to the same option as the DSL and passes the
same checks; a refusal names the key. Every key under `kuicksilver.` must be one of these: an unknown key fails the start
(`kuicksilver.http3.quic.maxConnections is not a Kuicksilver key; did you mean kuicksilver.http3.endpoint.maxConnections?`),
and a key of 0.2.x or of an earlier 0.3.0 snapshot names the key that replaced it
([Migrating from 0.2.x](#migrating-from-02x)). No old key is read.

| Key | Value | Default | Since | Sets |
|---|---|---|---|---|
| `kuicksilver.requestHeaderTimeout` | a duration | 30 s | 0.3.0 | `requestHeaderTimeout` |
| `kuicksilver.tls.certificateChain` | a PEM file, leaf first | | 0.2.0 | with `privateKey`: `tls { pemFiles(…) }`, and the deployment port serves TLS and HTTP/3 |
| `kuicksilver.tls.privateKey` | a PEM file, unencrypted PKCS#8 | | 0.2.0 | with `certificateChain` |
| `kuicksilver.tls.reloadInterval` | a duration, or `off` | `off` | 0.3.0 | `tls { reloadInterval }`: how often the TLS files are checked for a renewed certificate, CA bundle or OCSP response |
| `kuicksilver.tls.clientAuth` | `none`, `optional` or `required` | `none` | 0.3.0 | `tls { clientAuth }`; other than `none` needs `clientCa` (and the other way round) |
| `kuicksilver.tls.clientCa` | a PEM file of CA certificates | | 0.3.0 | `tls { clientCaFile(…) }` |
| `kuicksilver.tls.versions` | `tls13` or `tls12And13` | `tls13` | 0.3.0 | `tls { versions }` |
| `kuicksilver.tls.keyExchangeGroups` | a list of `KeyExchangeGroups` names, the most preferred first, or one string of them separated by `:` or `,` | the default groups | 0.3.0 | `tls { keyExchangeGroups }` |
| `kuicksilver.tls.ocspStapling` | a DER OCSP response file | | 0.3.0 | `tls { ocspStaplingFile(…) }` |
| `kuicksilver.tls.echKeys` | a list of ECH key PEM files, or one comma-separated string | | 0.3.0 | `tls { echKeys }`, read at startup |
| `kuicksilver.connector.allowMisdirectedHosts` | `true`/`false` | `false` | 0.3.0 | `allowMisdirectedHosts` of the deployment port |
| `kuicksilver.connector.h2c` | `off`, `withHttp11` or `only` | `off` | 0.3.0 | h2c on the cleartext deployment port; refused with the TLS files |
| `kuicksilver.connector.proxyProtocol.trustedSources` | a list, or one comma-separated string, of addresses and CIDR blocks | | 0.3.0 | turns the PROXY protocol on for the deployment port: `proxyProtocol { trust(…) }` |
| `kuicksilver.connector.proxyProtocol.headerTimeout` | a duration | 5 s | 0.3.0 | `proxyProtocol { headerTimeout }`; needs `trustedSources` |
| `kuicksilver.connector.proxyProtocol.maxHeaderSize` | bytes, 232..65 551 | 4096 | 0.3.0 | `proxyProtocol { maxHeaderSize }`; needs `trustedSources` |
| `kuicksilver.http1.allowBareLf` | `true`/`false` | `false` | 0.3.0 | `http1 { allowBareLf }` |
| `kuicksilver.http2.enabled` | `true`/`false` | `true` | 0.3.0 | `http2 { enabled }` |
| `kuicksilver.http2.repeatOffenderPenalty` | a duration, or `off` | `off` | 0.3.0 | `http2 { repeatOffenderPenalty }` |
| `kuicksilver.http3.enabled` | `true`/`false` | `true` | 0.3.0 | `http3 { enabled }` |
| `kuicksilver.http3.altSvc` | `true`/`false` | `true` | 0.3.0 | `http3 { altSvc }` |
| `kuicksilver.http3.earlyData.enabled` | `true`/`false` | `false` | 0.3.0 | `http3 { earlyData { enabled } }` (the policy is code only) |
| `kuicksilver.http3.endpoint.loops` | 1..255 | 1 | 0.3.0 | `http3 { endpoint { loops } }` |
| `kuicksilver.http3.endpoint.maxConnections` | at least 1 | 10 000 | 0.3.0 | `http3 { endpoint { maxConnections } }` |
| `kuicksilver.http3.endpoint.maxConnectionsPerIp` | at least 1, or `off` | 256 | 0.3.0 | `http3 { endpoint { maxConnectionsPerIp } }` |
| `kuicksilver.http3.endpoint.acceptQueue` | at least 1 | 128 | 0.3.0 | `http3 { endpoint { acceptQueue } }` |
| `kuicksilver.http3.endpoint.expert.connectionIdLength` | bytes, 4..20 | 8 | 0.3.0 | `http3 { endpoint { expert { connectionIdLength } } }` |
| `kuicksilver.http3.quic.maxIdleTimeout` | a duration, or `off` (none advertised) | 30 s | 0.3.0 | `http3 { quic { maxIdleTimeout } }` |
| `kuicksilver.http3.quic.handshakeTimeout` | a positive duration | 10 s | 0.3.0 | `http3 { quic { handshakeTimeout } }` |
| `kuicksilver.http3.quic.keepAlive` | a duration, at most 3/4 of the idle timeout, or `off` | `off` | 0.3.0 | `http3 { quic { keepAlive } }`: PINGs that keep a quiet connection (and a NAT's mapping) open |
| `kuicksilver.http3.quic.maxBidiStreams` | 0..2^60 | 100 | 0.3.0 | `http3 { quic { maxBidiStreams } }`: concurrent requests per connection |
| `kuicksilver.http3.quic.pathMtu.maxReceive` | bytes, 1200..1500 (the endpoint's datagram slots) | 1452 | 0.3.0 | `http3 { quic { pathMtu { maxReceive } } }` |
| `kuicksilver.http3.quic.pathMtu.initial` | bytes, 1200..65 527 | 1200 | 0.3.0 | `http3 { quic { pathMtu { initial } } }` |
| `kuicksilver.http3.quic.pathMtu.maxSend` | bytes, 1200..65 527 | 65 527 | 0.3.0 | `http3 { quic { pathMtu { maxSend } } }` ([Tunnels and NAT paths](quic.md#tunnels-and-nat-paths-wireguard)) |
| `kuicksilver.http3.quic.pathMtu.discovery` | `true`/`false` | `true` | 0.3.0 | `http3 { quic { pathMtu { discovery } } }` |
| `kuicksilver.http3.quic.migration.allow` | `true`/`false` | `true` | 0.3.0 | `http3 { quic { migration { allow } } }` |
| `kuicksilver.http3.quic.expert.maxUniStreams` | at least 3 (RFC 9114 section 6.2) | 100, raised for WebTransport | 0.3.0 | `http3 { quic { expert { maxUniStreams } } }` |
| `kuicksilver.webSockets.overHttp2` | `true`/`false` | `true` | 0.3.0 | `webSockets { overHttp2 }` |
| `kuicksilver.webSockets.overHttp3` | `true`/`false` | `true` | 0.3.0 | `webSockets { overHttp3 }` |
| `kuicksilver.webSockets.maxMessageSize` | bytes, at least 1 | 16 777 216 | 0.3.0 | `webSockets { maxMessageSize }` |
| `kuicksilver.tcp.maxConnections` | at least 1 | 10 000 | 0.3.0 | `tcp { maxConnections }` |
| `kuicksilver.tcp.maxConnectionsPerIp` | at least 1, or `off` | `off` | 0.3.0 | `tcp { maxConnectionsPerIp }` |
| `ktor.deployment.connectionIdleTimeoutSeconds` (Ktor) | seconds | 45 | 0.2.0 | `tcp { idleTimeout }` |

The `kuicksilver.tls.*` keys other than the two files need `certificateChain` and `privateKey`, and
`kuicksilver.connector.proxyProtocol.headerTimeout` and `maxHeaderSize` need `trustedSources`: the start fails otherwise.

## Low level

The builders of the protocol modules. The Ktor engines take the same builders in their `http3 { quic { } }`,
`http3 { settings { } }` and `http2 { settings { } }` blocks, minus what they derive; there the client and the server
refuse the derived options named in [`engine { http3 { } }`](#ktor-client) and [`configure { http3 { } }`](#ktor-server).
The immutable objects (`QuicConfig`, `QuicEndpointConfig`, `Http3Settings`, `Http2Settings`) are read by the library
only: build them with the DSL and copy them with `toBuilder()`.

### `quicConfig { }`

`QuicConfig.Builder`: transport settings of a connection; `QuicConfig.Default` for all defaults, `toBuilder()` to change
one value of an existing config. The options most applications touch are at the top, tuning is in `flowControl { }`,
`pathMtu { }`, `datagrams { }` and `migration { }`, RFC knobs in `expert { }`. The connection ID length and the qlog sink
are the endpoint's ([`quicEndpointConfig { }`](#quicendpointconfig--)). Guide: [QUIC](quic.md#configuration).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `maxIdleTimeout` | `Duration?` | 30 s | 0.2.0 | stable | | our `max_idle_timeout`; the connection closes silently after the smaller of both peers' values (never below 3 x PTO) without traffic, with `ConnectionLost.Timeout(TimeoutKind.Idle)`; `null` advertises none and leaves the timeout to the peer; positive, finite and whole milliseconds otherwise (0.2: `Duration.ZERO` for none) |
| `handshakeTimeout` | `Duration` | 10 s | 0.2.0 | stable | | a connection whose handshake has not completed by then closes with `TimeoutKind.Handshake`; positive (`Duration.INFINITE` leaves only the idle timeout); the Ktor client derives it from `connectTimeout` |
| `keepAlive` | `Duration?` | `null` (off) | 0.2.0 | stable | | PING interval while the application is quiet; positive and finite, at most 3/4 of `maxIdleTimeout` (any, when that is `null`); PINGs go out at least every half of the effective idle timeout, so a peer with a shorter timeout does not close the connection |
| `maxBidiStreams` | `Long` | 100 | 0.2.0 | stable | | bidirectional streams the peer may have open at once (`initial_max_streams_bidi`), 0..2^60, raised by MAX_STREAMS as streams close; a stream counts as closed once the application took it from `acceptStream()` and consumed it. For HTTP/3, the requests a client may have open at once |
| `versions` | `List<VersionProfile>` | `listOf(VersionProfile.V1)` | 0.2.0 | stable | | versions in preference order, non-empty, no duplicates; `listOf(V2, V1)` opts into QUIC v2 (RFC 9368/9369) |
| `congestionController` | `() -> CongestionController` | `{ Cubic() }` | 0.2.0 | stable | | controller of each path, a fresh instance per call: `Cubic` (CUBIC with HyStart++), `NewReno`, `Bbr` (*experimental*) ([Congestion control](quic.md#congestion-control)) |

### `quicConfig { flowControl { } }`

`QuicConfig.Builder.FlowControl`: receive windows and the send buffer.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `initialStreamWindow` | `Long` (bytes) | 524 288 (512 KiB) | 0.3.0 | stable | | receive window of each stream at its start (`initial_max_stream_data_*`), 1..`maxStreamWindow`; doubles while the application reads a whole window in under four RTTs |
| `initialConnectionWindow` | `Long` (bytes) | 786 432 (768 KiB) | 0.3.0 | stable | | receive window of the connection at its start (`initial_max_data`), 1..`maxConnectionWindow`; kept at least 1.5 x the largest stream window |
| `maxStreamWindow` | `Long` (bytes) | 6 291 456 (6 MiB) | 0.3.0 | stable | | ceiling of a stream's receive window, at least `initialStreamWindow`: the most unread data one stream holds |
| `maxConnectionWindow` | `Long` (bytes) | 15 728 640 (15 MiB) | 0.3.0 | stable | | ceiling of the connection's receive window, at least `initialConnectionWindow` |
| `maxSendBuffer` | `Long` (bytes) | 4 194 304 (4 MiB) | 0.3.0 | stable | | unacknowledged send data the connection buffers over all streams, 1..2^62; writers wait beyond it |

### `quicConfig { pathMtu { } }`

`QuicConfig.Builder.PathMtu`: datagram sizes ([Path MTU](quic.md#path-mtu)).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `maxReceive` | `Int` (bytes) | 1452 | 0.3.0 | stable | | advertised `max_udp_payload_size`, 1200..65 527 (a `QuicEndpoint` refuses more than 1500 at `bind`/`connect`), and a ceiling of the datagrams sent: `initial` and DPLPMTUD stay at or below it |
| `initial` | `Int` (bytes) | 1200 | 0.3.0 | stable | | the datagram size the connection's first path starts with, Initial padding included, on a socket that sets DF (1200 elsewhere), 1200..65 527 (less is refused, RFC 9000 section 14); lowered to `maxSend`, `maxReceive` and the peer's limit; black-hole detection drops it to 1200 when the path does not carry it; with `discovery = false` also the ceiling ([Tunnels and NAT paths](quic.md#tunnels-and-nat-paths-wireguard)) |
| `maxSend` | `Int` (bytes) | 65527 | 0.3.0 | stable | | the largest datagram sent, initial size and probes included (RFC 8899 section 4.4 MAX_PLPMTU), 1200..65 527; not advertised; 1372 inside WireGuard |
| `discovery` | `Boolean` | `true` | 0.3.0 | stable | | DPLPMTUD (RFC 8899) on sockets that set DF, from `initial` upwards; `false` keeps `initial` as the ceiling, with black-hole detection when it is above 1200 |
| `icmpHints` | `Boolean` | `true` | 0.3.0 | stable | | validated ICMP Packet Too Big (Linux, Android) and EMSGSIZE speed up DPLPMTUD as hints; a lower size drops the MTU to 1200 only until a probe of the old size is acknowledged |

### `quicConfig { datagrams { } }`

`QuicConfig.Builder.Datagrams`: unreliable datagrams (RFC 9221, [Datagrams](quic.md#datagrams-rfc-9221)).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `maxFrameSize` | `Long?` | 65 535 | 0.3.0 | stable | | our `max_datagram_frame_size`, 1..65 535; `null` does not advertise it and refuses DATAGRAM frames (no datagrams; 0.2: `maxDatagramFrameSize = 0`) |
| `receiveQueue` | `Int` | 128 | 0.3.0 | stable | | received datagrams held for the application, at least 1; a full queue drops the oldest |
| `sendQueue` | `Int` | 32 | 0.3.0 | stable | | datagrams queued for sending, at least 1 |
| `sendQueueBytes` | `Long` (bytes) | 1 048 576 (1 MiB) | 0.3.0 | stable | | byte ceiling of the same queue; whichever limit is reached first applies the `DatagramPolicy` |

### `quicConfig { migration { } }`

`QuicConfig.Builder.Migration` (RFC 9000 section 9, [Migration and paths](quic.md#migration-and-paths)).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `allow` | `Boolean` | `true` | 0.3.0 | stable | | server: follow a client to a new address; `false` advertises `disable_active_migration` and drops datagrams from other addresses |
| `allowToLoopback` | `Boolean` | `false` | 0.3.0 | delicate | 🔒 | server: accept a move to a loopback or link-local address from a connection that did not start on one (such a "client" is a reflection target) |
| `followPreferredAddress` | `Boolean` | `true` | 0.3.0 | stable | | client: move to the server's preferred address after the handshake, once the path there is validated (RFC 9000 section 9.6) |

### `quicConfig { expert { } }`

`QuicConfig.Builder.Expert`, *experimental*: RFC knobs and interop switches. The Ktor engines derive `resetStreamAt`
and `cancelErrorCode` and refuse them; they raise the default of `maxUniStreams` (and of `maxBidiStreams`) to fit their
WebTransport sessions, and keep an explicit value.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `maxUniStreams` | `Long` | 100 | 0.3.0 | experimental | | unidirectional streams the peer may have open at once (`initial_max_streams_uni`), 0..2^60; HTTP/3 needs at least 3 (RFC 9114 section 6.2): `Http3Endpoint` refuses less |
| `maxAckDelay` | `Duration` | 25 ms | 0.3.0 | experimental | | our `max_ack_delay`, 0..2^14-1 ms in whole milliseconds (advertised and used as the ACK deadline alike) |
| `ackDelayExponent` | `Int` | 3 | 0.3.0 | experimental | | our `ack_delay_exponent`, 0..20 |
| `activeConnectionIdLimit` | `Int` | 4 | 0.3.0 | experimental | | our `active_connection_id_limit`, at least 2: connection IDs of the peer kept for migration and rotation |
| `initialVersion` | `VersionProfile?` | `null` (the first of `versions`) | 0.3.0 | experimental | | the version of a client's first flight, one of `versions`: prefer v2 while starting in v1 (RFC 9368) |
| `initialRtt` | `Duration` | 333 ms | 0.3.0 | experimental | | RTT assumed before the first sample, in (0, 10 s]: the first PTO is 3 x this and a path validation lasts at least 6 x this; a client endpoint replaces it with the last smoothed RTT to the same server address ([fixed limits](#fixed-limits)) |
| `cancelErrorCode` | `Long` | 0 | 0.3.0 | experimental | | code of the STOP_SENDING / RESET_STREAM sent when a stream channel is cancelled, or when a peer stream is given up before it was accepted, 0..2^62-1; HTTP/3 uses its own codes |
| `greaseQuicBit` | `Boolean` | `true` | 0.3.0 | experimental | | send the fixed bit randomly when the peer allows it (RFC 9287) |
| `glitchProtection` | `Boolean` | `true` | 0.3.0 | experimental, delicate | 🔒 | close a connection whose peer keeps making us do useless work ([Glitch protection](quic.md#glitch-protection)) |
| `resetStreamAt` | `Boolean` | `false` | 0.3.0 | experimental | | advertise `reset_stream_at`: `QuicStream.resetAt` keeps a stream's first bytes when the peer advertised it too; `Http3Endpoint` turns it on for WebTransport |

### `quicClientConfig(tls) { }` and `quicServerConfig(tls) { }`

Pair a `TlsConfig` with a `QuicConfig`. `build()` throws `IllegalArgumentException` for a `TlsConfig` of the wrong role and
`TlsException.Config` for one QUIC cannot use: TLS 1.2 allowed, an empty `alpn` or `TLS_AES_128_CCM_8_SHA256`. An endpoint
applies its connection ID length and qlog sink to the `quic` of its server and of each client connection.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `tls` (constructor) | `TlsConfig` | | 0.2.0 | stable | | name to verify, trust, ALPN; identity on a server |
| `quic` | `QuicConfig` | `QuicConfig.Default` | 0.2.0 | stable | | transport settings |
| client `earlyData` | `EarlyDataState` | `EarlyDataState.Disabled` | 0.2.0 | experimental | 🔒 | keep the server's session tickets (per endpoint, single use) and send 0-RTT through `QuicEndpoint.connectEarly`; `Required` fails the connection with `ZeroRttRejected` when 0-RTT is refused or impossible ([0-RTT](quic.md#0-rtt-opt-in-experimental)) |
| client `tokenStore` | `QuicTokenStore?` | `null` | 0.3.0 | experimental | 🔒 | keep the servers' NEW_TOKEN tokens and present one on the next connection to the same server name and port: no Retry round trip; links those connections ([Address tokens](quic.md#address-tokens-new_token)) |
| server `acceptEarlyData` | `Boolean` | `false` | 0.3.0 | experimental | 🔒 | accept 0-RTT: fresh tickets only (the ticket's age within a 10 s window), once per ticket, only for the configuration that issued it; not with client certificates (0.2: `earlyData`) |
| server `earlyDataContext` | `ByteArray?` | `null` | 0.2.0 | experimental | | application settings bound into tickets, at most 256 bytes (`Http3Endpoint` puts its SETTINGS here) |
| server `newTokenLifetime` | `Duration?` | 24 hours | 0.3.0 | experimental | 🔒 | how long the NEW_TOKEN tokens this server issues validate a returning client's address, at most 7 days; `null` issues none |
| server `newTokenReplayCapacity` | `Int` | 1 048 576 | 0.3.0 | experimental | | the most NEW_TOKEN tokens the replay register holds per lifetime, 1..16 777 216 (32 bytes each); it starts at 128 KiB and doubles with its load up to this; once full a returning client's token counts as absent |
| server `preferredAddress` | `PreferredAddress?` | `null` | 0.3.0 | experimental | | also listen on these addresses (one per family) and offer them in `preferred_address` |

### `quicEndpointConfig { }`

`QuicEndpointConfig.Builder`: the endpoint that owns a socket and its connections; `QuicEndpointConfig.Default` (a
client-only endpoint), `toBuilder()`. The one place for the connection ID length and the qlog sink. Guide:
[Admission and endpoint limits](quic.md#admission-and-endpoint-limits).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `server` | `QuicServerConfig?` | `null` | 0.2.0 | stable | | the server side; `null` is a client-only endpoint, which admits no connection |
| `connectionIdLength` | `Int` (bytes) | 8 | 0.2.0 | stable | | length (4..20) of every connection ID the endpoint issues, applied to every connection's `QuicConfig`; with a `loadBalancer` it must be the load balancer's |
| `loops` | `Int` | 1 | 0.2.0 | stable | | endpoint loops sharing the port, 1..255; more than 1 needs a `server` and no `runtime { dispatcher }` ([Several loops on one port](quic.md#several-loops-on-one-port)) |
| `maxConnections` | `Int` | 10 000 | 0.2.0 | stable | 🔒 | beyond this many connections new Initials are dropped silently, counted over the whole endpoint, all loops; at least 1 |
| `maxConnectionsPerIp` | `Int?` | 256 | 0.2.0 | stable | 🔒 | connections one client IP may hold, ports ignored, over the whole endpoint; `null` for no limit; the excess is dropped silently, and the first refusal logs one warning (then at most one every 5 minutes) |
| `acceptQueue` | `Int` | 128 | 0.2.0 | stable | | handshaken connections waiting for `accept()`, over all loops, at least 1; while full, a new client is refused statelessly with CONNECTION_REFUSED |
| `maxConnectionLifetime` | `Duration?` | `null` (none) | 0.2.0 | stable | | server connections older than this close with NO_ERROR |
| `admission` | `ConnectionAdmission` | `ConnectionAdmission.default()` | 0.2.0 | stable | 🔒 | decides per new client Initial: `Allow`, `Retry`, `Drop` or `Close(code)`; `default(maxInflightHandshakes = 256, maxHandshakeBufferBytes = 8 MiB)` asks an unvalidated client for a Retry above either |
| `loadBalancer` | `QuicLbConfig?` | `null` | 0.3.0 | experimental | | QUIC-LB server connection IDs (draft-ietf-quic-load-balancers-21); needs a `server`, `connectionIdLength` = 1 + server ID + nonce and at least 8; change with `QuicEndpoint.updateLoadBalancer` ([Behind a load balancer](quic.md#behind-a-load-balancer)) |

### `quicEndpointConfig { observability { } }`

`QuicEndpointConfig.Builder.Observability` ([Observability](quic.md#observability)).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `logger` | `KuicksilverLogger` | `KuicksilverLogger.Default` | 0.3.0 | stable | | the endpoint's diagnostics: the platform's logger at warnings and up by default; `KuicksilverLogger.None`, `KuicksilverLogger.stderr(LogLevel.Debug)` or your own (0.2: `KuicksilverLogger.Stderr` by default) |
| `qlog` | `QlogSink?` | `null` | 0.3.0 | stable | | a qlog trace per connection of the endpoint ([qlog](quic.md#qlog)); a failing sink stops tracing for that connection only |
| `connectionListener` | `ConnectionListener?` | `null` | 0.3.0 | experimental | | lifecycle callbacks of every connection, on the loop |

### `quicEndpointConfig { runtime { } }`

`QuicEndpointConfig.Builder.Runtime`.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `dispatcher` | `CoroutineDispatcher?` | `null` (`Dispatchers.Default.limitedParallelism(1)`) | 0.3.0 | stable | | the single-threaded dispatcher of the endpoint loop; must stay `null` with `loops > 1`. Only on its own dispatcher does the loop also wait up to 1 ms for the next datagrams (not on Windows) |
| `io` | `(suspend (InetSocketAddress) -> DatagramIo)?` | `null` (`DatagramIo.open`) | 0.3.0 | experimental | | how the loop opens its socket; `MemoryNetwork.open` runs the endpoint in memory ([Testing](quic.md#testing-your-application)) |
| `crypto` | `QuicCrypto` | `KslQuicCrypto` | 0.3.0 | experimental | | TLS and packet protection (OpenSSL through `ksl`) |

### `quicEndpointConfig { expert { } }`

`QuicEndpointConfig.Builder.Expert`, *experimental*: admission internals; the server engine's
`http3 { endpoint { expert { } } }` sets them, next to its connection ID length.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `initialAdmissionQueue` | `Int` | 1024 | 0.3.0 | experimental | | new Initials queued for admission per receive batch, at least 1; more are dropped |
| `rejectInitialFromReflectivePorts` | `Boolean` | `true` | 0.3.0 | experimental, delicate | 🔒 | drop Initials from source ports 53, 123, 1900, 5353 and 11211 (reflection attacks) |
| `statelessPerAddressPerSecond` | `Int` | 8 | 0.3.0 | experimental | 🔒 | stateless answers (Retry, Version Negotiation, Stateless Reset, refusals) per client address per second, at least 1 |
| `statelessTotalPerSecond` | `Int` | 1000 | 0.3.0 | experimental | 🔒 | stateless answers per second over all addresses, at least 1 |

### Other QUIC options

| Where | Option | Default | What it does |
|---|---|---|---|
| `QuicConnection.openBidi`, `openUni` | `priority: StreamPriority` | `StreamPriority.Default` (`urgency = 3`, `incremental = false`; urgency 0..7) | send order between streams (RFC 9218 levels) |
| `QuicConnection.sendDatagram`, `trySendDatagram` | `policy: DatagramPolicy` | `DropOldest` | `DropOldest`, `LatestWins(key)` or `Reject` when the send queue is full |
| `DatagramIo.open(local, prefer)` | `prefer: IoPreference` | `Accelerated` | `Accelerated`: the `ksl` socket where it exists, `Portable`: NIO on the JVM, `ktor-network` on Kotlin/Native |
| `Cubic(maxDatagramSize, hystart)`, `NewReno(maxDatagramSize)` | | 1200, `true` | the stable congestion controllers |
| `Bbr(maxDatagramSize, random)` (*experimental*) | | 1200, `null` (jitter from send and ACK times) | BBRv3 ([Choosing a congestion controller](quic.md#choosing-a-congestion-controller)) |
| `DirectoryQlogSink(directory)`, `DirectoryQlogSink(directory, maxOpenTraces, maxTotalBytes, logHeaderValues)` (*experimental*) | | 256 open traces, 1 GiB in all, `logHeaderValues = false` | one `<odcid>_<client\|server>_<random>.sqlog` file per connection, created exclusively, never through a link; creates the directory owner-only and refuses one another user could change; `logHeaderValues` writes HTTP field values into the trace ([HTTP/3: qlog](http3.md#qlog)) |
| `qlogDirectory(context, name)` (Android, *experimental*) | | `name = "kuicksilver-qlog"` | a `DirectoryQlogSink` in the app's cache directory, created owner-only at once; API 26 and up |
| `AsyncQlogSink(delegate, queueCapacity, sampleEvery, dispatcher)` (*experimental*) | | 8192 records, 1 (every connection), `Dispatchers.IO.limitedParallelism(1)` | runs a sink off the endpoint loop; a full queue drops records (`dropped`) |
| `QlogSink.logHeaderValues` (*experimental*) | | `false` | HTTP/3 events carry header and trailer values; otherwise `[redacted]` except `:method`, `:scheme`, `:status`, `:protocol` (threat model 3.26) |
| `NetworkMigrator(connection, networks, openIo, scope)` (*experimental*) | | no defaults; client connections only | follows a `Flow` of networks ([Network changes](quic.md#network-changes)) |
| `QuicConnection.rebind(local, prefer)` (*experimental*) | | `null` (loopback of a loopback peer's family, else the wildcard of the peer's family), `Accelerated` | moves the connection to a fresh socket |
| `followDefaultNetwork(connectivity, scope, local, prefer)` (Android), `followDefaultNetwork(scope, local, prefer)` (Apple) (*experimental*) | | `null`, `Accelerated` | a started `NetworkMigrator` on the default network |
| `QuicEndpoint.shutdown(grace, code, reason)` (*experimental*) | | `code = 0`, `reason = "shutdown"` | graceful shutdown ([Graceful shutdown](quic.md#graceful-shutdown)) |

### `tlsConfig(role) { }`

`TlsConfig.Builder` (`tlsConfig(TlsRole.Client / TlsRole.Server) { }`); errors are `TlsException.Config`. One `TlsConfig`
drives QUIC, TLS over TCP and `Socket.tls()`; its properties stay readable (a `TrustConfig.Custom` reads them). Guide:
[TLS](tls.md#configuration).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `alpn` | `List<String>` | empty | 0.2.0 | stable | | ALPN protocol IDs in preference order, each 1..255 UTF-8 bytes, the list at most 255 bytes on the wire; QUIC needs at least one; a server over TCP selects without `h3` (QUIC only), and `h3` alone refuses every TCP client. The Ktor engines derive it |
| `serverName` | `String?` | `null` | 0.2.0 | stable | | SNI and the name the certificate must match; a client needs it (or `TrustConfig.ExpectedName`); an IP literal is verified but never sent as SNI; servers ignore it. The Ktor client derives it from the URL |
| `versions` | `TlsVersions` | `TlsVersions.Tls13` | 0.2.0 | stable | 🔒 | TLS 1.3 is the default (RFC 9852); `Tls12And13` allows TLS 1.2 over TCP under the RFC 9325 profile as narrowed by RFC 10015 (ECDHE and AEAD only); renegotiation is always refused; QUIC: `Tls13` only |
| `cipherSuites` | `CipherSuites` | `CipherSuites.Default` (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305) | 0.2.0 | stable | 🔒 | TLS 1.3 suites in preference order, at least one; QUIC refuses `TLS_AES_128_CCM_8_SHA256` |
| `identity` | `TlsIdentity?` | `null` | 0.2.0 | stable | 🔒 | certificate chain and key; a server needs one or an `sniSelector`; `TlsIdentity.reloadable(...)` for one replaced at run time ([TLS guide](tls.md#rotating-the-server-certificate)) |
| `trust` | `TrustConfig` | `TrustConfig.Platform` | 0.2.0 | stable | 🔒 | how the peer is verified ([TrustConfig](#trustconfig)); with `clientAuth` other than `None`: `AnchoredCa` or `ReloadableCa`, optionally under `Pinned` |
| `clientAuth` | `ClientAuth` | `ClientAuth.None` | 0.2.0 | stable | 🔒 | servers only: `None`, `Optional` or `Required` client certificates |
| `sniSelector` | `(suspend (ClientHelloInfo) -> ServerTlsOverride?)?` | `null` | 0.2.0 | stable | | servers, TCP and QUIC: picks a `ServerTlsOverride(identity, alpn, clientAuth, trust)` per ClientHello; `null` with SNI: `unrecognized_name`, without SNI: the default `identity` (none: `missing_extension`) ([TLS guide](tls.md#certificate-per-name-sni)) |
| `sessionTickets` | `SessionTicketConfig` | `SessionTicketConfig.Default` | 0.2.0 | stable | 🔒 | the keys and lifetime of a TLS-over-TCP server's tickets and of a QUIC server with `acceptEarlyData` (the only QUIC servers that issue tickets) |
| `keylog` | `KeylogSink?` | `null` | 0.2.0 | delicate | 🔒 | TLS secrets as RFC 9850 key log lines ([Key logging](tls.md#key-logging)) |
| `handshakeTimeout` | `Duration` | 10 s | 0.2.0 | stable | | TLS over TCP only (QUIC uses `QuicConfig.handshakeTimeout`); positive (`Duration.INFINITE`: no deadline); the Ktor client derives it from `connectTimeout` |
| `revocation` | `RevocationPolicy` | `RevocationPolicy.StapledIfPresent` | 0.3.0 | experimental | 🔒 | clients: how the OCSP response the server staples is checked: `Off`, `StapledIfPresent` (soft-fail without one), `RequireStapled` (only with a trust `ksl` verifies: `AnchoredCa`, `Platform` on Linux Native); a must-staple certificate needs one under every policy but `Off` (RFC 7633); a failed staple check is alert 113, a configured CRL gives 44, 45, 42, 51, 48 or 46 ([Certificate revocation](tls.md#certificate-revocation)) |
| `ocspStapling` | `OcspStapling?` | `null` | 0.3.0 | experimental | | servers: the OCSP response stapled when the client asks and it is for the leaf sent and fresh; `update` replaces it at run time |
| `keyExchangeGroups` | `KeyExchangeGroups` | `KeyExchangeGroups.Default` (X25519MLKEM768, X25519, P-256, X448, P-384, P-521; client shares for the first two) | 0.3.0 | experimental | 🔒 | 1 to 8 groups, most preferred first, no duplicates, 1 to 4 key shares from the list (clients only); with `Tls12And13` at least one elliptic curve; a server picks by its own order, a group the client sent a share for first, else a HelloRetryRequest ([Key exchange groups](tls.md#key-exchange-groups)) |
| `certificateCompression` | `Boolean` | `true` | 0.3.0 | stable | | TLS certificate compression (RFC 8879), TLS 1.3 only: offers brotli, then zlib, and sends the chain compressed when the peer offers one of them; a session that staples OCSP sends it uncompressed; `false`: no offer, and a compressed certificate from the peer is `unexpected_message` ([Certificate compression](tls.md#certificate-compression)) |

### `tlsConfig(role) { ech { } }`

`TlsConfig.Builder.Ech`, *experimental*: Encrypted Client Hello (RFC 9849, [Encrypted Client Hello](tls.md#encrypted-client-hello)).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `configList` | `EchConfigList?` | `null` | 0.3.0 | experimental | | clients: the configurations offered (an HTTPS record's `ech` parameter, RFC 9848, or out of band); not with `versions = Tls12And13`; unusable ECHConfigs are ignored one by one; a rejection fails with `TlsException.EchRejected` and its `retryConfigs` |
| `grease` | `Boolean` | `true` | 0.3.0 | experimental | | clients: GREASE ECH where no configuration is offered (RFC 9849 section 6.2.1) |
| `keys` | `EchServerKeys?` | `null` | 0.3.0 | experimental | 🔒 | servers: the ECH keys (shared mode), 1 to 16, at least one for `retry_configs`; `rotate` replaces them for new handshakes |

### `tlsConfig(role) { expert { } }`

`TlsConfig.Builder.Expert`, *experimental*.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `genericAlerts` | `Boolean` | `false` | 0.3.0 | experimental | | send `handshake_failure` instead of the specific alert; a failed stapled OCSP check is still sent as `bad_certificate_status_response` (113) |
| `alpnFallback` | `String?` | `null` | 0.3.0 | experimental | | servers, TLS over TCP (QUIC ignores it), 1..255 UTF-8 bytes, not `h3`: the protocol a client without ALPN speaks (`http/1.1` for HTTP, RFC 9113 section 3.3); such a client is refused with `no_application_protocol` (120) where the protocols in effect leave it out; null: it completes without ALPN |

### `SessionTicketConfig(…)`

`SessionTicketConfig(keys, rotateEvery, ticketLifetime)`:

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `keys` (constructor) | `List<ByteArray>?` | `null` (generated in the process) | 0.2.0 | stable | 🔒 | explicit ticket keys, 1 to 64 entries of 80 bytes, shared by the servers of one fleet |
| `rotateEvery` | `Duration` | 1 day | 0.2.0 | stable | | how often the active ticket key is replaced, positive, at most 7 days |
| `ticketLifetime` | `Duration` | 12 hours | 0.2.0 | stable | | how long a ticket stays valid, at least 1 s, at most `rotateEvery / 2` |

The keys stay in native memory: generated keys never reach Kotlin, explicit keys are copied there when the configuration
is built and the given arrays are zeroed (keep the keys in your secret store, not in the arrays).

### TrustConfig

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

### Identities and key logging

| API | Parameters (defaults) | What it does |
|---|---|---|
| `TlsIdentity.fromPem(chainPem, keyPem, password)` | `password = null` (encrypted keys are refused) | chain plus one PKCS#8 key; `keyPem` is zeroed and the key lives in OpenSSL only |
| `TlsIdentity.fromDer(chain, keyDer)` | | the same from DER; `keyDer` is zeroed |
| `TlsIdentity.fromKeyStore(keyStore, alias, password)`, `fromPkcs12(bytes, password)` | | JVM only |
| `keylogFile(path)` (*delicate*) | | a 0600 key log file, refused for links, foreign owners and file systems without POSIX permissions |
| `keylogFile(context, name)` (Android, *delicate*) | `name = "kuicksilver-keylog.txt"` | in the app's files; `null` in a non-debuggable build |
| `keylogFromEnvironment()` (*delicate*) | | `SSLKEYLOGFILE`, read only when called |

### `http3Settings { }`

`Http3Settings.Builder`: what we advertise in SETTINGS (RFC 9114 section 7.2.4) and our own limits; `Http3Settings.Default`,
`toBuilder()`. Guide: [HTTP/3](http3.md). The Ktor engines derive `enableConnectProtocol`, `h3Datagram` and (the server)
`earlyData`.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `maxFieldSectionSize` | `Long` (bytes) | 65 536 (64 KiB) | 0.2.0 | stable | 🔒 | largest decoded header or trailer section we accept, 1..2^30 (and so the longest single field; above it: 431, the connection lives), advertised as `SETTINGS_MAX_FIELD_SECTION_SIZE`; a connection reads at most 8 times this of HEADERS frames at once; interim (1xx) responses are bounded by it too |
| `maxHeaderBlockTime` | `Duration` | 10 s | 0.3.0 | stable | 🔒 | how long one field section (a HEADERS frame) may take to arrive, from its frame header; a server also counts a request head from its stream's first byte; a late request head is rejected with `H3_REQUEST_REJECTED`, other late sections cancel their request; the Ktor server bounds it by `requestHeaderTimeout` |
| `enableConnectProtocol` | `Boolean` | `false` | 0.2.0 | stable | | advertise Extended CONNECT (RFC 9220), for the raw HTTP/3 API |
| `h3Datagram` | `Boolean` | `true` | 0.2.0 | stable | | `SETTINGS_H3_DATAGRAM` (always sent); `Http3Endpoint` sends 0 when `quicConfig { datagrams { maxFrameSize = null } }` |
| `earlyData` | `Http3EarlyDataPolicy` | `WaitForHandshake()` | 0.2.0 | experimental | 🔒 | server: what happens to requests that arrive in 0-RTT (only with `acceptEarlyData`): `WaitForHandshake(replayable)` or `Reject425(replayable)` ([HTTP/3 0-RTT](http3.md#0-rtt-opt-in-experimental)) |

### `http3Settings { qpack { } }`

`Http3Settings.Builder.Qpack`: QPACK header compression (RFC 9204), dynamic tables off by default.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `maxTableCapacity` | `Long` (bytes) | 0 | 0.3.0 | stable | | `SETTINGS_QPACK_MAX_TABLE_CAPACITY` we advertise, 0..2^30: the dynamic table the peer's encoder may use |
| `blockedStreams` | `Long` | 0 | 0.3.0 | stable | | `SETTINGS_QPACK_BLOCKED_STREAMS` we advertise, 0..65 535 |
| `encoderMaxTableCapacity` | `Long` (bytes) | 4096 | 0.3.0 | stable | | ceiling of our own encoder's dynamic table, under what the peer allows, 0..2^30 |
| `enableDynamicTable()` | function | | 0.3.0 | stable | | sets `maxTableCapacity = 4096` and `blockedStreams = 16` |

### `http3Settings { webTransport { } }`

`Http3Settings.Builder.WebTransport`, *experimental*: WebTransport over HTTP/3 (draft-ietf-webtrans-http3-17, with the
draft-16 SETTINGS other libraries use and the draft-02 and draft-14 SETTINGS browsers use). The Ktor server sets it from
`http3 { webTransport { } }`; the Ktor client derives `enabled` and `maxSessions` and takes the three limits from here.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `enabled` | `Boolean` | `false` | 0.3.0 | experimental | | speak WebTransport; needs `enableConnectProtocol` and `h3Datagram`; `Http3Endpoint.bind` refuses it without QUIC datagrams and turns `resetStreamAt` on with it |
| `maxSessions` | `Int` | 4 | 0.3.0 | experimental | | sessions one connection carries at once when both sides use WebTransport flow control (draft-17 section 5.1), 1..65 535; a server refuses a CONNECT beyond it with `H3_REQUEST_REJECTED`, a client opens another connection; times the per-session limits it must fit the QUIC connection's stream limits and largest window |
| `initialMaxStreamsBidi` | `Long` | 24 | 0.3.0 | experimental | | bidirectional streams the peer may open in each session (`SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI`), 0..2^60; with all three limits 0 we declare no WebTransport flow control and a connection carries one session |
| `initialMaxStreamsUni` | `Long` | 24 | 0.3.0 | experimental | | the same for unidirectional streams |
| `initialMaxData` | `Long` (bytes) | 3 932 160 | 0.3.0 | experimental | | stream body bytes the peer may send in each session (`SETTINGS_WT_INITIAL_MAX_DATA`), 0..2^62-1; raised by WT_MAX_DATA as their bytes are consumed; read the streams concurrently (a strictly sequential reader under a tight limit can stall) |

### `http3Settings { expert { } }`

`Http3Settings.Builder.Expert`, *experimental*.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `grease` | `Boolean` | `true` | 0.3.0 | experimental | | send a reserved setting, frame and stream type (RFC 9114 section 7.2.8) |
| `maxEarlyPriorityUpdates` | `Int` | 32 | 0.3.0 | experimental | 🔒 | PRIORITY_UPDATE frames remembered for streams not yet open (RFC 9218 section 7), at least 0 |
| `glitchProtection` | `Boolean` | `true` | 0.3.0 | experimental, delicate | 🔒 | close with `H3_EXCESSIVE_LOAD` a peer that floods useless frames (unknown frame types; reserved and empty DATA frames beyond the first 8 of a stream) |

Endpoint and request parameters:

| API | Parameters (defaults) |
|---|---|
| `Http3Endpoint.bind(local, config, settings)` | `config = QuicEndpointConfig.Default`, `settings = Http3Settings.Default`; the server's TLS must offer ALPN `h3` |
| `Http3Endpoint.connect(remote, tls, quic, settings)` | `quic = QuicConfig.Default`, `settings = Http3Settings.Default`; `tls` must offer ALPN `h3` |
| `Http3Endpoint.connectEarly(remote, tls, quic, settings, earlyData)` (*experimental*) | as `connect`, `earlyData = EarlyDataState.Allowed` (not `Disabled`) |
| `Http3Endpoint.shutdown(grace, code, reason)` (*experimental*) | `code = H3_NO_ERROR`, `reason = "shutdown"` |
| `http3Request(method, authority, path) { ... }` (`Http3Request.Builder`) | `scheme = "https"`, `headers = Http3Headers.Empty`, `body = null` (no body), `trailers = null`, `priority = null` (the default `u=3`), `protocol = null`, `onInformational = null`, `allowEarlyData = false` (*experimental*; GET, HEAD and OPTIONS without a body only) |

### `capsuleConfig { }`

`CapsuleConfig.Builder`, *experimental*: how an Extended CONNECT stream speaks the Capsule Protocol (RFC 9297 section 3)
once `Http3Stream.useCapsuleProtocol(config)` is called; the constructor, `capsuleConfig { }`, `toBuilder()`. Guide:
[HTTP/3, capsules](http3.md#capsules-experimental).

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `knownTypes` | `Set<Long>` | empty | 0.3.0 | experimental | | capsule types delivered in `CapsuleStream.capsules`, each 0..2^62-1; other types are skipped as their bytes arrive. DATAGRAM (0x00) always goes to `datagrams` |
| `maxCapsuleLength` | `Int` (bytes) | 65 536 (64 KiB) | 0.3.0 | experimental | | longest capsule of a known type, 1..1 048 576; a longer one resets and stops the stream with `H3_MESSAGE_ERROR` |
| `maxDatagramLength` | `Int` (bytes) | 65 536 (64 KiB) | 0.3.0 | experimental | | longest DATAGRAM capsule, 1..1 048 576; a longer one is dropped without being buffered |
| `datagramFallback` | `Boolean` | `true` | 0.3.0 | experimental | | send datagrams as DATAGRAM capsules when HTTP/3 datagrams are unsupported (either side's `SETTINGS_H3_DATAGRAM` is 0, or the peer's SETTINGS have not arrived yet); a datagram too large for QUIC never falls back |
| `receiveQueue` | `Int` | 16 | 0.3.0 | experimental | | received capsules held for the collector, 1..4096; when full, reading the stream pauses |
| `sendQueue` | `Int` | 32 | 0.3.0 | experimental | | capsules waiting to be written, 1..4096; when full, `send` suspends and a fallback `trySendDatagram` answers `QueueFull` |
| `terminalTypes` | `Set<Long>` | empty | 0.3.0 | experimental | | among `knownTypes`, not DATAGRAM: a capsule of such a type must be the stream's last; any byte after it resets the stream with `H3_MESSAGE_ERROR` (WebTransport's WT_CLOSE_SESSION) |

### `UdpProxyConfig(…)`

`UdpProxyConfig(...)`, *experimental* (constructor parameters, immutable): how a `UdpProxy` serves CONNECT-UDP (RFC 9298);
a bad value throws `IllegalArgumentException` when the object is built. Guide:
[HTTP/3, CONNECT-UDP](http3.md#connect-udp-experimental); threats and limits: threat model 3.29.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `pathTemplate` | `String` | `ConnectUdp.WELL_KNOWN_PATH` | 0.3.0 | experimental | | a path and query URI Template with `target_host` and `target_port` once each: the path a request must have; another shape is answered 404, an invalid value 400 |
| `targetFilter` | `UdpTargetFilter` | `UdpTargetFilter.PublicOnly` | 0.3.0 | experimental | 🔒 | which resolved addresses and ports may be reached; a refusal is 403 with `destination_ip_prohibited`, before a socket is opened |
| `resolver` | `UdpProxyResolver` | `UdpProxyResolver.System` | 0.3.0 | experimental | | resolves a `target_host` that is a DNS name |
| `resolveTimeout` | `Duration` | 5 s | 0.3.0 | experimental | | a resolution that takes longer is answered 504 with `dns_timeout` |
| `idleTimeout` | `Duration` | 2 min | 0.3.0 | experimental | | at least 2 min: a tunnel without a datagram either way is closed, socket and stream (RFC 9298 section 3.1) |
| `linkMtu` | `Int` (bytes) | 1500 | 0.3.0 | experimental | | 1280..65 535; UDP payloads above `linkMtu - 28` (IPv4) or `- 48` (IPv6) are dropped rather than sent fragmented |
| `maxTunnels` | `Int` | 4096 | 0.3.0 | experimental | 🔒 | tunnels at once; one more is answered 503 with `connection_limit_reached` |
| `maxTunnelsPerClient` | `Int` | 64 | 0.3.0 | experimental | 🔒 | tunnels at once per client (an IPv4 address or an IPv6 `clientIpv6Prefix`); one more is answered 429 |
| `clientIpv6Prefix` | `Int` | 64 | 0.3.0 | experimental | 🔒 | 1..128: the prefix an IPv6 client is known by for its limits |
| `clientPackets` | `RateLimit` | `RateLimit(50000, 5000)` | 0.3.0 | experimental | 🔒 | UDP payloads per second all of a client's tunnels together send to targets, and the burst, on top of each tunnel's `packets` |
| `packets` | `RateLimit` | `RateLimit(20000, 2000)` | 0.3.0 | experimental | 🔒 | UDP payloads per second a tunnel sends to its target, and the burst; more are dropped |
| `unansweredLimit` | `Int` | 256 | 0.3.0 | experimental | 🔒 | payloads a client sends to a target before it answers once, counted across the client's tunnels; later ones are dropped until it does; 0 turns it off |
| `refuseOwnAddresses` | `Boolean` | `true` | 0.3.0 | experimental, delicate | 🔒 | refuse the proxy's own addresses as targets; 403 with `destination_ip_prohibited` |
| `requireCapsuleProtocolField` | `Boolean` | `true` | 0.3.0 | experimental | | a request without `capsule-protocol: ?1` is answered 400 |
| `proxyName` | `String` | `"proxy"` | 0.3.0 | experimental | | a Structured Field token: the proxy's name in the `proxy-status` of its refusals (RFC 9209) |
| `packetTooBig` | `Boolean` | `true` | 0.3.0 | experimental | | answer a target payload too large for the client's DATAGRAM frames with an ICMP Packet Too Big (RFC 9298 section 6.1) where the process may open a raw ICMP socket (Linux and Android with `CAP_NET_RAW`); without the privilege the payload is only dropped |
| `socketFactory` | `suspend (InetSocketAddress) -> DatagramIo` | `{ DatagramIo.open(it) }` | 0.3.0 | experimental | | opens a tunnel's UDP socket on a wildcard address of the target's family |
| `socketOpenTimeout` | `Duration` | 5 s | 0.3.0 | experimental | | a `socketFactory` call that takes longer is given up on: that family failed, the other is tried, else 502; `Duration.INFINITE` turns the bound off |

`RateLimit(perSecond, burst)` (*experimental*) is a token bucket: `perSecond` sustained, `burst` at once, both at least 1.

### `http2Settings { }`

`Http2Settings.Builder`, *experimental* (`http2Settings { }`, `Http2Settings.Default`, `toBuilder()`): the local side of an
HTTP/2 connection. The Ktor engines take it in `http2 { settings { } }`. Byte and stream counts are `Long`; `build()` refuses
a value its SETTINGS field cannot hold. Guide: [HTTP/2 on the client](ktor.md#http2-on-the-client),
[on the server](ktor.md#http2-on-the-server); limits against floods: threat model 3.23.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `headerTableSize` | `Long` (bytes) | 4096 | 0.3.0 | experimental | | `SETTINGS_HEADER_TABLE_SIZE`, 0..65 536: the HPACK dynamic table the peer may use towards us |
| `maxConcurrentStreams` | `Long` | 100 | 0.3.0 | experimental | 🔒 | `SETTINGS_MAX_CONCURRENT_STREAMS`, 0..2^31 - 1: streams the peer may have open towards us; a stream the peer reset still counts until its handler has finished |
| `initialStreamWindow` | `Long` (bytes) | 524 288 (512 KiB) | 0.3.0 | experimental | | `SETTINGS_INITIAL_WINDOW_SIZE`, 0..2^31 - 1: the receive window each stream starts with |
| `maxStreamWindow` | `Long` (bytes) | 6 291 456 (6 MiB) | 0.3.0 | experimental | | the largest a stream's receive window grows to while the application reads faster than the window |
| `initialConnectionWindow` | `Long` (bytes) | 786 432 (768 KiB) | 0.3.0 | experimental | | the connection's receive window, at least 65 535 |
| `maxConnectionWindow` | `Long` (bytes) | 15 728 640 (15 MiB) | 0.3.0 | experimental | | the largest the connection's receive window grows to, at most 2^31 - 1 |
| `maxFrameSize` | `Long` (bytes) | 16 384 | 0.3.0 | experimental | | `SETTINGS_MAX_FRAME_SIZE`, 16 384..16 777 215: the largest frame payload we accept |
| `maxFieldSectionSize` | `Long` (bytes) | 65 536 (64 KiB) | 0.3.0 | experimental | 🔒 | `SETTINGS_MAX_HEADER_LIST_SIZE`, 1..2^30 - 1: the largest field section we decode (name + value + 32 per field, as HTTP/3 counts its `maxFieldSectionSize`); a larger one fails only its stream, its compressed form is buffered up to twice this, beyond that the connection ends |
| `settingsAckTimeout` | `Duration` | 10 s | 0.3.0 | experimental | | how long our SETTINGS may go unacknowledged before the connection ends with `SETTINGS_TIMEOUT` |
| `maxHeaderBlockTime` | `Duration` | 10 s | 0.3.0 | experimental | 🔒 | how long one field block (HEADERS and its CONTINUATION frames) may take to arrive; the Ktor server bounds it by `requestHeaderTimeout` |

### `http2Settings { floodLimits { } }`

`Http2Settings.Builder.FloodLimits`, *experimental*: every limit ends the connection with `ENHANCE_YOUR_CALM` when the peer
passes it.

| Option | Type | Default | Since | Status | 🔒 | Description |
|---|---|---|---|---|---|---|
| `maxContinuationFrames` | `Int` | 8 | 0.3.0 | experimental | 🔒 | CONTINUATION frames allowed in one field block |
| `maxControlFramesQueued` | `Int` | 10 000 | 0.3.0 | experimental | 🔒 | control frames (SETTINGS and PING acknowledgements, RST_STREAM, WINDOW_UPDATE) queued for the peer |
| `maxEmptyFrames` | `Int` | 100 | 0.3.0 | experimental | 🔒 | DATA frames in a row with no content and no END_STREAM |
| `resets` | `RateLimit` | `RateLimit(33, 1000)` | 0.3.0 | experimental | 🔒 | a server's budget for the client's RST_STREAM frames (Rapid Reset): 33 a second, 1000 at once, as nghttp2 |
| `glitches` | `RateLimit` | `RateLimit(330, 10000)` | 0.3.0 | experimental | 🔒 | the glitch budget (PRIORITY, unknown frame types, SETTINGS, empty DATA, an unanswered-data PING, every stream error the peer causes), as nghttp2 |

### ktor-network

`Socket.tls(config, context)` and `Socket.tlsServer(config, context)` take a `TlsConfig` of the matching role (and a
`CoroutineContext`, empty by default); everything else comes from the `TlsConfig`.

## System properties and environment variables

| Name | Kind | Default | What it does |
|---|---|---|---|
| `kuicksilver.ktor.versionCheck` | JVM / Android system property | checked | `false` skips the Ktor 3.6.x check of the engines ([stability](../stability.md#ktor-versions)) |
| `kuicksilver.native.workdir` | JVM system property | `<java.io.tmpdir>/kuicksilver-native-<user>` | where `libksl` is extracted; must be a private directory of this user |
| `kuicksilver.native.path` 🔒 | JVM system property | unset | load `libksl` from this file, without the hash check |
| `kuicksilver.native.system` 🔒 | JVM system property | unset | `true` loads `ksl` with `System.loadLibrary`, without the hash check |
| `SSL_CERT_FILE`, `SSL_CERT_DIR` 🔒 | environment, Linux Kotlin/Native | unset | the CA store of `TrustConfig.Platform`; when set, they replace the distribution paths ([Linux trust store](tls.md#linux-trust-store)) |
| `SSLKEYLOGFILE` 🔒 | environment | | never read implicitly; `keylogFromEnvironment()` reads it on request. A `libksl` built against the system OpenSSL (Linux) refuses to load while it is set |

## Fixed limits

Not configurable, listed so you can plan around them:

| Limit | Value |
|---|---|
| Client endpoint's RTT memory | the last smoothed RTT (1 ms..10 s) of connections that ended on the endpoint's own socket, per server address and port, at most 256 addresses (least recently stored dropped); replaces `expert { initialRtt }` for the next connection to that address |
| PMTUD | base 1200 bytes, 20-byte steps, 3 probes per size, a new search every 10 minutes, a 60 s pause after a black hole |
| Retry tokens | valid for 10 s |
| Glitch bucket | 1000 tokens, 33 back per second (QUIC and HTTP/3) |
| Connection ID rotation | every migration and every 10 000 1-RTT packets |
| Reassembly | 256 gaps per stream, 4096 per connection |
| qlog per connection | 64 MiB; after that the connection is not traced further; at most 4096 HTTP/3 events queued for the endpoint loop (more are dropped) |
| TCP client session cache | 384 sessions (six tickets for each of 64 origins) per Ktor client engine (one process-wide cache for `Socket.tls` and `TlsConnection.client`) |
| Alt-Svc | 8 alternatives per origin, 1000 origins; default `ma` 86 400 s; broken marks 5 min doubling up to 2 days |
| Ktor client race head start | 100 ms..2 s when derived from the RTT |
| Datagram slots of `QuicEndpoint` | 1500 bytes (hence the `pathMtu { maxReceive }` ceiling) |
| Portable JVM socket buffers | 8 MiB send and receive |
| QUIC per-address warning | at most one line every 5 minutes per endpoint |

## Migrating from 0.2.x

0.3.0 puts the configuration in blocks (ADR-0026). There are **no deprecated aliases**: an old Kotlin name does not
compile, and an old configuration-file key stops the start with the key that replaced it. `tools/migrate/config-0.3.py`
rewrites most Kotlin assignments into their blocks (`python3 tools/migrate/config-0.3.py <file or directory>`, `--check`
to only list them) and reports the ones that need a decision (a `Duration.ZERO`, `Duration.INFINITE` or `0` that meant
"off" is `null` now). An option the 0.3.0 engines derive and refuse, or that the client's `tls { }` no longer has, is
commented out and reported; groups it writes twice in one block are merged. The tables list the options 0.2.x released; options added in 0.3.0 snapshots are in their sections
above under the new name only. Behaviour that changed with the defaults is in the CHANGELOG.

### Kotlin: Ktor client

| 0.2.x `engine { }` | 0.3.0 `engine { }` | Note |
|---|---|---|
| `trust = …`, `identity = …` | `tls { trust = …; identity = … }` | |
| `tls { … }` (a `TlsConfig.Builder` lambda) | `tls { … }` (`ClientTlsConfig`: `versions`, `cipherSuites`, `keyExchangeGroups`, `revocation`, `certificateCompression`, `keylog`, `ech { }`) | ALPN, the server name and the handshake deadline are derived |
| `tls { handshakeTimeout }` | `connectTimeout` | the TLS handshake's deadline is derived from it |
| `tls { sessionTickets }`, `tls { genericAlerts }` | no replacement | ticket keys are a server's; the client sends the specific alert (`tlsConfig(role) { expert { genericAlerts } }` stays for the low-level API) |
| `tls { echConfigList }` | `tls { ech { configLists = mapOf(host to list) } }` | per host; else the HTTPS record's |
| `quic = quicConfig { … }` | `http3 { quic { … } }` | `handshakeTimeout` (= `connectTimeout`), `expert { resetStreamAt; cancelErrorCode }` are derived |
| `quic = quicConfig { handshakeTimeout }` | `connectTimeout` | `http3 { quic { handshakeTimeout } }` is refused |
| `maxConnectionsCount` | `pool { maxConnections }` | |
| `maxConnectionsPerRoute`, `maxIdleConnectionsPerRoute`, `idleTimeout` | `pool { maxConnectionsPerRoute; maxIdleConnectionsPerRoute; idleTimeout }` | |
| `maxConnectionLifetime = Duration.INFINITE` | `pool { maxConnectionLifetime = null }` | `null` is the default |
| `connectTimeout` | `connectTimeout` | unchanged |
| `logger: KuicksilverLogger?` | `observability { logger }` | not nullable; default `KuicksilverLogger.Default`, the platform's logger |
| `eventListener` | `observability { eventListener }` | |
| `http3 { discovery = Http3DiscoveryMode.H1Only }` | `http3 { enabled = false }` | |
| `http3 { discovery = Http3DiscoveryMode.Auto / Preferred / H3Only }` | `http3 { discovery = Http3Discovery.Auto / Preferred / H3Only }` | the enum is renamed |
| `http3 { quicHints }` | `http3 { hints }` | |
| `http3 { altSvcStore }` | `http3 { altSvcStore }` | unchanged |
| `http3 { clearOnNetworkChange }` | `http3 { expert { clearAltSvcOnNetworkChange } }` | |
| `http3 { hardDelay = null / d / Duration.INFINITE }` | `http3 { expert { raceHeadStart = RaceHeadStart.Adaptive / Fixed(d) / NoRace } }` | |
| `http3 { networkId = { … } }` | `network { networkId = { … } }` | `null` (not set) is the default |
| `http3 { settings = http3Settings { … } }` | `http3 { settings { … } }` | `enableConnectProtocol`, `h3Datagram`, `webTransport { enabled; maxSessions }`, `earlyData` are derived |
| `http3 { settings = http3Settings { webTransportMaxSessions } }` | `http3 { webTransport { maxSessionsPerConnection } }` | |
| `http3 { endpoint = quicEndpointConfig { … } }` | `http3 { expert { connectionIdLength; dispatcher } }`, `observability { logger; connectionListener }` | the other endpoint options are a server's or tests' |
| `http3 { earlyData = true }` | `http3 { earlyData { enabled = true } }` | |
| `http3 { qlog }` | `observability { qlog }` | |
| `http3 { connectionListener }` | `observability { connectionListener }` | |

### Kotlin: Ktor server

| 0.2.x `configure { }` | 0.3.0 `configure { }` | Note |
|---|---|---|
| `identity = …` | `tls { identity = … }`, or `tls { pemFiles(chain, key) }` | Ktor's own connectors serve TLS once `tls { }` has an identity, as before |
| `tlsConnector(identity) { … }` | `tls { identity = identity }` and `tlsConnector { … }` | the connector takes no argument; `tlsConnector { tls { identity = … } }` for one of its own |
| `tlsConnector { host = "0.0.0.0" }` (the default) | `tlsConnector { }` | the default is `null`: every interface, IPv6 and IPv4; `host = "0.0.0.0"` keeps IPv4 alone |
| `tlsConnector { port }` | `tlsConnector { port }` | unchanged |
| `tlsConnector { clientAuth; trust; cipherSuites; sniSelector }` | `tls { clientAuth; clientTrust; cipherSuites; sniSelector }` | also per connector in `tlsConnector { tls { } }` |
| `connectionIdleTimeoutSeconds: Int` | `tcp { idleTimeout: Duration }` | |
| `requestHeaderTimeoutSeconds: Int` | `requestHeaderTimeout: Duration` | |
| `http3 = false` | `http3 { enabled = false }` | |
| `altSvc` | `http3 { altSvc }` | |
| `quic = quicConfig { … }` | `http3 { quic { … } }` | `expert { resetStreamAt; cancelErrorCode }` are derived |
| `quic = quicConfig { connectionIdLength = n }` | `http3 { endpoint { expert { connectionIdLength = n } } }` | the endpoint is its one place; refused next to `loadBalancer`, which dictates it |
| `quicMaxIdleTimeout` | `http3 { quic { maxIdleTimeout } }` | the second way to set it is gone |
| `udpSocketCount` | `http3 { endpoint { loops } }` | |
| `quicAdmission` (null: the default) | `http3 { endpoint { admission } }` | not nullable; default `ConnectionAdmission.default()` |
| `http3Settings = http3Settings { … }` | `http3 { settings { … } }` | `enableConnectProtocol`, `h3Datagram`, `webTransport`, `earlyData` are derived |
| `http3Settings { webTransport; webTransportMaxSessions; webTransportInitialMaxStreamsBidi; webTransportInitialMaxStreamsUni; webTransportInitialMaxData }` | `http3 { webTransport { enabled; maxSessionsPerConnection; initialMaxStreamsBidi; initialMaxStreamsUni; initialMaxData } }` | |
| `webSocketsOverHttp3` | `webSockets { overHttp3 }` | |
| `quicEarlyData` and `http3Settings.earlyData` | `http3 { earlyData { enabled; policy } }` | |
| `logger` (null: standard error) | `observability { logger }` | not nullable; default `ServerObservability.ApplicationLog`, Ktor's `environment.log`, for every engine line |
| `qlog`, `connectionListener`, `eventListener` | `observability { qlog; connectionListener; eventListener }` | |
| HTTP/2 off | `http2 { enabled = true }` by default | `http2 { enabled = false }` keeps 0.2's HTTP/1.1 over TLS |

### Kotlin: low level

| 0.2.x | 0.3.0 | Note |
|---|---|---|
| `quicConfig { maxIdleTimeout = Duration.ZERO }` | `quicConfig { maxIdleTimeout = null }` | `Duration.ZERO` is refused |
| `quicConfig { initialStreamWindow; initialConnectionWindow; maxStreamWindow; maxConnectionWindow; maxSendBuffer }` | `quicConfig { flowControl { … } }` | same names |
| `quicConfig { maxUdpPayloadSize }` | `quicConfig { pathMtu { maxReceive } }` | |
| `quicConfig { pmtud }` | `quicConfig { pathMtu { discovery } }` | |
| `quicConfig { maxDatagramFrameSize = 0 }` | `quicConfig { datagrams { maxFrameSize = null } }` | `0` is refused |
| `quicConfig { datagramReceiveQueue; datagramSendQueue; datagramSendQueueBytes }` | `quicConfig { datagrams { receiveQueue; sendQueue; sendQueueBytes } }` | |
| `quicConfig { allowMigration; allowMigrationToLoopback }` | `quicConfig { migration { allow; allowToLoopback } }` | `allowToLoopback` is delicate |
| `quicConfig { maxUniStreams; maxAckDelay; ackDelayExponent; activeConnectionIdLimit; initialVersion; initialRtt; greaseQuicBit; glitchProtection }` | `quicConfig { expert { … } }` | experimental; `glitchProtection` delicate |
| `quicConfig { defaultStreamErrorCode }` | `quicConfig { expert { cancelErrorCode } }` | |
| `quicConfig { connectionIdLength }` | `quicEndpointConfig { connectionIdLength }` | the endpoint applies it to every connection |
| `quicConfig { qlog }` | `quicEndpointConfig { observability { qlog } }` | no per-connection override |
| `quicConfig { handshakeTimeout; keepAlive; maxBidiStreams; versions; congestionController }` | the same | unchanged |
| `quicServerConfig(tls) { earlyData }` | `quicServerConfig(tls) { acceptEarlyData }` | |
| `quicEndpointConfig { crypto; dispatcher; io }` | `quicEndpointConfig { runtime { crypto; dispatcher; io } }` | |
| `quicEndpointConfig { initialQueueCap }` | `quicEndpointConfig { expert { initialAdmissionQueue } }` | |
| `quicEndpointConfig { rejectInitialFromReflectivePorts; statelessPerAddressPerSecond; statelessTotalPerSecond }` | `quicEndpointConfig { expert { … } }` | `rejectInitialFromReflectivePorts` is delicate |
| `quicEndpointConfig { logger }` (default `KuicksilverLogger.Stderr`) | `quicEndpointConfig { observability { logger } }` | default `KuicksilverLogger.Default` |
| `quicEndpointConfig { listener }` | `quicEndpointConfig { observability { connectionListener } }` | |
| `quicEndpointConfig { server; maxConnections; acceptQueue; admission; maxConnectionsPerIp; maxConnectionLifetime; loops }` | the same | unchanged |
| `tlsConfig(role) { genericAlerts }` | `tlsConfig(role) { expert { genericAlerts } }` | |
| `http3Settings { qpackMaxTableCapacity; qpackBlockedStreams; encoderMaxTableCapacity }` | `http3Settings { qpack { maxTableCapacity; blockedStreams; encoderMaxTableCapacity } }` | |
| `http3Settings { enableQpackDynamicTable() }` | `http3Settings { qpack { enableDynamicTable() } }` | |
| `http3Settings { grease; maxEarlyPriorityUpdates; glitchProtection }` | `http3Settings { expert { … } }` | experimental; `glitchProtection` delicate |
| `http3Settings { maxInformationalResponses }` | removed | ignored since 0.2.1: interim responses are bounded by `maxFieldSectionSize` |
| `config.maxIdleTimeout` (reading a `QuicConfig`, `QuicEndpointConfig`, `Http3Settings`) | `config.toBuilder()` | the readers are internal |

### `application.conf` keys

Every old key fails the start with `<old key> was replaced in 0.3.0 by <new key>` and is never read; the 0.2.x scalar
`kuicksilver.http3 = true` gets `kuicksilver.http3 = true|false was replaced in 0.3.0 by kuicksilver.http3.enabled`. A
file that holds both the scalar and the block keeps only the last definition (HOCON's rule), so remove the scalar.

| Old key | 0.3.0 key | From |
|---|---|---|
| `kuicksilver.http3` | `kuicksilver.http3.enabled` | 0.2.x |
| `kuicksilver.altSvc` | `kuicksilver.http3.altSvc` | 0.2.x |
| `kuicksilver.udpSocketCount` | `kuicksilver.http3.endpoint.loops` | 0.2.x |
| `kuicksilver.webSocketsOverHttp3` | `kuicksilver.webSockets.overHttp3` | 0.2.x |
| `kuicksilver.tls.certificateChain` | unchanged | 0.2.x |
| `kuicksilver.tls.privateKey` | unchanged | 0.2.x |
| `ktor.deployment.connectionIdleTimeoutSeconds` | unchanged (sets `tcp { idleTimeout }`) | 0.2.x |
| `kuicksilver.tls.trustedGateway` | `kuicksilver.connector.allowMisdirectedHosts` | 0.3.0 snapshot |
| `kuicksilver.http2` | `kuicksilver.http2.enabled` | 0.3.0 snapshot |
| `kuicksilver.h2c` | `kuicksilver.connector.h2c` | 0.3.0 snapshot |
| `kuicksilver.http2RepeatOffenderPenalty` | `kuicksilver.http2.repeatOffenderPenalty` | 0.3.0 snapshot (`0` is `off` now) |
| `kuicksilver.maxTcpConnections` | `kuicksilver.tcp.maxConnections` | 0.3.0 snapshot |
| `kuicksilver.maxTcpConnectionsPerIp` | `kuicksilver.tcp.maxConnectionsPerIp` | 0.3.0 snapshot (`0` is `off` now) |
| `kuicksilver.quicMaxConnections` | `kuicksilver.http3.endpoint.maxConnections` | 0.3.0 snapshot |
| `kuicksilver.quicMaxConnectionsPerIp` | `kuicksilver.http3.endpoint.maxConnectionsPerIp` | 0.3.0 snapshot (`0` is `off` now) |
| `kuicksilver.quicAcceptQueue` | `kuicksilver.http3.endpoint.acceptQueue` | 0.3.0 snapshot |
| `kuicksilver.webSocketsOverHttp2` | `kuicksilver.webSockets.overHttp2` | 0.3.0 snapshot |
| `kuicksilver.h1AllowBareLf` | `kuicksilver.http1.allowBareLf` | 0.3.0 snapshot |
| `kuicksilver.proxyProtocol.trustedSources` | `kuicksilver.connector.proxyProtocol.trustedSources` | 0.3.0 snapshot |
| `kuicksilver.proxyProtocol.headerTimeout` | `kuicksilver.connector.proxyProtocol.headerTimeout` | 0.3.0 snapshot |
| `kuicksilver.proxyProtocol.maxHeaderSize` | `kuicksilver.connector.proxyProtocol.maxHeaderSize` | 0.3.0 snapshot |
| `kuicksilver.quic.initialUdpPayloadSize` | `kuicksilver.http3.quic.pathMtu.initial` | 0.3.0 snapshot |
| `kuicksilver.quic.maxSendUdpPayloadSize` | `kuicksilver.http3.quic.pathMtu.maxSend` | 0.3.0 snapshot |
| `kuicksilver.quic.maxUdpPayloadSize` | `kuicksilver.http3.quic.pathMtu.maxReceive` | 0.3.0 snapshot |
| `kuicksilver.quic.pmtud` | `kuicksilver.http3.quic.pathMtu.discovery` | 0.3.0 snapshot |
| `kuicksilver.quic.maxIdleTimeout` | `kuicksilver.http3.quic.maxIdleTimeout` | 0.3.0 snapshot (`0` is `off` now) |
| `kuicksilver.quic.handshakeTimeout` | `kuicksilver.http3.quic.handshakeTimeout` | 0.3.0 snapshot |
| `kuicksilver.quic.keepAlive` | `kuicksilver.http3.quic.keepAlive` | 0.3.0 snapshot (`0` is `off` now) |
| `kuicksilver.quic.maxBidiStreams` | `kuicksilver.http3.quic.maxBidiStreams` | 0.3.0 snapshot |
| `kuicksilver.quic.allowMigration` | `kuicksilver.http3.quic.migration.allow` | 0.3.0 snapshot |
| `kuicksilver.quic.maxUniStreams` | `kuicksilver.http3.quic.expert.maxUniStreams` | 0.3.0 snapshot |
