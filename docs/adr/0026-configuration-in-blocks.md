<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0026. Configuration in 0.3.0: blocks, one name per concept, strict configuration-file keys

Date: 2026-11-26. Status: accepted (owner decisions 2026-11-26); implemented in 0.3.0.

## Context

An audit of the configuration surface before 0.3.0-rc1 counted 297 options: the Kotlin builders of every layer, the two
Ktor engines, the `kuicksilver.*` keys of `EngineMain` and the system properties. The defaults were sound; the structure
was not:

- flat lists of 23 to 35 options, with the options most applications set next to RFC knobs, interop switches and test
  hooks;
- one concept in two to five places under different names: early data five times, the logger, qlog sink and connection
  listener three times each, the connection ID length and the QUIC idle timeout twice, `loops` and `udpSocketCount`;
- the client engine in blocks (`http3 { }`), the server engine flat (`quicMaxConnections`, `quicAcceptQueue`...);
- more than half of the options a new user needs first behind `@OptIn(ExperimentalKuicksilverApi::class)`;
- time as `Duration` in one place and `Int` seconds in another, and "off" spelled four ways (`null`, `0`,
  `Duration.ZERO`, `Duration.INFINITE`);
- options whose value follows from another (the HTTP/3 minimum of unidirectional streams, `enableConnectProtocol`, the
  0-RTT context, ALPN, SNI) settable by hand, with silent precedence rules.

0.2.x was withdrawn and has no users; 0.3.0 is not released. The owner decided (2026-11-26) to restructure before rc1, for
the best end state rather than the smallest change, without deprecated aliases in Kotlin or in the configuration file.

## Decision

The principles, checked by `tools/check/config-table.sh` and review:

1. **A first screen of about ten options per engine, all stable.** The top level of a Ktor engine's configuration holds
   only the options most applications set, and blocks. Tuning lives in topic blocks, RFC knobs and interop switches in
   `expert { }`, diagnostics in `observability { }`.
2. **One concept, one place, one name** on every level. A name inside a block does not repeat the block's
   (`http3 { hints }`, `pool { idleTimeout }`); the same meaning on both engines has the same name
   (`maxSessionsPerConnection`, `maxConnectionsPerIp`, `allowMisdirectedHosts`).
3. **Symmetry.** Both engines have `tls`, `http2`, `http3`, `webSockets` and `observability` blocks; a protocol is
   turned on and off with `enabled` inside its block.
4. **Derived options are not settable.** The low-level builders record which options were assigned explicitly, and a
   Ktor engine refuses an explicit assignment of an option it derives with an `IllegalArgumentException` that names the
   option and why (for example `http3 { quic { expert { maxUniStreams } } } is derived by the engine (RFC 9114 section 6.2)`).
5. **Time is a `Duration`** everywhere; in the configuration file a duration string (`30s`, `1h`, `PT30S`).
6. **One encoding of "off" or "no limit":** `null` of a nullable type in Kotlin, `off` in the configuration file, where
   `0` for such a key is refused with a hint. Three options where "off" is not the only special value get a sealed type:
   `RaceHeadStart`, `KnownServers`, `WebTransportProxyPolicy`.
7. **Types:** byte counts and stream counts are `Long`; a rate with a burst is one `RateLimit(perSecond, burst)`.
8. **Security is visible:** every option whose wrong value weakens security carries `@SecuritySensitive` (no opt-in,
   shown as 🔒 in the reference); one that can only weaken the default is also `@DelicateKuicksilverApi`.
9. **Experimental status is per block.** `expert { }` is always experimental. An experimental option inside a stable
   block is allowed only when its type is experimental or it is a separately enabled feature with an ADR of its own
   (h2c, coalescing, CONNECT-UDP, the HTTP/2 repeat-offender penalty); each such exception is listed in
   `tools/check/config-table.spec`.
10. **Reading a configuration is not user API.** The readers of `QuicConfig`, `QuicEndpointConfig`, `Http3Settings` and
    `Http2Settings` are `@InternalKuicksilverApi`; users build with the DSL and copy with `toBuilder()`. `TlsConfig`
    keeps public readers: `TrustConfig.Custom` implementations read them.
11. **No shims.** Old names are removed. The cost of migration is carried by the migration tables of the CHANGELOG and
    of `docs/guide/configuration.md`, by `tools/migrate/config-0.3.py`, and by start-up errors for old keys.

The layout itself (every block, field, type, default and status) is the one `docs/guide/configuration.md` documents.
Its outline:

- client engine: `connectTimeout`, and the blocks `tls { ech { } }`, `http3 { earlyData { } stall { } webTransport { }
  quic { } settings { } expert { } }`, `http2 { settings { } }`, `http1 { }`, `pool { }`, `network { }`, `proxies { tls { } }`,
  `webSockets { }`, `observability { }`;
- server engine: `requestHeaderTimeout`, and `tls { }` (with `pemFiles`, `clientCaFile`, `ocspStaplingFile`),
  `tlsConnector { tls { } proxyProtocol { } }`, `plainConnector { proxyProtocol { } }`, `http1 { }`, `http2 { settings { } }`,
  `http3 { earlyData { } webTransport { } quic { } settings { } endpoint { expert { } } }`, `webSockets { }`, `tcp { }`,
  `observability { }`;
- low level: `quicConfig { flowControl { } pathMtu { } datagrams { } migration { } expert { } }`,
  `quicEndpointConfig { observability { } runtime { } expert { } }` (the endpoint is the one place for the connection ID
  length and the qlog sink), `tlsConfig(role) { ech { } expert { } }`, `http3Settings { qpack { } webTransport { } expert { } }`,
  `http2Settings { floodLimits { } }` (a builder now).

**Configuration-file keys follow the server DSL** under `kuicksilver.` (`kuicksilver.http3.endpoint.maxConnections` is
`http3 { endpoint { maxConnections } }`). Exceptions: the TLS files (`kuicksilver.tls.certificateChain`, `privateKey`,
`clientCa`, `ocspStapling`, `echKeys`), the `kuicksilver.connector` block for the deployment port, and Ktor's own
`ktor.deployment.connectionIdleTimeoutSeconds`. Every key under `kuicksilver.` must be known: an unknown key, or one
0.2.x or an earlier 0.3.0 snapshot used, stops the start with a message naming the key to use instead. The 0.2.x scalar
`kuicksilver.http3 = true` gives way to the block `kuicksilver.http3 { enabled = true }`; a compromise name (`h3`,
`quic`) for the block was rejected, since it would break principles 2 and 3 for good to save one line of migration.

**Defaults that change**, each with its own test:

- the server engine speaks HTTP/2 on its TLS connectors by default (`http2 { enabled = true }`): ALPN offers `h2` and
  `http/1.1`; plain connectors and h2c are unchanged;
- the default logger is the platform's (`KuicksilverLogger.Default`: SLF4J on the JVM, Logcat on Android, `NSLog` on
  Apple platforms, standard error elsewhere, warnings and up); a server engine without a logger of its own logs to Ktor's
  `environment.log`;
- a Kuicksilver connector's `host` defaults to null: every interface of both families with one dual-stack socket per
  protocol (`::`), or `0.0.0.0` where the host has no IPv6, instead of `0.0.0.0`; Ktor's own connectors keep Ktor's
  `0.0.0.0`;
- the NEW_TOKEN replay register grows on demand up to `newTokenReplayCapacity` instead of being allocated in full at the
  first token;
- `Http3Settings.maxInformationalResponses`, ignored since 0.2.1, is removed.

The QUIC per-address limit keeps its default (256) and logs one warning per endpoint at most every 5 minutes when it
refuses a client; the client logs one warning when it first marks an HTTP/3 alternative broken on a network.

## Consequences

- Applications of 0.2.x and of 0.3.0 snapshots must change their configuration: the compiler finds every Kotlin change,
  `tools/migrate/config-0.3.py` makes most of them, and `EngineMain` names the replacement of every old key.
- The ABI dumps of `kuicksilver-quic`, `kuicksilver-http3` and `kuicksilver-http2` lose the readers; the Ktor engines'
  configuration classes change wholesale.
- Interop and h2spec runs exercise the server's default HTTP/2; the engine-interop matrix keeps HTTP/1.1 over TLS covered
  with explicit `http2 { enabled = false }` cells.
- The reference `docs/guide/configuration.md` gains a status column, the 🔒 column, the first-screen tables and the
  migration tables, all checked against the sources.

## Decisions made during implementation

The design left these cases open or met them only in the code; each was decided as follows.

- **Low-level QUIC builders in one step.** `QuicConfig` and `QuicEndpointConfig` were regrouped in one commit, so that the
  connection ID length and the qlog sink moved to the endpoint at the same time as they left `QuicConfig`. The endpoint
  applies its length and sink to its server's `QuicConfig` when it is built and to each client connection's;
  `QuicConfig` keeps them as internal values set by the endpoint. A connection-level qlog override (a `QuicConfig` with its
  own sink passed to `connect`) is gone; a sink sees each trace's connection ID and can keep them apart. The engine-level
  conflict between two connection ID lengths cannot arise any more, and its test was removed.
- **Readers keep their names.** The readers of `QuicConfig`, `QuicEndpointConfig`, `Http3Settings` and `Http2Settings` are
  `@InternalKuicksilverApi` (principle 10) and keep their old names and internal encodings (`maxIdleTimeout` of
  `Duration.ZERO` for none, `maxDatagramFrameSize` of 0 for off, `initialQueueCap`, `listener`): only builder names are
  user-facing, and the hundreds of internal reads did not need rewriting.
- **`TlsConfig.Builder` records no assigned options.** The Ktor engines' TLS blocks are typed (`ClientTlsConfig`,
  `ServerTlsConfig`) without the options they derive, so there is nothing to refuse there; ALPN and the server name are
  simply not in those blocks.
- **The client's QUIC handshake deadline is `connectTimeout`.** An application that set a QUIC `handshakeTimeout` other than
  its `connectTimeout` gets `connectTimeout` now (a wire-visible change for it). Tests that need a shorter QUIC handshake
  deadline than the connect timeout use an internal test hook.
- **The 0.2 client `tls` lambda ran any `TlsConfig.Builder` code** (generic alerts, session tickets, its own handshake
  timeout). The typed `tls { }` block offers the options of this ADR only; tests about the lambda running once per ECH
  entry were removed with the concept. `proxies { tls { } }` offers the proxy the `ech { configLists }` entry of the
  proxy's host.
- **Engine-level QUIC settings are blocks.** `http3 { quic { } }` configures a builder the engine owns; a prebuilt
  `QuicConfig` can no longer be handed to an engine, and tests build their transports as blocks.
- **WebTransport receive limits stay settable on the client.** The client derives `enabled` and `maxSessions` of
  `http3 { settings { webTransport { } } }` from `http3 { webTransport { } }` and refuses them, but keeps
  `initialMaxStreamsBidi`, `initialMaxStreamsUni` and `initialMaxData` settable there: they are the client's own receive
  windows and have no other place. The server, whose `http3 { webTransport { } }` block sets all of them, refuses every
  assignment inside `settings { webTransport { } }`.
- **Contradictions fail early.** The client refuses `http3 { enabled = false }` with `discovery = H3Only` when the engine is
  created; the server refuses at its start `clientAuth` without a client trust, `reloadInterval` without `pemFiles`, an
  identity given twice in one block, a TLS connector without an identity, and h2c on a port its identity turns into TLS.
  A connector whose TLS configuration is refused fails before it registers anything.
- **`RateLimit` needs at least one token a second.** The HTTP/2 mode "`resetsPerSecond = 0` never refills" is gone.
- **The first screen is compiled without opt-in.** Each engine module has a `jvmFirstScreenTest` compilation, outside every
  global opt-in and with warnings as errors, that holds the first-screen guide snippets: an experimental option on the first
  screen fails the build. It found `FileAltSvcStore(File)`, which is on the mobile first screen and was stabilized for it.
- **Client test fixtures turn the server's HTTP/2 off.** Most client tests drive the HTTP/1.1 path; with the server's new
  default, a missing client certificate over HTTP/2 fails the call with `Http2Exception.ConnectionClosed` carrying the TLS
  alert (and the diagnostics suppressed), where HTTP/1.1 threw the `TlsException` itself. The engine-interop matrix keeps
  HTTP/1.1 over TLS with one `http2 { enabled = false }` cell per client that offers `h2`.
- **One dual-stack socket everywhere.** `host = null` binds `::` with `IPV6_V6ONLY` off on every platform: the JDK binds
  `::` dual-stack on every platform, Windows included, and Kotlin/Native's `bindTcp` turns `IPV6_V6ONLY` off on `::`
  (Windows defaults it on), so the two-socket fallback of the design was not needed. An explicit `host = "::"` binds the
  same socket; only `host = null` falls back to `0.0.0.0` (logged at Info) where IPv6 cannot be bound (no IPv6 in the
  kernel, `java.net.preferIPv4Stack`). The resolved connector reports `::`, so Ktor logs `Responding at https://:::443`.
- **Old configuration-file keys are refused, never read.** `RENAMED_KEYS` holds the four 0.2.x keys and every renamed key of
  the 0.3.0 snapshots; `DERIVED_KEYS` refuses `kuicksilver.quic.maxUniStreams` as derived. Any other unknown key gets the
  closest name: a renamed key within 3 edits, else a known key within 3 edits, else the one known key with the same last
  name. The checks read Ktor's key list, so `application.yaml` takes the same keys (not covered by a test:
  `ktor-server-config-yaml` is not in the dependency verification metadata).
- **The migration script handles conditional values by hand.** `tools/migrate/config-0.3.py` rewrites a plain
  `discovery = H1Only` into `enabled = false` and reports a conditional one (`if (h3Only) H3Only else H1Only`) for a hand
  rewrite; the engine-interop and soak sites were rewritten by hand.
- **The checker knows the blocks.** `tools/check/config-table.sh` reads each documented class through its DSL path from a
  root declared in `config-table.spec`, so an experimental block makes its options experimental in the reference too; the
  exceptions of principle 9 are `#field-experimental` lines, the mapping tests are `#mapped` lines, and the classes without
  one (`TlsConfig.Builder` and its blocks, the constructor-configured `SessionTicketConfig` and `UdpProxyConfig`, the
  unchanged `CapsuleConfig.Builder`) carry an `#unmapped` reason.
