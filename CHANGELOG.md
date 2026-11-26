<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, any 0.x release may contain breaking changes.

## [Unreleased]

### Added

- WebTransport (experimental): `WebTransportSession.maxStreamErrorCode`, the highest application code of the session's
  stream resets and STOP_SENDING: 255 on a draft-02 session (draft-02 section 4.3), which browsers negotiate, 2^32-1 on
  later drafts.
- `kq` (`samples/kq-cli`, not published): a curl-like command line on the Ktor client engine, built as a native
  executable for macOS arm64, Linux x64 and arm64 and Windows x64. `kq get|head <url>` with `--http3`, `--http3-only`,
  `--http2`, `--http1.1`, `-i`, `-H`, `-o`, `--repeat`, `--0rtt`, `--qlog <dir>`, `--cacert`, `--alt-svc <file>` and
  `--connect-timeout`; `-v` prints for each response the protocol and why (`ProtocolDiagnostics`), the QUIC connection
  (handshake time, RTT, ALPN, the 0-RTT outcome, the QUIC version offered), the race and the `Alt-Svc` fields received,
  and a failed call's connect failures. Public API only. Its tests run kq against an in-process server over loopback on
  the JVM and macOS; the local gate runs them and builds every executable in a new step, `sample: kq-cli (tests, the kq
  executables)`, and hosted CI in the `apple`, `apple-native` and `linux-native` jobs.
- README: a "Features" section right after the status note (HTTP/3, HTTP/2 and HTTP/1.1; Alt-Svc, the protocol race and
  fallback; WebTransport and its drafts; QUIC and HTTP datagrams; ECH; CONNECT-UDP; 0-RTT; connection migration; RFC
  compliance; interop; qlog), each linked to the page behind it, and the samples; the same list as keywords in
  `llms.txt` and in the summary of `llms-full.txt` (`tools/check/llms-full.sh`).
- Ktor client: connection coalescing across origins, opt-in and off by default (experimental;
  `pool { coalescing = true }`, ADR-0018, `docs/guide/ktor.md`, "Connection coalescing"). An `https` request may go on
  another origin's HTTP/2 or HTTP/3 connection when both conditions of RFC 9110 section 4.3.3 hold. Before, every
  origin had connections of its own.
  - The address: the request's host resolves, at each request, to the address and port the connection is connected to
    (over HTTP/3 the name of the request's own HTTP/3 endpoint).
  - The certificate: the chain the server presented passes every check a new connection to the host would make (RFC
    9113 section 9.1.1, RFC 9114 section 3.3): trust, pins, name, validity and a fresh staple where one is required, once
    per connection and host. A failure that holds for the connection's own origin too (expired, revoked) retires the
    connection and is logged at Warn.
  - A 421 to a coalesced request sends it once more on a connection of its own origin (RFC 9110 section 15.5.20); a
    streamed body already consumed fails the call with `H3BodyConsumed`.
  - Never through a proxy, for a WebSocket or WebTransport session, over h2c, under `TrustConfig.Tofu` or
    `TrustConfig.ExpectedName`, or on a 0-RTT connection. An ALTSVC frame on a request stream of a connection that carried
    another origin is ignored, and on an HTTP/2 connection other origins may share `cookie` is never indexed by HPACK.
- Ktor client, HTTP/2 and the TLS socket (experimental): `ConnectionEndedException` (package `io.kuicksilver.io`, in
  `kuicksilver-native`) says who ended a TCP connection under a call, so callers no longer match message strings.
  `PeerClosed` is the peer's FIN where more was expected, an HTTP/1.1 response cut short included (the cause of the
  `EOFException` it always was); `PeerUnresponsive` is an HTTP/2 PING unanswered (keepalive or health check), or the
  socket or WebSocket connect timeout while only the server's answer was awaited; `LocalClose` is this client closing
  the connection or reading after its close. The sites that threw a plain `IOException` for these throw them now, the
  TCP socket's own `Socket closed` and `The connection was aborted` included; the messages are unchanged and the types
  are still `IOException`s. A reset stays the platform's exception (`SocketException` on the JVM and Android, the
  receive error on Kotlin/Native). An HTTP/2 call sees one as the cause of `Http2Exception.ConnectionClosed`
  (`docs/guide/ktor.md`, "Who ended the connection"). `kuicksilver-native` now depends on `kotlinx-io-core`, which every
  other module already used.
- Ktor client (experimental): `AltSvcStore.originOf(url)` gives the origin key the engine stores a URL's alternatives
  under, in the one canonical form the `AltSvcStore` KDoc now states: `scheme://host:port` with the host's ASCII letters
  in lowercase (a trailing dot kept, an internationalised name as given), an IPv6 address in brackets in RFC 5952 text
  and the port always written. A store that seeds or looks up an origin no longer has to rebuild the engine's format.
- QUIC (experimental): `QuicConnection.version` and `ConnectionInfo.version` say which QUIC version the handshake settled,
  `VersionProfile.V1` or `V2` (RFC 9369); null until then. With both versions configured it can differ from the one the
  client's first flight offered (compatible version negotiation, RFC 9368). The Ktor client's `QuicConnectionSnapshot`
  carries it as `version`.
- HTTP/3 qlog: `http:capsule_created` and `http:capsule_parsed` (draft-ietf-quic-qlog-h3-events-14 section 6) for every
  capsule on an Extended CONNECT stream. Each event carries the capsule's type and lengths, never its value, so a trace
  shows a WebTransport WT_CLOSE_SESSION (0x2843) without its reason.
- QUIC qlog: `transport:parameters_set` (quic-events-04 section 5.3) for our transport parameters and the peer's, on both
  roles, once the peer's arrive. It carries `max_datagram_frame_size`, `reset_stream_at` and `grease_quic_bit` as the
  unspecified fields the section allows. Before, a trace could not show what the peer sent, `reset_stream_at`
  included.
- WebTransport (experimental): `WebTransportSendStream.reset(code, reliableOffset)` resets a stream but still delivers
  its first `reliableOffset` bytes to the peer's application, however many packets are lost. This is "abort send side"
  with an offset (draft-ietf-webtrans-overview section 4.3), carried by RESET_STREAM_AT with the stream's header plus
  the offset as its Reliable Size (draft-ietf-webtrans-http3-17 section 4.4).
  - An offset beyond the bytes written before the call is cut to them. The reset goes also after `output` was closed.
  - Sending the reliable bytes may wait for the peer's flow-control credit without a deadline. A later `reset(code)`
    takes over at once and keeps only the bytes already sent.
  - On a draft-02 session, which has no RESET_STREAM_AT, an offset above 0 throws IllegalStateException.
  - A stream reset by the peer now reads the bytes the transport delivered before the reset, then fails with
    `StreamReset`. Before, a reset that arrived before the application read them dropped them.
- QUIC: a configurable datagram size for tunnels such as WireGuard and NAT paths (experimental; `docs/guide/quic.md`,
  "Tunnels and NAT paths"): `quicConfig { pathMtu { initial } }` (1200 by default; less is refused, RFC 9000 section 14) is the
  size a connection's first path starts with on a socket that sets DF, Initial padding included, and
  `pathMtu { maxSend }` (no cap by default) the largest datagram sent, DPLPMTUD probes included (RFC 8899
  section 4.4). The start is lowered to both limits, `pathMtu { maxReceive }` and the peer's `max_udp_payload_size`; black-hole
  detection watches it from the first datagram, judging datagram sizes (coalesced packets included), so a size the path does
  not carry falls back to 1200 at the first PTO while nothing was acknowledged (two PTOs afterwards), during the handshake
  too, and comes back if the large datagram is acknowledged after all. A 0-RTT flight keeps to the remembered
  `max_udp_payload_size` (RFC 9000 section 7.4.1). DPLPMTUD searches on from the
  start; with `pathMtu { discovery = false }` the start is the ceiling (before, turning discovery off meant 1200; it still does by default). A
  path to a new IP address starts at 1200.
- Ktor server engine: `EngineMain` reads the QUIC transport of the HTTP/3 listeners from `kuicksilver.http3.quic.*`:
  `pathMtu.initial`, `pathMtu.maxSend`, `pathMtu.maxReceive`, `pathMtu.discovery`, `maxIdleTimeout`, `handshakeTimeout`,
  `keepAlive`, `maxBidiStreams` and `migration.allow` (`docs/guide/configuration.md`, "HOCON keys"). An unknown key
  under `kuicksilver.`, a value that does not parse and one out of range fail the start with an
  error naming the key.
- Ktor client: stall detection on HTTP/3 connections (experimental `http3 { stall { enabled } }`, on by default, with
  `probeTimeouts`, 3, `minSilence`, 2 s, and `abandonAfter`, 10 s; `docs/guide/ktor.md`, "Stalled HTTP/3
  connections"), after a field report from a network that cuts UDP flows: a request on an HTTP/3 connection the engine
  chose over TCP (`Auto`, `Preferred`, `http3 { hints }`) waited for the QUIC idle timeout (30 s) when the flow was cut after
  the handshake, and a 0-RTT request into a path that drops UDP waited for the connect timeout (10 s). Now a connection
  whose probe timeouts go unanswered (3 in a row, RFC 9002 section 6.2) with no packet from the server for 2 s, or,
  before the handshake, with no answer at all for 2 s and two probe timeouts, is drained: it takes no new request, its
  alternative is marked broken (RFC 7838 section 2.4), and a request that may be repeated (idempotent, RFC 9110
  section 9.2.2, a replayable body, no response yet, or never sent) goes over TCP at once
  (`FallbackReason.QuicStalled`). Other work (a POST, a response body being read) waits up to `stall { abandonAfter }` for
  the path to come back (a handover, Wi-Fi roaming) and then fails with `QuicStalledException`; a response that arrived
  whole is never touched. A quiet watched connection sends a PING now and then (RFC 9000 section 10.1.2; at most every
  half of the idle timeout in force) so that a slow server or an idle long-lived response (which acknowledge it) is never
  taken for a stall while a path cut with nothing in flight still shows. `H3Only`, WebSockets and WebTransport are not
  watched.
- QUIC: `QuicConnection.ping()` (experimental) sends one PING to test the path for liveness (RFC 9000 section 10.1.2);
  on a dead path it leads to probe timeouts (`stats.ptoCount`) where a quiet connection shows none.
  `ConnectionStats.idleTimeout` (experimental) is the idle timeout in force, the smaller of both sides'.
- HTTP/3: `Http3Response.bodyReceived` (experimental) completes once the whole response arrived: its FIN and every byte
  before it are local (the request stream's "Data Recvd" state, RFC 9000 section 3.2), however little the application
  read of it yet.
- QUIC: the connection IDs on each path (experimental, `docs/guide/quic.md`, "Observability"). `ConnectionInfo.paths`
  lists the connection's paths, the active one first, as `PathInfo`: the path's id, local and remote address, state,
  and our and the peer's connection IDs on it with their sequence numbers; `ConnectionInfo.pathChanges` counts the moves
  to another path. `ConnectionListener.onPathsUpdated` hears each new list (an ID rotated, a path added, validated,
  closed or made active, an address changed), and `QuicConnection.info` returns the connection's `ConnectionInfo`. The
  list is there from the connection's creation (the handshake's IDs first), is rebuilt on the loop only when it changed
  and read from any thread without a lock; a client notes which of its
  IDs the server's packets carry with one comparison per 1-RTT packet. Connection IDs are linkable identifiers: the
  library never logs them and `PathInfo.toString()` leaves them out.
- Ktor client: which connection served a call (experimental, `docs/guide/ktor.md`, "Which connection served this
  call?"). `ProtocolDiagnostics.connection` is a `QuicConnectionSnapshot` (the connection's `connectionId`, the
  `ConnectionInfo.id` the `connectionListener` hears, the active path with its connection IDs, every path, the smoothed
  and minimum RTT and their variation, and the path changes during the call: plain data, no handle that would keep the
  connection in memory) or a `TcpConnectionSnapshot` (protocol, addresses, ALPN, proxy, reuse); an HTTP/3 call's is read
  live during the call and kept as one snapshot from its end. `ProtocolDiagnostics.transport` says
  `Quic` or `Tcp`.
- Ktor client: which transport a failed call came from (experimental, `docs/guide/ktor.md`, "Why did this call fail?").
  `Throwable.kuicksilverDiagnostics` returns the failed call's `ProtocolDiagnostics` (on the exception or a cause): its
  `transport`, HTTP/3's failure when TCP came after it (`h3Failure`, now also when both setups failed), the connection the
  failure came from, and `connectFailures`, every connection setup that failed (`ConnectFailure`: transport, stage
  `TcpConnect`, `ProxyHandshake`, `TlsHandshake` or `QuicHandshake`, address, cause). The new
  `KuicksilverEventListener.connectFailed` reports each one as it happens, so a TCP or TLS handshake that fails — a
  `protocol_version` alert from a TLS 1.2-only server, say — is reported with its address although `protocolSelected`
  never comes for it. The connect timeout is reported too, per attempt it cut short and at the step it was in, or as
  what the time went to before an address was tried (`NameLookup`, `PoolWait`, `H2DialWait`); a QUIC failure says how
  far the handshake got (`QuicHandshakeProgress`: no packet from the server, or started) and names its connection
  (`connectionId`, tied to the attempt by the connection its own `connect` created, not by address); a handshake
  that fails after a 0-RTT start and a SOCKS5 refusal that moves on to the next address are reported as well. Through a
  CONNECT-UDP proxy each step is reported at the proxy's address with `viaProxy`: the QUIC handshake with each of its
  addresses, the CONNECT-UDP request (`ProxyHandshake`) and the origin's handshake through the tunnel. Ktor's
  `HttpRequestTimeoutException` carries the diagnostics like any other failure.
- TLS: Encrypted Client Hello (RFC 9849; experimental; in the Ktor engines too, see below).
  Clients: `tlsConfig(role) { ech { configList } }` (`EchConfigList.parse`, `parseBase64`: the `ech` parameter of an HTTPS record,
  RFC 9848; unusable ECHConfigs are ignored one by one, and `build()` refuses a list with none usable, or any list in a
  build without ECH, each with its own message), GREASE ECH by default (`ech { grease }`), `TlsException.EchRejected`
  with the server's retry configurations after an authenticated rejection, the certificate checked against the
  `public_name` then (a platform or custom verifier is asked for that name), `echStatus` on `TlsConnection` and
  `QuicTlsSession`. Servers: `echKeys` (`EchServerKeys` of `EchKey`s, the PEM `openssl ech` writes, kept in native memory; given as a `ByteArray` or
  `CharArray` it is zeroed once read)
  with `rotate`, shared mode only. Over QUIC and TCP, TLS 1.3 only. During a rejection the certificate is checked for the
  `public_name` by the base trust alone: the origin's pins (`TrustConfig.Pinned`) do not apply to it, and
  `TrustConfig.Tofu` needs a key stored for the `public_name` (a rejection is no first contact, and stores nothing).
  Session tickets of connections with ECH and without it are cached apart, never offered on the other kind.
  With ECH accepted, `TrustConfig.Platform` verifies offline (RFC 9849 section 10.7): Windows retrieves URLs and
  revocation from its cache only, Apple turns off SecTrust's network fetches, and the JVM builds the path from the
  presented certificates under the default anchors and checks it with a PKIX `CertPathValidator`, revocation off, so
  neither an OCSP/CRL request nor an AIA fetch goes out whatever the process set. A `TrustConfig.Custom` verifier gets a
  `VerificationContext` (`CertificateVerifier.verify` overload, experimental) with `hiddenName` and `echPublicName`.
- Ktor client: Encrypted Client Hello (experimental, `ech { }`, `EchClientConfig`; docs/guide/ktor.md, "Encrypted Client
  Hello"). Each connection offers the `ech` parameter of the HTTPS record of its endpoint (RFC 9848, `fromHttpsRecords`,
  on by default with `http3.httpsRecords` in `Auto`), else `configLists` for the host, else GREASE (`grease`, on by
  default), over TCP and HTTP/3 and inside a proxy's tunnel; a `configLists` entry with nothing usable (or any, in a build
  without ECH) fails the engine's creation. A rejection is retried once on a new connection with the
  server's retry configurations, or without ECH when it sent none; a rejected retry fails the request
  (`TlsException.EchRejected` in its causes). A 0-RTT request on a rejected connection is sent again on the retry (a `retry` event and one more
  `ProtocolDiagnostics.attempts`). With the
  records' ECH no ClientHello goes out before the records resolved (the request waits up to the connect timeout instead of
  `network { httpsRecordWait }`), and a request whose endpoints all have `ech` never falls back to a connection without it. The
  SVCB codec reads the `ech` SvcParam (a malformed value drops the RRset, `mandatory=ech` is compatible when the value has a usable ECHConfig) and an ECH
  rejection no longer marks an HTTP/3 alternative broken.
- Ktor server: `KuicksilverTlsConnector.Builder.echKeys` (experimental) for TCP and HTTP/3, rotated with
  `EchServerKeys.rotate`, and the `EngineMain` key `kuicksilver.tls.echKeys` (PEM files; docs/guide/ktor.md, "Encrypted
  Client Hello on the server"). During a rejection the `sniSelector` is asked for the `public_name`.
- Native layer: `ksl_udp_get` answers `KSL_UDP_GET_WAITS` (`KslConst.UDP_GET_WAITS`), the waits a receive began for a
  datagram, counted before each `poll` (POSIX) or `WSAPoll` (Windows) alike; additive in ABI 7. A test uses it to close a
  socket while its receive is in the native wait on every platform.
- Ktor client: `https://` proxies, TLS to the proxy itself (experimental; `docs/guide/ktor.md`, "Proxies"; ADR-0023):
  `ResolvedProxy.https(host, port, credentials)`, an `https://` proxy URL off the JVM, `https://` values of `https_proxy`
  and the other variables (port 443 by default), an `https://` entry of Windows' Internet settings and a PAC answer's
  `HTTPS host:port` (Chromium's extension), where 0.2 failed the request. The CONNECT or absolute-form request, its
  `Proxy-Authorization` and the origin's name travel only inside TLS with the proxy; the proxy's certificate is verified
  against the proxy's host (RFC 9525, SNI per RFC 6066 section 3), with the new `proxies { tls { } }` block, or by default the
  origin's trust without its `ExpectedName` and pins and without the client certificate; ALPN offers `http/1.1` only (no
  CONNECT over HTTP/2). The origin's TLS runs inside the tunnel unchanged (TLS in TLS, `h2` included). A failed handshake
  with the proxy is the new `ProxyTlsException` (a `ProxyException`, which is now open and takes a cause); an origin
  failure stays its `TlsException`. The pool keys routes by the proxy's scheme too. HTTP/3 never goes through a proxy
  (threat model 3.28). A request's own `Proxy-Authorization` is no longer sent in HTTP/2 or HTTP/3 fields (they go to
  origins only; through a tunnel it had reached the origin over HTTP/2), nor over HTTP/1.1 to an origin reached
  directly (before, only a tunnel dropped it). On the JVM and Android an HTTP `java.net.Proxy` on port 443 as the
  explicit `proxy` fails each request with `UnsupportedOperationException` instead of being spoken to in clear (it has no
  scheme: `ProxyBuilder.http(Url("https://..."))` produces it). Connections to an `https://` proxy resume TLS sessions
  from a ticket cache of their own.
- Documentation site: "How we verify" pages for each release (`/<version>/verify/`, also in Russian and Simplified
  Chinese), generated by `tools/docs/verify.py` from the CI run of the release commit: test counts per Kotlin target and
  CI host, the engine interop pairs (client × server × wire), h2spec and the QUIC Interop Runner where they ran, fuzz
  targets and corpora, artifact sizes, benchmarks with where and when they were measured, and the RFC compliance summary;
  each page names the commit, the run and its date, and data of another commit is refused. Every `build.yml` job uploads
  its counts as a `verify-<job>-a<attempt>` artifact; a rebuild after they expired keeps the published pages. The site
  also has `/dev/`, the development snapshot of `main`'s tip (guide, API reference and verification pages of one green
  `build.yml` push run, each page marked "development snapshot of <sha>, not a release"), published after every such
  run or by hand for a commit on `main`; `/latest/` stays the newest release. Hosted CI now also runs h2spec
  against the linuxX64 server (the image pinned by digest in `tools/interop/h2spec.sh`, checked by `pins.sh`) and builds
  the release `Kuicksilver.xcframework`, whose slice and zip sizes the pages show.
- Ktor client: a pluggable name resolver (experimental `dns`, after OkHttp's `Dns`; `docs/guide/ktor.md`, "Name
  resolution"): `Dns.System` (the default, the system's resolver exactly as before), `Dns.blocking { }` for a blocking
  resolver (run on a pool of 8 threads shared by every such resolver of the process, or a dispatcher you give; a caller
  that gives up takes its queued lookup off the pool), `FamilyDns` for one that answers IPv6 and
  IPv4 separately (RFC 8305 section 3), or any `Dns` returning `IpAddress`es (`IpAddress.of(InetAddress)` on the JVM and
  Android). It resolves the origin over TCP and QUIC, an `Alt-Svc` alternative, an HTTPS record's target and a proxy's
  name, never an IP literal nor the origin behind an HTTP or `socks5h` proxy; it is asked once per name per request and
  bounded by the connect timeout. Its answers are sorted by RFC 6724 and raced with Happy Eyeballs like the system's;
  duplicates, unspecified, multicast and broadcast addresses are dropped and at most 32 addresses per family kept; a
  failure or an empty answer fails the connection as an unresolvable name does. SNI and certificate verification use the
  host name, never the answer (threat model 3.25, ADR-0020).
- Ktor client: DNS events on `KuicksilverEventListener` (experimental), as OkHttp's `dnsStart` and `dnsEnd`: one pair per
  name lookup the engine makes, through the system's resolver (per address family) or `dns` (per family for a
  `FamilyDns`, once for both with a plain `Dns`); `dnsEnd` carries the addresses the engine may connect to, or the
  failure (a cancellation included). An address literal is no lookup and has no events.
- Ktor server engine: the PROXY protocol (HAProxy, versions 1 and 2) on TCP connectors, experimental and off by default:
  `proxyProtocol { trust("10.0.0.0/8") }` on `plainConnector { }` and `tlsConnector { }`, and
  `kuicksilver.connector.proxyProtocol.trustedSources`, `.headerTimeout`, `.maxHeaderSize` for `EngineMain`'s deployment port.
  Every connection of such a connector must start with a header from one of the trusted sources, before the TLS
  handshake on a TLS connector; any other peer is closed at accept, and a missing, malformed, oversized (version 1: 107
  bytes; version 2: `maxHeaderSize`, 4096 by default) or late (`headerTimeout`, 5 s, at least 3 s) header resets the
  connection (`connectionRefused` reasons `PROXY protocol untrusted source` and `PROXY protocol header`). A LOCAL header
  (a health check) is accepted with any length and family. Version 2 TLVs are checked to fit their block, a CRC32c TLV is
  verified, and the header is `call.request.proxyHeader`. The client it names becomes `call.request.origin` on HTTP/1.1
  and HTTP/2 while `call.request.local` keeps the TCP peer, and `http2 { repeatOffenderPenalty }` counts that client, never
  the proxy. HTTP/3 takes no header. A fuzz target (`server.proxyHeader`) covers the parser. ADR-0022; threat model 3.27.
- `kuicksilver-ktor-network`: `Socket.tlsServer(config, input)` (internal API) runs a TLS server on a socket whose read
  channel the caller already opened and read a prefix from.
- `tools/check/rfc-table.sh` takes `spec-<name>` in the RFC column for a specification outside the IETF;
  `tools/check/rfc-table-test.sh` holds its negative controls (in the gate and the hosted lint job).
- Configurable key-exchange groups (RFC 9846 sections 4.3.7 and 4.3.8): `TlsConfig.Builder.keyExchangeGroups`
  (`KeyExchangeGroups`, experimental) takes the groups most preferred first, from `X25519MLKEM768`,
  `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`, `x25519`, `x448`, `secp256r1`, `secp384r1` and `secp521r1`, and a client's
  `keyShares` (1 to 4; left out, the first group and the first later one of the other kind, hybrid or classical, as
  BoringSSL does). An unknown name, a duplicate, an empty list or shares outside it throw `TlsException.Config` when made;
  a group the OpenSSL in use lacks, shares on a server and `Tls12And13` without an elliptic curve when the configuration
  is built. A server picks by its own order: the first of its list the client sent a key share for, else a
  HelloRetryRequest for the first of its list the client supports, `handshake_failure` (40; over QUIC CRYPTO_ERROR
  0x0128) with none in common; an `sniSelector` answer may bring its own list (`ServerTlsOverride.keyExchangeGroups`), and
  the Ktor TLS connector has `keyExchangeGroups` for TCP and HTTP/3 (and `EngineMain` the key
  `kuicksilver.tls.keyExchangeGroups`, a list of names, for the deployment port). In TLS 1.2 a client's list also names
  the curves of ECDSA certificates it accepts (RFC 8422 section 5.1). `TlsConnection.keyExchangeGroup`,
  `QuicTlsSession.keyExchangeGroup` and `QuicConnection.keyExchangeGroup` report the group a handshake used (none for
  a TLS 1.2 abbreviated handshake). The default
  list and key shares are unchanged; a client that sends several key shares now gets the server's first of them, where
  OpenSSL took the client's order among them before. `ksl`: `ksl_ctx_set_groups` and `KSL_GET_GROUP`, additive under ABI
  7. Docs: [TLS: Key exchange groups](docs/guide/tls.md#key-exchange-groups).
- qlog: HTTP/3 and QPACK events in the connection's trace, in the schema of its transport events (qlog 0.3,
  draft-ietf-quic-qlog-h3-events-04; ADR-0021): `http:frame_created`/`frame_parsed` for every frame sent and read (field
  sections with their fields, SETTINGS, GOAWAY, push identifiers, reserved and unknown frames, PRIORITY_UPDATE as a
  `priority_update` frame, WebTransport's stream signal as an unknown frame with its Session ID), `http:stream_type_set`,
  `http:parameters_set`, `http:parameters_restored`, `qpack:state_updated` and `qpack:stream_state_updated`. Header and
  trailer values are written as `[redacted]` (except `:method`, `:scheme`, `:status`, `:protocol`) unless the sink sets
  the new `QlogSink.logHeaderValues` (*experimental*; `DirectoryQlogSink(..., logHeaderValues = true)`, forwarded by
  `AsyncQlogSink`); threat model 3.26 (CWE-532). The HTTP/3 layer queues its events (at most 4096 per connection) and the
  endpoint loop writes them, so sinks are still called on the loop only; a connection without a sink formats nothing.
  The traces are checked offline against the draft's definitions; loading them in qvis was not part of the tests.
- qlog: the trace header's `common_fields` give `protocol_type` (`["QUIC"]`, or `["QUIC","HTTP3"]` when the ALPN list
  offers `h3`) and `reference_time` (0, the trace's start), and times never go back from one record to the next
  (draft-ietf-quic-qlog-main-schema-05 sections 3.4.1 and 3.4.7, quic-events-04 section 2).
- h2c: HTTP/2 over cleartext TCP with prior knowledge (RFC 9113 section 3.3), opt-in on both Ktor engines (experimental;
  ADR-0018, which supersedes ADR-0017's "no h2c"). Client: `http2 { priorKnowledge = setOf(HostPort(host, port)) }`
  sends the connection preface at once to the `http://` origins listed, without TLS, ALPN or `Upgrade: h2c`; every other
  `http://` request stays HTTP/1.1, `https://` always negotiates by ALPN, a listed server that does not answer with
  SETTINGS fails the call (no fallback), an HTTP proxy is passed in a CONNECT tunnel, and no ALTSVC frame or `Alt-Svc`
  of an `http` origin is learned. Server: `plainConnector { h2c = H2cMode.WithHttp11 }` serves HTTP/1.1 and h2c on one
  port, told apart by the 24-octet client preface (looked at as it arrives, nothing consumed, a request shorter than the
  preface never held back, the wait within the request-head deadline), `H2cMode.Only` h2c alone (anything else is a
  PROTOCOL_ERROR); `EngineMain` key `kuicksilver.connector.h2c` (`off`, `withHttp11`, `only`), refused with the TLS identity
  files, as h2c is on a connector the configuration's identity turns into TLS. Every HTTP/2 setting, limit, deadline,
  flood defence, RFC 9218 priority and RFC 8441 WebSocket applies as over TLS; the call's scheme is `http`, and
  `:scheme https` over h2c gets 421 unless the connector's clients are trusted gateways. A `ws://` WebSocket to a listed
  origin with no h2c connection opens one (pooled) and goes as an RFC 8441 Extended CONNECT when the server's SETTINGS
  allow it, else as an HTTP/1.1 Upgrade. `Upgrade: h2c` (deprecated by
  section 3.1) is never sent, and a request that offers it is served as HTTP/1.1. Cleartext: only behind a trusted
  network or proxy (threat model 3.23.1, CWE-319). Interop: OkHttp's `H2_PRIOR_KNOWLEDGE`, Ktor's OkHttp engine and
  curl `--http2-prior-knowledge` against the server, the client against Netty and Ktor's Netty engine (`enableH2c`);
  `tools/interop/h2spec.sh` runs h2spec over h2c too (`--tls`, `--h2c`; both by default).
- TLS certificate compression (RFC 8879), on by default for clients and servers over QUIC and TCP: a client offers
  brotli, then zlib, a server sends its chain compressed with the first of the client's algorithms (compressed once per
  identity, when its context is built) and offers the same for client certificates. Over QUIC the smaller chain keeps
  more of a server's first flight inside the amplification limit (RFC 9000 section 8.1): the test chain of 13.7 KB goes
  from a first flight of 15,523 bytes, held at three times the ClientHello until the client is heard again, to 2,689
  bytes sent at once. `TlsConfig.Builder.certificateCompression` (experimental, default true) turns it off;
  `TlsConnection.peerCertificateCompression` and `QuicConnection.peerCertificateCompression` (experimental) tell what the
  peer's chain came in. What a peer sends is held to the certificate list bound of 100 KiB, compressed or not: an
  announced length above it is `bad_certificate` before anything is decompressed, as is a length that does not match or data
  that does not decompress; brotli's decoder, which sized its ring buffer by the stream's own claims (16.8 MiB from 68
  bytes), allocates at most 3 times the announced length plus 256 KiB; an algorithm not offered is `illegal_parameter`
  (threat model 3.30, CWE-409). A server session that staples an OCSP response
  sends its Certificate uncompressed, since the chain compressed beforehand has no response in it. ksl ABI 7, additive:
  `KSL_OPT_CERT_COMPRESSION`, `KSL_GET_CERT_COMPRESSION`, `KSL_GET_CERT_COMPRESSORS`. A context whose OpenSSL has no
  algorithm (a system OpenSSL without zlib and brotli) starts with it off, and asking for it is `KSL_E_NOT_SUPPORTED`.
- CONNECT-UDP (RFC 9298, Proxying UDP in HTTP), experimental, in `kuicksilver-http3` over HTTP/3: a client opens a UDP
  tunnel through a proxy with `Http3Connection.connectUdp(UdpProxyTemplate, host, port)` and sends and receives UDP
  payloads as HTTP datagrams with Context ID 0 (QUIC DATAGRAM frames, or DATAGRAM capsules when HTTP/3 datagrams are not
  negotiated); `UdpTunnel.asDatagramIo()` makes the tunnel the UDP socket of a `QuicEndpoint` or `Http3Endpoint`, so QUIC
  and HTTP/3 run end to end through the proxy (proxied QUIC, the MASQUE use). `UdpProxy.serve` is the proxy: the URI
  Template of section 2 (the well-known `/.well-known/masque/udp/{target_host}/{target_port}/` by default), DNS before the
  answer with `proxy-status` on errors, only globally reachable unicast targets by default (`UdpTargetFilter.PublicOnly`;
  loopback, private, link-local, multicast and broadcast refused, CWE-918), source validation, Not-ECT, a link-MTU limit,
  per-tunnel rate and unanswered-packet limits, tunnel limits in all and per client, and a two-minute idle timeout.
  HTTP/1.1 (sections 3.2, 3.3) and HTTP/2 (sections 3.4, 3.5) are not offered (ADR-0024). The ICMP Packet Too Big of
  section 6.1 is sent where the process may open a raw ICMP socket (Linux and Android with CAP_NET_RAW; `ksl_icmp_*`,
  additive under ABI 7; `UdpProxyConfig.packetTooBig`, on by default, `UdpProxyStats.packetTooBig` says whether it
  applies), through one raw socket per family for the proxy, rate-limited per target address across tunnels and over
  the proxy; without the privilege the payload is dropped and counted only. The proxy refuses its own
  addresses by default, keys clients by IPv4 address or IPv6 /64 with a rate shared by a client's tunnels and an
  unanswered budget per client and target, runs at most 16 blocking name lookups (4 per client), drops a target datagram above the
  link MTU whole and closes a tunnel on an ICMP port unreachable for its target that quotes a payload it sent (Linux and
  Android; RFC 8085 section 5.2). The Ktor client keeps
  tunnelled connections' session tickets apart from direct ones and has its own WebTransport switch for the CONNECT-UDP
  proxy (`http3 { webTransport { proxyPolicy } }`); the Ktor
  engines use it: the client's `proxies { connectUdp = ConnectUdpProxy(template) }` sends the `https` requests it applies to
  over HTTP/3 through a tunnel (never over TCP or directly, no Alt-Svc), and the server's `http3 { connectUdp = true }` with a
  `connectUdp(proxy)` route serves CONNECT-UDP through Ktor's pipeline, behind the application's authentication. Template
  and datagram parsing are fuzzed (`http3.udpTemplate`, `http3.udpDatagrams`).
- Building from source: the native build scripts (`tools/build-jni.sh`, `tools/build-android-so.sh`,
  `tools/build-ksl-a.sh`, `tools/openssl/build.sh`) add the builder's `CPPFLAGS`, `CFLAGS` and `LDFLAGS` after their own
  flags, and use `CC` where the compiler is the host's (the JNI library on macOS and Linux, `libksl.a` for macOS); the
  Gradle tasks rebuild when they change. OpenSSL gets them as `Configure` options: before, its `Configure` read them from
  the environment in place of the target's own flags, while the build cache and `configure-target.txt` ignored them, so
  a build with them could be served from the cache of one without. Words `Configure` would read as its own options
  (`--prefix=`, `-no-<feature>`, `-shared`, ...) are refused, no flag is glob-expanded, and one word in
  `configure-target.txt` stands for all the flags (paths included) and, for macOS, `CC`, so a prebuilt OpenSSL is reused
  only with the same ones; Android, iOS and mingw builds of OpenSSL ignore `CC`. Releases, the double build and
  `tools/verify/verify-release.sh` build with them unset, and with every other variable that changes a native build
  (`CCC_OVERRIDE_OPTIONS`, `CPATH`, `SDKROOT`, `OPT`, `AR`, `MAKEFLAGS`, OpenSSL's `__CNF_*`, ...; the list is
  `tools/clean-build-env.sh`), which before reached the release's compilers unchecked. `KSL_KEEP_DEBUG=1` leaves the
  JNI and Android libraries of a local build unstripped (with `CFLAGS=-g`, with their debug information); a release
  never sets it. `docs/guide/building.md` describes it;
  `tools/check/native-flags-test.sh` checks it in the gate's reproducibility step.
- Building from source: the Apple builds (macOS, including the macos-arm64 and macos-x64 JNI libraries, and iOS) archive
  OpenSSL, `libksl.a` and the test hooks with the NDK's `llvm-ar`, so they now need the NDK (or `LLVM_AR` naming an
  `llvm-ar`) as well: Xcode's `ranlib` leaves uninitialised bytes in an archive's index, which made two builds of the
  same `libcrypto.a` differ and the double build fail. The archiver is part of the OpenSSL target line (`ksl-ar=llvm-ar`),
  so `-Pkuicksilver.openssl.prebuilt` refuses an older, Xcode-indexed build. The shipped klib archives are rewritten by
  `llvm-objcopy` either way, so no published byte changes. A release, the double build and `verify-release.sh` take the
  LLVM tools from the pinned NDK only (`KSL_PINNED_NDK`, `tools/check/llvm-tool.sh`) and fail without it, instead of
  falling back to another NDK, `PATH` or Homebrew. The Docker Linux OpenSSL archives use GNU ar's deterministic mode
  (`ar D`, `ranlib -D`): they held each build's timestamps. `tools/check/double-build.sh` names the archive members that
  differ (`tools/check/ar-diff.py`).
- QUIC and HTTP/3 servers pick their certificate per SNI name: `TlsConfig.sniSelector` works over QUIC as over TCP (RFC
  6066 section 3), and a Ktor `tlsConnector` with an `sniSelector` now serves HTTP/3 and sends `Alt-Svc` (it served
  HTTP/1.1 only, with a warning). The QUIC handshake pauses at the ClientHello (`DriveResult.WantSni`); the endpoint runs
  the selector off the connection's loop (`QuicTlsSession.selectSni`, `resumeSni`; `ConnectionEvent.SniRequested` and
  `ConnectionCore.resumeSni` for sans-IO cores and `Simulator`) and cancels it when the connection ends first. The chosen
  identity's chain, key, client-certificate policy, trust and OCSP staple answer the handshake
  (`QuicConnection.localCertificates`); `null` for a name ends it with CRYPTO_ERROR `unrecognized_name` (0x170), a
  failing selector with `internal_error` (0x150, its text kept off the wire). Session tickets and their 0-RTT are only
  accepted under the name and the certificate they were issued under; an override with client certificates gets neither
  tickets nor 0-RTT. Over HTTP/3 a request must be for the name its connection's identity was chosen for (421 otherwise,
  as on HTTP/1.1 and HTTP/2). An answer's `alpn` restricts its name: listing `h3` (with the TCP protocols) keeps HTTP/3,
  leaving it out refuses the name's QUIC handshake (`no_application_protocol`, 0x178) and drops `Alt-Svc` from its TCP
  responses (RFC 7838 section 2.1); without `alpn` the name gets every protocol. TLS over TCP never negotiates `h3` from
  an answer's list (RFC 9114 section 3.1): one of `h3` alone ends the name's TCP handshake with `no_application_protocol`
  (120, RFC 7301 section 3.2). A TCP client without ALPN speaks HTTP/1.1 (RFC 9113 section 3.3: "HTTP/2 connections
  over TLS MUST use protocol negotiation in TLS"), so a name whose list leaves `http/1.1` out refuses it with
  `no_application_protocol` too (new `TlsConfig.Builder.alpnFallback`, experimental, set to `http/1.1` by the Ktor
  connector; it also covers a connector's own `tlsConfig(listOf("h2"))`). `ksl` applies these rules
  (`KSL_OPT_ALPN_POLICY`, additive under ABI 7) at every ClientHello, the second one after a HelloRetryRequest included,
  and again when the handshake completes; a server's own `alpn` over TCP goes without `h3` as well, and `alpnFallback`
  cannot be `h3`. A ClientHello whose ALPN extension is malformed gets `decode_error` (50) (RFC 7301 section 3.1), never
  `no_application_protocol`. Retry and address
  validation come before the selector and are unchanged. Docs: [Ktor: Certificate per name](docs/guide/ktor.md#certificate-per-name-sni),
  [TLS: Certificate per name](docs/guide/tls.md#certificate-per-name-sni). The context of a chosen identity is built
  once per answer (same identity, trust and staple objects, equal ALPN and client-certificate settings) and shared by
  later handshakes, over TCP too: a QUIC handshake through a selector costs about 2% more than one without (it rebuilt
  the context, about 60 µs, each time); a reloaded identity still reaches the next handshake. Up to 64 answers are
  kept, least recently used first out, and their contexts are counted apart from the base configuration's, which they
  never evict.
- QUIC qlog: a sent `reset_stream`, `reset_stream_at` or `stop_sending` frame now names its `stream_id` and `error_code`
  (and `final_size`, `reliable_size`), as qlog's QUIC event schema has them; before, only its type was recorded.
- Ktor client: `KuicksilverEventListener.webSocketFailed(request, cause)`, called when a coroutine of a WebSocket session
  (the engine's or Ktor's reader or writer) fails; the session may outlive its call while it writes its own Close, so
  this can come after `callEnd`.
- Fuzzing: the stateful QUIC connection fuzzer (`connectionNull`, `connectionTls`) runs a client and a server endpoint
  (`EndpointCore`) instead of two bare cores, and the input chooses what the sockets do (DF, ECN marking and reading) and
  what the run includes: a link MTU that turns into a black hole, routers answering with ICMP Packet Too Big and forged
  ones, ECN bleaching, remarking, CE marking and ECT-dropping paths, Retry and Version Negotiation (incompatible and
  compatible, RFC 9368) inside the run and forged ones, Stateless Resets (valid, retired, unused, random, from the wrong
  address, a server that lost its state), the server's preferred address, client migration (a migration socket losing
  ECN marking or DF included) and a stranger's copies.
  New invariants: no datagram but a probe above its path's MTU and no MTU above what the network delivered (RFC 8899
  section 3, RFC 9000 section 14), no MTU update raising the window, every path of a DF or marking socket running
  DPLPMTUD and ECN, no ECT mark after validation failed and no validation over a bleaching path (section 13.4.2), receiver
  counts within what arrived, resets recognised only for used tokens from their address and never answered with one,
  amplification, connection-ID reuse across addresses (section 9.5), the preferred-address and Retry/Version Negotiation
  rules. `ConnectionSeededTest` runs fixed programs in `jvmTest` and fails when one of the path, ECN, address, version or
  reset features is no longer reached; `ConnectionInvariantControlsTest` keeps negative controls. `BbrInvariantFuzzTest`
  joins the campaign table (`quic.bbrInvariants`), and `CommittedCorpusReplayTest` fails on a table row without exactly
  five fields or a `tools/fuzz/no-corpus.txt` entry that names no target.
- Fuzzing: 0-RTT is a dimension of the QUIC connection fuzzing. The new target `quic.zeroRttConnection`
  (`ZeroRttFuzzTest.zeroRttConnection`) resumes a ticket over real TLS and runs every outcome of the server's answer —
  accepted; rejected for another application context, lower limits, `Required` mode, another ALPN or a server without
  0-RTT; no answer — alone or after a Retry or a Version Negotiation, while both applications open, write, finish, reset,
  reset at a size, stop, read, close and queue datagrams and the network drops, duplicates and reorders. After every round
  it checks the 0-RTT invariant (`docs/architecture.md`, "0-RTT invariant"): nothing held, in flight, charged to flow or
  congestion control or left in the stream manager after the answer or the end, the rejection reported once, no event for
  a stream that is gone. `ZeroRttConnectionSeededTest` and `ZeroRttRuntimeSeededTest` (the runtime's Deferreds, channels
  and watchers) run a fixed seed set in `jvmTest`; `ZeroRttInvariantControlsTest` keeps a negative control per check. The
  connection fuzzer also checks the recovery bookkeeping and the connection's send credit after every step. Two modes
  make a ticket remember more than the server sends: an accepting server then looks lowered and the client must close
  with PROTOCOL_VIOLATION, and a client whose 0-RTT breaks the server's real limits must be refused with
  FLOW_CONTROL_ERROR or STREAM_LIMIT_ERROR (RFC 9000 sections 7.4.1, 17.2.3); a third makes the server's new limits
  higher, and the client must keep to the remembered ones until the handshake completes. The campaigns' committed corpora
  (`tools/fuzz/corpus/`) now replay in `jvmTest` (`CommittedCorpusReplayTest`) and in `tools/c-test.sh`.
- QUIC: `QuicStream.sentFinalSize` and `QuicStream.receivedFinalSize` (experimental) complete with the final size of
  each half of a stream (RFC 9000 section 4.5) once it can no longer change: after a reset (RESET_STREAM,
  RESET_STREAM_AT, the answer to STOP_SENDING) with the size the frame carries, or once a FIN fixed it, also when the
  bytes were never read or reading was stopped. The core reports it with the new `ConnectionEvent.StreamFinalSize`.
- QUIC: `QuicStream.receivedOffset` (experimental), the highest offset of the peer's half received so far, read or not
  and in order or not, then its final size: what flow control counts (RFC 9000 section 4.1). `StreamReadable` is now
  also raised when data beyond a gap raises it.
- WebTransport flow control and session pooling (draft-ietf-webtrans-http3-16 sections 5 and 8), experimental. Both
  sides send `SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI`/`_UNI` and `SETTINGS_WT_INITIAL_MAX_DATA` from the new
  `http3Settings { webTransport { initialMaxStreamsBidi / Uni / Data } }` (24, 24, 3 932 160 bytes per session) and keep
  to the peer's limits (WT_MAX_STREAMS, WT_MAX_DATA, the blocked capsules), and a peer that breaks them gets its
  session closed with WT_FLOW_CONTROL_ERROR (`WebTransportException.FlowControl`). With flow control on both sides a
  connection carries up to `http3Settings { webTransport { maxSessions } }` (4) sessions: a server refuses one more, or one
  above its rate (a burst of 32 a connection, then 8 a second; section 5.2), with H3_REQUEST_REJECTED before the
  application, and draft-14 clients are told the limit by `SETTINGS_WT_MAX_SESSIONS`. Sessions sharing a connection
  take weighted turns for its stream credit and send buffer (section 8; urgency weighs, never starves) and each holds at
  most its part of the send buffer. The Ktor client's `HttpClient.webTransport` now opens sessions on the engine's
  pooled HTTP/3 connection of the URL's origin, shared with its requests (RFC 9114 section 3.3), and on further
  connections only when the server cannot take another session; a client keeps to one session per connection without
  flow control (`WebTransportException.ConnectionFull`, which `Http3Connection.webTransport` now throws for a session
  the connection cannot take, before anything is sent, where it threw IllegalStateException for a second session; the
  internal `webTransportOwningConnection` the engine used for its dedicated connections is gone). Requests and sessions
  on a shared connection are not taken in turns against each other. `Http3Endpoint` refuses settings whose sessions do not fit the
  QUIC connection's limits. All three initial limits at 0 turn flow control (and pooling) off. A draft-14 peer that
  leaves a session without credit is reported by the internal `WebTransportDiagnostics.creditStall`, which the Ktor
  server logs. Docs: `docs/guide/http3.md`, `docs/guide/ktor.md`.
- QUIC: `QuicStream.sendReleased` (experimental), the bytes of a sending half the connection's shared send buffer
  (`maxSendBuffer`) released so far, acknowledged or dropped by a reset, so a protocol multiplexing independent users
  over one connection can give each a share of it; `ConnectionCore.maxSendBuffer` tells the buffer's size. A stream
  whose count is followed also raises `StreamWritable` when acknowledgements release its bytes.
- Ktor server, `EngineMain`: `kuicksilver.tls.ocspStapling` (a DER OCSP response file, stapled on TCP and QUIC, read
  again every `kuicksilver.tls.reloadInterval`; a response that is not stapled, at startup or later, is logged as a
  warning) and `kuicksilver.connector.allowMisdirectedHosts` (`true`: no `421 Misdirected Request` on the deployment port, TLS or the
  cleartext port behind a TLS-terminating proxy) set what `tls { ocspStaplingFile(…) }` and the connectors' `allowMisdirectedHosts`
  set in code; the stapling needs the identity files. Ktor's `-sslPort` connector cannot express
  either: next to it the stapling is refused, and so is the gateway with the identity files; without them the gateway
  is accepted and exempts only the cleartext port.
- Certificate revocation (RFC 9325 section 7.5), experimental. Clients ask for a stapled OCSP response and check it
  (RFC 6960 section 3.2; RFC 6066 section 8) where `ksl` verifies the chain (`AnchoredCa`, `Platform` on Linux Native):
  `TlsConfig.revocation` (`RevocationPolicy.Off`, `StapledIfPresent` (the default: a server without a staple passes),
  `RequireStapled`); a revoked or unsatisfactory response fails with `bad_certificate_status_response`
  (`VerifyReason.Revoked`, the new `VerifyReason.InvalidStatusResponse`), and an RFC 7633 must-staple certificate needs a
  staple. Servers staple a configured response over TCP and QUIC (`TlsConfig.ocspStapling`, `OcspStapling` with
  `update`; the Ktor TLS connector's `ocspStapling`; per `sniSelector` identity, `ServerTlsOverride.ocspStapling`) only when it is for the leaf sent and fresh,
  and over TLS 1.3 and QUIC only when it fits the certificate's extensions (65527 bytes, RFC 8446 section 4.4.2). Application CRLs:
  `TrustConfig.AnchoredCa(roots, crls)` with `CertificateRevocationList` (also as a `ReloadableCa` bundle on servers).
  Under `TrustConfig.Platform` off Linux Native the OS verifier decides: Apple and Windows apply their own revocation
  policy, while on Android (its blocklist only) and the JVM (off unless the application enables it) nothing checks
  revocation; `Custom` and `Tofu` decide alone. Delta, indirect and reason-partitioned CRLs are refused. `ksl` gains
  `ksl_ctx_set_crls` and `ksl_ocsp_check` (ABI 7, additive). Docs: `docs/guide/tls.md`, "Certificate revocation".
- Compose Multiplatform demo (`samples/compose-demo`, not published): an Android and iOS app that downloads over
  Kuicksilver HTTP/3 with `http3 { migration = followDefaultNetwork(...) }` next to OkHttp (Android) or CIO and Darwin
  (iOS) while the network switches, with the `connectionMigrated` events and an optional `Range` resume of the TCP
  download; a lossy-network screen against its server behind `tc netem` (`server/netem.sh`); and a diagnostics screen
  for any URL with the `http3 { allowed }` switch. Its JVM server (`server/`) serves `/bytes/{n}` with `Range` and `/stream`.
  The Kuicksilver lane asks for HTTP/3 only (`H3Only`), so a fallback can never be shown as HTTP/3. `DemoLogicTest`
  covers the screen models and the server's tests its `Range` parsing; `MigrationDemoAndroidTest` is the emulator check
  of the release gate, run by `:androidApp:migrationDemoDeviceTest` against the server on the host. Its
  build verifies every plugin and dependency against `gradle/verification-metadata.xml`, which now also covers Compose
  Multiplatform, the AndroidX libraries it brings, OkHttp 5.5.1 and Ktor's CIO, Darwin and mock engines.
- Two samples for adopting the Ktor engines (not published; each a Gradle build of its own that takes
  `io.kuicksilver:*` by coordinates, verified against `gradle/verification-metadata.xml`). `samples/http3-server` is
  an HTTP/3 Ktor server in about twenty lines: `EngineMain` and an `application.conf` with TLS from PEM files
  (reloaded hourly), HTTP/2 and HTTP/1.1 on the same port, `Alt-Svc`, and the PROXY protocol switched on by
  `PROXY_TRUSTED_SOURCES`; its README has the `curl --http3` commands and a deployment note for HAProxy and nginx, and
  `Http3ServerTest` starts it with that file and checks HTTP/2 with `Alt-Svc` then HTTP/3, HTTP/3 only, HTTP/1.1, a
  PROXY v1 header naming the client and a client without one refused. `samples/webtransport-chat` is a WebTransport
  chat room: a Ktor server (`webTransport("/chat")`) and a client in common code (`HttpClient.webTransport`, compiled
  for the JVM, macOS and the iOS simulator) with a bidirectional stream per member for messages and membership,
  datagrams for typing indicators (relayed at most every 250 ms), refusals as session close codes (a taken name, a
  full room of 25, a bad line), control characters in messages replaced, a slow reader dropped once its 256-line queue
  is full and `ServerDraining` on a graceful stop. No server key is in common code: the JVM server loads its identity
  from PEM files, with the sample's public one only on loopback. `ChatTest` runs the server and its clients in one JVM
  over UDP. Both run in the CI `apple` job (the chat's iOS simulator compile in `apple-native`) and in the local gate.
- Engine interop bench (`kuicksilver-engine-interop`, not published; docs/spec/interop.md, "Engine interop"): the Ktor
  client engine against Ktor's Netty server (HTTP/1.1, HTTP/2 and HTTP/3) and CIO server and a plain Netty server (1xx,
  trailers, GOAWAY), and the Ktor server engine against Ktor's CIO, OkHttp and Java client engines, OkHttp and the JDK's
  HttpClient on their own APIs and Netty's HTTP/3 client, in one JVM over loopback: bodies, fields, statuses, HEAD and
  304, cancellation, timeouts, graceful stop, TLS trust and ALPN, and WebSockets (fragments, Ping, close codes,
  permessage-deflate). It runs as the step `jvm: engine interop (Ktor engines, OkHttp, JDK, Netty)` of the gate and
  of CI.
- SwiftPM: Kuicksilver is a Swift package, [kuicksilver/kuicksilver-swift](https://github.com/kuicksilver/kuicksilver-swift),
  a repository without source code whose binary target is `Kuicksilver.xcframework.zip`, attached to every GitHub
  release from 0.3.0 and signed with the release key. A Swift-only app adds
  `.package(url: "https://github.com/kuicksilver/kuicksilver-swift", .upToNextMinor(from: "0.3.0"))` instead of building
  the xcframework from a checkout (docs/guide/ios.md, "Swift only"). `tools/release/xcframework.sh` builds the zip
  reproducibly (the same checksum from any checkout directory); `local-release.sh` builds it, signs it, lists it in the
  provenance and prepares the package repository's next commit with its checksum (`tools/release/swift-package.sh`,
  from `tools/release/swift-package/`), which the maintainer signs, tags `<version>` with the release key and pushes
  after the GitHub release;
  `verify-release.sh` checks that the package's `Package.swift` names the signed release asset. Each framework of the
  xcframework carries Kuicksilver's `LICENSE` and `NOTICE` and OpenSSL's licence. `KuicksilverInfo.VERSION`
  in the xcframework is now the version it was built as, not the `-SNAPSHOT` fallback.
- CI: `.github/workflows/public-h3.yml` (weekly and by hand) runs the Ktor client against public HTTP/3 servers, each a
  different QUIC implementation: Cloudflare, Google, Meta, Fastly, LiteSpeed and nginx. Per target: HTTP/3 with `H3Only`
  (ALPN `h3`, the negotiated QUIC version), `Alt-Svc` discovery from an HTTP/2 first contact, 0-RTT resumption, a
  migration to a new local port, and on Cloudflare ECH over HTTP/3 with the configuration of its HTTPS record, each judged
  from the client's diagnostics. A server that changed or could not be reached is a warning annotation; the job fails only
  when a verdict blames the client twice in a row, or when a check passes on none of three or more reachable targets
  while a hand-built Version Negotiation probe shows that UDP to port 443 gets through (docs/how-we-verify.md, "Public
  HTTP/3 servers"). The job summary has a table per run, and the qlog traces of the
  checks that did not pass are an artifact. By hand where UDP/443 is open:
  `./gradlew --max-workers=2 :kuicksilver-ktor-client:publicH3Check`; not part of `check` or `jvmTest`, and not in the
  release gate. Targets checked 2026-11-25.
- CI: `.github/workflows/gradle-wrapper.yml` validates `gradle/wrapper/gradle-wrapper.jar` against the official Gradle
  releases (Gradle's wrapper-validation action) on every push and pull request to `main` and `release/**`.
- WebSockets over HTTP/2 (RFC 8441, Extended CONNECT; `docs/guide/ktor.md`, "WebSockets over HTTP/2"), in both Ktor
  engines. Server: with HTTP/2 on (the default since), `webSockets { overHttp2 }` (`EngineMain` key
  `kuicksilver.webSockets.overHttp2`; on by default, as `overHttp3`) advertises SETTINGS_ENABLE_CONNECT_PROTOCOL
  and serves `webSocket {}` routes over an Extended CONNECT with `:protocol = websocket`, answered `:status 200`; another
  protocol or a classic CONNECT gets 501, a Sec-WebSocket-Version other than one 13 gets 400 with `sec-websocket-version: 13` (RFC 6455 section
  4.2.1; no 426, which needs Upgrade), and a route that is not a WebSocket one cannot answer the CONNECT with a 2xx (501). Client: a `wss://`
  WebSocket goes over an HTTP/2 connection to its origin that is there already and whose server allows Extended CONNECT,
  once that server's SETTINGS arrived (RFC 8441 section 3, waited for at most 1 s); otherwise it opens a connection of its own with `http/1.1`
  only, as before. Its handshake answer's extensions and subprotocol are checked against the offer (RFC 6455 section
  4.1); the session's frames go within the stream's flow-control windows and through the same frame guard as over
  HTTP/1.1 and HTTP/3; an orderly close is the stream's END_STREAM, anything else a RST_STREAM CANCEL. In
  `kuicksilver-http2` (internal API): `H2ServerConnection.start(enableConnectProtocol)`, `H2ServerStream.protocol`,
  `H2ClientConnection.open(protocol)`, `serverAllowsExtendedConnect`, `awaitServerSettings()` and
  `H2ClientStream.awaitServerEnd()`; a CONNECT answered with a 2xx is a tunnel (RFC 9113 section 8.5: a HEADERS frame on
  it is a stream error PROTOCOL_ERROR, no trailers are sent on it, a content-length does not apply), a server that takes
  SETTINGS_ENABLE_CONNECT_PROTOCOL back ends the connection with PROTOCOL_ERROR, and `:protocol` must be a token.
- Ktor client: `HttpClient.clearAlternativeServices(origin)` (experimental) for RFC 7838 section 9.4: "any alternative
  service information MUST be removed when origin-specific data is cleared (typically, when cookies [RFC6265] are
  cleared)". It forgets, under the engine's lock, the cached alternatives of one origin or of all (persistent ones too,
  from a `FileAltSvcStore`'s file before it returns), their broken marks and RTTs; call it where the application clears
  cookies or site data. `AltSvcStore.clear()` (experimental) backs it: a default method that throws
  `UnsupportedOperationException`, so stores written for 0.2.x keep working (for them a full clear removes the origins
  seen since the client started, with a warning that others kept from earlier may remain, and the call returns false);
  override it for section 9.4. `clearAlternativeServices` returns whether everything asked for was removed.
- HTTP/2: the ALTSVC frame (RFC 7838 section 4, type 0xa). The Ktor server sends the engine's `Alt-Svc` value as one on
  HTTP/2 besides the field (see the HTTP/2 server entry); the Ktor client learns from it as from the header: a frame on a
  request stream for the connection's origin, one on stream 0 only when its Origin is that origin, in `Auto`, never
  through a proxy, the latest frame per origin learned by one coroutine in order of arrival. Frames section 4 says to
  ignore are ignored, a server ignores the frame, and each one costs a glitch.
- Ktor client: `Http3ConnectionMigration.networks` (experimental): the networks a migration hook follows. The
  `followDefaultNetwork` factories return their system source, and while `networkId` is not set it is the engine's
  network: a change resets broken marks and QUIC confirmation, drops the `Alt-Svc` alternatives without `persist=1`
  (RFC 7838 section 2.2) and flushes the HTTPS record cache, which such an engine now keeps. `networkId` wins when set.
  On iOS and macOS the followed network is the default path's interface, gateways and the interface's addresses
  (`nwPathIdentities()`, compared in memory only; its `toString` is a hash, never the addresses), so a move between
  Wi-Fi networks on one interface is a change too; on Android the `Network`. Every update the source reports, changed
  or not, flushes the HTTPS record cache (RFC 9460 section 12). Neither survives a restart, so a followed value is never stored, and its first value after
  a start counts as a change, as for what was learned before it came (requests wait for it until 200 ms after the client
  was created, one deadline for all). A store that throws while a change is applied loses that change, not the following.
- Ktor client: `AltSvcStore.networkId` (experimental): the network the stored alternatives were learned on.
  `InMemoryAltSvcStore` keeps it, `FileAltSvcStore` writes it as the file's first line (which earlier versions skip), and
  the engine compares it with the first network `networkId` reports, so alternatives without `persist=1` learned on
  another network before a restart are dropped (RFC 7838 section 2.2). An application's store that keeps none loses
  those at each start.
- Documentation site: the API reference of the published modules (Dokka HTML, with module and package descriptions,
  source links to the release tag and links into the kotlinx-coroutines, kotlinx-io and Ktor references) and the guide
  as HTML, per version, at <https://kuicksilver.github.io/kuicksilver/> (`/<version>/api/`, `/<version>/guide/`,
  `/latest/`), from 0.3.0 on. Declarations annotated `@InternalKuicksilverApi` are left out of the reference.
  `tools/docs/site.sh <version> <outdir>` builds it locally, offline once the dependencies are cached;
  `.github/workflows/pages.yml` publishes it when a GitHub release is published (docs/release.md, "Every release").
  `./gradlew :dokkaGenerate` writes the API reference alone to `build/dokka/html`.
- Docs: [Why QUIC](docs/why-quic.md), HTTP/3 against HTTP/1.1 and HTTP/2 over TCP (Kuicksilver's own TCP client and
  OkHttp) with measured numbers: 10 MiB downloads over a grid of RTT and loss, 20 parallel requests (head-of-line
  blocking), time to first byte on a new connection (with 0-RTT), and an address change in the middle of a 50 MiB
  download, plus when QUIC does not help. `tools/bench/why-quic.sh` runs it in one container with `tc netem` on the
  loopback and generates the page's tables from `docs/benchmarks/why-quic.csv`; OkHttp is a dependency of the
  unpublished `kuicksilver-soak` module only.
- CI: the non-blocking job `openssl-next` (weekly, or `only=openssl-next` by hand) builds the newest OpenSSL 4.x release
  (4.1.0, pinned by version, SHA-256 and signing key in `gradle/openssl-next.toml`) on linux-x64 and macos-arm64 and runs
  the `ksl` C tests and a JVM smoke test against it. It is never required and produces no release artifact; 0.3.0 stays on
  OpenSSL 3.5 LTS. `KSL_OPENSSL_PIN` (`tools/openssl/fetch.sh`, `build.sh`) and `-Pkuicksilver.openssl.pin` select the pin
  profile; `KSL_OPENSSL_OUT` (`tools/c-test.sh`) only names the directory of the OpenSSL builds.
- System OpenSSL builds (Linux): the accepted version range has one switch, `KSL_SYSTEM_OPENSSL_MAX_MAJOR` (default 3), and
  `tools/ci/system-openssl.sh` follows it. OpenSSL 4.x is prepared but still refused by default (`KSL_INIT_VERSION`); a C
  test keeps it so. Not supported in 0.3.0 ([stability](docs/stability.md#openssl)).
- QUIC: `loops > 1` on macOS, iOS and Windows, and with a caller-supplied `DatagramIo`. Where the kernel does not balance
  a port over `SO_REUSEPORT` sockets (Darwin hands every datagram to one socket, Windows binds exclusively), the loops
  share one socket: one receiver thread hands each datagram to the loop its connection ID names (a new client's Initial
  by a keyed hash of its connection ID, the same loop for its retransmissions), and each loop sends through its own
  `ksl_udp_sender` clone (a caller's socket under a lock). A migrated client reaches its loop with no forwarding; a peer's
  Stateless Reset reaches the loop whose connection holds its token, and an ICMP Packet Too Big (Linux, Android) is
  offered to every loop. A failed preferred-address socket takes the preferred address down, not the endpoint. A loop
  that falls more than 512 datagrams behind loses its own datagrams, counted in the new
  `EndpointStats.datagramsDispatchDropped`; the receiver never waits for it. Linux and Android keep a socket per loop.
  Handshakes and many connections spread over the loops; one connection is not faster with more loops. See
  docs/guide/quic.md, "Several loops on one port". Measured on an Apple Silicon Mac (docs/benchmarks.md, "Several loops on one
  socket"): 4 loops complete 3.3–3.5 times the handshakes of one; 8 bulk connections move 1.2–1.3 times the bytes,
  capped by the receiver's one `recvmsg` per datagram on Darwin.
- Native: `KSL_GET_RENEGOTIATION`, a getter that reports a peer's TLS 1.2 renegotiation attempt on an established TCP
  session (a server's HelloRequest, a client's ClientHello), which OpenSSL refuses with a `no_renegotiation` warning as
  before; the `ksl_tcp_read` that refused one answers `KSL_OK` with nothing read, so the caller looks before it reads what
  came after it. Additive under ABI 7. `TlsConnection` fails the input of an `h2` connection at such an attempt (RFC 9113
  section 9.2.1) and reports it on any connection (`renegotiationAttempted`, internal API); other protocols go on as
  before.
- Native: `ksl_udp_sender`, a send-only clone of a `ksl_udp` socket with its own send scratch, so several threads send on
  one UDP socket (one per clone); it shares the descriptor, which closes with the last close of the group in any order,
  copies the granted flags (GSO/USO, ECN, DF, PKTINFO), and refuses to receive (`KSL_E_NOT_SUPPORTED`). Linux, Apple and
  Windows; additive under ABI 7. Kotlin: `KslUdpSocket.sender()` (internal API). New error code `KSL_E_NO_MEMORY` for a
  failed allocation in `ksl_udp_sender` and `ksl_udp_open` (which answered `KSL_E_BAD_ARG` for it).
- QUIC: routable server connection IDs for QUIC-LB load balancers (draft-ietf-quic-load-balancers-21), experimental:
  `QuicEndpointConfig.loadBalancer = QuicLbConfig(configId, serverId, nonceLength, key)` writes the server ID into
  every server connection ID (config rotation bits and self-encoded length in the first octet; with a key, made by
  `QuicCrypto.newLoadBalancerKey(bytes)` so the bytes live in `ksl` only, the server ID and nonce are AES-encrypted,
  single-pass or four-pass). `QuicEndpoint.updateLoadBalancer` (also `Http3Endpoint`, the sans-IO `EndpointCore`, and the
  Ktor engine's `http3 { endpoint { loadBalancer } }` / `engine.updateLoadBalancer`) rotates to a new configuration: each live connection
  gets one NEW_CONNECTION_ID under it that retires its earlier IDs, a second change waits for those retirements, and
  `null` issues unroutable `0b111` IDs. Nonces never repeat within a process for a key (shared by every endpoint and
  server ID using it); `QuicLbConfig.nonceReservation` carries the counter (and in clear a permutation secret) across
  restarts (a plaintext configuration must have one), otherwise each process start needs a fresh key. After a Retry the
  connection keeps the Retry's SCID as its one server ID. Spent nonces turn the endpoint
  unroutable, counted in `EndpointStats.loadBalancerNoncesExhausted`; failed reservations and nonces spent unused have
  their own counters. Every endpoint keeps its own copy of the configuration key.
  Plaintext and unroutable connections hand out only their handshake ID, unroutable ones with
  `disable_active_migration`. Several loops on one port share the configuration; the owner of an ID is the loop it
  hashes to, and only it answers a Stateless Reset, within the rate limit, for an ID of the current or previous
  configuration that decrypts to this server's ID (decryptions have their own rate limit). `ksl_key_lb`,
  `ksl_key_lb_dup`, `ksl_key_lb_derive` and `ksl_key_ecb16` are additive under ABI 7. See docs/guide/quic.md, "Behind a load balancer".
- Docs: [compatibility shims](docs/spec/compat-shims.md), every place where Kuicksilver departs from or goes beyond a
  standard only for a peer that lags behind or breaks it (WebTransport draft-02 and draft-14 for browsers, the pre-IANA
  `reset_stream_at` codepoint, quiche's FIN handling), each with its peers, the standard text, where it lives, its default, tests,
  risk and removal condition; linked from the RFC compliance summary and the interop results.
- Docs: every guide page opens with what it is for, what you need before you start (artifacts, versions, certificate) and a minimal example or a link to the section that has one; section pointers like "below" are links.
- Docs: a generated reliability page, `docs/reliability.md`, with the interop cells of the latest matrix, fuzzing hours
  and executions per target, soak results (duration, resource trends, flatness verdicts), the count of `negative_*`
  tests per module and the gate record. `tools/report/reliability.sh` reads the existing artifacts only (no network,
  deterministic output, "not measured in this gate" where an artifact is missing; `--check` fails instead) and
  `tools/report/reliability-test.sh` covers it (a lint step of the gate and of `build.yml`); the release procedure
  regenerates the page in the release-preparation commit.
- Soak: the report (`SoakResult.write()`) names the UTC start and the commit of the run (`Run: …` under the title).
- Ktor client: HTTPS resource records (RFC 9460) as a source of HTTP/3, opt-in and experimental:
  `http3 { httpsRecords = HttpsRecordSource.Exchange { query -> ... } }` (your DNS-over-HTTPS client, RFC 8484 wire
  format) or `HttpsRecordSource.System`. In `Auto` mode an `https://` request to a host name looks up the origin's
  records (following AliasMode) and connects to their endpoints in priority order over the transports each allows
  (RFC 9460 section 3): a record with `alpn=h3` lets the first request race HTTP/3 at once, TCP goes to the record's
  target and port, and an endpoint that fails is followed by the next, then by the origin; the certificate is still
  checked against the origin's name. `Exchange(secure = true)` declares answers protected (DoH, DoT, DNSSEC): a failed
  lookup then abandons the request (RFC 9460 section 3.1); `ProtectedSystem { ... }` and, on Android,
  `HttpsRecordSource.followingPrivateDns(connectivity)` (strict Private DNS) do the same for the system resolver. A cached `Alt-Svc` alternative's own HTTPS records decide
  where its HTTP/3 goes (section 9.3). An `http://` request to an origin with HTTPS records is answered by the engine
  with a 307 to its `https` URL, which Ktor follows (section 9.5). The request waits for
  the records at most `network { httpsRecordWait }` (50 ms) after the origin's addresses resolved; answers are cached by TTL
  and dropped on a network change. New `KuicksilverEventListener.httpsRecordUsed` and `AlternativeSource.HttpsRecord`
  (reserved before). `HttpsRecordSource.System` asks the system resolver: `res_nquery` on Linux, `DNSServiceQueryRecord`
  on macOS and iOS, `DnsQuery_W` on Windows (new `ksl_dns_query`, additive under ksl ABI 7; the Linux libraries now
  need `libresolv.so.2`, the Windows ones `dnsapi.dll`), `DnsResolver.rawQuery` on Android from API 29 (none below it).
  `docs/guide/ktor.md`, "HTTPS records".
- Docs: `llms-full.txt`, the guides in one file for language-model readers (generated by `tools/check/llms-full.sh`;
  `llms.txt` links it and lists the HTTP/2 sections). The configuration reference has a *Since* column, a table for
  `Http2Settings` and `SessionTicketConfig` and a map of where each option is set; the troubleshooting guide starts
  with a symptom index and has entries for ALPN mismatches and for refusals and limits, and names every
  `FallbackReason` and `ProtocolReason`. The lint step checks all of it against the code: `config-table.sh` (every
  public option has a row with the right default and release), `troubleshooting-msgs.sh` (every quoted message,
  exception and code exists in the source), `llms-full.sh --check`, and the HTTP/2 server sample is compiled by
  `GuideSamplesTest`.
- Ktor client: HTTP/3 connections can follow the device's network (connection migration, RFC 9000 section 9;
  `docs/guide/ktor.md`, "Connection migration"), opt-in and experimental: `http3 { migration = ... }` takes an
  `Http3ConnectionMigration`, with `Http3ConnectionMigration.followDefaultNetwork(connectivity)` on Android
  (`ConnectivityManager`) and `followDefaultNetwork()` on iOS and macOS (`NWPathMonitor`); elsewhere it wraps a
  `NetworkMigrator` over a source of your own. Every pooled HTTP/3 connection then moves to the new default network once
  its handshake has completed, over a validated path with a fresh connection ID, so a download carries on across a
  switch from Wi-Fi to the mobile network (without it a connection survives only if the system happens to route its
  unbound socket over the new network and the server follows that as a NAT rebinding); the transport still
  refuses to move before confirmation, towards a server that sent `disable_active_migration` or uses zero-length
  connection IDs, and onto a path that does not validate. New `KuicksilverEventListener.connectionMigrated(origin,
  event)` reports each step (a failed move is also logged at `Info`, a server that does not allow migration at
  `Debug`). Off by default, so 0.2's behaviour is unchanged; `networkId` stays separate. HTTP/1.1, HTTP/2 and the
  extra connections a server's WebTransport session limit makes do not migrate.
  A WebSocket over HTTP/3 (RFC 9220) moves with its connection: with the option and a server that allows active
  migration, the session carries on across the switch with no reconnect, every message both ways arriving once and in
  order (`ClientMigrationTest.webSocketSurvivesNetworkSwitch`; the network switch is simulated over loopback, the old
  socket going deaf once the connection moved); without the option it ends with the old network at the idle timeout,
  `closeReason` 1006. WebSockets over HTTP/1.1 and HTTP/2 do not migrate.
- QUIC: experimental `MigrationRefusedException` (an `IllegalStateException`, as before) with a `MigrationRefusal`
  reason (`NotConfirmed`, `DisabledByPeer`, `ZeroLengthConnectionId`) is what `QuicConnection.addPath`, `migrate` and a
  `NetworkMigrator` throw or report when the transport refuses a new path (RFC 9000 sections 9 and 9.5).
- Docs: a deployment guide for the HTTP/3 server (`docs/guide/deployment.md`): TCP and UDP on one port number and what
  the engine's `Alt-Svc` names (with a sample for a public port that differs from the bound one), firewalls and
  security groups, Docker and Kubernetes (mixed-protocol `LoadBalancer` Services, the client address and the per-IP
  connection limit), L4 load balancers versus proxies that terminate HTTP/3 (AWS NLB, Cloudflare, nginx; checked against
  their documentation), connection IDs without QUIC-LB, UDP socket buffers per OS (what Kuicksilver asks for and how to
  raise the Linux limits), GSO/GRO and `http3 { endpoint { loops } }`, certificates and their rotation, the run-time HTTP/3 switches,
  security limits, observability, and a checklist from symptom to cause. Linked from the README, `llms.txt` and the
  Ktor, QUIC and troubleshooting guides.
- Ktor server: TCP connection limits (`docs/guide/ktor.md`, "Connection limits"; threat model 3.2), experimental:
  `tcp { maxConnections }` (10,000 per connector, HTTP/1.1 and HTTP/2 alike, TLS handshakes included) is taken before
  `accept()`, so at the limit a connector stops accepting and the OS backlog holds new clients, as Go's
  `netutil.LimitListener`, Jetty and nginx do; `tcp { maxConnectionsPerIp }` (off by default; enable it, e.g. 256, only on
  a server that faces its clients directly: behind a proxy, load balancer, SNAT or NAT every client shares one address)
  resets one more connection from that address right after `accept()`, before its TLS handshake, which a proxy in
  front reports as 502/503. An address is its bytes (no reverse lookup), IPv4-mapped peers count as IPv4 and IPv6 peers
  by their whole address (a /64 holder gets around it), as QUIC `maxConnectionsPerIp`. `KuicksilverServerEventListener.connectionRefused(protocol, remote, reason)` reports a client
  closed at accept (`per-IP limit`, or `HTTP/2 repeat offender` for `http2 { repeatOffenderPenalty }`), the application log
  gets at most one warning per 10 s, and the soak probe counts `server.tcpConnections` and `server.tcpRefusedPerIp`.
  `EngineMain` keys `kuicksilver.tcp.maxConnections` and `kuicksilver.tcp.maxConnectionsPerIp` (`off` by default).
- TLS: experimental `VerifyReason.WeakKey` and `VerifyReason.WeakSignature` (alert `bad_certificate`) name a peer chain
  refused for a key or a certificate signature below 112 security bits (see "Changed").
- Ktor server: HTTP/2 over TLS (RFC 9113; `docs/guide/ktor.md`, "HTTP/2 on the server"): `http2 { enabled }`
  (`EngineMain` key `kuicksilver.http2.enabled`; on by default, see "Changed") makes every TLS connector offer `h2`
  before `http/1.1` in ALPN, and `http2 { settings { } }` (experimental) takes the windows and limits. Each stream is a Ktor call (`httpVersion`
  "HTTP/2"); requests are checked against RFC 9113 section 8 (a malformed one is reset with PROTOCOL_ERROR before any
  handler runs, a field section above the limit gets 431), responses go out without connection-specific fields, the
  engine's `Alt-Svc` goes on every response as the field ("Alt-Svc header fields remain valid in responses delivered over
  HTTP/2", RFC 7838 section 3) and as an ALTSVC frame ("servers SHOULD instead send an ALTSVC frame") ahead of the
  response, once per origin and value on a connection and again 12 hours after the last one,
  content within the client's flow-control windows and never past or short of its
  `Content-Length` (the stream is reset instead). One stream's failure (a client's reset, a handler's exception) ends
  that stream only, and the server never answers a client's RST_STREAM with one. The client's preface and field blocks are
  bounded by `requestHeaderTimeout`, request content and idle connections by `tcp { idleTimeout }`; a
  client's RST_STREAM cancels its handler, and a stop sends the two-step GOAWAY (RFC 9113 section 6.8). TLS 1.3 only, no
  h2c, no server push; WebSockets over HTTP/2 (RFC 8441), below. The event listener reports `HTTP_2_0`, and the soak probe
  counts `server.h2Connections` and `server.h2Streams`. Flood defences in the engine on top of the per-connection limits
  of `Http2Settings`: a reset stream's handler is cancelled and counts toward SETTINGS_MAX_CONCURRENT_STREAMS until it
  returns (Rapid Reset, MadeYouReset); a connection that is over gets the send-stall deadline for what it still has to
  write, for as long as the client takes it; experimental `http2 { repeatOffenderPenalty }` (`EngineMain` key
  `kuicksilver.http2.repeatOffenderPenalty`; off by default) closes at accept, for that long, the TCP connections of an
  address whose HTTP/2 connections ended in a flood limit three times within a minute (IPv6 by its /56): only for a
  server that sees real client addresses, never behind a NAT or a source-rewriting load balancer. The server passes
  h2spec 2.6.0, all 146 cases
  (`tools/interop/h2spec.sh`).
- Ktor client: HTTP/2 over TLS (RFC 9113; `docs/guide/ktor.md`, "HTTP/2 on the client"). Every `https://` connection
  over TCP offers `h2` and `http/1.1` in ALPN (also through HTTP CONNECT and SOCKS5 proxies; never for `http://`, no h2c,
  and never on a WebSocket's own connection; WebSockets over HTTP/2, RFC 8441, below); a server that picks `h2` gets one multiplexed connection per
  route while it has a free stream under its SETTINGS_MAX_CONCURRENT_STREAMS, a second one when it is full, within
  `maxConnectionsPerRoute`. Requests that start together toward a new origin open one connection: one connects while the others wait for it
  (RFC 9113 section 9.1). A request the
  server did not process (GOAWAY above its stream, REFUSED_STREAM; RFC 9113 section 8.7) goes again, at most twice, for
  any method; HTTP_1_1_REQUIRED makes the route offer only `http/1.1` for 5 minutes, doubling up to 2 days (new
  `FallbackReason.H2Refused`), and repeats the request over HTTP/1.1 when that is safe (not processed, or idempotent with a
  body that can be sent again; otherwise the call fails with the new `Http11RequiredException`, and the application may
  repeat it); any other HTTP/2 failure fails the call with the new
  `Http2Exception` (experimental, in `kuicksilver-http2`). Responses are checked against RFC 9113 section 8 (a malformed
  one fails the call); flow control follows the application's reading; the server's preface must arrive within the
  connect timeout, a connection quiet for 10 s is checked with a PING before it takes a request, and an optional PING
  interval closes a silent connection. A client that allows TLS 1.2 (`tls { versions = TlsVersions.Tls12And13 }`) offers
  `h2` too and speaks it with a TLS 1.2 server (RFC 9113 section 9.2: SNI, no compression, ECDHE with AEAD suites only,
  none of them prohibited by section 9.2.2); a server's renegotiation request (a HelloRequest) is refused and ends the
  connection with a connection error of type PROTOCOL_ERROR (section 9.2.1), the calls on it failing with
  `Http2Exception.ConnectionClosed`. Configuration:
  `engine { http2 { enabled; pingInterval; settings { } } }` (`Http2ClientConfig`; `settings` experimental); `enabled = false` offers only
  `http/1.1`, as in 0.2. The HTTP/3 kill switch (`http3 { allowed }`) does not turn HTTP/2 off. Responses report
  `HttpProtocolVersion.HTTP_2_0`, as do `ProtocolDiagnostics.protocol`, `connectionAcquired` and the race's
  `raceEnded(winner)`; the resource probe adds `client.h2Connections`, `client.h2Streams`, `client.h2Routes` and
  `client.h2Refused`.
- HTTP/2 module: the RFC 9113 section 8 field and message rules (`io.kuicksilver.http2.message`, a port of
  `kuicksilver-http3`'s), with the shared cases in `tools/vectors/http-fields.json` that both modules' tests run
  (`tools/http/gen-field-vectors.py`, checked in the local gate); a coroutine runtime over ktor-io channels that drives the
  connection core for the engines (ktor-io and kotlinx-coroutines are now API dependencies of `kuicksilver-http2`); and
  the fuzz target `http2.connectionClient`.

- Ktor server: HTTP/3 can be stopped from advertising, or drained, at run time without a restart (experimental
  `KuicksilverApplicationEngine.http3Advertising` and `Http3Advertising`; `docs/guide/ktor.md`, "Turning HTTP/3 off on
  the server"). `On` (the default) advertises `Alt-Svc: h3=":<port>"; ma=86400` as before; `Clear` sends `Alt-Svc: clear`
  (RFC 7838 sections 2.2 and 3) on HTTP/1.1 and HTTP/3 responses while HTTP/3 keeps serving; `Drain` also sends GOAWAY to
  every live HTTP/3 connection (RFC 9114 section 5.2: requests in flight complete; no drain deadline yet for WebSocket
  and WebTransport sessions) and refuses new QUIC connections at their first Initial with CONNECTION_REFUSED (RFC 9000
  section 5.2.2), keeping the UDP socket bound. Each response and each new client Initial reads the
  current value, so a keep-alive connection follows a change at its next response. With `altSvc = false` no `Alt-Svc` is
  sent in any mode; an application's own `Alt-Svc` is never replaced. HTTP/1.1 responses read the engine's `Alt-Svc`
  per response now instead of once per connection.
- Documentation: `docs/process.md`, how every change is checked before it reaches a release (a test that fails
  first, code review and a check against the RFC text, reference stacks, the compliance matrix and threat model, the
  local gate and its coverage, hosted CI, soak and fuzzing, signed releases with SBOM and provenance, and what is
  manual or partial today).
- TLS: certificate rotation without a restart (experimental `TlsIdentity.Reloadable`, `TlsIdentity.reloadable`;
  `docs/guide/tls.md`, "Rotating the server certificate"). `reload(next)` makes `next` the identity of every handshake
  that starts afterwards, over TCP and QUIC; each handshake takes chain and key from one snapshot, and running
  connections keep theirs. A closed identity, an expired leaf and a leaf not valid yet (beyond 5 minutes of clock skew)
  are refused and the old identity stays; the replaced one is closed and its native key freed once no connection uses it.
  Tickets are bound to the leaf they were issued under, so a ticket from before a reload is not resumed (a full
  handshake with the new certificate; its 0-RTT refused).
- Ktor server: certificate rotation without a restart (`docs/guide/ktor.md`, "Certificate rotation"). A connector's
  identity (`tls { identity }`, on the engine or a connector) may be a `TlsIdentity.Reloadable`: HTTP/1.1 and HTTP/3 handshakes after a
  `reload` present the new certificate, open connections keep theirs. `EngineMain` watches its PEM files with the new
  key `kuicksilver.tls.reloadInterval` (`tls { reloadInterval }`; off by default, at least 1 s): a changed
  chain is applied once two reads a second apart agree and the key matches; a failure keeps the identity in use, is
  logged once (never with key material) and retried after 1 s, then twice as long each time up to the interval.
  `EngineMain` now reads the key file without making a `String` of it or leaving it in kotlinx-io's pooled buffers
  (a buffer of its own, wiped), refuses PEM files above 1 MiB, and closes the identity it made when the server stops. The
  watcher reads the files again a second after a reload and refuses a chain file that also holds a private key (as
  `EngineMain` does at startup when reloading is on). A watcher read that never returns no longer holds up the stop.
- TLS: client CA rotation without a restart (experimental `TrustConfig.ReloadableCa`, `TrustConfig.reloadable`;
  `docs/guide/tls.md`, "Rotating the client CA"). A server's client-certificate trust (`tls { clientTrust }` in the Ktor server) may be a `ReloadableCa`
  (alone or as the base of `Pinned`). Once `reload(next)` returns, no handshake, over TCP or QUIC, accepts a client
  certificate that only a CA missing from `next` vouches for: a handshake takes the bundle when its ClientHello arrives,
  and one that completes after a reload replaced its certificates verifies the client's chain again against the current
  bundle (security level and the pins of a `Pinned` on the new path included). A reload to the same certificates changes
  nothing. Established connections are not affected. A bundle with no certificate valid now is refused and the old one
  stays. A session authenticated under the old bundle is not resumed, TLS 1.3 and TLS 1.2 tickets and QUIC's alike (the
  server's session ID context covers the bundle's certificates as a set, so a CA re-issued on its key counts as another
  bundle while reordered or repeated certificates do not), so a client of a dropped CA cannot come back with a ticket. Shared server contexts are kept per identity snapshot and
  bundle; the first handshake under the new bundle replaces the old bundle's context, which is freed with its last
  connection. With `clientAuth` None the bundle plays no part and a reload changes nothing. A client configuration with a
  `ReloadableCa` throws `TlsException.Config`.
- Ktor server: `EngineMain` keys `kuicksilver.tls.clientAuth` (`none`, `optional`, `required`) and
  `kuicksilver.tls.clientCa` (a PEM file of CA certificates) ask for client certificates on the deployment port. With
  `kuicksilver.tls.reloadInterval` the CA file is watched like the identity's files (two equal reads a second apart,
  retries with backoff, one warning per distinct failure, a file holding a private key refused) and new handshakes verify
  against the renewed bundle (`docs/guide/ktor.md`, "Certificate rotation"). A CA file with certificates that are not
  CA certificates (each would be an anchor) is applied with a warning. On the JVM the keys cannot be combined with a
  `-sslPort` connector, whose `ktor.security.ssl.trustStore` decides client certificates: the start is refused. A
  server's `tls { clientTrust }` may be a `TrustConfig.ReloadableCa`, shared by its TCP and QUIC handshakes (HTTP/1.1, HTTP/2 and
  HTTP/3).
- Ktor client: experimental `FileAltSvcStore(file: java.io.File)` on the JVM and Android, for an Android app's
  `File(context.filesDir, "altsvc.tsv")` (`docs/guide/ktor.md`, "Discovery and Alt-Svc"). It works on API 24 and 25 too:
  nothing on its path uses `java.nio.file` or `File.toPath()`, which arrived in API 26. The `kotlinx.io.files.Path`
  constructor is unchanged.
- QUIC: experimental `qlogDirectory(context, name)` on Android (`io.kuicksilver.quic.qlog`), the qlog counterpart of
  `keylogFile(context, name)`: a `DirectoryQlogSink` for the directory `name` (default `kuicksilver-qlog`) in the app's
  cache directory, which is private and not backed up. The directory is created owner-only (0700) and checked at once.
  Below API 26 it throws `IllegalArgumentException`, as `DirectoryQlogSink` refuses there (`docs/guide/quic.md`, "qlog").
- QUIC: experimental `QuicConnection.peerSupportsDatagrams`, true once the peer advertised `max_datagram_frame_size`
  above 0 (RFC 9221 section 3), exactly when `sendDatagram` does not answer `PeerDoesNotSupport`. `maxDatagramSize` is 0
  without support and also with a limit of 2 (room for an empty datagram only) or 1 (room for none: even an empty datagram is `TooLarge(0)`); this
  tells them apart.
- HTTP/2: a new published module, `kuicksilver-http2` (ADR-0017, superseding ADR-0009), with HTTP/2 (RFC 9113) and
  HPACK (RFC 7541) as a sans-IO core for the Ktor engines; it depends only on `kuicksilver-native` and is in the BOM. Its
  HPACK static and Huffman tables and the RFC 7541 appendix C vectors (`tools/vectors/`) are generated from the RFC text
  by `tools/http/gen-tables.py`, whose `--check` also verifies that `kuicksilver-http3` carries the same Huffman table.
  The module's frame codec (RFC 9113 sections 4 and 6) checks every declared frame length against the frame's type and
  the local SETTINGS_MAX_FRAME_SIZE before buffering anything and streams frames of unknown types past unbuffered;
  `Http2ErrorCode` (experimental) lists the section 7 error codes.
  HPACK (RFC 7541) matches appendix C byte for byte; the decoder bounds the decoded field list (an "HPACK bomb" of
  references stops at the limit and allocates nothing per reference) while keeping its table in step, rejects integers
  above 31 bits, oversized strings before allocating them and invalid Huffman padding; the encoder never indexes
  credentials and follows the peer's table size.
  The connection core (RFC 9113 sections 3.4, 5, 6) runs the preface, stream states, SETTINGS with an acknowledgement
  deadline, flow control that returns credit only as the application reads (with window auto-tuning), PING and a two-phase
  GOAWAY, and bounds every flood per connection: CONTINUATION frames and field-block bytes before decoding, queued control
  frames, empty DATA frames, a glitch budget for PRIORITY, SETTINGS, unknown frames, PINGs with nothing of ours in between
  and the stream errors the peer causes (MadeYouReset), a server's budget for the client's RST_STREAM frames (Rapid Reset), with reset streams counted
  until their handler returns. Field lists are HPACK-encoded in wire order. New experimental `Http2Settings`.
  New fuzz targets `http2.frames`, `http2.hpackDecode`, `http2.connectionServer` and `http2.hpackRoundTrip` (differential),
  with seeds from `tools/http/gen-fuzz-seeds.py`.
- HTTP/3: `Http3Endpoint.closeAndJoin()` (experimental) closes the endpoint and waits until its connections are closed
  and its UDP socket released, so the port can be bound again as soon as it returns. The Ktor server uses it for the
  endpoint of a TCP + UDP pair that failed with `port = 0`: that UDP port is free before the next attempt and before the
  start returns.
- QUIC: a server can advertise a preferred address (experimental `QuicServerConfig.preferredAddress`,
  `PreferredAddress`; RFC 9000 section 9.6). The endpoint listens there too (every loop of a group), advertises it with its
  sequence-1 connection ID, and moves a connection there once the client's address is validated on that socket,
  reporting the new `PathChangeReason.PreferredAddress`; a new connection is never started on a preferred socket.
  `bind` refuses a preferred address that is the endpoint's own, and a failed preferred socket takes the preferred address
  down on every loop (no more offers, moved connections closed, validations under way failed,
  `EndpointStats.preferredAddressFailures`) instead of ending the endpoint.
- QUIC: clients follow a server's preferred address (experimental `QuicConfig.followPreferredAddress`, on by default; RFC
  9000 section 9.6): after the handshake is confirmed they validate the path to the address of their family and move
  there, closing the original path; a failed validation keeps the connection where it was, and a public server cannot
  send the client to a local, unspecified, multicast or broadcast address. `disable_active_migration` does not stop the
  move, and after it the client may migrate.
- Ktor client: proxy resolution (experimental `proxies { resolver }`, `docs/guide/ktor.md`, "Proxies"):
  `ProxyResolvers.System` (the platform's settings: `ProxySelector` on the JVM and Android, CFNetwork on Apple
  platforms, WinHTTP's Internet settings on Windows, the environment on Linux), `ProxyResolvers.Environment` (curl's
  `https_proxy`, `http_proxy`, `all_proxy` and `no_proxy`, with `socks5://` and `socks5h://`), `ProxyResolvers.None`,
  or any `ProxyResolver` returning a `ResolvedProxy`. Answers are kept 30 seconds per route; `localhost` and loopback
  addresses always connect directly; a PAC or WPAD configuration on Apple platforms and Windows is not run (direct,
  one warning); a proxy the engine cannot use fails the request. `HttpClient.webTransport` refuses exactly the URLs a
  resolver sends through a proxy.
- Ktor client: SOCKS5 proxies (RFC 1928, CONNECT only) with username/password authentication (RFC 1929): a
  `ProxyBuilder.socks(host, port)` proxy now tunnels every request instead of being refused, the proxy resolving the
  origin's name. New experimental `proxies { credentials }` for the explicit `proxy` (SOCKS5 username/password, sent only
  when the proxy picks that method; `Proxy-Authorization: Basic` with the first CONNECT or absolute-form request to an
  HTTP proxy) and `ProxyException` (a SOCKS5 reply or CONNECT status other than success, as `replyCode`). Off the JVM
  a proxy URL's user info is used as its credentials, and an `https://` proxy URL is refused instead of being spoken
  to in clear. A SOCKS5 password has 1 to 255 bytes (RFC 1929 section 2: PASSWD is 1 to 255 octets): a SOCKS5 proxy
  configured with an empty one, also a URL with a user name only (`socks5h://user@host`), fails with
  `IllegalArgumentException` at once, the engine's creation for its `proxy`, `ResolvedProxy.socks5` or the request
  for a resolver's (curl and Go send PLEN 0 anyway; there is no user-only form, so give a one-byte password). An HTTP
  proxy takes an empty password (RFC 7617). The proxy's replies are read strictly, as Go's x/net/internal/socks does:
  the authentication reply's VER must be X'01' (RFC 1929 section 2) and the CONNECT reply's RSV X'00' (RFC 1928 section
  6), else `ProxyException` before the CONNECT or before any TLS.
- QUIC: ICMP Packet Too Big (Linux, Android) and EMSGSIZE (every accelerated socket) speed up path MTU discovery as
  hints (`quicConfig { pathMtu { icmpHints } }`, on by default; RFC 8899 section 4.6, RFC 9000 section 14.2.1). A
  Packet Too Big must quote one of the connection's packets on its active path and leave at least 1200 bytes of payload,
  and at most 64 a second per endpoint are looked at (`EndpointStats.ptbAccepted`, `ptbIgnored`). It ends larger probes
  at once. One below the size in use drops the MTU to 1200 at once (RFC 8899 section 4.6.2: "The PLPMTU SHOULD be set to
  BASE_PLPMTU"), provisionally (RFC 9000 section 14.2.1): a probe of the old size follows, and its acknowledgment
  restores that size and suspends Packet Too Big processing for 600 s (RFC 8899 section 8); only a probe sent after the
  drop counts. Forged messages therefore cost about one probe round trip at 1200 bytes per 600 s (the probe goes once
  the congestion window has room for it); when that probe is lost, the search starts from 1200 with the reported size
  first, without the black-hole pause. A congestion window still at its initial value when the size drops is lowered
  with it and not raised again on a restore (RFC 8899 section 3 item 7: an MTU update "MUST NOT increase the
  congestion window measured in bytes"). With zero-length connection IDs the quote proves only the address and port,
  so such a message is ignored: it neither lowers the size in use nor caps the search. A search started over (new
  socket capabilities, a new IP) ignores acknowledgments of the probes the search it replaced had sent. EMSGSIZE on a probe settles that size at once.
- Native (`ksl` ABI 7): on Linux and Android the accelerated UDP socket reads the ICMP error queue (`IP_RECVERR` /
  `IPV6_RECVERR`, set with DF) and keeps ICMP Packet Too Big messages, with the quoted start of the datagram and its
  destination, as hints for path MTU discovery (`ksl_udp_take_ptb`); every platform counts sends lost to `EMSGSIZE`
  (`ksl_udp_emsgsize`). A queued ICMP error (a port unreachable, real or forged) is a dropped datagram for the receive,
  never a socket error, and the drain is bounded so a flood cannot spin it. The library file name carries the new ABI
  (`libksl_7_…`).
- QUIC: the server issues NEW_TOKEN address-validation tokens (RFC 9000 section 8.1.3; experimental
  `QuicServerConfig.newTokenLifetime`, 24 hours by default, null issues none). One token after the handshake is confirmed
  and one after the client is validated on a new IP address, at most four per connection; a client that presents one on a
  later connection from the same IP arrives validated (`ConnectionAttempt.addressValidated`): no Retry under
  `AlwaysRetry` and no anti-amplification limit. Tokens are bound to the IP (not the port), sealed under hourly keys shared
  by the endpoint's loops and kept for the lifetime, sealed with a counter nonce (never a repeat under one key), and
  accepted once: a replay register sized by `QuicServerConfig.newTokenReplayCapacity` (1,048,576 tokens per lifetime in
  32 MiB by default) that treats a token as absent once it is full; a token that does not validate is treated as absent,
  never refused. New counters `EndpointStats.newTokensIssued`, `newTokensAccepted` and
  `newTokensRejected`.
- QUIC: clients keep NEW_TOKEN tokens and present them on their next connection (experimental
  `QuicClientConfig.tokenStore`, off by default because a token links the connections that use it; `QuicTokenStore`,
  `MemoryTokenStore`). Tokens are keyed by server name and port (without a server name, by the server's IP literal and
  port, a link-local one with its zone ID), used once, replaced by a Retry token when a Retry comes,
  and bounded per connection (eight of at most 1024 bytes; more NEW_TOKEN frames spend glitch tokens).
- HTTP/3 (*experimental*): the Capsule Protocol of RFC 9297 section 3 on Extended CONNECT streams whose protocol has
  datagram semantics (every one but `websocket`; on a WebSocket stream or a classic CONNECT it throws
  `IllegalStateException`, since section 3.2 has the protocol "only" for new upgrade tokens that use it).
  `Http3Stream.useCapsuleProtocol(CapsuleConfig)` returns a `CapsuleStream`: `capsules` delivers the declared
  `knownTypes` (64 KiB each at most by default) and skips other types without buffering them, `send` writes whole
  capsules, `close()` writes what is queued and then FIN. A FIN inside a capsule, a known capsule above the limit, or a
  message that uses capsules with `content-length`, `content-type`, `transfer-encoding` or a 204/205/206 status resets
  the stream with `H3_MESSAGE_ERROR` and fails with `Http3Exception.MessageError`, as does any byte after a capsule of
  `terminalTypes` (for WebTransport's WT_CLOSE_SESSION); the connection lives on. DATAGRAM
  capsules are received together with QUIC datagrams, dropped unread above `maxDatagramLength`, and sent instead of QUIC
  datagrams when HTTP/3 datagrams are unsupported (`datagramFallback`). `CapsuleProtocol` reads and writes the
  `Capsule-Protocol` header field. A message that announces the protocol with `Capsule-Protocol: ?1` is checked against
  section 3.2 before any tunnel exists: `acceptConnect` answers such a request that breaks it with 400 and STOP_SENDING
  `H3_MESSAGE_ERROR`, `connect` fails on such a 2xx with `MessageError`, and our own such CONNECT or 2xx is refused with
  `IllegalArgumentException` before it is sent. See `docs/guide/http3.md`, "Capsules".
- WebTransport over HTTP/3, first part (experimental, `docs/guide/http3.md`, "WebTransport"): `Http3Settings.webTransport`
  advertises the SETTINGS of draft-ietf-webtrans-http3-16 and of the draft-02 and draft-14 codepoints browsers still
  use; WebTransport streams (`0x54` uni, `0x41` bidi) are routed to their session, those that arrive before it wait in
  a bounded buffer (16 per connection, 5 s each); `Http3Connection.webTransport` opens a session (the `:protocol`
  token follows the server's draft, `WT-Available-Protocols`/`WT-Protocol` negotiation, ten-second deadlines for the
  server's SETTINGS and for the answer) and
  `Http3ServerRequest.isWebTransport`, `availableProtocols` and `acceptWebTransport` accept one. Flow control and
  several sessions per connection: see the entry below. A `WebTransportSession` opens and accepts bidirectional and
  unidirectional streams, sends and receives datagrams, closes with an application code and reason
  (WT_CLOSE_SESSION, then FIN) and drains; application error codes are mapped into the HTTP/3 space;
  `Http3ErrorCode` has the WebTransport codes.
- Ktor server (experimental): `http3 { webTransport { enabled = true } }` and `Route.webTransport(path, protocols, checkOrigin) { session -> }`
  serve WebTransport sessions over HTTP/3 (`docs/guide/ktor.md`, "WebTransport over HTTP/3"): the route matches only a
  WebTransport Extended CONNECT, refuses a foreign `origin` with 403 (`sameHostOrigin` by default), picks the
  protocol, and closes the session when the handler returns (code 0) or throws (`WEB_TRANSPORT_HANDLER_FAILED`).
- QUIC (experimental): RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset-11). `QuicConfig.resetStreamAt` advertises
  `reset_stream_at` (0x1d, and the unregistered codepoint of earlier drafts, as quic-go does); `QuicStream.resetAt(code, reliableSize)` and `ConnectionCore.resetStreamAt` reset a stream while
  still delivering its first bytes when the peer advertised it too, and fall back to RESET_STREAM otherwise. WebTransport
  resets the streams it opened this way, keeping their header (draft-ietf-webtrans-http3-16 section 4.4), and the Ktor
  server advertises it with `http3 { webTransport { enabled } }`.
  `QuicConnection.resetStreamAtEnabled` tells whether both sides advertised it.
- Ktor client (experimental): `HttpClient.webTransport(url, protocols, headers)` opens a WebTransport session on the
  Kuicksilver engine's pooled HTTP/3 connection of the URL's origin (see the session pooling entry below;
  `docs/guide/ktor.md`, "WebTransport on the client"); no fallback; refused with `http3 { enabled = false }` and through a proxy unless
  `http3 { webTransport { proxyPolicy = WebTransportProxyPolicy.BypassHttpProxy } }`; at most
  `http3 { webTransport { maxSessions } }` (64) at once.
- WebTransport interop with a real browser: `ChromeWebTransportTest` (opt-in, `-Pkuicksilver.browserTests=true`)
  drives an installed Chrome headless through streams, datagrams and both closes against the Ktor server; results and
  a manual check for Firefox and Safari in `docs/spec/interop.md`, "Interop WebTransport".
- Ktor client: Happy Eyeballs version 2 (RFC 8305) for every connect to a host name, HTTP/1.1 and HTTP/2 over TCP to the
  origin and to an HTTP proxy, and HTTP/3 over QUIC (`docs/guide/ktor.md`, "Happy Eyeballs"; `docs/spec/rfc/8305.md`).
  A name's IPv6 and IPv4 addresses are asked for separately (one `getaddrinfo` per family; on the JVM and Android
  through the native library, as `InetAddress` asks for both at once), the first IPv6 answer starts a connection at
  once and an IPv4 answer that comes first waits at most 50 ms for it; answers that come later join the attempts in
  progress. The addresses are sorted by RFC 6724 destination address selection of the engine's own on every platform
  (also those of HTTPS records), with the families alternating, and tried one `network { happyEyeballsDelay }` apart
  (250 ms; 100 ms to 2 s, or `null` for one address after another) or at once when an
  attempt failed, never within 10 ms of the last one; the first connection wins and the others are cancelled or
  closed. HTTP/3 races its QUIC handshakes over the same addresses, so a family that drops UDP costs one attempt
  delay, `H3Only` included (with `http3 { earlyData { enabled } }` and a session ticket the first address sends 0-RTT at once and the others
  are not tried for that setup; a failed handshake there falls back as before); a server's CONNECTION_REFUSED at one address now moves on to the next, and counts as a
  refusal (no broken mark) only when every address refused. On an IPv6-only network without 464XLAT, IPv4 addresses
  the host has no route to (IPv4 literals, IPv4-only names) are reached through the network's NAT64 (RFC 6052): Apple's
  own synthesis, Android's `LinkProperties.getNat64Prefix` (API 30) when the application gave the engine a
  `ConnectivityManager` (`followDefaultNetwork`, `followingPrivateDns`), elsewhere the prefix of RFC 7050 discovery, asked only when needed; IPv4 is asked for only when needed. The name is
  resolved once per request for both sides of the h3/h1 race, off the caller's thread and within the connect timeout.
  On the JVM an application's own resolver (`InetAddressResolverProvider`, `jdk.net.hosts.file`) is still used, answers
  are kept for the JDK's `networkaddress.cache.ttl` and `.negative.ttl`, and `java.net.preferIPv6Addresses` no longer
  orders the addresses. Native: `ksl_resolve`, `ksl_addr_info` and `ksl_nat64_synthesize`, additive under ABI 7.
- Ktor engines: WebSocket extension negotiation and frame checks (RFC 6455 sections 4.1, 5.2 and 9.1; RFC 7692
  section 6.1; `docs/guide/ktor.md`, "Client"). The client engine declares `WebSocketExtensionsCapability`, so Ktor's
  `WebSockets` plugin offers and negotiates the installed extensions over HTTP/1.1 and HTTP/3 (Ktor's JVM
  `WebSocketDeflateExtension` included); an answer that accepts an extension the client did not offer fails the call
  with `WebSocketException`. Both engines end a session whose peer sets an RSV bit no negotiated extension defines, or
  uses a reserved opcode, or masks its frames in the wrong direction (RFC 6455 section 5.1), or gives a 64-bit payload
  length with its most significant bit set (section 5.2), with a Close frame with code 1002 (threat model 3.20.1).
- WebSockets: permessage-deflate on every target (RFC 7692; experimental `PerMessageDeflate` in
  `kuicksilver-ktor-network`; `docs/guide/ktor.md`, "WebSocket compression"). A Ktor `WebSocketExtension` for the client
  and server `WebSockets` plugins on any engine: java.util.zip on the JVM and Android, the platform's zlib on
  Kotlin/Native (Linux binaries now need `libz.so.1`; Windows links it statically). The negotiation follows RFC 7692
  sections 5, 7 and 7.1 (invalid offers declined, invalid answers fail the handshake, `server_max_window_bits` honoured
  where the deflater can keep to it; the engines refuse, as server, and fail, as client, permessage-deflate negotiated
  next to another extension that uses RSV1); RSV1 goes on the first frame of a message only; an incoming message may inflate
  to `maxInflatedMessageSize` (16 MiB by default). Kuicksilver's engines decompress the frames as they arrive and close
  a connection whose message passes the limit with 1009, over HTTP/1.1 and HTTP/3 (threat model 3.20.2).
  `compressIf { }` keeps chosen messages uncompressed (CRIME/BREACH, RFC 7692 section 8; the guide says when). Two
  Jazzer targets, `ktor-network.inflate` and `ktor-network.wsGuard`.
- Ktor server: RFC 9218 priorities (experimental). `call.request.priority` is the client's signal (the `priority`
  field, over HTTP/3 also its PRIORITY_UPDATE frames, which `call.request.priorityUpdates` follows as a `StateFlow`),
  and `call.response.priority(urgency, incremental)` sets the response's `Priority` field with only the given
  parameters; over HTTP/3 they are merged into the client's signal and schedule the response. Over HTTP/1.1 the field
  is read and sent only.
- Ktor client: RFC 9218 priorities (experimental). `priority(urgency, incremental)` in a request builder sends the
  `priority` field and, over HTTP/3, schedules the request's stream with it (a WebSocket over HTTP/3 included); it
  replaces a `Priority` header on the same request. `response.updatePriority(urgency, incremental)` sends a
  PRIORITY_UPDATE while the response is coming and returns false over HTTP/1.1 or once the call is over.
- Ktor client: per-call protocol diagnostics (experimental; `docs/guide/ktor.md`, "Why did this request not use
  HTTP/3?"). Every response carries a `ProtocolDiagnostics` (`response.kuicksilverDiagnostics`, the call attribute
  `KuicksilverDiagnosticsKey`): the protocol that served it, the `ProtocolReason`, why it did not go over HTTP/3 as a
  `FallbackReason` (`HandshakeTimeout`, `TlsFailure`, `BrokenAlternative`, `H3NotReady`, `MisdirectedRequest`, ...), the HTTP/3 alternative
  and its `AlternativeSource`, the race and its head start, the HTTP/3 failure and the number of attempts. The engine's
  logger gets one line per call HTTP/3 could have served but did not, at `observability { protocolChoiceLogLevel }` (`Info` by
  default; HTTP/3 calls at `Debug`; `null` for none), without the URL's query or user info. A broken alternative now
  remembers why it broke, and when both the HTTP/3 and the HTTP/1.1 setups fail the HTTP/1.1 failure carries the HTTP/3
  one in `suppressed`.
- Ktor client: an HTTP/3 kill switch (`http3 { allowed = { ... } }`; `docs/guide/ktor.md`, "Turning
  HTTP/3 off remotely"), read once per `https://` request from the application's remote configuration. While it returns
  false requests go over HTTP/1.1 (`ProtocolReason.Http3Disabled`, `FallbackReason.Http3Disabled`), open HTTP/3
  connections take no new requests, `Alt-Svc` is still learned, and `H3Only` requests and `HttpClient.webTransport` fail
  with `UnsupportedOperationException` without any connection; a switch that throws an exception allows HTTP/3 and is
  logged at most once per 5 minutes. `HttpClient.closeHttp3Connections()` sends GOAWAY on every pooled HTTP/3 connection
  and closes each once its calls are done (a request handed one just before goes again on a new connection), and sends
  every open WebTransport session `WT_DRAIN_SESSION`.
- Ktor server: the QUIC endpoint limits of the HTTP/3 listeners are set from the engine configuration:
  `http3 { endpoint { maxConnections } }` (10,000), `maxConnectionsPerIp` (256; `null` turns it off) and `acceptQueue`
  (128), with the same defaults and ranges as `QuicEndpointConfig`, and `EngineMain` keys
  `kuicksilver.http3.endpoint.maxConnections`, `kuicksilver.http3.endpoint.maxConnectionsPerIp` (`off` turns it off) and
  `kuicksilver.http3.endpoint.acceptQueue`. Behind a NAT, Kubernetes
  `kube-proxy` with `externalTrafficPolicy: Cluster` or a UDP proxy that sends from its own address every client shares
  one address and hit the fixed 256 per address; raise or turn off the limit there (docs/guide/deployment.md, "QUIC
  connection limits").
- Ktor server: `engine.http3Stats` (experimental) returns the QUIC endpoint counters (`EndpointStats`) of every HTTP/3
  listener: datagrams, drops, refusals by admission, the connection limits and the accept queue, handshakes. The engine
  gave no access to them before.
- Build: `tools/check/deployment-guide.sh` runs the commands of docs/guide/deployment.md, "Checking a deployment"
  (`curl --http3-only`, the `Alt-Svc` check, `tcpdump`), as they stand against the engine in one Docker container; a step
  of the local matrix and of the CI `linux-native` job.
- Docs: every guide shows the imports of its samples (compiled by the guide tests), the README has an Install section with
  per-target Gradle blocks and the BOM, and the guides gained mutual TLS, per-request protocol logging, a complete raw
  QUIC example with a custom ALPN, a 0-RTT section for application authors, Kubernetes health checks, NAT idle timeouts,
  container notes (glibc, a read-only root file system, port 443 without root), an `EngineMain` `application.conf` and a
  handshake-timeout diagnosis procedure. `tools/check/guide-sync.sh` requires an import block to equal its test's imports
  (negative controls in `guide-sync-test.sh`), and `tools/release/local-release.sh` refuses a README that still calls the
  version it releases the release in preparation.
- Build: repository checks for bug classes that came back after review (docs/process.md, "Repository checks"), in
  steps 3 and 4 of the local gate (now `lint: doc refs, test gates, commit types` and its negative controls; the step
  count is unchanged) and in the CI `lint` job, each with negative controls: `tools/check/test-discovery.py` (a `@Test`
  no runner runs, such as one declared inside a helper's body), `test-bytecode.py` (the same in the compiled JVM and
  Android host test classes: a test returning a value, which JUnit 5 skips, a static or private one, one in an object;
  it runs after the JVM tests), `test-count.py` (every test listed in `test-count.lock`, so a drop names the test),
  `test-sleeps.py` (the sleeps per test file, polling helpers included, may only go down, `test-sleeps.lock`),
  `env-apis.py` (host-name lookups in library code, counted per file in `env-apis.allow`), `rfc-tests.py` (the tests a ✅ RFC section
  names exist, and it names one; `rfc-tests.lock` lists the three sections without one) and `commit-msg.sh` (a
  conventional type in every commit subject of the branch; also a `commit-msg` hook). The RFC details files named
  tests that had been renamed, or named them after the wrong class; those names are corrected, four ✅ sections
  that named no test now name theirs, and the RFC 9460 section 9.3 text says that a cached Alt-Svc alternative does not
  skip the HTTPS records (it shares the origin's lookup), as the client has done since 0.3.0.
- Fuzzing: the 120 committed `quic.connectionNull` and `quic.connectionTls` inputs that lost their early server
  application operations when the connection fuzzer moved to endpoints are refreshed: each decodes again to the operations
  it was kept for (463 server application operations instead of 216); 110 old versions that a Jazzer merge found redundant
  are removed, and every corpus input is named by the SHA-1 of its bytes again, which `CommittedCorpusReplayTest` checks.
- Fuzzing: the ksl harness's driver names its inputs by the standard FNV-1a 64 (its offset basis was missing a digit), the
  `ksl.parsers` corpus is renamed accordingly, and `tools/c-test.sh` fails on an input whose name is not the FNV-1a 64 of
  its bytes (`tools/fuzz/ksl/corpus-names.c`, with reference values and negative controls).
  `tools/fuzz/campaign.sh minimize` and `prune` rename a `ksl.parsers` merge's output the same way, so a minimize with
  libFuzzer (Linux), which names inputs by SHA-1, keeps those names.
- Build: `tools/fuzz/formats/flags.txt` names every flag bit, setup bit and outcome of the traced connection fuzz
  programs (`ConnProgram`, `ZeroRttProgram`) by its constant, value and trace name. `tools/check/fuzz-formats.py` checks
  it against the programs' sources and KDoc (no gap, no duplicate, no stale or unlisted name, the trace name the
  constant's in lowerCamelCase; a renamed or moved flag needs a reason in `changes.txt`), and `FuzzTraceTest` against the
  compiled programs, each with negative controls.
- Build: `tools/check/commit-msg.sh` also checks the commit hashes a message cites: each must name a commit in the
  history of the branch (`--range`, step 3 of the local gate) or of `HEAD` (the hook). After a rebase or a rewrite of the
  dates, messages kept citing the old hashes, which name nothing. A 7 to 40 digit hex word counts when it names a commit
  here or follows a keyword (`Review of`, `commit`, `since`, ...); numbers, quoted values (a CID), `0x` constants, paths
  and URLs do not, and another repository's or branch's commit is written `<name>@<hash>`; a commit on `origin/main`
  passes too. Commits already on
  `origin/main` are not read; a shallow clone lists what it could not judge instead of failing (docs/process.md,
  "Repository checks").
- Build: `tools/ci/local-matrix.sh --only <steps>` (e.g. `--only 25,48-49,52`) and `--from <n>` run some steps of the
  local gate again after a fix, with the step numbers of a full run. Such a run is never a gate: it writes
  `build/ci/gate/<commit>.partial` (the selection, `result=partial-pass` or `partial-fail`), never the stamp, and
  `local-release.sh` now also requires `selection=all` in the stamp. A selection that leaves out a step whose output a
  selected step reads is refused before anything runs; `tools/ci/local-matrix-test.sh` checks these refusals through
  `--dry-run`, a new gate step (48, after the local-release refusals: the later steps move up by one; the gate has 71
  steps by default and 76 for a release) and a step of the CI `lint` job. The JNI exports and OpenSSL prefix checks now build what they
  check instead of reading what earlier steps or builds left (the iOS archives were checked before the steps that build
  them), the Windows step rebuilds the mingw dll unless this run's mingw step built it, and the JVM interop image
  rebuilds its Linux libraries unless this run's Docker JVM steps built them. Behaviour changes of a full run: a step
  whose input step failed in the same run (the AAR, the link step, an interop image) now fails without running instead
  of checking what an earlier build left; with `--skip-docker`, `--with-windows` now builds the mingw-x64 OpenSSL in the
  preflight and the mingw dll in Docker on every run (before, only when it was older than the C sources), so Docker
  must be running, and `--with-interop` builds the Linux
  OpenSSL of the host's architecture; a dry run's last line now says how many steps it listed, not that they passed.
- HTTP/2, never-indexed fields (RFC 7541 sections 6.2.3 and 7.1.3; experimental): the Ktor engines report the fields a
  peer sent as literals never indexed (`ApplicationRequest.neverIndexedHeaders` on the server,
  `HttpResponse.neverIndexedHeaders` on the client) and send the fields an application names as such
  (`ApplicationResponse.neverIndex(...)`, `HttpRequestBuilder.neverIndex(...)`), so an application that proxies with
  both engines keeps the representation an intermediary must keep. Before, the bit was dropped on decoding and only the
  engine's own list of credentials went out never indexed. The same API carries QPACK's 'N' bit over HTTP/3 (RFC 9204
  sections 4.5.4 and 7.1.3): the decoder reports it (`Http3Headers.neverIndexed`), and fields named with
  `Http3Headers.withNeverIndexed(...)` (or the engines' `neverIndex`) go as literals with the bit, never inserted nor
  referenced; a received section forwarded as it is keeps it. Before, the decoder dropped the bit. A WebSocket's Extended CONNECT
  and its answer (RFC 8441, RFC 9220) carry the marks the same way.
- Ktor server: TLS 1.2 on request (RFC 9325 section 3.1.1, "Implementations MUST support TLS 1.2"). The
  `tls { versions }` option (`TlsVersions.Tls13` by default, `TlsVersions.Tls12And13` to serve
  TLS 1.2 clients over TCP), the `EngineMain` key `kuicksilver.tls.versions` (`tls13` or `tls12And13`, for the deployment
  port; refused next to `-sslPort`) and, on the JVM, Ktor's own `enabledProtocols` on `sslConnector` (`TLSv1.2` with
  `TLSv1.3`). TLS 1.2 runs under the RFC 9325 profile of the TLS layer (ECDHE with AES-GCM or ChaCha20-Poly1305,
  Extended Master Secret required, no renegotiation, no compression); a client with TLS 1.3 still gets it, and HTTP/3 on
  the same port stays TLS 1.3. With HTTP/2 on, it is offered over TLS 1.2 too (RFC 9113 section 9.2), and a client's
  renegotiation attempt on an HTTP/2 connection ends it with GOAWAY PROTOCOL_ERROR (section 9.2.1). The default connector
  still refuses a TLS 1.2 client with `protocol_version` (docs/guide/ktor.md, "TLS 1.2 on the server").
- Release: prereleases on GitHub only. `tools/release/local-release.sh <version> --github-prerelease` builds, checks and
  signs a prerelease as a Central release does, uploads nothing and reads no Central credentials, and writes a signed
  Maven repository zip of the publication (`kuicksilver-<version>-maven-repository.zip`, with checksums and
  `maven-metadata.xml`), a file on how to consume it, and a signed `SHA256SUMS` of the assets for the GitHub prerelease.
  It refuses a final version; without it a prerelease is refused unless `--central-prerelease` sends it to Central.
  The Swift package commit is prepared as for a release (in UTC), and `tools/release/swift-package-check.sh` checks it
  before its immutable tag is pushed (`local`: an empty package built for the iOS Simulator and iOS against the local
  zip; `remote --draft`: the draft release's zip and GitHub's digest against `Package.swift`, then `remote` at the public
  URL; `prepush`: UTC commit and tag dates, no home-directory path) and after (`resolve`: `exact: "<version>"`). The
  documentation site is no longer built for a published prerelease, and `/latest/` is only ever a final release.
  The Swift package clone gets a pre-push hook that runs those checks on every push of it, and its own git config
  carries the release identity, which the checks require of every commit and tag (both also signed by the release key).
- Release privacy: `tools/hooks/pre-push` (UTC commit and tag dates, one identity, no maintainer name, home directory or
  host name in a pushed commit or its author, release tags signed by the release key), installed by symlink with the names and the identity in git config
  (`kuicksilver.privacy.names`, `kuicksilver.privacy.identity`, and `kuicksilver.privacy.tagger`, the release key's
  identity `Kuicksilver <hello@kuicksilver.io>` that release tags and the Swift package's commits and tags carry, so that
  GitHub can show them as Verified), and required by
  `local-release.sh` (docs/process.md, "Privacy pre-push hook"). `tools/check/build-paths.py` also refuses temporary
  directories (`/tmp/`, `/var/folders/`, ...), home-relative paths, and the user, host and configured names, looked up
  at scan time. 0.3.0-rc1 is published this way, not on Maven Central (docs/release.md,
  "Prereleases on GitHub only").

### Changed

- Configuration in blocks (breaking; ADR-0026, `docs/guide/configuration.md`). Every builder and both Ktor engines group
  their options in blocks with one name per concept: the client keeps `connectTimeout` at the top and puts the rest in
  `tls { }`, `http3 { }`, `http2 { }`, `http1 { }`, `pool { }`, `network { }`, `proxies { }`, `webSockets { }` and
  `observability { }`; the server keeps `requestHeaderTimeout` (now a `Duration`) and puts the rest in `tls { }`,
  `tlsConnector { }`, `plainConnector { }`, `http1 { }`, `http2 { }`, `http3 { endpoint { } }`, `webSockets { }`, `tcp { }`
  and `observability { }`; the low-level builders get `flowControl { }`, `pathMtu { }`, `datagrams { }`, `migration { }`,
  `qpack { }`, `ech { }`, `observability { }`, `runtime { }`, `floodLimits { }` and an experimental `expert { }` each.
  "Off" is `null` everywhere (`Duration.ZERO`, `Duration.INFINITE` and `0` for "none" are refused), time is a `Duration`,
  byte and stream counts are `Long`, a rate with its burst is one `RateLimit`. An engine derives what follows from other
  options (ALPN, the server name, the connection ID length, Extended CONNECT, the client's
  handshake deadline) and refuses an explicit assignment with `... is derived by the engine (<why>); remove it`; the QUIC
  stream limits stay settable (`expert { maxUniStreams }` at least 3, RFC 9114 section 6.2) and default to 100, raised to
  fit the WebTransport sessions of a connection (`kuicksilver.http3.quic.expert.maxUniStreams` in `EngineMain`). The
  readers of `QuicConfig`, `QuicEndpointConfig`, `QuicClientConfig`, `QuicServerConfig`, `Http3Settings` and
  `Http2Settings` are internal: build with the DSL, copy with `toBuilder()`. The first-screen options of both engines are stable; `@SecuritySensitive` marks the options whose
  wrong value weakens security (🔒 in the reference). No deprecated aliases exist: an old Kotlin name does not compile, and
  `tools/migrate/config-0.3.py` rewrites most of them into their blocks. The options 0.2.x released move as follows
  (options added in 0.3.0 snapshots: under their new name in the reference):

  | 0.2.x | 0.3.0 |
  |---|---|
  | client `trust`, `identity` | `tls { trust; identity }` |
  | client `tls { }` (a `TlsConfig.Builder` lambda) | `tls { }` (`ClientTlsConfig`; ALPN, server name and handshake deadline derived) |
  | client `tls { handshakeTimeout }` | `connectTimeout` (the TLS handshake's deadline is derived from it) |
  | client `tls { sessionTickets }`, `tls { genericAlerts }` | no replacement: ticket keys are a server's, and the client sends the specific alert (`tlsConfig(role) { expert { genericAlerts } }` stays for the low-level API) |
  | client `tls { echConfigList }` | `tls { ech { configLists = mapOf(host to list) } }` |
  | client `quic = …` | `http3 { quic { … } }` |
  | client `quic = quicConfig { handshakeTimeout }` | `connectTimeout`: `http3 { quic { handshakeTimeout } }` is derived and refused |
  | client `http3 { settings = http3Settings { webTransportMaxSessions } }` | `http3 { webTransport { maxSessionsPerConnection } }` |
  | client `maxConnectionsCount`, `maxConnectionsPerRoute`, `maxIdleConnectionsPerRoute`, `idleTimeout` | `pool { maxConnections; maxConnectionsPerRoute; maxIdleConnectionsPerRoute; idleTimeout }` |
  | client `maxConnectionLifetime = Duration.INFINITE` | `pool { maxConnectionLifetime = null }` (the default) |
  | client `logger: KuicksilverLogger?`, `eventListener` | `observability { logger; eventListener }` (`logger` not nullable, `KuicksilverLogger.Default`) |
  | client `http3 { discovery = Http3DiscoveryMode.H1Only }` | `http3 { enabled = false }` |
  | client `Http3DiscoveryMode.Auto / Preferred / H3Only` | `Http3Discovery.Auto / Preferred / H3Only` |
  | client `http3 { quicHints }` | `http3 { hints }` |
  | client `http3 { clearOnNetworkChange }` | `http3 { expert { clearAltSvcOnNetworkChange } }` |
  | client `http3 { hardDelay = null / d / Duration.INFINITE }` | `http3 { expert { raceHeadStart = RaceHeadStart.Adaptive / Fixed(d) / NoRace } }` |
  | client `http3 { networkId }` | `network { networkId }` (`null`: not set) |
  | client `http3 { settings = … }` | `http3 { settings { … } }` |
  | client `http3 { endpoint = … }` | `http3 { expert { connectionIdLength; dispatcher } }`, `observability { }` |
  | client `http3 { earlyData = true }` | `http3 { earlyData { enabled = true } }` |
  | client `http3 { qlog; connectionListener }` | `observability { qlog; connectionListener }` |
  | server `identity`, `tlsConnector(identity) { }` | `tls { identity }` (or `tls { pemFiles(chain, key) }`) and `tlsConnector { }` |
  | server `tlsConnector { clientAuth; trust; cipherSuites; sniSelector }` | `tls { clientAuth; clientTrust; cipherSuites; sniSelector }` (per connector: `tlsConnector { tls { } }`) |
  | server `tlsConnector { host = "0.0.0.0" }` (the default) | `tlsConnector { host = null }` (the default: every interface, see below) |
  | server `connectionIdleTimeoutSeconds: Int` | `tcp { idleTimeout: Duration }` (HTTP/1.1 and HTTP/2) |
  | server `requestHeaderTimeoutSeconds: Int` | `requestHeaderTimeout: Duration` |
  | server `http3: Boolean`, `altSvc` | `http3 { enabled; altSvc }` |
  | server `quic = …`, `quicMaxIdleTimeout` | `http3 { quic { … } }`, `http3 { quic { maxIdleTimeout } }` |
  | server `quic = quicConfig { connectionIdLength }` | `http3 { endpoint { expert { connectionIdLength } } }` (`kuicksilver.http3.endpoint.expert.connectionIdLength`; refused next to `loadBalancer`) |
  | server `udpSocketCount` | `http3 { endpoint { loops } }` |
  | server `quicAdmission` (null: the default) | `http3 { endpoint { admission } }` (not nullable) |
  | server `http3Settings = …` | `http3 { settings { … } }` |
  | server `http3Settings { webTransport; webTransportMaxSessions; webTransportInitialMaxStreamsBidi; webTransportInitialMaxStreamsUni; webTransportInitialMaxData }` | `http3 { webTransport { enabled; maxSessionsPerConnection; initialMaxStreamsBidi; initialMaxStreamsUni; initialMaxData } }` |
  | server `quicEarlyData`, `http3Settings.earlyData` | `http3 { earlyData { enabled; policy } }` |
  | server `webSocketsOverHttp3` | `webSockets { overHttp3 }` |
  | server `logger`, `qlog`, `connectionListener`, `eventListener` | `observability { logger; qlog; connectionListener; eventListener }` (`logger` not nullable, `ServerObservability.ApplicationLog`) |
  | `quicConfig { maxIdleTimeout = Duration.ZERO }` | `quicConfig { maxIdleTimeout = null }` |
  | `quicConfig { initialStreamWindow; initialConnectionWindow; maxStreamWindow; maxConnectionWindow; maxSendBuffer }` | `quicConfig { flowControl { … } }` |
  | `quicConfig { maxUdpPayloadSize; pmtud }` | `quicConfig { pathMtu { maxReceive; discovery } }` |
  | `quicConfig { maxDatagramFrameSize = 0 }`, `datagramReceiveQueue`, `datagramSendQueue`, `datagramSendQueueBytes` | `quicConfig { datagrams { maxFrameSize = null; receiveQueue; sendQueue; sendQueueBytes } }` |
  | `quicConfig { allowMigration; allowMigrationToLoopback }` | `quicConfig { migration { allow; allowToLoopback } }` |
  | `quicConfig { maxUniStreams; maxAckDelay; ackDelayExponent; activeConnectionIdLimit; initialVersion; initialRtt; greaseQuicBit; glitchProtection }` | `quicConfig { expert { … } }` |
  | `quicConfig { defaultStreamErrorCode }` | `quicConfig { expert { cancelErrorCode } }` |
  | `quicConfig { connectionIdLength }`, `quicConfig { qlog }` | `quicEndpointConfig { connectionIdLength }`, `quicEndpointConfig { observability { qlog } }` |
  | `quicServerConfig(tls) { earlyData }` | `quicServerConfig(tls) { acceptEarlyData }` |
  | `quicEndpointConfig { crypto; dispatcher; io }` | `quicEndpointConfig { runtime { … } }` |
  | `quicEndpointConfig { initialQueueCap; rejectInitialFromReflectivePorts; statelessPerAddressPerSecond; statelessTotalPerSecond }` | `quicEndpointConfig { expert { initialAdmissionQueue; … } }` |
  | `quicEndpointConfig { logger; listener }` | `quicEndpointConfig { observability { logger; connectionListener } }` |
  | `tlsConfig(role) { genericAlerts }` | `tlsConfig(role) { expert { genericAlerts } }` |
  | `http3Settings { qpackMaxTableCapacity; qpackBlockedStreams; encoderMaxTableCapacity }`, `enableQpackDynamicTable()` | `http3Settings { qpack { maxTableCapacity; blockedStreams; encoderMaxTableCapacity; enableDynamicTable() } }` |
  | `http3Settings { grease; maxEarlyPriorityUpdates; glitchProtection }` | `http3Settings { expert { … } }` |

  The `EngineMain` keys follow the server's DSL under `kuicksilver.` (`kuicksilver.http3.endpoint.maxConnections` is
  `http3 { endpoint { maxConnections } }`), `off` is the one "none" (`0` there is refused), and every key under
  `kuicksilver.` must be known. Kuicksilver refuses to start with a 0.2.x key and names the new one
  (`kuicksilver.altSvc was replaced in 0.3.0 by kuicksilver.http3.altSvc`); no old key is read. The 0.2.x keys:

  | 0.2.x | 0.3.0 |
  |---|---|
  | `kuicksilver.http3` | `kuicksilver.http3.enabled` |
  | `kuicksilver.altSvc` | `kuicksilver.http3.altSvc` |
  | `kuicksilver.udpSocketCount` | `kuicksilver.http3.endpoint.loops` |
  | `kuicksilver.webSocketsOverHttp3` | `kuicksilver.webSockets.overHttp3` |
  | `kuicksilver.tls.certificateChain`, `kuicksilver.tls.privateKey` | unchanged |

  The keys of the 0.3.0 snapshots are refused the same way; their replacements are in `docs/guide/configuration.md`,
  "Migrating from 0.2.x". New keys: `kuicksilver.requestHeaderTimeout`, `kuicksilver.http3.earlyData.enabled`,
  `kuicksilver.webSockets.maxMessageSize`. New in code: `tls { pemFiles(chain, key); clientCaFile(path);
  ocspStaplingFile(path) }` with `reloadInterval` watching the files, as `EngineMain` did, and
  `http3 { endpoint { maxConnectionLifetime; expert { } } }`.
- Ktor server: HTTP/2 is on by default (breaking behaviour; ADR-0026). Every TLS connector, and the deployment port of
  `EngineMain` with TLS files, offers ALPN `h2`, then `http/1.1`: a client that offers both (browsers, OkHttp, the JDK's
  client, curl, Kuicksilver's) gets HTTP/2 where 0.2 gave it HTTP/1.1, and WebSockets come over HTTP/2 with it (RFC 8441)
  unless `webSockets { overHttp2 = false }`. `http2 { enabled = false }` (`kuicksilver.http2.enabled = false`) keeps
  HTTP/1.1 alone. Plain connectors and h2c are unchanged. A Ktor client call that lacks a client certificate the server
  requires now fails with `Http2Exception.ConnectionClosed` carrying the TLS alert, where HTTP/1.1 threw the
  `TlsException` itself. The `http2 { }` blocks of both engines are stable; `http2 { settings { } }` stays experimental.
  Over TLS 1.2 (`tls { versions = TlsVersions.Tls12And13 }`) `h2` goes only to a handshake that can support
  `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` with P-256 (RFC 9113 section 9.2.2 MUST): one whose certificate has no
  rsaEncryption key or whose groups leave P-256 out gets `http/1.1` (in every TLS server, `ksl`'s ALPN selection), and the
  engine refuses to start a connector serving HTTP/2 over TLS 1.2 whose `keyExchangeGroups` leave `secp256r1` out.
- Logging: `KuicksilverLogger.Default` is the platform's logger at warnings and up, and every QUIC endpoint and the Ktor
  client start with it: SLF4J on the JVM (logger `io.kuicksilver`; standard error when no SLF4J provider is on the
  classpath, or no `slf4j-api` at all: the module compiles against it, Ktor brings it), Logcat on Android (tag `Kuicksilver`), `NSLog` on Apple platforms, standard error on Linux and Windows.
  Before, the default was `KuicksilverLogger.Stderr`. The Ktor server logs to the application's log (`environment.log`)
  unless `observability { logger }` is set: its default is `ServerObservability.ApplicationLog` (not nullable, as on the
  client), and a logger of the application's own takes every engine line, TCP, HTTP/1.1, HTTP/2 and the TLS file
  watchers included, not the HTTP/3 endpoints' alone. `KuicksilverLogger.platform(level)` gives the platform's
  logger at another level; `KuicksilverLogger` and `LogLevel` are stable.
- Ktor server: `tlsConnector { }` and `plainConnector { }` without a `host` bind every interface of both families (breaking
  behaviour): one dual-stack socket per protocol on `::`, IPv4 clients arriving as IPv4-mapped addresses, or `0.0.0.0` where
  the host has no IPv6 (logged at Info). `call.request.local` reports such a client, and the local address it reached, as
  the IPv4 addresses they are (`127.0.0.1`, on Kotlin/Native too, where TCP sockets reported `::ffff:127.0.0.1`), and an
  HTTP/3 call's `localAddress` is the address the client sent to where the UDP socket reports it, else the connector's. 0.2 bound `0.0.0.0`, so such a server was unreachable over IPv6; `host = "0.0.0.0"`
  keeps IPv4 alone. `host` is `String?` now, and Ktor logs `Responding at https://:::443` for such a connector (`[::]:443`;
  `resolvedConnectors()` keeps the bare `::`, which socket APIs take back). The deployment port of `EngineMain` without
  `ktor.deployment.host` (or `-host`) binds the same way; an explicit `ktor.deployment.host = "0.0.0.0"` keeps IPv4
  alone. Ktor's own `connector { }` keeps Ktor's `0.0.0.0`.
- QUIC: the NEW_TOKEN replay register grows on demand, from 128 KiB, doubling at 3/4 load, up to
  `newTokenReplayCapacity`, instead of allocating all of it (32 MiB at the default) with the first token. The protection
  is unchanged: a full register still treats a token as absent and never accepts one twice; the 0-RTT register does the
  same.
- QUIC: the per-address connection limit (`maxConnectionsPerIp`, 256 by default) logs one warning when it first refuses a
  client, then at most one every 5 minutes per endpoint: `QUIC per-IP limit (256) reached for <address>; behind NAT or
  kube-proxy set http3 { endpoint { maxConnectionsPerIp = null } }`. Before, the excess was dropped silently.
- Ktor client: the first alternative marked broken on a network logs one warning, `HTTP/3 to <origin> failed (<reason>);
  using TCP for <backoff>. See response.kuicksilverDiagnostics`; a network change arms it again. The line per call that
  HTTP/3 did not serve stays at `observability { protocolChoiceLogLevel }` (Info), which the default logger leaves out.
- HTTP/3: `Http3Settings.maxInformationalResponses`, ignored since 0.2.1, is removed (breaking). Interim responses are
  bounded by `maxFieldSectionSize` (RFC 9110 section 15.2).
- HTTP/2: the flood budgets have a ceiling (breaking strictness): `http2Settings { floodLimits { resets } }` takes at most
  `RateLimit(3300, 100000)` and `glitches` at most `RateLimit(33000, 1000000)`, 100 times their defaults
  (`FloodLimits.MAX_RESETS`, `MAX_GLITCHES`), so the Rapid Reset defence (CVE-2023-44487) cannot be configured away;
  `maxContinuationFrames` takes at most 800 (`MAX_CONTINUATION_FRAMES`) and `maxControlFramesQueued` at most 100 000
  (`MAX_CONTROL_FRAMES_QUEUED`).
- QUIC: `quicConfig { maxIdleTimeout }` and `expert { maxAckDelay }` must be whole milliseconds, and `maxAckDelay` at
  least 0 (breaking strictness, RFC 9000 section 18.2). Both go on the wire in milliseconds while the connection timed
  itself on the full `Duration`: a fraction was advertised rounded down (`500.microseconds` as 0, "no idle timeout"). The
  `EngineMain` duration keys take whole milliseconds too (`kuicksilver.http3.quic.maxIdleTimeout = 0.5ms` is refused).
- WebTransport (experimental), draft-02 sessions, which Chrome and Firefox negotiate (breaking strictness,
  draft-ietf-webtrans-http3-02 section 4.3: stream codes are "limited to an unsigned 8-bit integer"): `reset(code)`,
  `reset(code, reliableOffset)` and `stopSending(code)` with a code above 255 now throw IllegalArgumentException there,
  and a peer's reset or STOP_SENDING code above 255 reads as no application code (`StreamReset.code` and
  `StreamStopped.code` null). Before, any 32-bit code went out and came in. An application that serves browsers keeps its
  stream codes within 0..255 (`WebTransportSession.maxStreamErrorCode`). Later drafts keep 0..2^32-1, and the code of a
  session's close stays 32-bit in every draft (draft-02 section 5).
- Ktor client: the origin key of the Alt-Svc store, the broken marks and the remembered RTTs is canonical. The host's
  ASCII letters are lowercased (RFC 6454 section 4) and an IPv6 host is written in RFC 5952 text with its brackets, so
  `https://Example.com/` and `https://example.com/`, or two spellings of one IPv6 address, share their alternatives.
  Before, they were two origins. A trailing dot is kept: `example.com.` stays another origin. `FileAltSvcStore` reads the
  origins of an older file into the canonical key, merging two spellings of one origin.
- Ktor client: `client.engine.coroutineContext.job.join()` after `HttpClient.close()` now returns once the engine closed
  its pools, its UDP endpoints and its selector. That includes every QUIC connection's qlog trace, so an app that exits
  after the join keeps complete traces (`docs/guide/ktor.md`, "Closing the client"). The join first waits for every call
  in flight (bodies until read or cancelled, WebSocket and SSE sessions until closed) and has no bound of its own. Before,
  the cleanup ran outside the engine's job, and the join returned as soon as the calls had finished. The endpoints of
  CONNECT-UDP tunnels are now also closed by `close()` instead of waiting for their connections to end, and each cleanup
  step runs even when one before it failed.
- Ktor client, `Alt-Svc`, and Ktor server, the application's own `Connection` field over HTTP/1.1 (breaking strictness,
  RFC 9110 section 5.6.3, RFC 7838 section 3): only SP and HTAB are OWS around a protocol, an authority, a parameter or a
  connection option, no longer any Unicode space: `<U+00A0>h3=":443"` is no `h3` alternative, `<U+00A0>ma=1` is an
  unknown parameter, and `close<U+00A0>` set by the application is not the `close` option (the server adds its own).
- TLS, `HostName.normalize` (breaking strictness, RFC 9525, RFC 1123 section 2.1, RFC 1035 section 2.3.4, RFC 3696
  section 2, RFC 3986 section 3.2.2): a reference identifier (the URL's host, `TlsConfig.serverName`, an expected name,
  an ECH `public_name`) that was accepted before now fails with `TlsException.Config` when it is an IPv4 literal with a
  leading zero (`010.0.0.1`, which `inet_aton` reads as 8.0.0.1; before an IP literal), has a last label of digits only
  (`1.2.3`, `a.123`) or of `0x` and hex digits (`a.0x1f`, the WHATWG URL standard reads both as an IPv4 address), has a
  label over 63 octets or is over 253 octets, has a hyphen at the start or end of a label (`-a.example`), puts brackets
  around anything but an IPv6 literal (`[1.2.3.4]`), or carries a Unicode space around it (only SP and HTAB are trimmed).
  Go refuses these too. The underscore was refused before as well. The certificate matcher shares the IP-literal parser
  (its IPv6 groups take ASCII hex digits only). An ECHConfig whose `public_name` breaks these rules is ignored as unusable
  (RFC 9849 sections 4 and 6.1.7), where OpenSSL alone took an underscore, an empty `0x` last label and names up to 255
  octets.
- Ktor server, HTTP/1.1 request line (breaking strictness, RFC 9112 section 3): the method, request-target and version
  must be separated by exactly one SP, with nothing before or after them. A request line with HTAB, VT, FF or a bare CR
  as a separator, two spaces, or whitespace before the method or after the version now gets `400 Bad Request` and the
  connection closes, as Go's net/http and llhttp answer; section 3 only lets a recipient accept those (MAY) and warns of
  request smuggling between parsers that split the line differently. There is no switch to bring them back.
- Ktor server, HTTP/1.1 line ends (breaking strictness, RFC 9112 sections 2.2 and 11.2): a request whose request line,
  field lines, closing empty line or trailer lines end with a bare LF (no CR before it) now gets `400 Bad Request` and the
  connection closes, as llhttp answers. RFC 9112 section 2.2 only lets a recipient accept it (MAY), and a server behind a
  proxy that reads the LF as part of a line frames the request otherwise. New delicate
  `http1 { allowBareLf }` (`EngineMain` key `kuicksilver.http1.allowBareLf`, false by
  default) turns the old behaviour back on for hand-written clients. Empty lines before the request line are still
  skipped, a bare LF among them. The client is unchanged: it still ends a response line at a bare LF (it is the final
  recipient; Go's net/http and curl do the same).
- Ktor client and server, HTTP/1.1 chunked trailers (breaking strictness, RFC 9112 sections 7.1.2 and 2.2, RFC 9110
  sections 5.1 and 5.5): each line of a trailer section must now be a field line (a token name right before its colon, no
  control character but HTAB in the value). The server answers another line with 400 and closes the connection (and
  refuses an obs-fold there, as in the head); the client fails the response body (an obs-fold still continues the line
  before it, RFC 9112 section 5.2). Before, the lines were discarded unread, so a NUL, a line without a colon or a
  non-token name passed; Go's net/http and curl refuse them.
- Ktor client, HTTP/1.1 response head (breaking strictness, RFC 9110 section 5.1, RFC 9112 section 5.1): a field line
  whose name is not a token followed directly by its colon (bytes above 0x7F, a delimiter such as `/` or `"`, an empty
  name, whitespace before the colon, no colon) now fails the response with `ParserException`, as Go's net/http and
  llhttp hold; Ktor's parser let bytes above 0x7F through.
- Ktor client and server, WebSocket handshake (breaking strictness, RFC 6455 sections 4.1 and 4.2.1, RFC 9110 section
  5.6.3, RFC 7692 section 7): the values of `Upgrade`, `Sec-WebSocket-Accept`, `Sec-WebSocket-Protocol` and
  `Sec-WebSocket-Extensions` (client), of `Sec-WebSocket-Key` and `Sec-WebSocket-Version` (server), and the extension names
  and `permessage-deflate` parameters both sides negotiate lose only SP and HTAB around them, no longer any Unicode space:
  `Upgrade: <U+00A0>websocket` fails the client's handshake with `WebSocketException`, `Sec-WebSocket-Version: <U+00A0>13`
  gets 426 from the server, and `<U+00A0>permessage-deflate` or `<U+00A0>server_no_context_takeover` is not that
  extension or parameter (an offer with it is declined, an answer with it fails), as x/net/websocket holds.
- Ktor client, proxy credentials (breaking strictness, RFC 7617 section 2): `ProxyCredentials` sent as
  `Proxy-Authorization: Basic` (an HTTP or `https://` proxy, `ConnectUdpProxy`) with a colon in the user name, or with a
  control character (0x00-0x1F, 0x7F) in the user name or password, now fail with `IllegalArgumentException` where the
  proxy is configured (`ResolvedProxy.http`/`https`, `ConnectUdpProxy`, the engine's creation for its `proxy`) instead
  of being sent: the proxy would split such a user-id at its colon and read another user and password. SOCKS5
  credentials are unchanged (RFC 1929 has no such rule).
- Ktor client, SOCKS5 (breaking strictness, RFC 1929 section 2 and RFC 1928 section 6): a proxy that answers the
  username/password subnegotiation with VER 5 (the SOCKS version) instead of X'01' now fails with `ProxyException`
  ("answered the authentication with version 5") before the CONNECT is sent; the compatibility shim that accepted it
  is removed (no proxy that needs it was ever named; Go refuses it too). A CONNECT reply whose reserved byte (RSV) is
  not X'00' fails with `ProxyException` ("non-zero reserved field") before any TLS.
- QUIC (hardening): frames that RFC 9000 lets a receiver refuse and that ngtcp2, quic-go and picoquic refuse now close
  the connection with PROTOCOL_VIOLATION; each could come only from a peer that broke a sender MUST. A RETIRE_CONNECTION_ID
  in a 0-RTT packet (section 12.5: "A server MAY treat receipt of these frames in 0-RTT packets as a connection error");
  a known frame type encoded in more bytes than it needs (section 12.4; an unknown type stays FRAME_ENCODING_ERROR,
  the section's MUST); a RETIRE_CONNECTION_ID naming the connection ID the
  packet carrying it was sent to (section 19.16: "MUST NOT refer to the Destination Connection ID field of the packet in
  which the frame is contained"); a NEW_CONNECTION_ID that repeats a sequence number with another stateless reset token,
  or an issued connection ID under another sequence number (section 19.15; before, the first was ignored and the second
  taken as a new ID).
- QUIC client (hardening): a server that upgraded the client's version through compatible version negotiation without
  sending `version_information` fails the handshake with VERSION_NEGOTIATION_ERROR, as in ngtcp2 (RFC 9368 section 4
  lets a client complete it, "MAY"; a server that upgrades implements RFC 9368). A server that keeps the client's version
  may still omit the parameter.
- QUIC: a PTO probe puts the stream data it resends ahead of DATAGRAM frames (RFC 9002 section 6.2.4). Datagrams without
  an urgency went ahead of all stream data in every packet, so with datagrams queued a probe could carry datagrams, which
  are never retransmitted, and leave the data it took over from its unacknowledged packets for later packets. Outside
  probes datagrams still go first (`DatagramSender.nextUrgency`).
- HTTP/2 (hardening): an unexpected SETTINGS ACK (no SETTINGS of ours outstanding) is a connection error of type
  PROTOCOL_ERROR, as in nghttp2 and Go (RFC 9113 has no receiver rule; section 5.4.1); it was ignored. A GOAWAY whose last
  stream identifier is above that of an earlier GOAWAY (section 6.8: "MUST NOT increase") is a PROTOCOL_ERROR, as in
  nghttp2 and in our HTTP/3; it was clamped. On the client, a server's GOAWAY naming an even stream is one too; the server
  does not check a client's GOAWAY for parity, since Go's `ClientConn.Shutdown` sends its own next (odd) stream ID.
- HTTP/2 (hardening): a half-closed (local) stream's send window follows SETTINGS_INITIAL_WINDOW_SIZE changes and is
  checked on WINDOW_UPDATE like any other (RFC 9113 section 6.9.2: "all stream flow-control windows that it maintains";
  section 6.9.1: above 2^31 - 1 the stream or connection MUST be terminated): a WINDOW_UPDATE that takes it above the
  maximum is a FLOW_CONTROL_ERROR stream error, a SETTINGS change that does a connection error, as in nghttp2 and Go.
  Before, such a stream kept no window and its updates were ignored.
- WebTransport (experimental) speaks draft-ietf-webtrans-http3-17 (November 2026), the highest version both sides speak
  (draft-17 section 7.1), next to draft-16 (webtransport-go and picoquic), draft-14 (Safari) and draft-02 (Chrome,
  Firefox). A server announces `SETTINGS_WT_ENABLED` of draft-17 (0x20b8933b) and draft-16 (0x2c7cf000),
  `SETTINGS_WT_MAX_SESSIONS` (draft-14) and `SETTINGS_ENABLE_WEBTRANSPORT` (draft-02). A client announces draft-17,
  draft-16 and draft-02, so two Kuicksilver endpoints speak draft-17. What draft-17 changed, each from this release:
  - A server whose client announces no draft selects draft-17 and accepts its `webtransport-h3` CONNECT ("Otherwise,
    the server selects the version described in this document"). Before, such a request was refused with 400. The
    older `webtransport` token from such a client is still malformed.
  - A WebTransport client takes a server's `SETTINGS_WT_ENABLED` above 1, draft-17's or draft-16's, as
    `H3_SETTINGS_ERROR`. A server ignores the value a client sends and reads only a 1 as a version (section 3.1). An
    endpoint without WebTransport ignores both, as RFC 9114 section 7.2.4 asks of a setting it does not understand.
    Before, every endpoint closed on draft-16's value above 1.
  - A server takes only the selected draft's `:protocol` token: `webtransport-h3` for draft-17 and draft-16,
    `webtransport` for draft-14 and draft-02 (draft-17 section 3.2). Another token is answered with 400. Before,
    either token went with any draft.
  - A `WT_STREAM` signal out of place closes a draft-17 connection with `H3_FRAME_UNEXPECTED` (section 4.3). Draft-16
    and draft-14 keep `H3_FRAME_ERROR`.
  - After 0-RTT, a client takes a draft-17 server's WebTransport settings as the resumed connection sends them (section
    3.2: "a client MUST discard any values ... retained from a previous connection"). Before, it closed the connection
    with `H3_SETTINGS_ERROR` when they were lowered or omitted, whether the client used WebTransport or not. A draft-16
    or draft-14 server is still held to its earlier values.
  - The client sends the draft-02 request field only on a draft-02 CONNECT.
  - qlog names `SETTINGS_WT_ENABLED` for draft-17's codepoint; draft-16's goes by its number.

  Capsule types, error codes, stream types and the other settings are the same in draft-17. The reset's reliable size
  (the header, section 4.4) and the first WT_MAX_* floor (the initial SETTINGS value, sections 5.6.2 and 5.6.4) already
  met draft-17's wording. RESET_STREAM_AT follows draft-ietf-quic-reliable-stream-reset-11, which keeps 0x1d and frame
  0x24. `docs/spec/compat-shims.md` §1 to §4 have the hardening audit's verdicts:
  - draft-02 and draft-14 kept;
  - the draft-02 response field kept and narrowed;
  - the draft-02 fallback without `reset_stream_at` removed (below);
  - the pre-IANA `reset_stream_at` codepoint kept for Google QUICHE.

- QUIC, DPLPMTUD: a connection's first path MTU search begins with its first application data (a STREAM or DATAGRAM
  frame) sent after the handshake is confirmed, no longer right at confirmation (RFC 8899 sections 4.3 and 5.1.1: probes
  "MAY" wait for application data). A connection that only acknowledges, or idles or closes after its handshake, sends no
  full-size probe; a sender searches as before, and a begun search runs to its end.
- QUIC Interop Runner endpoint: the client waits for its endpoint's close before it exits, so its qlog traces, which are
  buffered until a connection is released, are complete (they were often empty files). The server, which the runner stops
  with SIGTERM, closes and joins its endpoints first (at most 3 s; a JVM shutdown hook, a signal handler on Native), so its
  traces are complete too.
- The bundled OpenSSL moves from 3.5.9 (the 3.5 LTS branch) to **4.1.0**, and to the 4.2 LTS branch once it is released
  (ADR-0019): Encrypted Client Hello needs OpenSSL 4. The pin keeps its form (version, tarball SHA-256 and signing key,
  verified before every build); `configure-flags.txt` drops the four options 4.0 removed (`no-engine`, `no-atexit`,
  `no-ssl3`, `no-ssl3-method`), and `tools/openssl/build.sh` rewrites the read-only `crypto/buildinf.h` that 4.x makes.
  The native libraries grow by about 10 % (the macOS arm64 JNI library: 2,544,072 to 2,809,416 bytes). `Ksl.version()`
  names OpenSSL 4.1.0. Building `ksl` against a system OpenSSL (Linux, `KSL_SYSTEM_OPENSSL`) still takes 3.5 to 3.x.
- The Android size gate (`tools/check/size.sh`) fails above 3,550,000 bytes and warns above 3,500,000 (was 3,200,000 and
  2,900,000): OpenSSL 4.1.0 with Encrypted Client Hello grows the arm64-v8a `libksl.so` from 3,136,784 to 3,473,712 bytes
  (armeabi-v7a 2,452,436 to 2,637,372, x86_64 3,991,440 to 4,205,360). `configure-flags.txt` turns off the three KDFs 4.x
  adds that nothing uses (`no-ikev2kdf`, `no-snmpkdf`, `no-srtpkdf`; about 14,000 bytes per ABI).
- The bundled OpenSSL carries two patches on the 4.1.0 tarball, as an exception to "the upstream tarball only"
  (ADR-0019): OpenSSL 4.1.0 fails Encrypted Client Hello with internal_error after a HelloRetryRequest whenever the
  client has a custom extension of its own, which every QUIC client has (its transport parameters), and ends an ECH
  rejection after a HelloRetryRequest with illegal_parameter instead of `ech_required` and the retry configurations. The
  patches (`tools/openssl/patches/`) are pinned by their SHA-256 in `gradle/openssl.toml` (`patch`, `patch_2`), applied in
  that order and exactly by `tools/openssl/build.sh` (`apply-patch.pl`: no fuzz, no offset, both or neither), part of the
  build cache key, the target line and `provenance.txt`, listed in the release provenance and in the SBOM
  (`kuicksilver:openssl:patch`), and each dropped with the first OpenSSL release that fixes its bug. Both patches are
  upstream code: the first is the `ssl/statem/extensions.c` hunk of OpenSSL commit openssl/openssl@981f976bb0 (on the openssl-4.1 branch,
  so it goes with 4.1.1), the second the `ssl/statem/statem_clnt.c` hunk of OpenSSL pull request #33233 (in review; it
  goes with the first release that merges it). The second also aborts with illegal_parameter when a HelloRetryRequest
  rejected ECH and the ServerHello then confirms it (RFC 9849 section 6.1.4: acceptance is decided by the server's first
  message).
- The bundled OpenSSL carries two more ECH patches of Kuicksilver's own (`patch_3`, `patch_4`; the pin profile now takes
  up to `patch_9`, each after all the ones before it). `openssl-4.1.0-ech-retry-configs-raw.patch` makes
  `SSL_ech_get1_retry_config` hand over the server's `retry_configs` once their framing holds. Before, one ECHConfig
  OpenSSL could not use dropped the whole list, as did a first entry of another version and a list past 1500 bytes.
  `openssl-4.1.0-ech-sni-padding.patch` pads the inner server name by max(0, M − D) (RFC 9849 section 6.1.3; 4.1.0
  padded 9 bytes less). Upstream issues are to be filed.
- The bundled OpenSSL carries three more ECH patches of Kuicksilver's own (`patch_5` to `patch_7`):
  - `openssl-4.1.0-ech-ee-checks.patch`: the client checks the `encrypted_client_hello` of EncryptedExtensions:
    `unsupported_extension` after an acceptance; `decode_error` for `retry_configs` that do not parse or have bytes
    after the list, also after GREASE; nothing handed out after GREASE (RFC 9849 sections 5, 6.1.6, 6.2.1).
  - `openssl-4.1.0-ech-psk-after-rejection.patch`: `illegal_parameter` for a pre_shared_key in the ServerHello after a
    rejection (section 6.1.2).
  - `openssl-4.1.0-ech-grease-length.patch`: a GREASE payload has the length a real offer of the same ClientHello would
    have (section 6.2.1), not a random one.
  - These alerts now go out over TCP too, before any `ech_required`.
  - `tools/openssl/build.sh` refuses a pin key it does not read, such as `patch_10`.
- The bundled OpenSSL carries an eighth ECH patch (`patch_8`, `openssl-4.1.0-ech-reject-client-flight.patch`, the fix
  posted with upstream issue openssl/openssl#33831). On a rejection the client sent `ech_required` while it processed the
  server's Finished, before its own flight. Now it answers a CertificateRequest with an empty Certificate and no
  CertificateVerify (RFC 9849 section 6.1.7), sends its Finished, and then `ech_required` under the application keys
  (section 6.1.6), as BoringSSL does. Over QUIC the transport sends that flight in the packets of the CONNECTION_CLOSE
  (before, a failed TLS session's last CRYPTO was dropped). With middlebox compatibility mode the alert no longer leaves
  in a plaintext record over TCP.
- TLS, Encrypted Client Hello: a server key set whose keys share a config_id is refused (`TlsException.Config` from
  `EchServerKeys`). OpenSSL tries only the first key of a config_id, so a client of the other would have been rejected.
  Make one of the keys again.
- TLS, Encrypted Client Hello, review of 2026-11-20:
  - Retry configurations whose ECHConfigs are all of the supported version but none usable (an unknown KEM, say) were
    reported as a rejection without retry configurations, which the Ktor client took for "securely disabled" and
    retried with the name in the clear. RFC 9849 section 6.1.6 allows that only when no entry has a supported version:
    the handshake now fails instead (`ksl`: `KSL_ECH_OFFERED`).
  - `ksl` refuses ECH on a client session that verifies nothing (`KSL_VERIFY_NONE`), which reported unauthenticated
    rejections and retry configurations; an empty ECHConfigList no longer parses (section 4); the verify name of an ECH
    session cannot change once the handshake started; the ECH private key's bytes `ksl` decodes to read the config_id
    are wiped.
  - QUIC: the verifier off the connection's loop read the verify name from the native session, which the loop may
    have freed by then (a handshake timeout, a close); the name is now taken on the loop when the handshake pauses.
  - Ktor client: the TLS hop to an `https://` proxy offered the `tls` block's ECH configuration and sent GREASE
    regardless of `ech.grease`, and a rejection on that hop was taken for the origin's (its retry configurations
    offered to the origin). The proxy hop now offers none, GREASE as configured, and its rejection is a proxy failure.
    The HTTP/3 connection inside a CONNECT-UDP tunnel offers the origin's ECH, with its one retry through the tunnel.
  - `EchServerKeys` is `AutoCloseable`: `close()` frees its native set, which otherwise stayed for the life of the
    process.
- The bundled OpenSSL carries a ninth ECH patch (`patch_9`, `openssl-4.1.0-ech-alpn-padding.patch`), with
  `KSL_OPT_ECH_ALPN_PAD` (16, ABI 7, additive) in `ksl`. RFC 9849 section 6.1.3 has a client pad its inner ALPN
  extension "to the total size of the longest ALPN extension across all application profiles"; OpenSSL 4.1.0 padded the
  server name only. Now every client context pads it to the longest of Kuicksilver's profiles (`h2` with `http/1.1`,
  18 octets) or to its own list when that is longer, and a GREASE payload is sized alike. A connection offering `h3`
  and one offering `h2` and `http/1.1` give one ECH payload length for every server name.
- TLS, Encrypted Client Hello, second review of 2026-11-20:
  - JVM, RFC 9849 section 10.7: under an accepted ECH the path is built from the presented certificates and checked with
    a PKIX `CertPathValidator`; no AIA fetch of a missing intermediate goes out any more where the process set
    `com.sun.security.enableAIAcaIssuers` (before, a process-wide switch the connection could not turn off).
  - A rejection is told from an acceptance by the session's ECH outcome, not by comparing names: an origin named like
    the configuration's `public_name` was verified as if ECH had been accepted (pins, offline, TOFU first contact).
  - An `EchServerKeys` that fails to build gives its keys back unwiped; before, a bad key wiped the good ones taken
    with it. The server engine closes the `EchServerKeys` it made from `kuicksilver.tls.echKeys` when it stops.
  - Ktor client: `configLists` keys are compared as host names (case, a trailing dot, IPv6 brackets); before, a key in
    another spelling sent GREASE with the name in the clear. Two keys for one host are refused. A 0-RTT request on a
    rejected connection that was already the retry is no longer sent a third time.
  - `ksl`: a key whose ECHCONFIG block holds several ECHConfigs has each config_id checked for uniqueness; running out
    of memory while an ECHConfig is read is reported as such, never as "nothing usable"; `KSL_LIVE_ECH_KEYS` (ABI 7,
    additive; `KSL_LIVE_COUNT` is 8) counts the key-set handles; the dead `ECH_GREASE` macro is gone.
- TLS, Encrypted Client Hello (`ksl`). Each item is checked where OpenSSL 4.1 does not:
  - An ECHConfigList whose 0xfe0d ECHConfig is malformed, for example by a trailing byte or an extension type given
    twice, does not parse (RFC 9849 sections 4, 4.2).
  - A rejection where the server resumed a session (section 6.1.2), or whose `retry_configs` do not parse (section
    6.1.6), fails the handshake instead of reporting a rejection: no retry configurations, never "securely disabled".
  - `retry_configs` on an accepted ECH (section 5), and malformed ones after GREASE (section 6.2.1), fail the session.
  - These failures close with the alert the RFC names, over TCP and QUIC (patches 5 and 6 below).
  - A server refuses an accepted inner ClientHello that offers TLS 1.2 or below, with `illegal_parameter` (section 7.1).
  - GREASE takes a cipher suite at random per handshake.
  - A server context's ECH key lock is made with the context. A first key set from several threads raced, and
    ThreadSanitizer saw it.
  - A lock failure answers `KSL_E_NO_MEMORY`.
  - The JVM binding no longer reports a failed allocation as an ECHConfigList that does not parse.
- Docs: the README is now one screen: what Kuicksilver is, the dependency lines, swapping the Ktor engine and one
  platform table, with everything else linked. The Install section and the module list moved to `docs/install.md`, the
  per-platform limits to `docs/stability.md` ("Limits per platform"), the interop numbers to `docs/how-we-verify.md`.
  New pages: `docs/why-kuicksilver.md` (Kuicksilver against Cronet, URLSession, OkHttp, Netty QUIC, quiche and quic-go,
  each claim with its source, and the measurements still missing) and `docs/how-we-verify.md` (RFC tables, interop,
  fuzzing, the release gate, hosted CI, soak, threat model and reproducible builds, with the numbers and their dates).
- Ktor client: a request that waits for its response on an HTTP/3 connection the engine chose over TCP keeps that
  connection open past the QUIC `maxIdleTimeout`: stall detection sends a PING when the connection is quiet, at most
  every half of the idle timeout in force, as RFC 9114 section 5.1 expects of a client with responses outstanding.
  Before 0.3.0 a long poll that the server held longer than the idle timeout ended there. `http3 { stall { enabled =
  false } }` sends no PING.
- Ktor client: a completed QUIC handshake no longer lifts a broken mark the alternative got for a stall
  (`FallbackReason.QuicStalled`), so the backoff of a network that lets handshakes through and cuts the flows after
  them keeps doubling; each later connection that carried a whole exchange and that the client closed in order without
  it ever stalling takes it one level down.
- Ktor client: a POST or another request that may not be repeated, on an HTTP/3 connection that stalls, now waits up to
  `stall { abandonAfter }` (10 s) for the path and then fails with `QuicStalledException`, where it failed at the QUIC idle
  timeout (30 s) with `QuicException.ConnectionLost.Timeout` before 0.3.0.
- Ktor client: a failed call's `ProtocolDiagnostics` stay in the request's attributes until `callFailed` returned (they
  were removed before it), and the thrown exception carries them as a suppressed exception (`FailureDiagnostics`: a
  one-line message without URL, host, address or connection ID, and on the JVM and Android no stack of its own); code
  that reads `suppressedExceptions` of a failed call sees it after the HTTP/3 failure. A copy coroutines make of a
  `QuicException` or an `Http3Exception` (the stack of the receiving side) keeps the original's suppressed exceptions.
- Ktor client: a call that fails in the engine on a connection-wide failure — the one instance every call on the
  connection gets: a QUIC connection's end (what `onClosed` and `QuicConnection.closed` hold), the HTTP/3 session's close
  (an `Http3Exception`, `RequestNotProcessed` for H3_REQUEST_REJECTED included), an HTTP/2 connection's
  `Http2Exception.ConnectionClosed` (a GOAWAY with an error, a dropped connection), a shared setup's failure — now throws
  its own copy of it (same type, fields and cause) carrying its diagnostics, and `callFailed` gets that copy, no longer
  the shared instance; the instance itself carries no call's diagnostics.
- QUIC: `ConnectionStats.memoryCeiling` counts the allocation of the stream reassembly buffers as its receive part,
  `3 x maxConnectionWindow` plus 1 KiB for each stream the peer may open (`maxBidiStreams + maxUniStreams`), where it
  counted `maxConnectionWindow`, the unread bytes alone; the allocation is now bounded by that (see Security). With the
  defaults the value grows by about 30 MiB. Streams the application opens add up to 1 KiB each, which the value leaves out.
- Testing (`kuicksilver-testing`, the unpublished test module): `SimResult.traceHash` is an FNV-1a-style mix of whole
  values, now starting from the standard offset basis (14695981039346656037; it was one digit short), so its values differ
  from earlier versions; the same seed still gives the same hash in every run.
- Ktor client: an answer of the system resolver that no connection may go to is dropped before connecting, over TCP and
  QUIC: "this network" (0.0.0.0/8), `::`, multicast (224.0.0.0/4, `ff00::/8`) and 255.255.255.255, IPv4-mapped forms
  included (RFC 1122 section 3.2.1.3, RFC 4291 section 2.5.2, RFC 9293 section 3.9.1 MUST-46), as for an application's
  `dns`; also the addresses an HTTPS answer carries. Before, an answer of 0.0.0.0 (a DNS sinkhole's, say) reached the
  device's own listeners on Linux and macOS, and QUIC sent its Initials there. A name left without addresses fails as one
  that resolves to none (threat model 3.25).
- Ktor client: an IP address written in the URL that no connection may go to (`https://0.0.0.0/`, `https://[::]/`, a
  multicast group such as `https://[ff02::1]/` or `224.0.0.251`, 255.255.255.255) fails with an `IOException` before any
  packet, over TCP and QUIC; before, `0.0.0.0` reached the device's own listeners on Linux and macOS and QUIC sent its
  Initials to the group. A host with the form of an IPv4 address that is not a dotted quad is read by the engine, with
  the system's resolver too: `127.1` is still 127.0.0.1, while one platforms read differently (`010.0.0.1`, octal
  8.0.0.1 to getaddrinfo; `0x7f.1`) or that is no address fails without a lookup (RFC 1123 section 2.1; threat model 3.25).
- qlog transport events use the enumerations of draft-ietf-quic-qlog-quic-events-04: `connection_state_updated` is
  written for every state change with `old` and `new`, `handshake_complete`, `handshake_confirmed`, `closing`,
  `draining` and `closed` (before: only `established`, the handshake's completion); `connection_closed` names its
  owner `local` or `remote` (before: `peer` for the peer's close); a lost or dropped 0-RTT packet is `0RTT` (before:
  `1RTT`); a `packet_dropped` for a packet on an address the connection left has
  the trigger `rejected` (before: `unexpected_packet`); `packet_lost` has no trigger (before: `time_or_packet_threshold`,
  not one of the draft's); a `connection_closed` that is not a peer's close or a timeout has the trigger
  `stateless_reset`, `version_mismatch` or `error`, its message in `reason` (before: the message as the trigger).
- qlog `packet_sent` and `packet_received` carry every frame with the members of draft-ietf-quic-qlog-quic-events-04
  section 8.11 (before: the frame type alone, and no frames for received packets or close packets): ACK ranges,
  `ack_delay` and ECN counts, STREAM and CRYPTO offsets and lengths, limits, connection IDs, path data, CONNECTION_CLOSE
  codes and reason; RESET_STREAM_AT and DATAGRAM through the draft's extension point. Tokens, stateless reset tokens and
  payloads are never written. 0-RTT packets are `0RTT` (before: `1RTT`). `connection_closed` is written once and the
  trace stays open through the closing period, until the connection releases it (before: it ended at the first
  `connection_closed`). HTTP/3 events queued for the loop take its time when they were stamped later, so transport
  events keep theirs. `http:frame_created` is logged once the frame's write call returned, and not for a write that throws (before,
  HEADERS and DATA were logged ahead of it). `tools/interop/prohibited-port-rebind.py` counts a CONNECTION_CLOSE as not
  ack-eliciting and reads a trace up to its `connection_closed`.
- The bundled OpenSSL now contains zlib 1.4 and brotli 1.2.1, for TLS certificate compression (RFC 8879; ADR-0025):
  both are pinned in `gradle/compression-libs.toml` and verified by `tools/openssl/fetch.sh` before they are compiled
  (zlib by SHA-256 and its release key's signature, `tools/openssl/zlib-release-key.asc`; brotli, which signs no release,
  by SHA-256; the tag's commit, which the tarball's pax header names, is only a consistency check, and a pin update checks
  the tag and the tree against the repository with `tools/openssl/brotli-pin-check.sh`), with OpenSSL's own compiler and
  flags, into `libcrypto.a`
  (`tools/openssl/compression.mk`), so their symbols carry the `ksl_ossl_` prefix on Kotlin/Native and nothing of them is
  exported from the JNI libraries. OpenSSL is configured `enable-zlib enable-brotli no-zstd` instead of `no-comp`; TLS
  record compression stays off (`SSL_OP_NO_COMPRESSION`), and `ksl` configures certificate compression itself (on by
  default, `KSL_OPT_CERT_COMPRESSION`). brotli's one-shot encoder and decoder, the two OpenSSL uses for certificates, go
  through `ksl` wrappers built into libcrypto: the encoder at quality 9 at most (`tools/openssl/brotli/ksl_compress.c`), the
  decoder with its allocations capped at 3 times the output plus 256 KiB (`ksl_decompress.c`). Android and iOS get brotli's
  decoder only (the encoder's entry points are stubs that fail), the other targets the encoder with its static tables
  computed on first use (`BROTLI_STATIC_INIT_LAZY`, run once by `tools/openssl/brotli/ksl_static_init.c`): the Android
  arm64 `libksl.so` grows from 2,898,576 to 3,128,112 bytes, the macOS arm64 JNI library from 2,544,056 to 3,056,808
  (ADR-0025 has every option measured), and the Android size gate (`tools/check/size.sh`) moves up by 200,000 bytes to a
  limit of 3,200,000. brotli's encoder needs `libm`: the Linux libraries link it (`libm.so.6` joins the Linux import
  whitelist of the release; the glibc floor stays 2.17); the Android library, without the encoder, does not. `provenance.txt` of every
  OpenSSL build names the two tarballs' SHA-256, which `-Pkuicksilver.openssl.prebuilt` checks; the SBOM lists zlib (Zlib
  license) and brotli (MIT) as components inside OpenSSL, the provenance statement as resolved dependencies; NOTICE and
  every published artifact carry their licenses (`licenses/LICENSE.zlib.txt`, `licenses/LICENSE.brotli.txt`); Renovate
  watches both pins.
- TLS server with an `sniSelector` and no `identity`: a ClientHello without SNI that the selector answers `null` now ends
  with `missing_extension` (109), the alert RFC 9846 section 9.2 names for a server that requires `server_name`, sent once
  TLS 1.3 is chosen (OpenSSL turned an earlier one into `handshake_failure`); a TLS 1.2 handshake still gets
  `handshake_failure` (TLS 1.2 has no such alert).
- `ksl` C ABI: applying an SNI override to a QUIC session (`ksl_ssl_sni_resume`) keeps what the QUIC TLS layer set on it:
  TLS 1.3 as the lowest version, middlebox compatibility mode off (RFC 9001 sections 4.2, 8.4: a server context had it on
  for TCP, and its change_cipher_spec failed the QUIC handshake) and `max_early_data_size` 0xffffffff, or 0 for an override
  without early data (RFC 9001 section 4.6.1; the context's 0 had taken 0-RTT from every override).

- HTTP/3: a field section waiting for QPACK dynamic-table inserts no longer looks every 50 ms whether its stream or
  connection ended; it wakes on the end itself.
- HTTP/3: `SETTINGS_H3_DATAGRAM=1` from a peer whose transport has no `max_datagram_frame_size` no longer closes the
  connection with `H3_SETTINGS_ERROR`: RFC 9297 section 2.1.1 makes only a value other than 0 or 1 an error. No HTTP/3
  datagram is sent to such a peer (RFC 9221 section 3); `trySendDatagram` answers `Unsupported(PeerDoesNotSupport)`.
- HTTP/3 client: after an accepted 0-RTT, a server whose SETTINGS change or omit the remembered non-zero
  `SETTINGS_QPACK_MAX_TABLE_CAPACITY` ends the connection with `QPACK_DECODER_STREAM_ERROR` (RFC 9204 section 3.2.3,
  the text for this setting) instead of `H3_SETTINGS_ERROR` (RFC 9114 section 7.2.4.2, for settings in general).
- TLS over TCP, client: TLS 1.3 handshakes no longer use middlebox compatibility mode (RFC 9846 appendix E.4, optional).
  The ClientHello carries an empty `legacy_session_id` (section 4.2.2: "Otherwise, it MUST be set as a zero-length
  list") instead of a random 32-byte one, and the client sends no dummy `change_cipher_spec` before its second flight
  (also none after a HelloRetryRequest). This is what lets the client protect its alerts after the ServerHello (see
  Fixed). A client that resumes a TLS 1.2 session ID still sends that ID. Servers keep the mode and answer a client's
  non-empty session ID with `change_cipher_spec`; QUIC never used it. A network whose middlebox drops TLS 1.3 handshakes
  that do not look like TLS 1.2 resumption can now fail TLS-over-TCP connections it let through before; there is no
  setting to turn the mode back on ([TLS guide](docs/guide/tls.md#middleboxes)).
- QUIC: `CongestionController.onEcnCe` is now called for every valid ECN-CE report of the path, not once per recovery
  period the core kept for CE reports alone (RFC 9002 section 7.3.2 and appendix B.6: losses and CE reports share one
  recovery period, which only the controller knows). Migration: a custom controller must apply its own recovery-period
  check in `onEcnCe`, judged by `sentTime` against the start of its current recovery period, as it already does in
  `onLoss`; NewReno, CUBIC and BBR do.
- Ktor client: the CONNECT that opens a tunnel through an HTTP proxy no longer carries `Proxy-Connection: Keep-Alive`
  (RFC 9112 appendix C.2.2: "clients are encouraged not to send the Proxy-Connection header field in any requests"). It
  was there for HTTP/1.0 proxies; a CONNECT tunnel does not depend on keep-alive.
- QUIC client: strict on RFC 9000 sections 7.2 and 7.3, like quic-go, ngtcp2, quinn and picoquic; the msquic exception of
  0.2.1 is removed. The first server Initial that decrypts fixes the server's Source Connection ID, an ACK-only one from
  the client's own DCID too, and later packets with another SCID are discarded (section 7.2: "Once a client has received a
  valid Initial packet from the server, it MUST discard any subsequent packet it receives on that connection with a
  different Source Connection ID"); `initial_source_connection_id` must name that first SCID, else the connection closes
  with TRANSPORT_PARAMETER_ERROR (section 7.3). A handshake that can no longer complete ends at once: while nothing
  with CRYPTO came from the fixed SCID, a discarded packet from another SCID that decrypts and carries CRYPTO closes the
  connection silently with the new `QuicException.ConnectionLost.ServerConnectionIdChanged` (experimental) instead of the
  handshake timeout, and the Ktor client reports `FallbackReason.ServerConnectionIdChanged` (experimental). When that
  handshake offered resumption (`ServerConnectionIdChanged.resumptionOffered`) it does not mark the alternative broken:
  it drops the host's session tickets (the new `SessionCache.dropQuic`, which checks no chain; again when the backoff
  ends, for tickets stored during it) and stops resuming to it (no 0-RTT) for 5 minutes, doubling at each new failure up
  to 2 days and forgotten on a network change, so the next calls use HTTP/3 with full handshakes; on a full handshake the
  alternative is marked broken as for any failure. Before, such an ACK-only Initial was processed without fixing the
  SCID, so
  that an msquic server, which sends from the client's DCID until its listener accepts the connection and then switches
  to a new SCID that it also names in `initial_source_connection_id` (msquic#3762, #4905), could finish the handshake.
  msquic servers (IIS, .NET Kestrel on Windows) with a ClientHello of 3 or more datagrams (resumption with ML-KEM and ECH
  GREASE): QUIC fails per RFC 9000 section 7.3 (msquic#4905); requests go over TCP (`docs/guide/troubleshooting.md`,
  "msquic servers and a large ClientHello"): the Ktor client resumes only with `http3 { earlyData { enabled } }`, and then the failed call goes
  over TCP about two round trips in instead of after the 10 s handshake or connect timeout, and later calls use HTTP/3
  with full handshakes. The RFC 9000 §7.2 row is ✅; the interop cells `msquic->kuicksilver` and
  `msquic->kuicksilver-native` `resumption` and `zerortt` (and `transferloss`/`transfercorruption` when a ClientHello
  datagram is lost) are expected red because of msquic and leave `required.json` (`docs/spec/interop.md`).
- Clients that verify with `ksl` (`TrustConfig.AnchoredCa`, and `Platform` on Linux Native, also inside `Pinned` and
  `ExpectedName`) now send `status_request` and check a stapled OCSP response by default
  (`RevocationPolicy.StapledIfPresent`): a server that staples a revoked, unverifiable, foreign or stale response, which
  0.2.x accepted, now fails the handshake with `bad_certificate_status_response`, and a must-staple certificate (RFC 7633)
  without a staple fails too. `TlsConfig.revocation = RevocationPolicy.Off` restores the 0.2.x behaviour.
- The bundled OpenSSL now includes its `http` and `ocsp` modules (`no-http` dropped from
  `tools/openssl/configure-flags.txt`; Configure turns `ocsp` off with `http`), for OCSP stapling. `ksl` calls no HTTP
  client code. Every OpenSSL build cache is rebuilt once, since the cache key hashes the configure flags.
- Ktor client, proxy auto-configuration (RFC 6455 section 4.1 step 3): `ProxyResolvers.System` runs a PAC script or
  WPAD. On Windows with WinHTTP's PAC engine (`WinHttpGetProxyForUrl`: automatic detection, WPAD, by DHCP and DNS,
  then the PAC URL; each call goes without the user's credentials first, and with them only when the script's server
  asks). On Apple platforms the engine runs PAC itself, as CFNetwork's engine drops the path and query before the
  script runs: the script of the settings' PAC URL (downloaded directly, `http`, `https` or local `file`, at most 1 MiB read,
  one download per URL at a time, kept 30 minutes, a failure 1 minute) or given inline, or WPAD's when the settings say "auto discover" (DHCP option 252, `http` or `https`
  only, on macOS; then `wpad.<domain>` for each configured DNS search domain exactly, never a parent domain; then
  `http://wpad/wpad.dat` for the system resolver to complete), run on JavaScriptCore with the PAC utility functions
  (`…Ex` included) in a context without network, file or timer APIs, each run limited to 2 seconds from its start and
  its DNS lookups within that (threat model 3.20.3); a new script's text is prepared before that start (its size
  checked, its characters handed to JavaScriptCore whole, a NUL included), so a script of the largest size is not
  failed by a device slow at that; strings are read back whole too, so an answer with a NUL fails the run and a name
  with a NUL given to `dnsResolve` resolves to nothing. An answer naming only proxies the engine cannot use (`HTTPS`,
  `SOCKS4`) fails closed: the next setting, else the request fails, never a direct connection. A WPAD discovery that
  finds no script is logged once at Info. The script gets the URL as Chrome builds it (lower-case host, also as the
  `host` argument): a `ws://` URI whole, with its resource name (RFC 6455 section 4.1); `wss` and `https` as their
  origin only (`wss://host[:port]/`; see Security); `http` as its origin too, because the engine keeps answers per
  scheme, host and port (Chrome and Android pass an `http` path); on the JVM and Android `ProxySelector.select` gets a WebSocket's resource name (`ws` as `http`, `wss` as
  `https`, the schemes selectors know), though Android's PAC selector keeps it for `http` URIs only and the JDK's
  passes only the scheme and host to the OS. On Apple platforms a run makes at most 20 distinct lookups (a name looked
  up by both `dnsResolve` and `dnsResolveEx` counts twice), an answer is
  at most 64 KiB of ASCII, an answer entry that breaks the grammar is skipped (none left: the script failed), and a
  script given inline has the 1 MiB cap too. A lookup waits for the script at most 5 seconds (on Windows a WinHTTP call still running then, which
  cannot be cancelled, ends on its own thread and its answer is dropped); a script that cannot be fetched or run in
  that time gives the next setting (on Windows the fixed proxy), else a direct connection, with one warning. On
  Windows a WPAD detection that finds no script is logged once at Info (automatic detection is on by default there)
  and is not run again for 5 minutes; at most 4 WinHTTP calls run at once, and none while one that overran still
  runs. Before, those requests connected directly.
- Ktor client, HTTP/1.1 request framing (RFC 9112 section 6.1 MUST NOT): Transfer-Encoding (a body of unknown length,
  or a transfer coding the application applied) goes only to a server known to handle HTTP/1.1: an HTTP/1.1 response
  on the route, or ALPN `http/1.1`. On first contact without that knowledge (cleartext, or TLS without ALPN) the engine
  first sends an `OPTIONS` for the request's target on the same connection and reads the version of its answer. A
  server that answers with HTTP/1.0 gets a body of unknown length framed by Content-Length from a buffer of at most
  1 MiB, sent once the body ended; a longer body, one that does not end within the connect timeout (or the request
  timeout when that is shorter: a slow or duplex body), or a transfer coding of the application, fails that request
  with IllegalStateException before anything of it is sent. `http1 { knownServers }` (`KnownServers.Listed(…)`: servers known to handle HTTP/1.1; `All`: every server) is the
  RFC's "specific user configuration": requests to them go chunked at once, without the probe (experimental).
- Ktor client, HTTP/3 (RFC 9114 section 3.3, "Clients SHOULD NOT open more than one HTTP/3 connection to a given IP
  address and UDP port"): one origin reached under several names that resolve to one address and port (its host, an
  `Alt-Svc` alternative, an HTTPS-record target, an address literal) got a connection per name, all with the same
  configuration. Before a new connection, the pool now resolves the name and shares a connection of the same origin
  whose address (the literal its Happy Eyeballs race connected to, or the server's preferred address it moved to; the
  zone of a link-local address and the NAT64 synthesis counted) and port match,
  waiting for one still in its handshake for one `network { happyEyeballsDelay }` at most; setups that ran past each other keep
  the older connection and close the newer before any request used it. WebTransport sessions still take a connection each (session pooling is
  separate work). Different origins still get a connection each, and `Alt-Svc` bookkeeping stays
  per alternative (a 421 removes, a failure marks broken, the alternative the request used).
- TLS 1.2 cipher suite order (RFC 9325 section 4.2.1): a client now offers TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as its
  first TLS 1.2 suite (it offered the ECDSA variant first), and a TLS 1.2 server picks by its own order, AES-256-GCM, then ChaCha20-Poly1305,
  then AES-128-GCM, keeping ChaCha20-Poly1305 for a client that puts it first (it took the client's order, so a client
  that listed AES-128 before AES-256 got AES-128). TLS 1.3 is unchanged.
- Ktor server on the JVM (breaking): the `enabledProtocols` of Ktor's `sslConnector` (`ktor.security.ssl.enabledProtocols`)
  were ignored, and every such connector served TLS 1.3 only; now they choose the TLS versions. A configuration with
  `["TLSv1.2", "TLSv1.3"]` now turns TLS 1.2 on for a connector that was TLS 1.3-only, and one with any other list, such as
  `["TLSv1.1", "TLSv1.2", "TLSv1.3"]` or `["TLSv1.2"]`, now fails the start with `TlsException.Config`. Unset, or
  `["TLSv1.3"]`, stays TLS 1.3 only.
- RFC 9325 section 4.2 recommends deterministic ECDSA (RFC 6979); handshake ECDSA signatures keep OpenSSL's default
  nonce, derived from the private key, the message digest and fresh random bytes, since OpenSSL's TLS code (3.5 and 4.1)
  asks for no other. That is the hedged construction the same section names against the side-channel and fault attacks
  deterministic ECDSA invites ("combining both randomness and determinism"), as Go and BoringSSL sign, so
  docs/spec/rfc/9325.md records it as met, not as a deviation.
- Ktor server: a connector that serves HTTP/2 over TLS 1.2 with a certificate without an rsaEncryption key (an EC or an
  RSA-PSS key) gives its TLS 1.2 clients HTTP/1.1 and says so at startup at Info (RFC 9113 section 9.2.2: such
  deployments "MUST support TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"; see "HTTP/2 is on by default" above).
- `KuicksilverTlsConnector.tlsConfig(alpn)` returns the TCP configuration with the connector's `versions`, or a TLS
  1.3-only one when `alpn` holds `h3`.
- TLS server with client certificates (`trust` an `AnchoredCa`): the session ID context now covers the CA certificates
  as a set (each certificate's DER, not only its key), so tickets issued by a 0.2.x server do not resume on 0.3.0. In a
  rolling upgrade whose nodes share `SessionTicketConfig` keys, a client resuming across versions does one full handshake.
- Kotlin/Native klibs record source paths relative to the repository (`-Xklib-relative-path-base`) instead of the
  absolute paths of the machine that built them, in their debug information and in the symbol names Kotlin/Native
  derives from file paths, so a build no longer depends on (or reveals) the checkout directory.

- Release provenance: from 0.3.0 the GitHub release carries `kuicksilver-<version>.intoto.jsonl`, an in-toto
  attestation bundle (JSON Lines) whose one DSSE envelope holds the SLSA provenance statement and is signed by the release
  key, instead of the bare statement `kuicksilver-<version>.intoto.json` of 0.2.1. `tools/verify/verify-release.sh`
  checks the envelope's signature as well and still reads the 0.2.1 form (docs/release.md, "Build provenance").

- QUIC: a QUIC TLS config with a cipher suite other than TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384 or
  TLS_CHACHA20_POLY1305_SHA256 is refused with `TlsException.Config`. TLS_AES_128_CCM_SHA256 passed the check before and
  the handshake failed once it was chosen (QUIC packet protection has no AES-CCM).
- QUIC, DPLPMTUD: a probe declared lost by loss detection fails no earlier than 1 s after it was sent (RFC 8899 section
  5.1.1: the PROBE_TIMER "MUST NOT be smaller than 1 second"); it used to fail, and the next probe to go, within a few
  round trips. A probe declared lost whose acknowledgment still comes now confirms its size. The section's 15 s SHOULD is
  not followed (docs/spec/rfc/8899.md).
- Native UDP sockets: every IPv6 socket asks the kernel for flow labels (`IPV6_AUTOFLOWLABEL`, RFC 9000 section 9.7), so a
  Linux host that labels only on request (`net.ipv6.auto_flowlabels` = 2) or a Darwin host with
  `net.inet6.ip6.auto_flowlabel` = 0 labels QUIC datagrams too. Linux labels per path, Darwin per socket.
- Docs: RFC 9000 rows for section 9.7 and sections 21.6, 21.8, 21.10 and 21.11, the section 21.6 row relabelled 21.9; an
  RFC 9406 (HyStart++) row.
- Ktor client: `Alt-Svc` freshness counts from the response's generation (RFC 7838 section 3.1: fresh "for 24 hours from
  generation of the message", `ma` "the number of seconds since the response was generated"): the first valid member of
  `Age` plus the time from the request to the response is subtracted (RFC 9111 section 4.2.3, `corrected_age_value`).
  Before, freshness counted from receipt, so a copy a CDN had kept for a day stayed fresh for another day.
- Ktor client: a broken-alternative mark ends on whichever of a monotonic clock and the wall clock passes its end first:
  a backward step of the system clock cannot extend its backoff, nor deep sleep (which stops the monotonic clock on
  Android and iOS) stretch it; before, it ran on the wall clock alone. `Alt-Svc` freshness stays on the wall clock: its
  expiry is epoch time that `FileAltSvcStore` keeps across restarts.
- Ktor client: of the cached alternatives of an origin, the first fresh one that is not marked broken is used, in the
  server's order (RFC 7838 section 2.4). Before, a broken mark on the first one sent the call to TCP although a second
  fresh one was cached.
- HTTP/2 client: the first request on a new connection no longer waits for the server's SETTINGS (RFC 9113 §3.4), which
  saves one round trip per new connection. Only that request goes out before them: the other requests for the route wait
  for the SETTINGS (and their SETTINGS_MAX_CONCURRENT_STREAMS) rather than open streams under the initial "unlimited" of
  §6.5.2 or connections of their own. The server's SETTINGS must still arrive within what the connect timeout left after
  TCP and TLS, else the connection ends with SETTINGS_TIMEOUT: the call fails with `ConnectTimeoutException` when its
  request had no content or the content had not started, else with `Http2Exception.ConnectionClosed` (SETTINGS_TIMEOUT),
  so that `HttpRequestRetry` does not take a request whose body went out for one that never left. A server that refuses
  that first stream all the same (REFUSED_STREAM) does not count against the connection. `H2ClientConnection.start`
  (internal API) gained `prefaceTimeout` and returns at once; `tryReserve` grants one stream until the server's SETTINGS.
- TLS over TCP: the reader pump decrypts all the ciphertext a transport read brings before it hands the plaintext on (up
  to 64 KiB in one write instead of one write per 16 KiB record) and wakes the drainer only after records that carried no
  application data: the thread wake-ups between the pumps were the largest client CPU cost. A 10 MiB HTTP/1.1 download
  over a paced 200 Mbit/s, 100 ms path took 0.44 s of client CPU instead of 0.57 s (median of 20); HTTP/2 about the same.
- Ktor server: `http3 { endpoint { loops } }` above 1 serves HTTP/3 on every platform with a QUIC server (macOS, iOS and Windows
  included, the loops sharing one socket there); before, those platforms logged "HTTP/3 is not served" and answered over
  HTTP/1.1 without `Alt-Svc`. See docs/guide/ktor.md.
- QUIC: `QuicEndpoint.bind` with `loops > 1` no longer throws `UnsupportedOperationException` on macOS, iOS and Windows
  or with `quicEndpointConfig { runtime { io } }`: the loops share one socket there (see Added). It still throws without the
  accelerated socket and no `io`.
- Ktor server: a TCP connector holds at most 10,000 connections by default (`tcp { maxConnections }`, see "Added"); before,
  it accepted without a bound. At the limit it stops accepting and new clients wait in the OS backlog.
- QUIC (performance): one connection moves about 7 times the bytes over a fast path. The endpoint loop's receiver,
  reading the socket on the loop's thread, let the application's writes and commands queued on the loop run only every
  16 datagrams or 1 ms, so a stream's writer waited up to 1 ms per write while the sender sat idle. They now run before
  its next batch, and the receiver does not wait in the socket while one is queued; a stream's reader still runs every
  16 datagrams or 1 ms, so a paced sender's client costs no more CPU (quinn → JVM client 8.8 s/GB before and after).
  Over loopback (an Apple Silicon Mac): 29 -> 213 MiB/s on the JVM, 27 -> 209 MiB/s on Kotlin/Native. On Linux 8 connections over 4
  loops move 3.2 times what one loop moves instead of 0.6 times (docs/benchmarks.md, "One connection over loopback").
- QUIC (performance): the packet path on the accelerated socket allocates nothing per datagram: the connection ID table
  routes a datagram without boxing its hash, the endpoint loop takes a flowing socket's batches and flushes (a send on
  that socket never suspends) without a coroutine frame, boxed times or a copy of its list of connections, and a stream's
  output hands the core its buffered bytes without a peek and a second copy. Moving a GiB over loopback UDP allocates
  132-139 MiB on the JVM heap instead of 234-259 MiB (docs/benchmarks.md, "Allocation-free packet path (P.2)").

- HTTP/3: an idle server connection no longer keeps its last request stream (with that stream's input buffer and an
  8 KiB kotlinx-io segment, about 10 KB) when the request arrived while the session waited for it: the accept loop's
  coroutine frame held the stream until the next one came.

- Native: `ksl_open` decrypts a packet in its own buffer instead of through a heap copy that it then wiped: no `malloc`,
  copy or wipe per received packet. A packet whose authentication tag fails still leaves no plaintext behind: its
  payload is wiped in place (before, the buffer kept the ciphertext; nothing reads a rejected packet's payload, and its
  tag, the bytes a Stateless Reset check reads, is untouched).

- QUIC: a stream no longer holds two 16 KiB staging arrays (one per direction) and a connection's datagram flow no longer
  holds a 64 KiB one; the copies between the core and the application's channels go through one scratch array per endpoint
  loop. An idle HTTP/3 server connection holds about 80–90 KB of heap instead of about 290 KB (JVM), and an idle HTTP/3 connection pair
  takes about half the resident memory on Kotlin/Native (docs/benchmarks.md, "Memory"). A connection's ring for received
  DATAGRAM frames (1 KB) is made by its first datagram, and a stream's reassembly window starts at 512 bytes instead of
  4 KiB (HTTP/3's control and QPACK streams carry a few bytes for the life of the connection).

- TLS (breaking): a peer's certificate chain below OpenSSL security level 2 (RFC 9325 section 4.5) is refused under
  every trust configuration, not only where OpenSSL verifies the chain (`docs/guide/tls.md`, "Platform trust"): every key
  needs 112 security bits (RSA and DSA 2048 bits, elliptic curves 224 bits) and every certificate signature too, except
  the trust anchor's (no SHA-1 or MD5; RFC 9846 section 4.5.1.3: MD5 MUST, SHA-1 SHOULD be refused). A weaker chain ends
  the handshake with `bad_certificate` (42; `handshake_failure` with `genericAlerts`). Before, `TrustConfig.Platform` on
  the JVM, Android and Windows accepted 1024-bit RSA keys and SHA-1-signed intermediates when the platform did. Under
  `Platform` on the JVM, Android, Apple and Windows (also under `Pinned` and `ExpectedName`) the check runs after the
  platform's yes on the path the platform built, leaf to its trust anchor, as OpenSSL checks its own path (the anchor's
  key counts, its signature does not): a certificate the server sends that the platform does not use, such as an extra
  SHA-1 cross-certificate above the root it trusts, does not refuse the chain; when the platform does not say which path
  it took (the JDK's path cannot be rebuilt with its PKIX builder, SecTrust's chain cannot be read), the presented chain
  is checked as below. Under `Custom` and `Tofu`, `ksl` checks the certificates the peer sent before the verifier or the
  store is asked: every presented certificate reachable from the leaf through issuers whose key verifies the signature (a
  decoy with the intermediate's name cannot hide it; cross-certificates are all checked), only the own signature of a
  certificate that verifies under its own key exempt, which is stricter than OpenSSL's own verifier for an extra
  cross-certificate a server sends above the anchor the application trusts (one signed with SHA-1 refuses the chain).
  This endpoint's own chain is checked the same way when the identity is made
  (RFC 9325 section 4.5: servers MUST NOT authenticate with SHA-1 or MD5 or with RSA under 2048 bits): `TlsIdentity`
  factories throw `TlsException.Config` for a SHA-1- or MD5-signed certificate (OpenSSL checked only the keys). What breaks:
  `Custom` and `Tofu` now refuse weak keys too, so devices with legacy 1024-bit RSA certificates no longer connect, and
  an existing `Tofu` pin of such a key fails with `VerifyReason.WeakKey` instead of matching; a server or client
  certificate signed with SHA-1 or MD5 now fails when the configuration is made; and `VerifyReason` has two
  new subtypes, `WeakKey` and `WeakSignature` (experimental), so an exhaustive `when` over it no longer compiles without
  them. They are reported on OpenSSL's path too (`AnchoredCa`, `Platform` on Linux, client certificates), which reported
  `VerifyReason.Custom("X509 verification error 66")` and the like.
- Ktor client: `KuicksilverEventListener.protocolSelected` for the TCP path now comes once the connection is in hand,
  with its real protocol (`HTTP_2_0` when the server picked `h2`, else `HTTP_1_1`), still before `connectionAcquired`;
  it came before connecting and always said `HTTP_1_1`. A call whose TCP connection cannot be set up therefore gets no
  `protocolSelected`. TCP responses may report `HttpProtocolVersion.HTTP_2_0`: `https://` servers that offer `h2` are now
  spoken to over HTTP/2 by default (`engine { http2 { enabled = false } }` restores HTTP/1.1), and `http3 { enabled = false }`
  means "no HTTP/3" (HTTP/1.1 or HTTP/2 over TCP). `pool { maxConnections }` and `maxConnectionsPerRoute` count HTTP/2
  connections too (once each).

- TLS (performance): a server no longer builds an OpenSSL context (`SSL_CTX`, with its identity, suites and ticket keys)
  per connection. The handshakes of one server configuration share one context per identity snapshot, for QUIC and TCP
  alike; a `TlsIdentity.Reloadable` reload makes the next handshake build one from the new identity, and the old one is
  freed after its last connection. An identity keeps the contexts built from it (at most 8, one per server configuration)
  until it is closed. The process's generated session ticket keys are now looked up at each ticket, so they keep
  rotating (`SessionTicketConfig.rotateEvery`) under a context that lives as long as the server. The context was about
  10 % of a server's CPU per handshake (`EndpointHandshakeBenchmark`, Kotlin/Native profile).
- Performance (handshakes): a connection that ends normally builds no exception objects but its two close reasons (an
  unused `ConnectionLost.Internal` and a `JobCancellationException` per side are gone); ksl fetches HKDF and the packet
  ciphers from OpenSSL once per process instead of per key; the CRYPTO streams' buffers grow on first use (a connection
  allocates about a third less on the JVM heap). In-process benchmarks on a loaded host: 11–18 % more connections per
  second (`docs/benchmarks.md`, "0.3.0 work in progress").
- WebTransport: `drain()` also sets the session's own `drainRequested` (draft-ietf-webtrans-http3 section 4.7: the
  side that asks winds down too); before, it reflected only the peer's drain or GOAWAY.
- WebTransport needs the transport parameters and settings of draft-ietf-webtrans-http3-16 section 3.1 from the peer:
  for draft-14 and later `reset_stream_at` on both sides and the peer's `max_datagram_frame_size` above 0. A client
  throws `Http3Exception.Settings` before its CONNECT when the server lacks one ("A client MUST NOT establish
  WebTransport sessions if ..."); a server also requires the client's own WebTransport setting (`SETTINGS_WT_ENABLED`,
  draft-14 `SETTINGS_WT_MAX_SESSIONS`, draft-02 `SETTINGS_ENABLE_WEBTRANSPORT`) and treats a CONNECT without them as
  malformed: 400, STOP_SENDING `H3_MESSAGE_ERROR`, and `acceptWebTransport` throws `Http3Exception.Settings` (before,
  only `H3_DATAGRAM` was checked, and the 400 came without the stream error). Draft-02 sessions, which Chrome and
  Firefox open, need no `reset_stream_at`, as that draft predates it. The draft is the highest both sides announce
  (section 7.1; before, a client took the server's highest, draft-14 included, which it never announced). A peer that
  announces a newer draft without `reset_stream_at` but also draft-02 gets a draft-02 session when its CONNECT is a
  draft-02 request (`:protocol webtransport` with `sec-webtransport-http3-draft02: 1`; our client then sends one), our
  reading of section 7.1 ("the highest version supported by both endpoints" taken as the highest both can actually
  run; the draft does not say this); its draft-16 or draft-14 CONNECT, and a peer that announces only the newer draft,
  are refused. Safari speaks draft-14 (see `docs/spec/interop.md`). `Http3Endpoint` turns `quicConfig { expert { resetStreamAt } }`
  on with `http3Settings { webTransport { enabled } }`, as the Ktor engines already did, and every reset of a WebTransport stream is a
  RESET_STREAM_AT keeping the header we wrote (0 bytes on a stream the peer opened; section 4.4; before, a plain
  RESET_STREAM without the parameter and for rejected or abandoned peer streams). With
  `webTransport`, `SETTINGS_ENABLE_WEBTRANSPORT` other than 0 or 1 closes the connection with `H3_SETTINGS_ERROR`
  (draft-02 section 3.1).
- WebTransport: a session's streams are sent at the RFC 9218 priority of its CONNECT stream and follow the client's
  PRIORITY_UPDATE for it (draft-ietf-webtrans-http3-16 section 3.4); before, they had the default priority. Its
  datagrams, like every HTTP/3 datagram, go with their request stream's urgency (strict, both ways): never ahead of
  more urgent streams' data, so more urgent bulk streams can hold them back, and ahead of streams of the same or a lower
  urgency, so a datagram flood can starve those (before, every datagram went ahead of all stream data).
- QUIC (experimental): `QuicConnection.sendDatagram(data, policy, priority)` and `trySendDatagram(data, policy,
  priority)` schedule a datagram by RFC 9218 urgency (not ahead of strictly more urgent streams' data); the send queue
  keeps one FIFO per urgency, so a datagram never waits behind a less urgent one, and order is kept within an urgency.
  The sans-IO hook is `DatagramSender.nextUrgency`. Without a priority datagrams still go ahead of every stream.
- Ktor client: a `wss` WebSocket belongs to the `https` origin (RFC 8441 section 5 via RFC 9220; RFC 7838 section 2.4):
  it uses the alternatives, broken marks and RTTs learned from `https` responses, and Alt-Svc on its HTTP/1.1 answer is
  filed under `https`; `ws` likewise under `http`. Before, `wss` was an origin of its own and never found an alternative.
- Ktor client: an `Alt-Svc` alternative whose host is a valid RFC 3986 host but no connection target (sub-delims,
  pct-encoding, `_`, `~`) is skipped.
- HTTP/3: a request on a connection after this client's own `goAway()` fails with `Http3Exception.RequestNotProcessed`
  (retry-safe, message "request not sent: this client sent GOAWAY") instead of `IllegalStateException`: it was never
  sent, as one above a received GOAWAY, so a pool that handed the connection out just before may repeat it on a new
  connection. The new experimental `RequestNotProcessed.neverSent` says when nothing of the request left the client (its
  body unread), so even a streamed body can be sent again.
- Ktor client: an `Alt-Svc` alternative whose host is not an RFC 3986 host (RFC 7838 section 3: a space, a control
  character, a bare IPv6 address) is malformed and skipped; before, the text was taken as it came.
- Security policy (`SECURITY.md`): an OpenSSL advisory whose issue is reachable through Kuicksilver now gets a patch
  release with the fixed OpenSSL within 7 days (Moderate and Low; was 14 days for Moderate and the next planned release
  for Low), Critical and High still within 72 hours, each with a GitHub Security Advisory of this repository naming the
  OpenSSL CVE and the fixed version. New: where to see advisories and security releases, the emergency path when the
  month's Maven Central quota is used up, and `main` in the supported-versions table.
- Release policy (`docs/roadmap.md`, "Version policy", decided on 2026-11-26; `SECURITY.md`, `docs/stability.md`): every
  minor release 0.X.0 carries new features and the fixes found since the previous one; a patch release 0.X.Y is made
  only when users need a fix before the next minor release or for a security fix that cannot wait: an OpenSSL security
  release reachable through Kuicksilver (72 hours and 7 days as before), a Critical or High vulnerability (always,
  within 30 days of the assessment), and a Medium one that is publicly known or whose disclosure date is within 60 days
  of the assessment (within 60 days). A non-security OpenSSL 4.1.x patch release now ships in the next minor release
  (was: a patch release within 30 days), and the move to OpenSSL 4.2 LTS in a minor release (was: a planned patch
  release).
- TLS: the sealed `TlsIdentity` gains a member, `TlsIdentity.Reloadable` (docs/stability.md: sealed hierarchies grow);
  a `when` over it without an `else` branch no longer compiles, and one compiled against 0.2.x throws
  `NoWhenBranchMatchedException` when it meets a `Reloadable`.
- TLS: the sealed `TrustConfig` gains a member, `TrustConfig.ReloadableCa`, likewise: a `when` over it without an `else`
  branch no longer compiles.
- TLS: resumption is bounded on every server (RFC 9846 section 4.7.1). A ticket resumes only under the leaf certificate it
  was issued under, at most 7 days after the full handshake that authenticated the session (renewed tickets keep that
  time, as BoringSSL's `auth_timeout`) and not past the leaf's notAfter; otherwise the client runs a full handshake.
  Before, every resumption renewed the ticket with a fresh lifetime, so a client reconnecting within the ticket lifetime
  resumed without bound, also under a replaced or expired certificate. The lifetime a ticket announces is cut to what is
  left of both bounds, and an authentication time up to 60 s ahead of the server's clock (another node sharing ticket keys)
  is accepted. Tickets issued by earlier versions are not resumed. During a rolling upgrade of nodes that share
  `SessionTicketConfig.keys`, a 0.2.x node renews 0.3.0 tickets in the old format, which 0.3.0 nodes refuse: those clients
  run a full handshake (harmless, one per client).
- Windows (mingwX64) TCP: an idle connection's read tries the receive again after 1, 2, 4 and then every 8 seconds
  instead of every second, and after 1 second again once data was read: the bound on a lost `FD_CLOSE` costs an idle
  keep-alive connection a receive every 8 s, not every second.
- HTTP/3: only an Extended CONNECT whose protocol is not `websocket` has HTTP datagrams (RFC 9297 section 2). A datagram for
  a classic CONNECT or a WebSocket (RFC 9220) stream whose direction is still open now aborts that stream with
  `H3_DATAGRAM_ERROR`, as one for a GET does, and `Http3Stream.trySendDatagram` answers `Closed` on such a stream
  (`sendDatagram` throws `IllegalStateException`); before, every CONNECT took and sent them.
- TLS: a client session cache keeps 384 sessions by default instead of 256, so that the six tickets a TCP origin keeps
  (one per parallel connection) cover 64 origins, as the bound did before tickets came six at a time; 256 covered 42.
- Ktor server: with `port = 0`, a TLS connector whose HTTP/3 endpoint refuses its configuration (an argument or state it
  rejects, a TLS identity it cannot use) fails the start at once, as with a fixed port. Before, every such failure was
  taken for a taken UDP port: the pair was tried 16 times and the server then served HTTP/1.1 alone with only a warning.
  Only a failure to bind is retried now. The accelerated UDP socket reports a refused bind (a port in use) as an
  IOException, so a taken twin with `http3 { endpoint { loops } }` above 1 is retried like any other.
- HTTP/3: stricter towards peers (each also under "Fixed"); a peer that got away with these before now fails a request or
  the connection. An HTTP/3 datagram for a stream beyond the client-initiated bidirectional stream limit closes the
  connection with `H3_ID_ERROR` (RFC 9297 section 2.1, SHOULD); one for a request other than CONNECT whose stream is
  still receiving aborts that request with `H3_DATAGRAM_ERROR` (RFC 9297 section 2, MUST); and on a server every
  MAX_PUSH_ID after the first spends a glitch token, so a client that keeps re-sending it (some stacks send one with every
  push-credit update) meets `H3_EXCESSIVE_LOAD` once the bucket is empty (RFC 9114 section 10.5).
- Ktor client and server, HTTP/1.1: a chunk-size line with SP or HTAB right before its CRLF (`5 \r\n`, `0 \r\n`,
  `5;a=b \r\n`) is now refused: the server answers the request with 400 and closes the connection, and the client fails
  the response with `MalformedChunkedBodyException` ("Whitespace before the end of a chunk size line"). RFC 9112
  section 7.1 has BWS only before the `;` of a chunk extension and around its `=`, and a recipient that frames such a
  line otherwise than a peer in front of it is the chunk-line request smuggling class. Before, both engines tolerated
  it, as Go's net/http and nginx do on reading; a peer that writes such lines (some servlet containers and
  hand-written servers) has to be fixed.
- Ktor client: the h3/h1 race starts HTTP/1.1 10 ms after HTTP/3 on a network where QUIC was never confirmed, instead
  of at the same time, and an explicit `http3 { expert { raceHeadStart = RaceHeadStart.Fixed(d) } }` must be 10 ms..2 s (else the
  engine's creation fails with `IllegalArgumentException`; before, any value was used as is). `RaceHeadStart.NoRace`
  starts HTTP/1.1 only after HTTP/3 failed on every network, a never-confirmed one included. RFC 8305 section 5: a
  subsequent connection attempt MUST NOT start within 10 ms of the previous one, and attempts SHOULD NOT be
  simultaneous.
- Ktor client: `http3 { expert { clearAltSvcOnNetworkChange } }` is now true by default: when `network { networkId }` reports a new network, the
  engine forgets the Alt-Svc alternatives without `persist=1`, as RFC 7838 section 2.2 says a client SHOULD. Before, it
  kept them unless asked. `clearAltSvcOnNetworkChange = false` restores the old behaviour.
- QUIC: when the server rejects 0-RTT, the client resets every stream it opened before the handshake completed, as
  RFC 9001 section 4.6.2 requires ("MUST reset the state of all streams"); before, it sent their data again in 1-RTT. The
  streams fail with the new `QuicException.StreamError.EarlyDataRejected` (experimental), nothing of them reached the
  server, their IDs and the connection's credit start over from the server's new transport parameters, and the
  connection goes on; send again on new streams what is still wanted. A stream opened while the rejection was still on
  its way to the runtime (a flush waiting for socket room) is a stream of its own: it never gets the wrapper of the early
  stream whose ID it took, and a reset or STOP_SENDING issued on an early stream never reaches it. A rejection closes the connection with
  `ZeroRttRejected` only for another ALPN or under `EarlyDataState.Required` (no longer for lower limits). The HTTP/3
  client still sends its SETTINGS in 0-RTT (RFC 9114 section 7.2.4.2: "settings MUST be sent as soon as the transport is
  ready to send data"); after a rejection it opens its control and QPACK streams again, sends SETTINGS once more and
  after it the control frames of the dropped control stream that are still wanted (a GOAWAY; not a PRIORITY_UPDATE
  for a dropped request), sends
  no QPACK Stream Cancellation for the early requests (the request sent again reuses the stream ID, and a cancellation
  arriving after its response was encoded made the server fail the connection with `QPACK_DECODER_STREAM_ERROR`) and
  repeats each early request once.
- Ktor client: requests now follow the platform's proxy settings by default (`proxies { resolver = ProxyResolvers.System }`):
  where the system, the JVM's properties or (on Linux) the environment name a proxy, requests go through it over
  HTTP/1.1, without HTTP/3 or Alt-Svc. Before, only an explicit `proxy` was used. `proxies { resolver = ProxyResolvers.None }`
  restores direct connections.
- Ktor client: a `ws://` WebSocket through an HTTP proxy now goes in a CONNECT tunnel (RFC 6455 section 4.1), as
  browsers do, instead of an absolute-form Upgrade the proxy may not forward. A CONNECT the proxy refuses fails with
  `ProxyException` (`replyCode` 407 when it wants credentials) instead of a plain `IOException`. The
  `protocolSelected` reason for a request through a proxy is the new `ProtocolReason.Proxy` (was `NotSecure`).
- HTTP/3 scheduling (RFC 9218): a CONNECT tunnel without a priority signal, a WebSocket over HTTP/3 or a WebTransport
  session among them, keeps RFC 9218's defaults on both sides (u=3, non-incremental, section 4.2) like any request, on
  HTTP/2 too; a client that wants a tunnel to share bandwidth with the incremental streams of its urgency signals
  `priority: i` (section 11). (An earlier change in this release made unsignalled tunnels incremental; that is undone.
  For a WebTransport session the default means its credit goes to its streams in open order, where a stream that keeps
  writing holds the later ones; `priority: i` shares it.) Within one urgency the incremental and the non-incremental streams now
  take turns frame by frame (section 10), where non-incremental streams used to go strictly first and could starve an
  incremental stream or tunnel; and a CONNECT tunnel gets at least one frame in 16 while more urgent streams have data
  (section 10.1: "servers SHOULD allocate some amount of bandwidths to streams acting as tunnels"). A `priority` header on a request now schedules the client's own stream too, and a
  `priority` field in a server's response is merged into the client's signal and applied to the response's scheduling.
- QUIC client: a server's `preferred_address` is now followed (validated, then moved to) instead of ignored; set
  `QuicConfig.followPreferredAddress = false` to keep the old behaviour.
- QUIC: `ConnectionAdmission.default()` lets in every attempt whose address a token already validated
  (`ConnectionAttempt.addressValidated`: a Retry token, or from 0.3.0 a NEW_TOKEN token), whatever the handshakes in
  flight and their buffers. Before, under load it asked such a client for a Retry: a NEW_TOKEN holder lost the round
  trip the token was for, and a client that had just answered a Retry was dropped as a contract violation
  (`admissionContractViolations`) until the load fell. The hard limits (`maxConnections`, `maxConnectionsPerIp`,
  `acceptQueue`) still apply.
- `Http3ErrorCode.isKnown` and `normalize` recognise the WebTransport codes (`WT_SESSION_GONE` and the others now in
  `Http3ErrorCode`): an `Http3Exception` carrying one keeps it instead of reading as `H3_NO_ERROR`.
- Ktor engines: a WebSocket peer that masks in the wrong direction (a client sending unmasked frames, a server masked
  ones, RFC 6455 section 5.1), sets RSV bits no negotiated extension defines, or sends RSV1 on a later fragment of a
  compressed message (as Ktor's own `WebSocketDeflateExtension` does, RFC 7692 section 6.1) is now closed with 1002;
  before, both engines took such frames.
- Ktor client on the JVM and Android: an HTTP/1.1 connection to a host name now tries every address the name resolves
  to (Happy Eyeballs), not only the first; on Kotlin/Native the addresses are tried 250 ms apart instead of one after the
  other. `network { happyEyeballsDelay = null }` restores one address after another. HTTP/3 no longer connects to
  the first address only.
- Ktor client: name lookups run at most 8 of each address family at a time on their own share of `Dispatchers.IO`, one
  per name and address family however many requests wait for it; an IP address literal is never looked up, and a dotted-decimal string with an octet above 255
  is a name, not an address (one with a leading-zero octet, octal to `inet_aton`, goes to the platform as before).

### Fixed

- WebTransport (experimental): on a draft-02 session, which Chrome and Firefox speak, a stream the peer resets before its
  header named a session now reaches the session's application with the reset's code (draft-02 section 4.3: an
  implementation that "intentionally allows only one session over a given HTTP/3 connection [...] SHALL forward the error
  codes within WebTransport application error code range to the application that owns the only session"). A draft-02
  connection carries one session, so its application accepts the stream and reads the reset. Before, the stream was
  dropped and its code lost.
- Ktor client: a `ConnectTimeoutException` names the connect timeout that fired, also when only the engine's own
  `connectTimeout` is set and `HttpTimeout` is not installed. Before, the name lookup and pool wait of HTTP/1.1 and
  HTTP/2, a WebSocket's name lookup, the wait for an HTTP/2 server's preface and an HTTP/3 setup said
  `connect_timeout=unknown ms`: they used Ktor's `ConnectTimeoutException(request, cause)`, which reads the plugin's
  value alone. A WebTransport session's connect timeout names the session's URL now, not only its host and port.
- The portable JVM and Android socket (`IoPreference.Portable`) no longer leaks its channel and selectors when opening it
  fails after the channel is bound (registering it with its selector, or setting up the socket), a failure not seen in
  practice.
- QUIC client: after a Version Negotiation packet moved it to QUIC version 1, a server without `version_information` failed
  the handshake with VERSION_NEGOTIATION_ERROR, so a client that started with v2 (`QuicConfig.versions`) could not reach a
  server that knows only v1. RFC 9368 section 8: the client "SHALL proceed as if" the server had sent Chosen Version 1 and
  Available Versions [1], and now does (as ngtcp2); after a Version Negotiation to another version the parameter is still
  required.
- HTTP/3: resetting an Extended CONNECT stream (`Http3Stream.reset`) now ends its writer too. Before, the tunnel's
  writer kept waiting for content, so the exchange never ended until the connection closed. A WebTransport client
  session that ended because the server broke it (a malformed WT_CLOSE_SESSION, a capsule section 5.4 prohibits) kept
  its slot in the connection's session count, so `http3Settings { webTransport { maxSessions } }` sessions failed that way blocked new ones on
  that connection. The server side was not affected.

- WebTransport no longer runs a draft-02 session when the selected draft lacks `reset_stream_at` (compatibility shim 3,
  removed; hardening audit S3). Its one expected user, Safari, sends the parameter: Safari 27.2 ran its draft-14
  session without the shim (`docs/spec/interop.md`). The draft-17 section 7.1 selection decides, and nothing else:
  - A client that announced a newer draft without the transport parameter but also draft-02 got a draft-02 session for
    a draft-02 request. It now gets 400 with `H3_MESSAGE_ERROR` (section 3.1).
  - Our client no longer sends a draft-02 CONNECT to such a server; it throws `Http3Exception.Settings`.
  - A draft-02-form CONNECT from a client whose selected draft is newer is now malformed, since its token is not the
    selected draft's. Before, it ran draft-02.

- WebTransport: a peer's WT_CLOSE_SESSION that arrived with its CONNECTION_CLOSE (Firefox 160 sends both in one packet)
  is reported in `closed` with its code and reason, also when the application, or a Ktor route whose handler the
  connection's end cancelled, calls `close()` first. Once the connection is gone `close()` sends nothing and waits for
  the session's end. Before, it completed `closed` with code 0 ahead of the peer's capsule.
- WebTransport server: a client's STOP_SENDING on a session's CONNECT stream no longer counts as an abandoned request
  (`awaitAbandoned`). Safari 27.2 sends it with its WT_CLOSE_SESSION and FIN in one packet. The Ktor engine cancelled
  the route's handler on it, and the route then closed the session with code 0 ahead of Safari's capsule (code 7 and
  "bye" in the manual check). Only the connection's end abandons such a request now; the session's `closed` reports
  the client's close.
- WebTransport: a session whose peer stops our side of its CONNECT stream (STOP_SENDING) ends, as draft-17 section 6
  asks of a CONNECT stream closed abruptly. What the peer sent before decides first, as Safari's WT_CLOSE_SESSION and
  FIN in the same packet do; it gets one second. Otherwise the session ends as ended by the peer, with code 0, and its
  streams are reset with WT_SESSION_GONE. A cancelled `close()` again stops only its wait.

- WebTransport server: `sec-webtransport-http3-draft: draft02`, the response field Chrome's draft-02 client needs, goes
  only to a session that runs draft-02 and whose client sent `sec-webtransport-http3-draft02: 1`. Before, any request
  that carried the request field got it, with any value and in any draft. So a draft-16 session whose
  `webtransport-h3` CONNECT carried the field was answered with a draft-02 marker.

- QUIC `connect` / `connectEarly` to a target whose name does not resolve fails at once with
  `QuicException.ConnectionLost.NoViablePath`, its cause a `kotlinx.io.IOException` naming the target, the same on every
  platform. On the JVM its datagrams were lost until the handshake timeout; on Kotlin/Native the lookup's `PosixException`
  escaped, with a stale errno (Ktor's `resolveAddress()` throws there after `getaddrinfo` fails, where the JVM answers
  null), and `withLiteralHost` threw it too instead of keeping the name as documented.
- CONNECT-UDP proxy: a target socket that failed to open for another reason than Don't Fragment (out of descriptors, a
  sandbox) answered 502 `proxy_internal_error` at once; the other address family's candidates are now tried first, and
  502 comes only when none opened (also when the other family lacked DF).
- CONNECT-UDP proxy: a `socketFactory` call that did not return (one blocked in a lookup, a suspension that never
  ends) left the request unanswered until the client gave up. The call is now bounded by `UdpProxyConfig.socketOpenTimeout`
  (5 s by default, `Duration.INFINITE` turns it off): it runs on a `Dispatchers.IO.limitedParallelism(16)` view of each
  proxy's own (up to 16 threads per proxy, beside `Dispatchers.IO`'s 64), a suspending one is cancelled at the deadline or
  when the `serve` call is cancelled, a blocking one given up on, and a socket it returns late is closed; that family counts
  as failed, so the other family is tried and the answer is 502 `proxy_internal_error` with `details="socket open timed
  out"` when none opened. A `CancellationException` the factory throws itself now fails its family too (502), where it
  cancelled the request without an answer. A throwable that would still escape a factory call (none should: a late
  socket's throwing `close` is caught too) is counted in the new `UdpProxyStats.socketFactoryUncaught` rather than reaching
  the platform's uncaught-exception handler, which ends the process on Android and Kotlin/Native. Found through a
  test socket factory that read the wildcard bind's `hostname` (on the JVM `getHostName()`, a reverse lookup of `0.0.0.0`)
  and hung for minutes in the local matrix's JDK 25 step; `tools/check/env-apis.py` now covers test sources too.
- Android and Linux on AArch64: `libksl` died with SIGILL while it loaded (and the app's process with it) on a kernel
  that reports SVE2 without SVE, as an Android emulator on Apple M4 does (SME, no SVE; kernels without Linux's fix
  "arm64: Filter out SVE hwcaps when FEAT_SVE isn't implemented"): OpenSSL's CPU detection, run as the library loads,
  executed an SVE instruction to probe the vector length. The bundled OpenSSL carries a tenth patch (`patch_10`,
  `openssl-4.1.0-armcap-sve2-without-sve.patch`; owner decision 2026-11-21, ADR-0019), upstream's fix carried verbatim
  (openssl/openssl@cb5f5d00e4, pull request #33481; openssl-4.1 658a1c947b) and dropped with 4.1.1: the probe runs
  only when SVE is reported too. Seen as every device test crashing on the local gate's API 34 emulator.
- CONNECT-UDP proxy: a payload the tunnel's socket refused as too large for the path or link (EMSGSIZE or WSAEMSGSIZE:
  an interface or route toward the target with a smaller MTU, or, on a socket in DO mode only, an ICMP Packet Too Big,
  genuine or forged, that lowered the kernel's cached path MTU) ended the whole tunnel as a failed socket (reset and
  STOP_SENDING `H3_CONNECT_ERROR`) on the sockets that throw for it, and on the accelerated socket, which skips such a
  slot, was counted as sent (`toTargets`, the unanswered limit). RFC 9298 section 5 carries "the unmodified payload" and
  such a payload cannot be forwarded whole, but the socket is still usable: the payload is now dropped and counted in the
  new `UdpProxyStats.droppedRefusedAsTooLarge`, neither keeps the tunnel from its idle timeout nor counts toward
  `unansweredLimit`, and the tunnel goes on forwarding the next ones. The accelerated socket reports its refusals through
  the new internal `EmsgsizeReports`; the others' are recognized by `isRefusedAsTooLarge` (`kuicksilver-quic`, shared
  with the portable JVM socket's own check: `PathMtuRefusedException`, the system's localized text, "Message too long",
  the Windows JDK's text, ktor's `PosixException` with EMSGSIZE on Kotlin/Native). Any other send failure still ends the
  tunnel (section 3.1) (`ConnectUdpTest.negative_payloadTheSocketRefusesAsTooLargeIsDroppedAndTheTunnelStays`,
  `.negative_aRefusalTheAcceleratedSocketReportsIsNotCountedAsSent`, `.negative_refusedPayloadsDoNotKeepATunnelAlive`,
  `.negative_refusedPayloadsDoNotCountTowardTheUnansweredLimit`, `.negative_anotherSendFailureStillClosesTheTunnel`,
  `SendRefusalTest`).
- CONNECT-UDP proxy: `UdpProxyStats.packetTooBig` stayed `NotProbed` after the first tunnel opened, contrary to its
  documentation ("as probed at its first tunnel"): the raw ICMP privilege was probed only at the first payload dropped as
  too large for the client, after that drop was counted, so a reader that saw the drop could still find `NotProbed` (a
  flaky `ConnectUdpTest` on the Android 7.0 emulator in CI). The proxy probes again at its first tunnel, before the
  tunnel's 2xx.
- HTTP/3 client: a request that failed before its body was sent left the body alone, so a coroutine writing it waited
  forever: the connection ended while the request's HEADERS were flushed (a flaky `ConnectionEndTest` on macOS CI), it
  had already ended, the request was refused as malformed, or its caller gave up while it waited for stream credit. Only
  the body's sender, never started then, ended the body. A failed request now ends its body with the failure; one refused
  before anything of it left (`RequestNotProcessed.neverSent`) still leaves it unread, and the Ktor engine still sends it
  again with that body. The body's writer fails with the exception the request threw, also from `request()` on a
  server's connection.
- Ktor client: a request whose body comes from a writer (`WriteChannelContent`), refused by a GOAWAY before anything of it
  went out and sent again (on a new HTTP/3 connection or over HTTP/1.1), never ended: the refused attempt's writer waited
  forever on a channel no one read, in the call's context, so the call's Job never completed and the connection the
  answering attempt used was never released. A failed attempt now ends its own body channel.
- HTTP/3 client: the datagram channel of an extended CONNECT tunnel (CONNECT-UDP, WebTransport) stayed registered, and
  open, when the connection ended: its removal was launched into the connection's scope, which the connection's end
  cancels before it ran. Every channel still registered now closes once the connection's coroutines are gone, so a reader
  of the tunnel's datagrams sees the end (`ConnectionEndTest.clientTunnelDatagramChannelEndsWithTheConnection`; found by
  the leak sentinel).
- Ktor client: a closed client still waited for a QUIC setup that had lost its race to TCP (it goes on in the background
  to fill the pool or to mark the alternative broken) until that setup's own bound, up to the connect timeout, before it
  released its endpoint and connections. `close()` now cancels such setups at once: no call waits for them, and a closed
  engine cannot use what they make. Requests still running are left to finish, as Ktor's `close()` promises
  (`ClientEarlyDataTest.closeCancelsAQuicSetupThatLostTheRace`; found by the leak sentinel).
- TLS over TCP (`Socket.tls`, `Socket.tlsServer`): a socket that ended kept its job, and the pumps under it, for good when
  the application had stopped reading (the relay waited for room in the application's channel) or, for an abort, kept its
  write channel open without writing (the pump waited for its next bytes). The descriptor was closed; the coroutines
  stayed, one set per such connection. A close and an abort now end both pumps
  (`TlsSocketReleaseTest`; found by the leak sentinel). A behaviour change: the application's read channel stops at
  `close()` (see the next entry), not once the close is over; a read still waiting on it ends with a cancellation, and
  plaintext the session had not handed to that channel yet is dropped (read what you need before you close).
- TLS over TCP: a closing socket waited for the peer's close_notify behind input the application would never read: the
  session waited for room in the read channel, the peer's writes waited behind it, and a client's close ran to its 3 s
  bound (a client that closed without reading the rest of a response). From `close()` on, what the peer still sends is
  read and dropped, so its close_notify ends the wait as soon as it comes. Closing only the write channel (a half-close)
  still delivers the rest. A read channel opened once `close()` has begun fails at once and starts no second reader,
  which took the input from the close's drop and brought the wait back (`TlsSocketCloseTest`; found by the leak
  sentinel's slow-close report).
- Ktor client, HTTP/1.1 over TLS: the orderly close of a connection whose response nobody would read any more waited
  behind it in the same way. A response refused after its head (an invalid `Content-Length`) while the server went on
  sending held its close_notify wait to the 1 s bound; a response the application abandoned went the other way, its
  session stopped reading at once and the connection closed under the rest of the body, so the kernel reset it, which
  can erase the client's close_notify before the server reads it. Both now read and drop what still comes until the
  server's close_notify (`TlsConnection.cancelInput`, internal), and a session ticket that comes meanwhile is still taken
  (`ClientOrderlyCloseTest.negative_aRefusedResponseDoesNotHoldTheOrderlyClose`,
  `negative_anAbandonedResponseDoesNotHoldTheOrderlyClose`). The same for HTTP/2: a connection that ended (a connection
  error, a missed health PING, a local failure) while the server still sent DATA waited for its close_notify behind it,
  its read loop already stopped, until the bound (`negative_anH2CloseDoesNotWaitBehindDataNobodyReads`). A closing TLS
  socket now drops its input the same way, instead of reading it out. On a client the drop is bounded: past 256 KiB
  the session stops reading and the connection closes under the rest (the kernel resets it, and the server's writes
  fail), so a response abandoned or timed out mid-body is not downloaded for as long as the close waits; as first
  merged it was read at line rate for up to the 1 s bound, and a server could write a whole 1 GiB response nobody read
  (engine interop's `ClientToNettyH1Test.requestTimeoutMidBody`;
  `ClientOrderlyCloseTest.negative_anAbandonedLargeResponseIsCutPastTheDropBound`,
  `negative_aRefusedLargeResponseIsCutPastTheDropBound`, `TlsCancelInputTest`,
  `TlsSocketCloseTest.negative_aClientCloseCutsAResponseFarBeyondItsDropBound`). A server's drop has no such bound: a
  reset there could erase its last response before a slow client read it, so it drops until the client's close_notify
  or FIN, and whoever accepted the socket bounds the close
  (`TlsSocketCloseTest.aServerCloseStillDeliversTheLastResponseToASlowUploadingClient`).
- HTTP/3 server: requests could stay registered on a connection (for as long as its object lived) or leave their stream
  open, which on a live connection also held off the GOAWAY idle close:
  - a response open when the connection was lost, its writer waiting for content: the writer, cancelled with the
    connection, ended without ending the request, and the handler's next write or `finish` failed before the response
    was marked complete. The request now ends with its writer
    (`ConnectionEndTest.responseOpenWhenTheConnectionEndsLeavesNoRequest`; seen as
    `EarlyDataTest.earlyRequestEndsWhenTheConnectionIsLostBeforeTheAnswer` failing on Windows);
  - a request the handler reset after the connection ended: its end was launched into the connection's finished scope
    and never ran (`requestResetAfterTheConnectionEndedLeavesNoRequest`);
  - a request the handler never answered (a failed body read, a throw before `respond`, a handler its engine
    cancelled): every request still registered now ends once the connection's coroutines are gone, and a later
    `respond`, `acceptConnect` or `acceptWebTransport` fails with the connection's error instead of "request is
    finished" (`requestNeverAnsweredEndsWithTheConnection`);
  - a handler cancelled inside `finish` while the content was still being handed over: neither FIN nor reset was sent,
    and the client's body read waited for good. The response is now abandoned with `H3_REQUEST_CANCELLED` (RFC 9114
    section 4.1.1) and the request ends (`finishCancelledWhileThePumpHandsOverAbandonsTheResponse`).
- Ktor server, HTTP/1.1: a request whose first bytes arrived just as the server began to stop could be dropped: the wait
  for the next request head raced the stop, and when the stop won, the connection closed over the head without reading
  or answering it (and a close over unread input may reset the connection). The stop's side now ends the wait and looks
  at the input again: a head that has started to arrive is read and answered with `Connection: close`, as the stop
  promised ([Ktor guide](docs/guide/ktor.md)); only a connection with nothing to read closes at once.
- Ktor server, HTTP/1.1: a request the engine had already read from the socket when the stop had completed before the
  pipeline's first wait for a head (a connection accepted as the server stopped, or one an h2c `WithHttp11` preface check
  handed to HTTP/1.1 as the stop won it) was closed unanswered: that wait looked only at the pipeline's own, still empty,
  buffer. It now looks at the channel it reads from too, so such a request is read and answered with `Connection:
  close` (`H1PipelineSelectRaceTest.negative_aRequestInTheSocketsBufferBeforeAStopThatAlreadyCompletedIsAnswered`).
  Bytes still in the kernel's socket buffer, or a TLS record not yet decrypted, when the stop begins are not seen: such a
  connection is still closed as idle. A connection whose head has started (any of its bytes read) now holds the stop
  until that head is complete, or for at most the remaining request-head deadline (`requestHeaderTimeout`, then
  408) or the stop's grace period, whichever ends first.
- Ktor server, HTTP/1.1 (and h2c on a `WithHttp11` port): a connection accepted just before the server stopped, whose
  first request was still on its way, was closed at once without an answer, and its client could not tell whether a
  non-idempotent request had been processed (RFC 9112 section 9.3.1). A connection that has received nothing yet now gets
  until 2 s after its acceptance for its first byte (within the request-head deadline and the grace period), and that
  request is answered with `Connection: close`; a keep-alive connection idle between requests still closes at once
  (`StopFirstRequestJvmTest`). A silent new connection can so hold a stop for up to 2 s.
- Ktor server, HTTP/1.1: a pipelined request the engine had already read when a handler before it failed could still be
  processed: the wait for its head ends on the failure as on the server's stop, and a head already read was handed on.
  After a failed response (or a stopped response writer) no later request is processed (RFC 9112 section 9.3.2), and a
  head that has started is read no further: the connection ends after the responses before it, not at the request-head
  deadline (`H1PipelineSelectRaceTest.negative_aHeadBufferedWhenAHandlerFailedIsNotProcessed`,
  `negative_aPartialHeadWhenAHandlerFailedIsReadNoFurther`).
- QUIC client, 0-RTT: a stream sent and reset in 0-RTT before the server answered kept its runtime wrapper (its channels
  and its ticker, which every poll of the connection wakes) after an acceptance until the server acknowledged the reset,
  and until the connection ended when it never did. Its final size stands at the acceptance, and the wrapper now goes
  then, as it does for a stream reset in 1-RTT; only its `awaitFinished` still waits for the acknowledgment (RFC 9000
  section 3.1), its `awaitSendStopped` now returns null at the acceptance (both halves are done, as for a stream reset in
  1-RTT) instead of waiting for the acknowledgment or the connection's end, and a lost RESET_STREAM is sent again from
  the code and final size it carries (section 13.3). Rejected and lost 0-RTT keep their behaviour (the streams fail with
  `EarlyDataRejected` or the connection's loss). Pinned by
  `ZeroRttApiTest.acceptedEarlyStreamsResetAndNeverAcknowledgedLetTheirWrappersGo`,
  `ZeroRttTest.earlyStreamRetiredBeforeTheAnswerIsOfferedAgainAtTheAcceptance` and
  `StreamStateTest.cancelledEarlyRequestWhoseResponseEndedBeforeTheAnswerIsOfferedAgainAtTheAcceptance`.
- QUIC client: a 0-RTT attempt answered with a HelloRetryRequest (a server whose key-exchange groups did not include
  any the client sent a key share for) never completed. The second ClientHello was handed to the transport at the 0-RTT
  level, where a server reads no CRYPTO frame (RFC 9000 section 12.4; RFC 9001 section 4.1.4 puts every ClientHello in
  Initial packets), and it offered `early_data` again, which RFC 9846 section 4.2.2 removes and the server answered with
  `illegal_parameter`; the client also got a second 0-RTT key from it. `ksl` now gives a ClientHello the Initial level,
  hands out no 0-RTT key after a HelloRetryRequest, and has each 0-RTT connection offer a copy of its session, whose
  0-RTT allowance a HelloRetryRequest clears (OpenSSL 3.5's QUIC client otherwise keeps offering it). The handshake
  completes with 0-RTT rejected (RFC 9001 section 4.6.2: "A server will always reject 0-RTT if it sends a TLS
  HelloRetryRequest") and the session resumed.
- HTTP/2 server: a stop waited for a client that had sent part of its connection preface, up to the stop's grace period:
  the preface wait did not watch the stop. A stopping server now ends such a connection at once with GOAWAY, over TLS
  and over h2c; its last stream is the last one the core took (0 when none), and requests taken before it (a preface and
  a request that arrived as the stop came) are served, never left unanswered under a GOAWAY that names them (RFC 9113
  section 6.8).
- HTTP/3 client (ktor-client) and `QuicConnection.rebind`: a local process could take the replies of an HTTP/3
  connection to a server on localhost on macOS (and the other BSD-socket systems, iOS included). The client's endpoint was
  bound to the wildcard address, which shares its port with a socket another process binds to 127.0.0.1 or ::1, and the
  kernel even handed the wildcard bind a port such a socket held; the server's replies to the loopback address then went to
  that socket, and the connection failed or timed out. A connection to a loopback server (127.0.0.0/8, ::1) now leaves
  from an endpoint bound to the loopback address of its family, created at its first use and closed with the client;
  every other destination keeps the shared wildcard endpoint; all of them share the client's session tickets, so a name
  that resolves to both families (`localhost`) still resumes in 0-RTT over either. The sockets that connection migration
  and `rebind` open for a loopback peer bind the loopback address too.
- QUIC client: a ticket renewed without the `early_data` extension (a resumption on a server that no longer accepts 0-RTT)
  carried the 0-RTT allowance of the ticket it renewed, so the next connection offered 0-RTT the server had withdrawn.
  OpenSSL's client copies the old session for each NewSessionTicket and only overwrites `max_early_data` from an
  extension present; `ksl` now clears it for a ticket without one (RFC 9846 section 4.6.1: the client may send early data
  "when using this ticket" up to its `max_early_data_size`; RFC 9001 section 4.6.1). A value other than 0xffffffff is
  still a PROTOCOL_VIOLATION.
- TLS and QUIC clients no longer resume a session issued under another server name (RFC 9846 section 4.7.1: clients
  "SHOULD only resume if the SNI value matches the one used in the original session"; DNS names compare
  case-insensitively): `QuicTlsSession.resume` returns false and the handshake is a full one. The session cache never
  offered one, but a ticket handed to `resume` for another name with 0-RTT failed the handshake in OpenSSL ("inconsistent
  early data sni"); a name that differs only in case resumes without 0-RTT for the same reason. A session's name is the
  one the client sent, also when the server did not acknowledge it (RFC 6066 section 3 leaves that to a server that used
  the name; OpenSSL's client records the name only from the acknowledgment), so sessions from such servers (ngtcp2,
  quiche and msquic in the interop runner) resume, with 0-RTT, under their own name. A session made under a server name
  other than the verify name (`TlsConfig.serverName`) resumes only when its certificate also names that server name
  (RFC 9846 section 4.7.1: "Clients MUST only resume if the new SNI value is valid for the server certificate presented in
  the original session"); before, the server name itself was never checked against the certificate.

- WebTransport flow control: a stream stopped (`stopSending`, or its input cancelled) right as it was accepted, before
  its reader had run, never gave its bytes back as session credit (draft-ietf-webtrans-http3-16 section 5.6), so a
  session whose window it filled stalled for good. Its bytes now count as consumed as for a stream stopped later.
- WebTransport flow control: a stream slot given back by an open that was given up while it waited for the
  connection's stream credit did not wake the opens waiting for a slot, so they waited with one free until the peer
  raised its limit, if ever. They now take it at once.
- TLS over TCP, client: an alert sent after the ServerHello (a refused server certificate, name or pin, a malformed
  server flight) went out in the clear, because OpenSSL's middlebox compatibility mode moves a client to its handshake key
  only right before its second flight. RFC 9846 appendix A.1: clients "SHOULD first rekey to the handshake keys if
  possible". A server already reading under that key could not take it: a JDK (Netty) server failed with "Insufficient
  buffer remaining for AEAD cipher fragment (2)" instead of reporting the client's alert. Clients now run without the
  compatibility mode (appendix E.4, optional): the hello carries no compatibility session ID, no dummy
  `change_cipher_spec` is sent, and every alert after the ServerHello is protected under the client handshake key. Servers
  keep the mode (they must answer a client's session ID with `change_cipher_spec`); QUIC never used it.
- QUIC: a path whose socket capabilities change to no DF (`setPathCapabilities`) went on sending datagrams of the
  size its path MTU search had reached, which the network may then fragment; it goes back to 1200 bytes (RFC 9000
  section 14: "UDP datagrams MUST NOT be fragmented at the IP layer").
- A step done as its deadline fired was reported as not done: `withTimeoutOrNull` drops a block's result when the timeout,
  which fires on another thread, lands after the block returned and before the timeout's scope completed. Each site whose
  block has an effect now keeps the result once the block returned: a WebTransport close capsule and FIN were followed by
  a RESET_STREAM that could discard the capsule, and a WT_DRAIN_SESSION that went out failed `drain()`; a WebTransport
  CONNECT answered then was reported as timed out and its session left open; an address-validation token taken from the
  `QuicTokenStore` was lost (the next connection needed a Retry); a request body read to its end for an HTTP/1.0 server
  failed the request; an HTTP/3 WebSocket whose CONNECT was answered threw `ConnectTimeoutException` and left the stream
  open; the HTTP/1.1 server answered a request head parsed at its deadline with 408, dropped a response its writer
  took off the queue at the idle timeout, and ended a reading client's connection when a flush returned as the send-stall
  deadline fired; an HTTP/2 health PING answered at its bound retired a healthy connection; a TLS handshake completed at
  its deadline failed as timed out; the other address family's answer at the end of the Resolution Delay (RFC 8305
  section 3) was taken off its queue and dropped.
- HTTP/3: a HEADERS frame read whole as its `maxHeaderBlockTime` fired failed its stream with `H3_REQUEST_CANCELLED`
  (the same `withTimeoutOrNull` race); the section is now kept once it was read.
- The same race at the end of a WebSocket: the server's end of the transport read as T2 fired was taken for T2. Over
  HTTP/3 a server's reset was then answered with a FIN instead of `RESET_STREAM` with `H3_REQUEST_CANCELLED` (RFC 9220
  section 3), over HTTP/2 a reset stream got `END_STREAM` and one more close wait, and over HTTP/1.1 with TLS the server's
  FIN was not read before the close. A data tick seen as the socket inactivity timeout fired no longer cuts the exchange,
  and the Ktor server no longer ends an HTTP/2 connection with GOAWAY for a client preface read as its deadline fired.
- A client WebSocket whose call failed or was cancelled before it sent its own Close ended without the closing handshake
  (RFC 6455 sections 7.1.7 and 7.3): cancelled at once, or, depending on timing, with the Close 1000 Ktor's session sends
  in answer to the cancellation; over HTTP/1.1 a frame not yet taken by the socket's writer (a loaded host) also made the
  connection reset. Such a session now sends one Close, 1001 Going Away (or the application's own code when it sends one,
  as from a `finally`), waits the close wait for the server's, and ends its transport in order; whole frames still queued
  go out before the FIN, and only a session the close wait cut is reset with data queued.
- HTTP/2: a request or response body whose peer opened its window as the send-stall bound fired failed as stalled.
- TLS: `KslDns.query` reported no answer for a lookup that answered as its timeout fired.
- Ktor server: request body bytes that arrived as the body deadline (HTTP/1.1) or the idle deadline (HTTP/2) fired failed
  the read with `RequestBodyTimeout` (408).
- Ktor client: what a request had as one of its deadlines fired was dropped: response data that arrived as the socket
  timeout fired (`SocketTimeoutException`), a proxy answer as the connect timeout fired (`ProxyException`), a Windows PAC
  answer, HTTPS records and the RFC 9460 section 9.5 upgrade decided from them (a secure source's request failed, a plain
  one was not upgraded), an HTTP/1.1 connection or stream obtained as the connect timeout fired
  (`ConnectTimeoutException`), a WebSocket's resolved addresses, an HTTP/3 connection made then (closed and failed), and
  on Android and Apple the DNS answers of the system resolver, the PAC evaluation, its host lookups, script runs and
  downloads. Each is now kept once it was had.
- QUIC: a connection whose loop was held up past its idle deadline (a GC pause, a stopped VM, a loaded host) was closed
  as idle even when the loop had already received its peer's packet, from before the deadline, and only not processed it
  yet. A timer wake-up later than a due deadline now lets the loop process the datagrams it already received first (RFC
  9000 section 10.1: the idle timer restarts when a packet is "received and processed"), as quic-go does with its queued
  packets. Datagrams still in the operating system's socket buffer are drained before an idle close (the entry below).
- QUIC: a process frozen past a connection's idle deadline (an Android app freeze or Doze, a sleeping laptop, a stopped
  debugger) closed the connection as idle on waking although its peer's packets waited in the socket's buffer, read only
  after the timer. Before an idle timer closes a connection the endpoint now drains its sockets without waiting (the
  accelerated socket's recvmsg or WSARecvMsg, the JVM's non-blocking channel, the shared socket's per-loop ring,
  ktor-network's channel on Native) and processes what they held; the connection closes only if none of it restarted the
  idle timer (RFC 9000 section 10.1). The connection's other timers wait for that too, and nothing is sent past the idle
  deadline, an application write included (`ConnectionCore.poll` sends nothing then, for sans-IO drivers too), so no
  packet sent after the deadline restarts the timer. A drain takes at most 64 datagrams per socket and a connection waits
  for it at most 500 ms, so a flood or junk from the peer cannot keep a connection open; on the accelerated socket the
  receive in flight ends with its native wait slice, so an idle close may come up to about 100 ms after the deadline. Not
  reached: what the kernel still holds for the in-process dispatcher of a shared socket (`loops > 1` on Darwin and
  Windows) or for ktor-network's own receiver on Native, what another loop's socket of a group holds, and a caller's own
  `DatagramIo`.
- QUIC: native memory was not freed on some error paths: the 1-RTT write key that arrived with a peer's missing
  transport parameters (RFC 9001 section 8.2), the TLS session of a connection whose construction failed (client and
  server, including a reset token that failed for its first connection ID), the first derived key of a key phase whose
  second derivation failed, and the TLS session of a server whose OCSP staple could not be set.
- QUIC: a server whose active path failed its validation could fall back to a validated path on the same local address, or
  answer a new client address there, with the client's current connection ID although the client's packets from that address
  never showed which ID of ours they carried (RFC 9000 section 9.5 allows the current ID only when the client used it from the
  new address); it now waits for a spare ID as it does when the client showed another one.
- QUIC: a server reverting to the last validated peer address after a failed path validation, or keeping a peer address
  validated on another of its addresses, took an address validated or heard from just now for one never seen when the other
  of the two times was unknown, and validated it again (RFC 9000 section 9.3 lets it skip that). A revert that ends a
  validation still under way on the path it goes back to no longer leaves that validation's PATH_CHALLENGE pending.
- HTTP/3: a loaded host closed connections to healthy peers with `H3_GENERAL_PROTOCOL_ERROR` ("control and QPACK
  streams not open after 3s"). The 3 s deadline meant for a peer that does not allow the three unidirectional streams
  HTTP/3 needs (RFC 9114 section 6.2) also covered opening and writing them, so a host that took that long to schedule the
  work (a loaded CI VM) gave up on its own connection. With three streams allowed the streams are now opened without a
  deadline; only a peer whose limit is lower still gets 3 s to raise it.
- QUIC key update (RFC 9001 section 6.4): "Packets with higher packet numbers MUST be protected with either the same or
  newer packet protection keys than packets with lower packet numbers", and a packet opened against that order "MUST" be
  a KEY_UPDATE_ERROR. The check compared a new phase only with the lowest packet number of the current one and let a
  packet of the current phase lower that number unchecked, so old keys on pn 20 and new ones on pn 15 (or, after our own
  update, old keys on 30 and new ones on 25) were accepted. Every packet number opened with a generation of keys is now
  checked against the highest one opened with older keys and the lowest and highest with newer ones, in both orders of
  arrival and across consecutive updates. An ACK frame in a packet protected with old keys that acknowledges one of our
  packets protected with newer keys is a KEY_UPDATE_ERROR as well (section 6.2's MAY).
- QUIC (RFC 9001 section 6): a TLS KeyUpdate message received in the 1-RTT CRYPTO stream is a connection error 0x010a
  whatever `QuicCrypto` provides the TLS stack; the transport checks the stream's handshake messages itself (ksl's
  OpenSSL already refused one). A `ksl` session in QUIC mode refuses `ksl_ssl_key_update` ("Endpoints MUST NOT send a
  TLS KeyUpdate message"); before, the C API would have written one.
- QUIC: a stream reset (by us, or in answer to STOP_SENDING) while it waited for flow credit was still reported blocked:
  the repeat timer and a lost STREAM_DATA_BLOCKED queued STREAM_DATA_BLOCKED for it again, against RFC 9000 section 3.1
  ("A sender MUST NOT send a STREAM or STREAM_DATA_BLOCKED frame for a stream in the "Reset Sent" state"), it stayed on
  the connection's blocked list so DATA_BLOCKED kept being repeated, and a later MAX_STREAM_DATA raised StreamWritable for
  it. A reset now drops the unsent bytes from what the stream waits to send; a stream reset with RESET_STREAM_AT whose
  reliable bytes were all sent no longer keeps DATA_BLOCKED repeating either, and `sendCredit` is 0 for a stream that
  takes no more writes (reset, or its FIN queued).
- QUIC: persistent congestion (RFC 9002 section 7.6.2: "none of the packets sent between the send times of these two
  packets are acknowledged") ignored acknowledged ACK-only packets between the two lost ones, as loss detection does not
  keep them; an acknowledged range now counts whatever it covers, so a path that delivered in between is not collapsed to
  the minimum window. Beyond the 32 acknowledged ranges (and 16 send times of other spaces) kept for the check, what is
  forgotten no longer counts as acknowledged: the check errs towards declaring persistent congestion, the one error the
  section accepts, instead of missing it.
- QUIC: a lost FIN took a sending stream from "Data Sent" back to "Send", a transition RFC 9000 section 3.1 does not
  have; the FIN is now sent again from "Data Sent".
- QUIC: a client checked no Stateless Reset during the handshake: the server's connection ID it sends its Handshake
  packets to was not counted as used until a short header packet went out, so the reset token of the server's transport
  parameters was ignored (RFC 9000 section 10.3.1: the tokens "associated with the connection IDs and remote addresses
  for datagrams it has recently sent"). A reset that arrives before a 0-RTT answer now ends the connection and drops
  what was held for the answer.
- HTTP/3: a GOAWAY or MAX_PUSH_ID frame whose Length is above 8 bytes (more than its one variable-length integer) closes
  the connection with H3_FRAME_ERROR from its header, as RFC 9114 section 7.1 requires; above 4096 bytes it was
  H3_EXCESSIVE_LOAD, and below that the reader waited for a payload that could only be malformed.
- HTTP/3: a `Capsule-Protocol` field whose parameters hold a Byte Sequence that is not valid base64 (`:Y:`, `:=YQ:`) is
  no longer read as `?1`: the byte sequence is checked as RFC 8941 section 4.2.7 says, with the same code as the
  `priority` field.
- WebTransport: a `WT-Available-Protocols` or `WT-Protocol` field whose parameters do not parse as RFC 8941 (a value
  such as `@@` or `:Y:`, a key with an uppercase or non-ASCII letter or starting with a digit) is ignored as a whole, as
  draft-ietf-webtrans-http3-16 section 3.3 asks; such parameters were skipped and the protocols read.
- JVM and Android: a TCP socket closed or aborted while its selector waited for nothing was not closed: the JDK keeps
  the descriptor of a channel still registered with a selector until that selector selects again, and an idle ktor
  selector never did. An aborted connection sent no reset (its peer waited for ever), a closed one kept its descriptor.
  The engines' sockets now have their selector run a selection after every close.
- WebTransport: a session's data credit is shared between its streams by the session's RFC 9218 priority
  (draft-ietf-webtrans-http3-16 section 3.4; section 5 sets no order), read again at every grant. A non-incremental
  session (`i=?0`) serves its streams in the order they were opened: while a stream waits for credit, or writes what it
  was just given, no stream opened after it gets any; a stream that asks more than there is gets what there is and keeps
  its place. Streams the application writes one after another then reach a peer that reads them one after another
  without a stall; the cost is that a stream that keeps writing holds the later ones. An incremental session (`i`,
  signalled with `priority: i`; without a signal a session is non-incremental, RFC 9218 section 4.2; each side chooses
  for its own sending) lets each grant start one stream further along the streams that ask, so none starves behind a
  busy one. In both, a stream with nothing to send, or cancelled
  or reset while it waits, keeps no credit and loses none, and opens waiting for the peer's stream limit are served in
  the order they asked. Before, waiting streams were served in no particular order, so a peer that read a session's
  streams strictly one after another under a tight limit could stall. Both roles, every session on its own; the weighted
  turns between sessions are unchanged. Credit for an open stream still comes back as the application takes its bytes
  (for a stream that ended cleanly, once all of it was handed to its input; for a reset or stopped one, by its final
  size); the guide, the configuration table and `Http3Settings` say when to read a peer's streams concurrently.
  `Http3Settings`'s KDoc no longer says the credit follows bytes taken from the transport.
- HTTP/3: a CONNECT (a tunnel, or an Extended CONNECT such as a WebTransport session) whose `Http3Request.priority`
  the caller set now always carries the `priority` field, RFC 9218's defaults included (`StreamPriority(3, incremental
  = false)` is sent as `i=?0`), so a server with a tunnel default of its own cannot override the caller's choice. An
  ordinary request at the defaults still sends no field.
- Ktor client: a WebSocket session over HTTP/1.1 that ends with something it wrote still queued in front of the socket
  after the close wait (a server that does not read), cut inside a frame, or with a failed writer, now has its connection
  reset (`SO_LINGER` 0, over TLS without close_notify), as documented. Before, the connection was closed gracefully: it
  went on sending what was queued for up to 3 s after the close wait and ended with a FIN, so a frame cut part-way read
  as a truncated frame followed by a clean end. A session whose stream is whole and was taken by the socket (its Close
  taken by the kernel and the server's never came, or cancelled while idle between frames) is closed cleanly instead: a
  FIN, and over TLS close_notify first (RFC 9846 section 6.1), where before the TLS session was dropped without one.
  HTTP/2 and HTTP/3 streams were already reset.
- Ktor client and server: a WebSocket session cut inside a frame (a large frame behind a peer that does not read, its
  writer cancelled) could still get a clean end after the part of the frame that went out, as if the stream were whole:
  Ktor's `WebSocketWriter` ends its channel with `flushAndClose()` also when it is cancelled, and that end counted as a
  finished writer. The frame guard now resets the transport in place of such a close (a TCP reset; over TLS the fatal
  alert internal_error where one can be sent, then a FIN, never close_notify; RST_STREAM CANCEL; RESET_STREAM
  H3_REQUEST_CANCELLED), counts a frame as started before its header (or a compressed frame's tail) is handed on, and
  every engine checks for a cut frame before a FIN, close_notify or END_STREAM (the clients that the guard is between
  frames); the HTTP/1.1 client's end decision takes only the guard's position for a whole stream. Seen in Docker as a server reading a 16 MiB frame cut after about 5 MB
  and then a clean end (HTTP/1.1 client). Over HTTP/3 the client now follows the HTTP/1.1 rule: a session its close wait
  cut with frames still queued in front of QUIC's send buffer is reset, as documented, where before a finished writer
  ended it with a FIN and the queued frames went on after the close wait; one whose writing was all handed to the
  transport keeps its FIN, and one its call cancelled between frames gets a FIN.
- WebSockets close their transport in RFC 6455's order (sections 5.5.1 and 7.1.1; RFC 8441 section 5, RFC 9220 section
  3), client and server, over HTTP/1.1, HTTP/2 and HTTP/3. The client engine no longer closes its side right after its
  own Close (Ktor's writer ends its channel then): it waits for the server's TCP FIN (close_notify first over TLS, which
  it answers then), END_STREAM or FIN, reading and dropping what still comes, and closes its side cleanly after it, or
  after the close wait (5 s) counted from both Closes; an HTTP/2 or HTTP/3 stream is reset (CANCEL,
  H3_REQUEST_CANCELLED) only another close wait later, and a peer's STOP_SENDING while the FIN is held is answered with
  RESET_STREAM.
- Ktor client, WebSockets over HTTP/1.1 and HTTP/3: a session that sent its Close to a server that never answers with its
  own no longer hangs. Ktor's session waited for that Close for good, and with it the call and `client.close()`; now, as
  over HTTP/2 already, the session is cancelled 5 s after its own Close (the close wait, RFC 6455 section 7.1.1: the client
  may close "if it has not received a TCP Close from the server in a reasonable time period") and the connection closed
  (HTTP/1.1) or the stream reset with H3_REQUEST_CANCELLED (HTTP/3). For a silent server `client.close()` waits at most
  three close waits (15 s) after the session's Close (docs/guide/ktor.md).
- Ktor server, WebSockets: the server closes first: an upgraded HTTP/1.1 connection closes as soon as the
  WebSocket ends (before, it stayed open until the client closed it), its FIN follows close_notify at once (before, it
  waited up to 3 s for the client's close_notify; this applies to every TLS connection the server engine closes,
  HTTP/1.1 and HTTP/2 alike: its FIN right after its close_notify, then at most 3 s for the client's close_notify or FIN
  before the socket closes, the write side first as RFC 9112 section 9.6 has it, and RFC 8446 section 6.1 allows not
  waiting for the peer's close_notify), and over HTTP/3 the client's direction is read to its FIN for up to 5
  s after the server's FIN, STOP_SENDING H3_NO_ERROR only after that (before, right after the server's FIN).
- QUIC, Kotlin/Native portable UDP socket: a refused bind (the port taken) returned while its selector's wakeup pipe was
  still open; ktor-network closes it from the selector's own loop, so a busy process held those descriptors for a while.
  The bind now waits for that loop to end before it fails.
- Ktor client, WebSockets: a session closed with `close(reason)` after `HttpClient.webSocketSession()` could end its
  connection without the Close frame (the server saw 1006, "closed without close frame"): Ktor's builder cancels the
  call as soon as the session queues its Close, and the session's writer, running under the call, was cancelled with it,
  often before it wrote that Close. The session now runs under a job of its own: a call that ends with a failure or a
  cancellation after the session's Close was queued leaves it, within 5 s counted from that Close (one deadline that
  also covers the server's Close and, over HTTP/2, its END_STREAM), to write that Close and the frames before it, over
  HTTP/1.1, HTTP/2 and HTTP/3 alike (RFC 6455 section 7.1.2). The connection, the HTTP/3 pool's count and the engine's
  `close()` wait for the session's end, not the call's, so `client.close()` right after `close(reason)` no longer cuts
  the Close off. The extensions' state (permessage-deflate) is freed with the session.
- HTTP/1.1 server: a GET that offers an upgrade (`Connection: Upgrade` with an `Upgrade` field, `h2c`, `websocket` or any
  other token) and whose handler read the request body before answering hung its connection for good: the body stayed
  open until the response head settled the upgrade. Such a request has no body (RFC 9112 section 6.3 item 7), so the
  body now ends at once whether or not the upgrade is taken, and the new protocol reads the connection from a separate
  input. Upgrades (WebSocket) are unchanged.
- HTTP/1.1 client and server: an empty `Connection` field, or one of only commas and whitespace, is a valid empty list
  (RFC 9110 section 5.6.1.2). The client failed the call with an IllegalArgumentException from Ktor's
  `ConnectionOptions.parse`, and the server answered 400. Connection options are now read over all field lines, with
  HTAB as whitespace (`keep-alive,<HTAB>close` closes) and empty elements ignored.
- HTTP/1.1 server: a 101 must name the new protocol in Upgrade and only one the request offered (RFC 9110 section 7.8).
  An application upgrade that breaks either is now answered 500 (logged as an error) instead of switching. Whether a
  101 is a WebSocket handshake (RFC 6455 checks and the frame guard) is decided by the protocol it switches to; before,
  a substring of the request's first Upgrade line decided, so a `websocket` offer on a second line skipped the checks.
- Client proxy from the environment (`http_proxy`, `https_proxy`, `all_proxy`): user info with a broken percent-escape
  failed with Ktor's URLDecodeException, whose message quoted the password; a URL whose user info held `://` was
  refused with a message that quoted it as a scheme; and user info that lost its `@` became the proxy's host, shown in
  its text. All three now fail without repeating any of the URL (an unsupported scheme is no longer named either: a
  user name before `://` reads as one): a scheme is one only when it is RFC 3986's, the authority ends at `/`, `?` or
  `#`, and the host must be an IP literal or a plain name.
- QUIC, Stateless Reset (RFC 9000 section 10.3.1): a client ignored a valid reset for the server's handshake-time
  connection ID when the server had issued no other ID (that ID counted as used only once a NEW_CONNECTION_ID arrived), and
  waited for its idle timeout; a datagram routed to a connection by one of our own IDs was compared with every used token
  whatever its source, while a token now counts only for a datagram from a remote address its ID was used towards; and the
  server's preferred-address socket dropped datagrams of unknown IDs before comparing them with the tokens of the
  connections there, so a connection that had moved never recognised its client's reset
  (`StatelessResetTest.negative_resetForTheHandshakeIdEndsAClientThatGotNoOtherId`,
  `.negative_resetFromAnAddressTheIdWasNeverUsedTowardsIsIgnored`, `.negative_aResetToThePreferredAddressIsRecognised`).
- QUIC: a switch to a validated path on another local address — `ConnectionCore.switchPath`, `QuicConnection.migrate`, or
  the fallback after the active path failed validation — kept the connection ID used from the old address when no unused
  one was left, against RFC 9000 section 9.5 ("MUST NOT reuse a connection ID when sending from more than one local
  address"). A client's validated path now keeps the ID it probed with until it is closed or fails, and
  `ConnectionCore.switchPath` and `QuicPath.switchTo` throw `IllegalStateException` while no unused ID is left for the path;
  `QuicConnection.migrate` then closes the validated path and the new socket, as after a failed validation. The fallback
  after a failed validation (RFC 9000 section 9.3.2) chooses, without reserving IDs for the paths it passes over, the most
  recently validated path it may send on; when there is none, a server goes back to the last validated peer address from
  the failed path's own local address — to the path already there, one path per local and peer address, a path under
  validation giving way when all four are taken, the address validated again when it was not heard from recently — with
  the current ID only where the client used ours from that address, else a spare one, else sending nothing until the
  client provides one (a NEW_CONNECTION_ID, a Retire Prior To that leaves an unused ID current, or the client's packets
  from that address with the ID of ours it used on the path left end the wait, and a re-validation starts only then); it closes only without
  a validated peer address — a previous path being validated again after a migration (section 9.3.3) counts as one
  (`PathTest.negative_aNewPathFailingWhileThePreviousIsValidatedAgainRevertsToIt`), a path on the preferred-address socket is
  no fallback before the server moved there (section 9.6.2;
  `.negative_theFallbackNeverMovesToThePreferredAddressBeforeTheClientDid`), and an active path whose own peer address the
  client validated on another path stays active (sections 9.3, 9.3.2;
  `.negative_anAddressValidatedThroughThePreferredSocketKeepsTheConnectionOnTheOriginalAddress`) when it was seen within a
  validation period, else after validating it again, once per staleness (section 9.3 "seen recently";
  `.negative_anAddressValidatedLongAgoOnThePreferredSocketIsValidatedAgain`,
  `.negative_aSuccessfulRevalidationOfAStaleAddressAllowsTheNextOne`)
  (`PathTest.negative_aSwitchToAnotherSocketNeverTakesTheIdOfTheOldOne`,
  `.negative_theFallbackChoiceReservesNoIdForThePathsItPasses`,
  `.negative_aFailedValidationRevertsToTheLastValidatedPeerAddressFromItsOwnLocalAddress`,
  `.negative_aRevertOnTheSameLocalAddressKeepsOnePathPerPeerAddress`, `.negative_aRevertWithEveryPathSlotTakenDoesNotClose`,
  `.negative_aRevertedPathWaitingForAnIdSendsNothingUntilOneArrives`,
  `SocketLostTest.negative_aSwitchRefusedAfterTheProbeClosesThePathAndTheSocket`).
- QUIC: a client's path to the server's preferred address, also when probed again from an application's new socket, and a
  server's handshake-time candidate path kept the portable socket capabilities: after moving to the preferred address the
  client ran no DPLPMTUD (it stayed at 1200-byte datagrams) and no ECN (RFC 9000 sections 13.4.2, 14.2); a server's path on
  its preferred-address socket copied the main socket's capabilities, DF and ECN included, whatever that socket can do.
  Every path now gets the capabilities of its own socket, kept per socket (and per address family for the preferred-address
  sockets) by the core; a closed migration socket's are forgotten
  (`PreferredAddressTest.negative_thePreferredPathGetsTheSocketsDplpmtudAndEcn`,
  `.negative_thePreferredPathFromAMigrationGetsItsSocketsDplpmtudAndEcn`,
  `.negative_aServerPathOnThePreferredSocketGetsThatSocketsCapabilities`,
  `.negative_eachPreferredSocketFamilyKeepsItsOwnCapabilities`, `PathTest.negative_aClosedClientSocketIsForgotten`).
- QUIC client: the move to the server's preferred address could keep the ID the connection used toward the original
  address, so one ID went to both (RFC 9000 section 9.5 "MUST NOT reuse a connection ID when sending to more than one
  destination address"): when the server's Retire Prior To retired the ID the preferred path probed with before the
  validation finished, the switch took the ID in use toward the original address. The client now moves only with an ID
  never used toward the original address and, with none, moves once the server's next ID arrives; the same holds when
  the application's active path takes the preferred address its new socket probed (section 9.6.3) (found by the connection fuzzer over TLS with a compatible version;
  `PreferredAddressTest.negative_theMoveToThePreferredAddressNeverTakesTheIdUsedTowardTheOriginalOne`,
  `.negative_theCarriedPreferredProbeNeverMovesTheActivePathWithTheIdUsedTowardTheOriginalAddress`).
- QUIC: a connection that started closing or draining kept the PATH_RESPONSEs it still owed, up to 1024 of them, until it
  was gone, although a closing endpoint sends only CONNECTION_CLOSE and a draining one nothing (RFC 9000 sections 10.2.1,
  10.2.2). They are dropped when the connection starts closing or draining
  (`PathTest.negative_owedPathResponsesGoWhenTheConnectionCloses`).
- QUIC runtime: a STOP_SENDING watcher (`awaitSendStopped`, internal API) waited forever once its stream could no longer
  be stopped. It now ends with the connection's `ConnectionLost` when the connection ended, with
  `StreamError.EarlyDataRejected` when a rejected 0-RTT dropped the stream (RFC 9001 section 4.6.2: the client resets
  "application state bound to those streams"), and returns null once both halves are done without one; HTTP/3's
  watchers of its critical streams, which stayed suspended for the rest of a connection whose 0-RTT was rejected, end
  quietly. Found by the 0-RTT runtime invariant test; pinned by `SendStoppedTest` and
  `ZeroRttApiTest.negative_sendStoppedWatcherOfARejectedStreamEnds`.
- QUIC client, 0-RTT and Version Negotiation: after a Version Negotiation answered a first flight that carried 0-RTT,
  the new attempt numbers its packets from 0 again (RFC 9368 section 2.1, "a new first flight") while the client still
  took the abandoned 0-RTT packets' numbers for its 0-RTT; the server's acknowledgment of the new attempt's first 1-RTT
  packets then counted as an acknowledgment of rejected 0-RTT and the client closed with PROTOCOL_VIOLATION (RFC 9001
  section 4.6.2 means "an acknowledgment for a 0-RTT packet"). Found by the 0-RTT connection fuzzer; pinned by
  `ZeroRttTest.negative_versionNegotiationAfterZeroRttKeepsTheConnection`.
- QUIC: `QuicStream.reset` after all of a stream's data and its FIN were acknowledged no longer sends a RESET_STREAM.
  RFC 9000 section 3.1 lets a sender abandon a stream only from the "Ready", "Send" or "Data Sent" states; in "Data
  Recvd" there is nothing left to abandon, as `resetAt` already treated it.
- HTTP/3 Capsule Protocol: a collector of `CapsuleStream.capsules` cancelled while it waited could lose the capsule
  being handed to it (a coroutine channel's receive drops an element taken by a receiver cancelled before it resumes),
  and one cancelled while it handled a capsule lost the next one. Capsules now wait in a queue they leave only when a
  running collector is about to get them: the next collector gets them, in order. What a wrapper around the collection
  (`withTimeout`, `async`) does with a capsule already delivered stays the wrapper's: collect in one long-lived coroutine
  rather than polling `first()` under a timeout, and directly: operators that collect ahead in another coroutine
  (`buffer`, `flowOn`, `conflate`, `produceIn`, `shareIn`, `stateIn`, and `collectLatest` by design) lose the capsules
  they took and had not delivered when the collection is cancelled.
- HTTP/3 server: `Http3Connection.acceptRequest` cancelled while it waited could lose the request being handed to it,
  which was then never answered and kept counting as open (a graceful shutdown waited for it). The next call now
  returns it. A request returned to a `withTimeout` or `async` that was cancelled meanwhile is still dropped by that
  wrapper (kotlinx.coroutines behaviour): accept in a long-lived loop rather than polling under a timeout.
- WebTransport: `acceptBidi` and `acceptUni` cancelled while they waited, or while they set the stream up, lost it; the
  peer's stream stayed open and unread, holding its data and stream credit until the session ended. The stream now goes
  back to the head of the queue for the next accept (the same caveat about wrappers as for `acceptRequest`).
- HTTP/2 (RFC 9113 section 5.4.2, "A RST_STREAM is the last frame that an endpoint can send on a stream"): when the
  peer sent DATA on a stream that had ended both ways while our last HEADERS or DATA were still queued, our RST_STREAM
  went out first and the queued frames followed it. They are now dropped with the reset (their DATA gives the connection
  window back). Found by the `http2.connectionServer` and `http2.connectionClient` fuzz targets.
- HTTP/2 client (RFC 9113 section 5.1): frames on a request whose HEADERS were still queued (a stream idle to the
  server) were accepted, so a server could answer, credit or reset a request it had never seen, and the request went out
  afterwards. Every such frame but PRIORITY is now a connection error PROTOCOL_ERROR, also on a request dropped before
  it went out while no later one did (section 5.1.1); unknown frame types and ALTSVC stay ignored there.
- QUIC: a stream that ended with our RESET_STREAM is reported finished (`ConnectionEvent.StreamFinished`, and the HTTP/3
  graceful close that waits for it) once the RESET_STREAM is acknowledged, RFC 9000 section 3.1 "Reset Recvd", not when
  it is sent (also for RESET_STREAM_AT). The stream is retired at once as before, and the runtime lets go of its channels
  then; a peer stream's credit returns at the acknowledgment, so a peer that leaves our resets unacknowledged cannot open
  more such streams than its limit. A server's graceful close no longer overtakes the reset of a request its application
  abandoned.

- HTTP/3 client: a request waiting for stream credit when the server's GOAWAY arrived was sent on the stream it got
  next, against RFC 9114 section 5.2 ("Endpoints MUST NOT initiate new requests ... after receipt of a GOAWAY frame"),
  or failed with the client's own close of the idle connection; it now fails with `Http3Exception.RequestNotProcessed`
  (never sent, safe to retry) without opening a stream, and so does one waiting when the client sent its own GOAWAY. HTTP/3 server: a request
  stream the client reset before its HEADERS stayed open in the server's direction; it is reset with
  H3_REQUEST_REJECTED.

- TLS over TCP: a server whose first flight is larger than about 17 KiB (a long certificate chain, a large stapled OCSP
  response) stalled until the handshake deadline: OpenSSL stops writing when ksl's BIO pair is full, and the handshake
  loop then waited for the peer instead of sending the rest. It now drives again after each drain that sent something.
- Ktor client: a request made right after a pooled HTTP/3 connection's QUIC transport ended (an idle timeout, a lost
  network, a close) no longer goes to that dead connection in the moment before its HTTP/3 session takes note of the
  end, nor when the transport ends between the connection's lookup and the moment the request is counted on it; it
  opens a new HTTP/3 connection instead of failing there and falling back to TCP. Found as the intermittent failure of
  `ClientMigrationTest.negative_noMigrationWithoutConfig`; pinned by
  `ClientPoolTest.negative_connectionWhoseTransportEndedIsNotReused` and
  `.negative_connectionWhoseTransportEndsBeforeItIsCountedIsNotUsed`.
- Ktor client: an HTTP/3 connection whose server sent GOAWAY no longer counts as one that can carry a WebSocket's
  Extended CONNECT (RFC 9114 section 5.2: no new requests on it; RFC 9220), so with `Preferred` a WebSocket is no longer
  sent to HTTP/3 on its strength (`ClientH3WebSocketTest.negative_goAwayConnectionDoesNotCountForExtendedConnect`).
- Ktor client engine: over HTTP/2 a response body that a request timeout or the caller's exception cut short failed
  with the stream's own `CancellationException` ("the call ended") instead of the call's cause
  (`HttpRequestTimeoutException`), as HTTP/1.1 and HTTP/3 already reported it. Found by the engine interop bench.
- Ktor server engine: over HTTP/1.1 the connection point's addresses came from a reverse DNS lookup made for every
  accepted connection on the JVM and Android (`remoteAddress` and `remoteHost` read `localhost` for 127.0.0.1); they
  are now the IP literals, as over HTTP/2 and HTTP/3, and no lookup is made. `remoteAddress` and `localAddress` are the
  literals in Ktor's Netty and CIO engines too; their `remoteHost` and `localHost` are names (a reverse lookup on
  first use), ours stay literals on every protocol, by decision. Found by the engine interop bench.
- Ktor server engine: over HTTP/1.1 on the JVM and Android the connection point wrote an IPv6 address as java.net
  does, `0:0:0:0:0:0:0:1`; it is now the RFC 5952 text (`::1`), as over HTTP/3. The deprecated `host` was a reverse DNS
  lookup of the local address there; it and the deprecated `port` are now `serverHost` and `serverPort`, as over HTTP/3,
  and `host` names its replacements as Ktor does ("Use localHost or serverHost instead"). The deprecated `port` thereby
  differs on purpose from Ktor's Netty and CIO engines, where it is the local port: one meaning on every protocol here.
  Without a Host field (HTTP/1.1) or `:authority` (HTTP/3), `serverHost` is the local address as a Host field writes it,
  an IPv6 literal in brackets and without its zone ID (`[::1]`, `[fe80::1]`: the `IP-literal` of RFC 3986 section 3.2.2,
  RFC 9110 section 7.2 `uri-host`, which has no zone since RFC 9844); it was the bare literal (a name over HTTP/1.1).
- HTTP/3, Ktor server engine: the connection point's addresses never call a resolver; on Kotlin/Native each one called
  `getaddrinfo`. An IPv6 zone ID is kept (`fe80::1%en0`, as java.net and Netty write it; it was dropped), and an
  address with an embedded IPv4 address under a well-known prefix is written in mixed notation on every platform (RFC
  5952 section 5: IPv4-mapped `::ffff:192.0.2.1`, IPv4-translated `::ffff:0:192.0.2.1`, IPv4-compatible `::192.0.2.1`);
  it was hexadecimal.
- Testing (`kuicksilver-testing`, not published): `MemoryNetwork` named an ephemeral-port socket after a reverse DNS
  lookup of its host on the JVM and Android (a lookup per bind; `localAddress` carried the name), and
  `Simulator.rebindClient` did the same to the client's address; both keep the literal now. Both compare addresses by
  their bytes, so two spellings of one IPv6 address (`::1`, `0:0:0:0:0:0:0:1`) are one address on Kotlin/Native too.
  Found when CI runners whose resolver names private addresses failed three tests.
- Ktor server engine: a graceful stop took 3 s longer while an HTTP/1.1 client over TLS kept its connection in a pool,
  reading nothing until its next request (OkHttp, the JDK's HttpClient), idle or just answered: after its own
  close_notify the server waited up to 3 s for the client's. A stopping server now closes without waiting for it (RFC
  8446 section 6.1 lets a closing side close its read side without the peer's close_notify). Found by the engine
  interop bench.
- TLS: `ksl_ctx_verify_chain`, which re-verifies a client's cached chain before it resumes (ADR-0011), now applies
  OpenSSL's security level as a handshake does; before, the re-verification was weaker than the handshake it stands for
  (a client's cached chains come from handshakes at the same level under the same trust, so no weaker chain could resume
  in practice). The client CA recheck of a server relies on it.
- TLS: a TCP server takes its identity (and client CA bundle) when the client's ClientHello arrives, not when the
  connection is accepted. Before, a connection accepted before a `TlsIdentity.Reloadable.reload` whose ClientHello came
  later (an HTTP server waits up to its request header timeout) was served the replaced certificate and key. The wait
  for the ClientHello counts toward `handshakeTimeout`.
- TLS: a TCP server that negotiated TLS 1.2 failed every resumed handshake (and every accepted handshake with pinned
  client certificates) with "ticket request failed": the explicit ticket request after the handshake is TLS 1.3 only. TLS 1.2
  keeps the ticket OpenSSL sends in the handshake.
- QUIC, CUBIC: HyStart++ ran in every slow start, the one after persistent congestion included, with the round state of the
  initial slow start; a rising RTT there entered Conservative Slow Start and could end slow start far below the ssthresh the
  loss had set (RFC 9406 section 4.3: "SHOULD use HyStart++ only for the initial slow start"). It now runs only while
  ssthresh is unset, and its exit sets cwnd_prior (RFC 9438 section 4.10).
- QUIC, BBR: the window grew on ACKs that came while the sender was application-limited (draft-ietf-ccwg-bbr-06 SetCwnd
  adds every ACK's delivered bytes). It now grows only on ACKs of a sender that used its window, as for NewReno and CUBIC
  (RFC 9002 section 7.8).
- QUIC: the NewReno and CUBIC pacing rate overflowed above a window of about 7.4 GB, and the pacer then held the next
  datagram for hours; the rate now saturates.
- QUIC: at the AEAD confidentiality limit with no key update possible, the CONNECTION_CLOSE and its repetitions were sealed
  with the exhausted key (RFC 9001 section 6.6: "MUST stop using those keys"). The connection now closes with
  AEAD_LIMIT_REACHED while 16 packets are left under the key, and nothing is sealed with it past the limit.
- QUIC: a Stateless Reset was looked for only among connections whose active path leads to the datagram's source; one from
  the server's preferred address under validation, or from an old address being revalidated, was dropped and the
  connection waited for its timeout (RFC 9000 section 10.3.1). Every path's peer address is a candidate now.
- QUIC: `QuicStream.priority` set from several threads at once could leave the scheduler on an older value than the
  property read, since each setter handed its own value to the loop and those hand-overs could run in another order.
  The loop now applies the property's current value.
- HTTP/2 PRIORITY_UPDATE (RFC 9218 section 7.1): a server now reads the frame with every check of section 7.1 (stream
  0 only, no prioritized stream 0, no push stream, idle prioritized streams plus active ones within our
  SETTINGS_MAX_CONCURRENT_STREAMS, each a PROTOCOL_ERROR connection error) and keeps the latest one for a stream not
  open yet (section 7); the Ktor server's `call.request.priorityUpdates` follows them over HTTP/2 and the response is
  rescheduled unless it set its own `Priority` field. The Ktor client's `HttpResponse.updatePriority` sends the frame
  over HTTP/2 (true) unless the server's SETTINGS left SETTINGS_NO_RFC7540_PRIORITIES at 0 (section 2.1.1). A client
  that receives the frame ends the connection with PROTOCOL_ERROR, as section 7.1 requires; before, both roles ignored
  it as an unknown frame type. A Priority Field Value above 4096 bytes is ENHANCE_YOUR_CALM (HTTP/3's ceiling for a
  control frame), and a change of the peer's SETTINGS_NO_RFC7540_PRIORITIES after its first SETTINGS is PROTOCOL_ERROR
  (section 2.1 allows it). Before the server's SETTINGS, and while it leaves the setting at 0, `updatePriority` also
  sends an RFC 7540 PRIORITY frame, and the request's own DATA always follows the new priority.
- HTTP/2 client (RFC 9218 section 2.1.1: "until the client receives the SETTINGS frame from the server, the client
  SHOULD send both the HTTP/2 priority signals and the signals of this prioritization scheme"): the client no longer
  sends SETTINGS_NO_RFC7540_PRIORITIES = 1, and its request HEADERS carry an RFC 7540 signal (dependency 0, not
  exclusive, weight 256, 220, 183, 147, 110, 74, 37 or 1 for urgency 0 to 7, Chromium's mapping) next to the `priority`
  field until the server's SETTINGS say SETTINGS_NO_RFC7540_PRIORITIES = 1. The request's own DATA is scheduled by its
  priority too.
- HTTP/2 (RFC 9218 section 10): the connection sent the DATA of its streams round-robin, whatever their priority, so a
  u=0 response got no precedence over a u=7 one and two default responses were interleaved instead of sent in stream
  order. DATA now goes by priority as on HTTP/3: urgency first, non-incremental streams of one urgency in ascending
  stream order, incremental ones sharing, the two kinds taking turns, and a CONNECT getting one frame in 16 whatever its
  urgency (section 10.1). When a more urgent stream's writer is about to hand over its next frame, the others wait for
  it for at most 2 ms. The Ktor server feeds it the request's `Priority` field merged with the response's (section 8,
  `call.response.priority`); a field that fails to parse is ignored.
- HTTP/2: a HEADERS frame (opening a stream, or on an open one, as trailers) or a PRIORITY frame whose stream depended
  on itself was reset with PROTOCOL_ERROR even after the peer sent SETTINGS_NO_RFC7540_PRIORITIES = 1, when RFC 9218
  section 2.1 says such a server "MUST ignore HTTP/2 priority signals". The RFC 7540 self-dependency check now applies
  only to peers that did not send the setting, in all three places.
- HTTP/2 (RFC 9113 section 6.5.3, "MUST immediately emit"): the acknowledgement of a SETTINGS that shrank
  SETTINGS_INITIAL_WINDOW_SIZE waited behind the DATA already taken from the larger window, which went in priority
  order: it waited as long as more urgent streams, or an earlier non-incremental stream of the same urgency, kept
  sending (with several busy streams it was never sent, and a peer with a SETTINGS timeout ended the connection), and
  later SETTINGS waited behind it. Every acknowledgement now goes at once; DATA queued but not written gives its stream
  window back (a SETTINGS does not touch the connection window) and is charged again against the new window when it goes
  (RFC 9113 section 6.9.2), in parts when less is available. While it waits for a window it holds no connection window,
  which the other streams use meanwhile. A WINDOW_UPDATE that takes a window above 2^31 - 1 counting DATA charged but
  not written is now a FLOW_CONTROL_ERROR too, as is such a SETTINGS_INITIAL_WINDOW_SIZE.
- HTTP/2 (RFC 9113 section 6.9.2): a stream we had finished sending on (half-closed (local)) was reset with
  FLOW_CONTROL_ERROR when the peer, after lowering SETTINGS_INITIAL_WINDOW_SIZE, credited it up to 2^31 - 1 by its own
  count, as nghttp2 may: such a stream has no active window, so the SETTINGS change skipped it while its WINDOW_UPDATEs
  still counted. They are now ignored, and the response still arriving on it is no longer cut.
- HTTP/2 (RFC 7541 section 6.3, RFC 9113 section 4.3.1): a larger SETTINGS_HEADER_TABLE_SIZE from the peer was used
  by our HPACK encoder before our acknowledgement of it was written when that acknowledgement waited behind DATA, so a
  field block sent in between could start with a table size update above the peer's acknowledged limit (a
  COMPRESSION_ERROR at the peer). The value now applies with the acknowledgement, which goes first. A SETTINGS frame
  carrying several values is signalled with its smallest and then its last value (RFC 7541 section 4.2), as nghttp2
  requires. Client and server alike.
- HTTP/3 client: `Http3Request.priority` now replaces a `priority` field among the request's headers. The header went
  out while the explicit priority scheduled the stream, so the server and the client used different priorities.
- HTTP/3 (RFC 8941 section 4.2): a `priority` field that fails to parse now counts as absent wherever its presence
  mattered. A CONNECT carrying one was not scheduled as a tunnel (on either side), and a server response carrying one
  stopped the client's later PRIORITY_UPDATEs from rescheduling it, as if the server had chosen a priority.
- HTTP/3 server: a PRIORITY_UPDATE whose payload was longer than 256 bytes was dropped before any check, so one naming
  a non-request stream or a stream beyond our limit did not close the connection with H3_ID_ERROR (RFC 9218 section
  7.2: "MUST be treated as a connection error of type H3_ID_ERROR"), and a valid long one (extension parameters) was
  lost. Every PRIORITY_UPDATE within the 4096-byte ceiling of control frames is now checked and applied.
- Ktor client: `Alt-Svc: clear, h3=":443"` (or `clear` in any list element, as when an intermediary folds two field lines)
  stored the alternative; RFC 7838 section 3: a value "containing the special value "clear"" invalidates all alternatives
  of the origin, "including those specified in the same response". Any element that is exactly `clear` clears now.
- Ktor client: an alt-authority port with a sign (`h3=":+443"`) was taken as 443; RFC 3986's `port = *DIGIT` (RFC 7838
  section 3) makes it malformed, and only digits are taken now, in headers and in stored records.
- Ktor client: `FileAltSvcStore` checked only the port range and the expiry of the records it loads, so a file written by
  an older version, edited by hand or by another program could bring in what the header path refuses (a local
  destination, a host that is no connection target, text for the diagnostics log line). Every field is checked again on
  load (origin form, protocol token, host and protocol of at most 255 characters, ports, expiry, persist flag), at most
  the first 8 MiB of a file are read (a full store takes less), and the engine
  checks every entry it is about to use as it checks a header's, whatever the store.
- Docs: the Alt-Svc rules said a 421 removes the origin's alternatives (a 421 from the origin changes nothing; one from
  the alternative removes that alternative only), the threat model cited a test that does not exist
  (`status421RemovesEntry`), the RFC 7838 cache-bounds row cited section 9.4 (now a row of its own), and the server's
  `Alt-Svc` was described as HTTP/1.1 only.
- HTTP/3 client: `Http3Response.cancel(code)` and a client `Http3Stream`'s `reset`/`stopSending` sent H3_REQUEST_REJECTED
  when the application passed it, a code clients MUST NOT use (RFC 9114 section 4.1.1: it tells that the server did not
  process the request). It now goes out as H3_REQUEST_CANCELLED.
- HTTP/3 client over 0-RTT (RFC 9114 section 7.2.4.2): the client now stores the server's SETTINGS with its session
  tickets ("Clients SHOULD store the settings") and complies with them in 0-RTT until the new connection's SETTINGS
  arrive (a stored SETTINGS_MAX_FIELD_SECTION_SIZE bounds the early requests). When the server accepted 0-RTT and then
  sends SETTINGS that lower a stored value, change a non-zero SETTINGS_QPACK_MAX_TABLE_CAPACITY or omit a value stored
  as non-default, the connection ends with H3_SETTINGS_ERROR. Before, the client stored nothing and used the defaults.
  A ticket whose `remembered` bytes the application replaced with its own is left as it is.
- HTTP/3 server: a response abandoned because a response field or its trailers were refused (or its head could not be
  written) was reset with H3_INTERNAL_ERROR; RFC 9114 section 4.1.1 says a server that abandons a response after partial
  processing SHOULD use H3_REQUEST_CANCELLED, which it now does, as for a failed body.
- HTTP/3 client: a response with a field value longer than the decoder takes was reset with H3_EXCESSIVE_LOAD, and one
  whose string length did not fit a 62-bit integer ended the whole connection; RFC 9204 section 7.4 makes "a value
  larger than it is able to decode" a stream error of type QPACK_DECOMPRESSION_FAILED. Both are now that stream error.
  A server still answers such a request with 431 (RFC 9114 section 4.2.2), and now stops it with
  QPACK_DECOMPRESSION_FAILED instead of H3_EXCESSIVE_LOAD.
- HTTP/3 with the QPACK dynamic table: a field section that waited for inserts had been read off its stream whole first,
  so its bytes left the flow-control window and the peer got the credit back (RFC 9204 section 2.2.1: SHOULD remain in
  the window). With blocked streams allowed, request streams are now read without read-ahead and a section's prefix
  first; a section that needs inserts waits there, its other bytes left in the transport.
- HTTP/3 with the QPACK dynamic table (`qpack { enableDynamicTable() }`): the encoder wrote insert instructions whatever the
  encoder stream's flow-control credit, under its lock (RFC 9204 section 2.1.3: SHOULD NOT), so a peer that granted
  the stream no credit could leave every field section waiting behind instructions it would not take. An insert is now
  made only when the encoder stream has the credit for the whole instruction; the field goes as a literal otherwise.
- HTTP/3 client: `Http3Connection.request()` with a `protocol` (Extended CONNECT) sent `:protocol` without waiting for
  the server's SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220 section 3, RFC 8441 section 4), although its documentation
  promised that a request the server must refuse fails locally. It now waits for the server's SETTINGS and throws
  IllegalArgumentException unless they enable Extended CONNECT; `connect()` behaves as before.
- HTTP/3: a response `content-length` was not checked before it went out (`respond(200, content-length: abc)` or two
  conflicting values passed, and our own client then took the response for malformed), and neither a response nor a
  request body was held to its `content-length`. A malformed value now fails `respond` with IllegalArgumentException,
  and content that does not match the declared length (more, or less at the end) is never sent as a complete message:
  the stream is reset with H3_REQUEST_CANCELLED (RFC 9114 sections 4.1.1, 4.1.2) and the writer or the request fails
  with an IOException. HTTP/2 already did this for responses. A request without a body (or with trailers only) and a
  non-zero `content-length` fails with IllegalArgumentException before a stream is opened.
- HTTP/3: a 204 from the Ktor server engine went out with the content's Content-Length, and Ktor's `Content-Length: 0`
  went out on a 304 (RFC 9110 section 8.6); the engine now drops both, as over HTTP/1.1 and HTTP/2, and drops it from the
  2xx of a WebSocket CONNECT. `Http3ServerRequest.sendInformational`, `respond` and `acceptConnect` refuse
  `content-length` on a 1xx, a 204 and a 2xx to CONNECT (section 9.3.6) with IllegalArgumentException.
- Ktor server over HTTP/3: a request with `Expect: 100-continue` never got its interim 100 (RFC 9110 section 10.1.1:
  MUST), so a client that held its content until then waited for its own timeout (curl: 1 s), or for good. As over
  HTTP/1.1 and HTTP/2, the 100 now goes out as the call is dispatched, and another expectation is answered 417.
- HTTP/3: a HEADERS frame after the trailers whose declared length was above the field section cap was a stream error
  (H3_EXCESSIVE_LOAD: a 431 on the server, `FieldSectionTooLarge` on the client) instead of the connection error
  H3_FRAME_UNEXPECTED that RFC 9114 section 4.1 requires for any frame after the trailers. A smaller one already was.
- HTTP/2 and HTTP/3 servers: a request whose `:scheme` was no URI scheme (`ht tp`, `1http`, `http:`) was accepted;
  only control characters were refused. `:scheme` is the scheme portion of the target URI (RFC 9113 section 8.3.1,
  RFC 9114 section 4.3.1), so a value outside RFC 3986 section 3.1's syntax now makes the request malformed. The shared
  field vectors carry the cases.
- HTTP/2 client (internal `H2ClientConnection.open`): a request with `:protocol` (Extended CONNECT) went out whether or
  not the server had sent SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 (RFC 8441 section 4). It now fails locally with
  IllegalArgumentException until the server enabled it. The Ktor engine never sends `:protocol` over HTTP/2.
- HTTP/2 client: requests whose HEADERS were still queued when the server's GOAWAY arrived were written afterwards
  when their stream ID was not above the GOAWAY's last stream (a graceful GOAWAY names 2^31 - 1), opening streams after
  the GOAWAY (RFC 9113 section 6.8: MUST NOT). They are now dropped unwritten and fail as not processed, so the engine
  sends them on another connection.
- HTTP/2: an invalid connection preface whose first frame the decoder refused (an HTTP/1.1 answer, whose "HTT" reads
  as a frame length above the limit, or a PING of 7 bytes) ended the connection with FRAME_SIZE_ERROR; RFC 9113 section
  3.4 makes any invalid preface a PROTOCOL_ERROR. Only a malformed SETTINGS frame keeps FRAME_SIZE_ERROR (section 6.5).
- HTTP/2 server: response heads and trailers were never checked before they were sent, and HPACK wrote a character
  above U+00FF as its low byte: a value with U+010D, U+010A or U+0100 (`call.response.header("X-Name", "č")`) went out
  with a CR, LF or NUL inside, a name with DEL or a byte above 0x7F passed, and `HttpStatusCode(42, …)` went out as
  `:status 42` (RFC 9113 sections 8.2.1, 8.3.2). Such a section is now refused: the stream is reset with INTERNAL_ERROR
  and the call fails with IllegalArgumentException; connection-specific fields, `te` and 101 are refused the same way.
  HPACK and QPACK refuse a character above U+00FF instead of truncating it.
- HTTP/2 server: trailers that arrived on a stream whose handler had already answered and released it (its response
  still being written to a client that does not read) were taken for a new request: a field section with request
  pseudo-header fields started a handler, outside `maxConcurrentStreams` (RFC 9113 sections 8.1, 5.1.2). Only the field
  section that opens a stream is a request now; such trailers are dropped.
- Ktor server, WebSockets over HTTP/3 (RFC 9220): a call cancelled while its upgrade ran skipped the end of the CONNECT
  stream: the flush of our side threw the cancellation before the client's direction was stopped, so that direction
  stayed open and the exchange counted as running until the connection ended. A cancelled call now aborts both
  directions with `H3_REQUEST_CANCELLED`, STOP_SENDING first and then RESET_STREAM (RFC 9220 section 3: "RST exceptions
  are represented with a stream error ... of type H3_REQUEST_CANCELLED"; RFC 9114 section 4.1.1), instead of ending the
  stream with a FIN; an orderly end still stops an unread client direction with `H3_NO_ERROR`.
- HTTP/3: trailers could be sent on an established CONNECT tunnel, by a server through `finish(trailers)` after a 2xx to
  CONNECT and by a client through `request()` with a CONNECT and `trailers`; RFC 9114 section 4.4 allows only DATA once
  the CONNECT completed, and the peer closed the whole connection with `H3_FRAME_UNEXPECTED`. `finish(trailers)` on a
  tunnel now throws IllegalArgumentException before anything is sent (`finish()` still ends it), and a CONNECT with
  `trailers` is refused before a stream is opened.
- HTTP/3: `:protocol` was neither checked as a token nor matched in one way: an empty or non-token value went out from
  the client and was accepted by the server (RFC 8441 section 4: a name from the HTTP Upgrade Token Registry), and
  `WebSocket` or `WebTransport-H3` were refused by the Ktor engine (501) or not taken for WebTransport, while the
  library took `WebSocket` for a WebSocket. Such a value is now malformed on receipt (`H3_MESSAGE_ERROR`; HTTP/2's codec
  checks it the same way) and refused with IllegalArgumentException before it is sent, and protocol names match in any
  case (RFC 9110 section 7.8, SHOULD).
- HTTP/3 server: a `capsule-protocol` field went out in any response; RFC 9297 section 3.4 keeps it out of responses
  other than 2xx (and 101). `respond` and `sendInformational` now refuse it there with IllegalArgumentException, as any
  other invalid response field.
- Ktor server, WebSockets over HTTP/3: a route other than `webSocket` (a `get` on the same path) that answered the
  WebSocket CONNECT with a 2xx opened a tunnel nobody accepted (RFC 9110 section 9.3.6): a streamed response reached the
  client as an open WebSocket, one with `content-length` reset the stream. Such a 2xx is now answered 501, as an
  unsupported protocol is (RFC 9220 section 3), the way a WebTransport CONNECT already was. For both, and for the 400
  that answers a WebTransport or WebSocket CONNECT the client could not make, `call.response.status()` now reports the
  status that went out (before, the route's 200 or the upgrade's 101); an accepted upgrade still reports 101, Ktor's
  model of the switch, which HTTP/3 carries as a 2xx. The same holds on HTTP/1.1 for the 501 that replaces a 2xx to
  CONNECT and on HTTP/2 for the 501 that answers an upgrade (before, 200 and 101).
- Ktor server: `webSockets { overHttp3 = false }` did not turn WebSockets over HTTP/3 off when `http3 { webTransport { enabled = true } }`
  advertised Extended CONNECT: a WebSocket CONNECT still reached the `webSocket {}` routes. It is now answered 501.
- HTTP/3: a reserved (GREASE) frame type on the peer's control stream spent a glitch token, while on a request stream it
  costs nothing. RFC 9114 sections 7.2.8 and 9 have reserved types ignored, and peers are meant to send them; a peer
  that greased its control stream often could have its connection closed with H3_EXCESSIVE_LOAD. They are now free on
  the control stream too; other unknown frame types still spend a token each.
- HTTP/3 client (`Http3Connection.request`): when the request's trailers were refused (above the server's
  SETTINGS_MAX_FIELD_SECTION_SIZE) after the response had begun, the response was abandoned without a QPACK Stream
  Cancellation (RFC 9204 section 4.4.2). Response trailers blocked on the dynamic table at that moment kept their
  blocked-stream slot for the connection's life; with `qpack { enableDynamicTable() }`, 16 such requests made the next
  legitimately blocked section end the connection with QPACK_DECOMPRESSION_FAILED. The stream is now cancelled once the
  response's reader stopped, as it is for `cancel()`. The Ktor engine was not affected.
- HTTP/3 server: when request trailers above `maxFieldSectionSize` arrived while the application called `respond()`,
  both could answer: the runtime's 431 and the application's response went out as two final responses on one stream (a
  malformed response, to the client that sent the oversized trailers). The response is now taken on the connection's
  dispatcher by whichever comes first; a `respond()` after the 431 fails with `Http3Exception.FieldSectionTooLarge`, as
  the request's trailers do.
- HTTP/3 server: a request that came in 0-RTT and was answered 425 under `Http3EarlyDataPolicy.Reject425`, or was held
  for a handshake that then failed, stayed registered until the connection ended: its stream, its PRIORITY_UPDATE
  routing and, for an Extended CONNECT, its datagram channel. It is now forgotten when it is answered or dropped.
- HTTP/3 WebTransport: every session stayed reachable until its QUIC connection closed (a handler on the connection's
  end held it, with its CONNECT stream and request). A client that opens and closes sessions one after another on one
  connection to a server with WebTransport on grew the server's memory by about 10 KB per session for as long as it kept
  the connection open. The handler is now removed when the session ends.
- HTTP/2: with `Http2Settings.maxFrameSize` raised above its 16 KiB default, the frame decoder allocated a frame's whole
  declared payload as soon as its 9-byte header arrived, so a peer could hold up to 16 MiB per connection by declaring a
  large frame and sending nothing more. The payload buffer now starts at 16 KiB at most and grows with the bytes that
  arrive.
- HTTP/2 client: a connection whose protocol was over (after GOAWAY its last stream ended, or a connection error) kept
  its socket and its place under `maxConnectionsPerRoute` until the engine closed when the server had stopped reading
  while our writer waited on the socket: nothing bounded the writing of what was left (with the default `pingInterval`,
  no PING notices it). The transport is now closed hard 2 s after the connection's end when the writer has not finished
  by then, as it already was for a connection whose PING went unanswered.
- HTTP/2 server: a request whose field section was above `http2Settings { maxFieldSectionSize }` (answered 431, RFC 9113 section 8.2) took
  the whole connection down, or failed an unrelated call, when its stream could no longer send by the time the request
  was handled: the client reset the stream in the same read, a later error in that read closed it, or the client's own
  SETTINGS_MAX_HEADER_LIST_SIZE was too small for the 431 head. The 431 threw out of the event dispatch: on the reader
  the connection ended with GOAWAY INTERNAL_ERROR; on an application thread that happened to dispatch, its call failed,
  and inside a stream's `release` that stream and the 431 stream both kept their slot under `maxConcurrentStreams`
  until the connection ended. Nothing is answered on a stream that ended, a 431 head the client cannot take resets the
  stream with CANCEL, and the stream is always released.
- QUIC: a packet carrying a PATH_CHALLENGE on the active path is acknowledged at once, so a non-probing packet
  answers it (RFC 9000 section 9.3.3 SHOULD) also when our own PATH_CHALLENGE on that path sends the PATH_RESPONSE in a
  probing-only packet; the ACK used to wait for `max_ack_delay` then.
- QUIC, ECN: a move of a path's peer address to another IP during the handshake started congestion control, RTT and
  DPLPMTUD over but kept the old address's ECN validation; it now starts over too (RFC 9000 section 13.4.2: per network
  path), and losses and acknowledgments of packets sent to the old address no longer count toward it. The one-congestion-event-per-recovery-period rule for CE reports was kept for the whole connection, so a CE
  report on a second path in the first path's recovery period was ignored; it is now per path, as each path has its
  own controller. A CE increase in ECN counts that fail validation is no longer acted on. The core no longer keeps a
  recovery start of its own for CE reports: it set one on every report even when the controller ignored it, so after a
  loss had started recovery, or after persistent congestion, a CE report for a packet sent later was dropped and NewReno
  and CUBIC never reduced (RFC 9002 section 7.3.2 and appendix B.6: losses and CE share one recovery period). Every
  valid CE report now reaches the path's controller, which decides; a custom `CongestionController` gets every report
  and applies its own recovery period, as for `onLoss`. `ConnectionStats.ecnCeEvents` counts only the reports NewReno
  or CUBIC took as a new congestion event (every report with other controllers).
- QUIC client: a migration (`migrate`, `addPath`) from a new socket while the server's preferred address was still
  being validated closed that validation for good. The preferred address is now validated again from the new socket,
  concurrently with the original address (RFC 9000 section 9.6.3 SHOULD); when it succeeds the application's new path
  takes it and the validation of the original address ends ("MUST abandon validation of the original address and
  migrate to using the server's preferred address"). A migration on the same socket still replaces the probe.
- QUIC: every PATH_CHALLENGE is now answered (RFC 9000 section 8.2.2 MUST). A fourth challenge waiting at once was
  dropped; it is now queued, past three waiting each costs a glitch token as before, and past 1024 waiting (glitch
  protection off) the connection closes with PROTOCOL_VIOLATION. A server on a wildcard socket with several addresses
  answered a challenge that reached another of its addresses from the path's own address; the PATH_RESPONSE now leaves
  from the address the challenge reached ("on the network path where the PATH_CHALLENGE was received"), in a datagram
  of its own carrying a connection ID of the client's that no path used (section 9.5), or is dropped when the client
  gave none to spare or the retirement backlog has no room to retire it afterwards.
- QUIC: path validation gave up after max(3 PTO, 6 times the initial RTT), 2 s with the default 333 ms, where RFC 9000
  section 8.2.4 recommends three times the larger of the current PTO and the new path's PTO computed from the initial
  RTT (3 times the initial RTT plus the peer's `max_ack_delay` once confirmed), 3.07 s. A client moving to a path with a
  long first round trip (a cellular link) was abandoned early. The same timeout bounds the wait for a spare connection
  ID before a probe and the undoing of a move during the handshake.
- QUIC server: a client's first Initial carrying another server's address validation token (one behind the same name)
  whose first byte happens to be the Retry token type was refused with a stateless INVALID_TOKEN close. A Retry-type
  token that does not open under our keys is now treated as absent (RFC 9000 section 8.1.3) unless the Initial's
  Destination Connection ID is in our format, which marks an answer to our Retry (a token whose key is gone after a
  restart, or damaged): that one still gets INVALID_TOKEN (section 8.1.2), never a second Retry. Retry tokens now carry the client address and version they are bound to inside the encrypted
  part instead of the associated data, so a token of ours presented from another address or for another version still
  opens and gets INVALID_TOKEN (section 8.1.2), as does an expired one or one under another Destination Connection ID.
- QUIC: short-header packets are now padded to at least 22 bytes more than the connection's own connection ID length
  (RFC 9000 section 10.3 SHOULD), so the peer's Stateless Reset sent in reply, one byte shorter, still looks like a
  packet to us. PING-only packets were 29 bytes with 8-byte IDs, and ACK-only packets about 30 with 20-byte IDs or a
  peer using short ones. An ACK-only packet grows by longer variable-length integers in its ACK frame instead (section
  16), so it stays out of flight (RFC 9002 section 2 counts a packet with PADDING as in flight). A client whose 0-RTT was
  rejected now closes the connection with PROTOCOL_VIOLATION when the server acknowledges one of its 0-RTT packets
  (RFC 9001 section 4.6.2 SHOULD); such acknowledgments used to be processed.
- QUIC client, 0-RTT with `resetStreamAt`: the server's new `reset_stream_at` transport parameter took effect when its
  EncryptedExtensions arrived, while 0-RTT could still be sent (the server's Finished not yet received), so a
  `resetAt` on an early stream could put RESET_STREAM_AT in a 0-RTT packet although the ticket's parameters did not offer
  it. 0-RTT now uses only the remembered offer, and the new one applies from 1-RTT on (RFC 9000 section 7.4.1).
- QUIC: a connection in the closing state (after our CONNECTION_CLOSE) still processed every frame the peer sent:
  STREAM data was buffered and charged to flow control, NEW_CONNECTION_ID and RETIRE_CONNECTION_ID changed the
  connection IDs, PATH_CHALLENGEs were answered and events followed the `Closed` one. RFC 9000 section 10.2.1 keeps
  only what is needed to answer with CONNECTION_CLOSE: a packet is now authenticated and searched for the peer's
  CONNECTION_CLOSE (section 10.2.2, draining); nothing else in it is acted on but, on a client, a NEW_TOKEN for the
  token store. The peer's CONNECTION_CLOSE in the
  closing state no longer replaces our reason in `ConnectionCore.closedReason` nor raises a second `Closed` event.
- QUIC: after the handshake, every CRYPTO byte received counted toward a 64 KiB budget that never refilled,
  retransmissions included, so a long-lived client connection to a server that resends or reissues NewSessionTickets
  was closed with CRYPTO_BUFFER_EXCEEDED. The limit is now on bytes buffered that TLS has not read (RFC 9000 section
  7.5: the error is for an endpoint "unable to buffer all data in a CRYPTO frame"). Every RESET_STREAM raised a
  `ConnectionEvent.StreamReset`, copies and resets after all the data was read too; the event now comes once, when the
  receive half moves to Reset Recvd.
- QUIC: connection IDs. A peer that retired every connection ID it was given got a replacement for each at once, so
  each 2-byte RETIRE_CONNECTION_ID made the endpoint draw a new ID (with QUIC-LB, a nonce of a space every endpoint of
  the process that uses the key shares). A retirement is now replaced at once while at most twice the IDs the connection
  keeps issued were retired within the last 3 PTO; past that it costs a glitch token and its replacement is issued when
  an earlier retired ID stops routing (RFC 9000 section 5.1.1 sets no time for it). The periodic rotation of the peer's
  ID (every 10,000 packets) threw CONNECTION_ID_LIMIT_ERROR out of `poll` when 32 of our retirements were unacknowledged;
  it now waits. The backlog of unacknowledged retirements is at least twice `activeConnectionIdLimit` (it was fixed at
  32, so a limit above 16 let an honest peer's rotation close the connection; section 5.1.2). A new connection ID,
  client or server, is never one the endpoint loop already routes or one of the connection's own live or retired IDs:
  `ConnectionIdRegistry.add` kept the earlier owner of a colliding ID, so the new connection advertised an ID (and its
  stateless reset token) that routed to another connection (sections 10.3.2, 19.15). With the default 8-byte IDs the
  chance was small; with `connectionIdLength = 4` (16 random bits) a collision was likely after a few hundred IDs. When
  16 draws all collide, a server drops the Initial, a NEW_CONNECTION_ID waits, and `connect` fails with
  `QuicException.ConnectionLost.Internal`.
- QUIC server: removing a connection walked every slot of the endpoint's connection ID table, and the table never shrank.
  An Initial that does not decrypt creates a connection and removes it at once, so each forged 1200-byte Initial from any
  address cost a walk over the IDs of every connection on the loop (and over the slots a past peak left behind). A removal
  now visits only the connection's own IDs, and the table halves once at most an eighth of it is in use.
QUIC loss recovery and congestion control (RFC 9002 review):

- A PTO probe owed in a packet number space that was then discarded (a server's Initial probe held back by its
  anti-amplification budget, then the client's Handshake packet) stayed owed for ever, and every later datagram was sent
  as a probe, outside the congestion window, for the rest of the connection (RFC 9002 section 7). Discarding a space or
  accepting a Retry now drops its probe, and only a probe owed in a live space with keys exempts a datagram.
- A client whose only ack-eliciting packets in flight were 0-RTT, after the server acknowledged its Initial, armed no PTO
  (the Application space arms none before confirmation), so a lost server Handshake flight stalled the handshake until
  its timeout. The anti-deadlock PTO of RFC 9002 section 6.2.2.1 now counts Application packets only once the handshake
  is confirmed.
- With one byte of room in the congestion window a full datagram still went out, taking bytes in flight up to one MTU
  above the window (RFC 9002 section 7). A datagram now goes only while its largest possible size fits.
- DPLPMTUD probes bypassed the congestion window and the pacer and never counted in bytes in flight. They now count in
  flight and wait for room ("PMTU probes consume congestion window", RFC 9000 section 14.4); a lost probe leaves flight
  without a congestion event, as before.
- NewReno and CUBIC were neither paced nor burst-limited below 1 ms of smoothed RTT, so a whole window could leave back
  to back, and their 10-datagram send quantum exceeded the initial window above 1472-byte datagrams (RFC 9002 section
  7.7). They are now paced at every RTT, in bursts of at most the initial window.
- The pacer could hold back a PTO probe when its bucket was empty (RFC 9002 section 7.5: probes are not blocked by the
  congestion controller).
- An ACK in a packet held for its keys was sampled when the packet was finally processed, so the RTT included the wait
  (RFC 9002 section 5.3). It is now sampled from the packet's arrival.
- Persistent congestion was broken only by an acknowledged packet of the same packet number space, and the time of the
  first RTT sample was per connection, so after a migration the old path's sample counted for the new path's packets
  (RFC 9002 section 7.6.2). Acknowledgements in every space now count during the handshake, and each path waits for its
  own first sample.
- BBR kept the bytes in flight plus one datagram on persistent congestion; it now collapses to its minimum window of 4
  datagrams, as RFC 9002 section 7.6.2 requires of every controller.
- A PTO in the Initial or Handshake space did not probe Application data in flight (a client's first 1-RTT data behind
  its Finished, or 0-RTT data); it now does (RFC 9002 section 6.2.4).
- The window grew with up to three datagrams of it unused, or with just over half of it in flight in slow start
  (quic-go's margins). It now grows only when the window had no room for another datagram before the ACK frame, or when
  the sender still had data at the end of its last send, held back by the pacer, the window or a burst limit (RFC 9002
  section 7.8). A sender that runs out of data or flow-control credit with room in the window no longer grows it.
- NewReno and CUBIC recompute the initial window when the datagram size changes: a window still at its initial value
  shrinks with a smaller size; a larger size never raises it (RFC 9002 section 7.2, RFC 8899 section 3).
- BBR's bursts (its send quantum, up to 64 KiB) exceeded the initial window above about 15 MB/s (RFC 9002 section 7.7);
  the burst is now capped at the initial window. Over loopback (`UdpThroughputBenchmark`, JVM) BBR moves 208-214 MiB/s
  instead of 225-231, as CUBIC does.
- A window smaller than the MTU (a window that collapsed before DPLPMTUD raised the MTU to a jumbo size) sent nothing
  any more; a datagram is now cut to the room left when that is at least 1200 bytes.
- Persistent congestion of another path's lost packets was judged with the active path's RTT; it now uses that path's
  own estimate. A probe owed for rejected 0-RTT stayed owed and let one datagram pass the window; Application data
  waiting for its keys during the handshake let the window grow.
- Bytes of a discarded space or of rejected 0-RTT were taken from the active path's congestion controller, whichever
  controller had counted them. The PTO backoff wrapped after 31 unanswered PTOs (possible only with both idle timeouts
  disabled): the timer fired at once, then restarted; it now stops doubling at 2^30.
- TCP (JVM, Android, Kotlin/Native): a connection reset that a write took was read as an orderly end, so a response
  body delimited by the connection's close (RFC 9112 section 6.3 item 8) could pass cut for complete (section 8) on
  plain HTTP/1.1. On Linux, Android included, a socket's pending error goes to the first system call that looks at it
  and is then cleared: a send that ran between the arrival of the peer's reset and the next receive failed with
  ECONNRESET, and the receive then returned the end of the stream. The read side now fails with the send's failure when
  it reads an end after a send failed (waiting for a send under way), instead of ending; an orderly close and a failed
  application stream are not recorded as the send's failure. On Kotlin/Native a failed send failed the read side with a
  CancellationException rather than the send's error. TLS already treated such an end as a truncation (no
  `close_notify`).
- Ktor client and server, HTTP/1.1 and HTTP/2 over TCP and TLS: bytes received before the connection failed were lost
  when the application had not read them yet: ktor-io's channel drops what it holds once it fails. A response the server
  sent completely before resetting the connection (a 413 or 401 to an upload it stopped reading, whose close over unread
  data the kernel answers with a reset, RFC 9112 section 9.6) failed the call instead of reaching it. The engines now
  read their connections through a channel that hands out everything received, then fails (a reset, a receive error, a
  failed send, an abort, a failed TLS session); TLS's raw input reads the same way, so an alert received before a reset
  is not lost either. A socket's read channel opened with ktor's `openReadChannel` fails at once, as before.
- TCP (JVM, Android, Kotlin/Native): a socket's own `close()` or `abort()` ended its read side differently by platform:
  the JVM and Android cancelled the read channel (a reader got a CancellationException, which a coroutine takes for its
  own cancellation), Kotlin/Native ended it as if the peer had closed. Both now fail it with an IOException, "Socket
  closed" after a close and "The connection was aborted" after an abort ("The connection was reset" after a reset that
  a failed application stream caused on Kotlin/Native). When the socket's job is cancelled under the read loop, the
  read side fails with that cancellation instead: the JVM and Android cancel the channel with it, Kotlin/Native fails a
  channel opened by the engines with a failure that wraps it. A cause the reader set by cancelling its channel itself
  (a socket timeout) stays the one the channel reports after the socket closes.
- JVM and Android TCP: the read loop is now Kuicksilver's own, as the write loop already was (ktor's reader is no longer
  used); it reads into the application's channel directly, as ktor's did.
- HTTP/2: a request or response body started before the peer's SETTINGS arrived could be reset with
  FLOW_CONTROL_ERROR when those SETTINGS shrank SETTINGS_INITIAL_WINDOW_SIZE (a client uploading to a server with a
  16 KiB stream window). A DATA frame taken from the larger window but not yet written went out after the SETTINGS
  acknowledgement, and the peer counts what follows the acknowledgement against the smaller window (RFC 9113 sections
  6.5.3, 6.9.2). Such frames are now charged again against the smaller window (see the SETTINGS acknowledgement
  entry above).
- Ktor server: a response whose content is a channel that failed (`call.respond(channel)`, `ReadChannelContent`; a proxy
  relaying an upstream body that was cut) went out as complete over HTTP/1.1 and HTTP/3 when the failure was recorded
  before the engine read the channel, or while it waited for the client: ktor-io's `copyTo`, under Ktor's
  `respondFromChannel`, stops on a channel failed with a cause as at its end, without throwing. The response then ended
  with the last chunk (RFC 9112 section 7.1), with a FIN after a body delimited by the close (section 8), or with a FIN on
  HTTP/3 (RFC 9114 section 4.1), and the client took the cut body for the whole one. The failure now cuts the response
  short: the HTTP/1.1 connection is reset without the last chunk and carries no later response; the HTTP/3 stream is
  reset with `H3_REQUEST_CANCELLED` (section 4.1.1), as it now is for any response body the application abandons (it was
  `H3_INTERNAL_ERROR`). A channel cancelled with a `CancellationException` (a cancelled upstream call or `writer {}`) is a
  failure too: on HTTP/1.1 it ended a close-delimited response with a FIN, on HTTP/3 it left the stream with neither a FIN
  nor a reset. A channel that fails after all its Content-Length bytes leaves the response complete, and an HTTP/3 HEAD,
  204 or 304 no longer reads the channel. HTTP/2 already reset the stream. Likewise an HTTP/1.1 request body the
  connection cut short (the client closed or reset it mid-upload) now fails the handler's `readAvailable` with the cause
  instead of answering -1 as at a complete body, as the HTTP/2 and HTTP/3 request bodies already did. On HTTP/1.1 the
  engine cuts a failed chunked response itself before the call ends: the chunk encoder's cut, resumed on
  `Dispatchers.Unconfined`, came after the end of the call when the content failed inside another unconfined resumption,
  and the response then ended cleanly without its last chunk, a pipelined response following it on the connection.
- Ktor engines, TLS over TCP: a failed handshake closed the socket right after its alert and FIN, while the peer might
  still be sending (a TLS 1.3 client sends its request right after its Finished, before it learns that a server that
  requires a client certificate refuses it). Those bytes met a reset, which on Windows erases the alert from the peer's
  receive buffer: the client saw "An established connection was aborted" instead of `certificate_required`. The close is
  now staged as RFC 9112 section 9.6 describes: after the alert and the FIN, what the peer sends is read and dropped (at
  the TCP layer; TLS processes nothing after its alert) until it closes too, for 2 s and 256 KiB at most (250 ms after a
  client's failed handshake; no wait after the handshake's own deadline), then the socket closes. A stream that fails
  after the handshake, whose internal_error alert goes out the same way, closes the same way.
- Ktor engines, WebSockets: a connection that failed in the middle of a frame (a reset while the session's reader was
  behind, or while a compressed message was inflated) ended the session's input as if the peer had closed the stream,
  without the failure. The input now fails with the connection's cause.
- Ktor server: the TLS handshake of a TCP connection was cut after 10 s (`TlsConfig.handshakeTimeout`'s default), not at
  `requestHeaderTimeout` (30 s) as documented. A client on a slow, lossy path (200 ms, 5 % loss) whose last
  handshake flight needed retransmissions had its connection closed after it had sent its request, and saw "unexpected end
  of stream". The request-head deadline alone bounds the handshake now.
- QUIC: `maxConnections` and `maxConnectionsPerIp` bound the endpoint as a whole with `loops > 1`. Each loop counted its
  own connections, so N loops admitted up to N times either limit (SO_REUSEPORT spreads one address's source ports over
  the loops, and the in-process dispatch hashes new clients' connection IDs). The loops of a group now share the slots:
  one counter for the total, and a table of the addresses holding connections (keyed-hash buckets replaced by
  compare-and-set, never larger than the connections themselves). A slot is reserved when an Initial passes the limits,
  given back when no connection comes of it (policy refusal, Retry, an Initial that does not decrypt), and released when
  the connection is removed or its loop closes. `ConnectionAttempt.connections` and `connectionsFromAddress` count the
  whole endpoint too. One loop behaves as before. Upgrading with `loops > 1` (the Ktor server's `http3 { endpoint { loops } }`): the
  limits are now endpoint-wide, so multiply the old values by the loop count to keep the same capacity.
- Ktor client: connections end with TLS `close_notify` whenever the client's write side is whole (RFC 9846 section 6.1):
  an HTTP/1.1 connection after a `Connection: close` response, an abandoned response body, a finished upload or upgrade,
  or an exchange that failed after the whole request went out (a malformed response head, a timeout, the call
  cancelled), idle connections evicted or closed with the engine, and HTTP/2 connections after their last GOAWAY; before,
  the socket was closed without one, and the server saw a truncation. The close waits for the peer's `close_notify` and
  the socket's last bytes within 1 s, in the background; closing the engine waits for those closes, about 3 s at most.
  A connection whose request body was cut off, or whose TLS session failed, is still closed at once.
- HTTP/2 client: the GOAWAY of a connection error, of an unanswered PING and of closing the engine reached the server
  only by chance: the TLS session was closed as soon as the GOAWAY was handed to it (RFC 9113 section 5.4.1). The
  transport now closes in order behind it. A TLS 1.3 post-handshake CertificateRequest from a server (which OpenSSL
  refuses, as no post_handshake_auth is offered) fails the connection's calls with PROTOCOL_ERROR (RFC 9113 section
  9.2.3) instead of a TLS failure.

- HTTP/3: a server's `respond()` no longer fails when the client stops the request stream right after receiving the
  response HEADERS (a client abandoning a rejected CONNECT does so at once). The HEADERS frame was already handed to QUIC,
  but the flush after it met the client's STOP_SENDING and `respond()` threw a raw `ClosedWriteChannelException` and
  reset the stream with H3_INTERNAL_ERROR; it now returns the writer, whose writes and `finish()` report the stop as an
  `Http3Exception`. On the client, a request whose stream the server stops before the flush after the request HEADERS
  with a code other than H3_NO_ERROR now still reads and returns the response, and releases a request body that was not
  sent yet; it fails only when no response comes (RFC 9114 section 4.1: "Clients MUST NOT discard complete responses as
  a result of having their request terminated abruptly").

- Ktor network (JVM, Android): a socket whose writer fails or is cancelled now ends the pending read at once. The writer
  closed the descriptor directly, which only cancels its selection key, so a read waiting in the selector was never woken:
  a TLS client that the server reset before its ClientHello waited out its whole handshake timeout.

- QUIC: a closed endpoint no longer keeps its connections reachable. `close()` released every connection's native state, but
  the endpoint's timer heap and its table of connections by peer address still referenced each `ConnectionCore` (about
  40 KB of Kotlin state per connection), so an application that kept a reference to a closed endpoint kept all of them.

- Ktor client: a QUIC setup the server refuses with CONNECTION_REFUSED (a server in `Drain`, stopping, or with a full
  accept queue; RFC 9000 sections 5.2.2 and 20.1) no longer marks the HTTP/3 alternative broken. The call falls back to
  HTTP/1.1 once (`ProtocolDiagnostics.fallback = Refused`), the alternative stays cached (RFC 7838 sections 2.2 and 3),
  and the next call tries HTTP/3 again. It was marked broken for 5 minutes, doubling up to 2 days at each refusal, so a
  rolling restart of a multi-instance server put the whole origin on HTTP/1.1. Any other close of the setup by the
  server still marks the alternative broken. The refusal on an established connection (a handshake completed into a
  full accept queue) counts the same.
- Ktor client: a connection the server closes with H3_NO_ERROR after it sent GOAWAY (a graceful stop whose grace period
  ended with requests open: RFC 9114 section 5.2) no longer marks the HTTP/3 alternative broken when a request in flight on it
  falls back to HTTP/1.1. The close (H3_NO_ERROR) read as a failed connection and marked the alternative broken for 5
  minutes up to 2 days, so a long poll, a server-sent event stream or a slow response caught by a rolling restart put
  the origin on HTTP/1.1. A close with an error code after GOAWAY, and an H3_NO_ERROR close without a GOAWAY first,
  still mark it.
- QUIC: a server bound to a wildcard address (`0.0.0.0`, `::`, the Ktor connector's default `host`) answers from the address
  the client sent to. Its accelerated UDP socket (Linux, Android, Apple, Windows) did not use `IP_PKTINFO` / `IPV6_PKTINFO`,
  so every answer left from the address the route back to the client picks: on a host with several addresses, a floating
  or virtual IP (keepalived) or a VIP on `lo` for IPVS direct routing and other direct server return, the client dropped
  the answers as a stranger's (RFC 9000 section 9) and HTTP/3 never connected while TCP worked. The socket now reads each
  datagram's destination and sends from it: a server path takes the address its first datagram reached and keeps it (only a
  client migrates; datagrams of the same client to another server address, or an attacker's copies of them, change
  nothing), a path to a new client address takes the address its datagram reached and never the old address's connection
  ID (section 9.5), and stateless answers (Version Negotiation, Retry, Stateless Reset, refusals) leave from the address of
  the datagram they answer. Multicast, broadcast (subnet-directed too) and IPv6 link-local destinations are not answered
  from.
  New experimental API: `PacketBatch.localAddress` / `setLocalAddress`, `EndpointCore.handleDatagram(…, local)`,
  `ConnectionCore.handleDatagram(…, local)`; ksl (additive in ABI 7): `KSL_UDP_PKTINFO`, `ksl_udp_send_src`,
  `ksl_udp_recv_dst`. The portable sockets (NIO on the JVM, ktor-network on Kotlin/Native) cannot do this: bind them to
  the address clients use ([deployment guide](docs/guide/deployment.md#reply-addresses)).
- QUIC 0-RTT: a server accepts early data only under the cipher suite of the ticket's own connection (RFC 8446
  §4.2.10, RFC 9846 §4.3.10: MUST). OpenSSL 3.5 resumed a ticket under another suite with the same hash (a
  TLS_AES_128_GCM_SHA256 ticket where the server picks TLS_CHACHA20_POLY1305_SHA256) and accepted its early data; such a
  resumption now continues in 1-RTT, as OpenSSL 4.1 does.
- QUIC 0-RTT: a ticket a client receives on a resumed connection names that connection's ALPN protocol. OpenSSL 3.5
  kept the protocol of the resumed ticket, so after a resumption under another protocol the client offered 0-RTT for
  the old one and failed the handshake with illegal_parameter when the server accepted it under the new one.
- Ktor server: `KuicksilverServerEventListener.connectionClosed` for an HTTP/3 connection comes after the
  `requestEnded` of every request it carried. It came as soon as the connection took no more requests, so a client
  that closed the connection as soon as it had the answer could be reported gone while its handler still ran.
- TLS: bytes the peer sent right before closing the TCP connection without `close_notify` are delivered before the
  input fails with the truncation; they were dropped with it (`TlsConnection.input`, so HTTP/1.1 bodies and the last frames
  of an HTTP/2 connection, such as a GOAWAY, were cut). The truncation is still an error, never a clean end of the stream.
- Ktor engines: closing a TCP or TLS socket while the application's write waits for room (a peer reading slower than
  we write) ends that write as the close does: it returns, and later writes fail with `ClosedWriteChannelException`.
  The close flushed the channel with a suspending `flushAndClose`, which took the channel's single write slot, and
  ktor-io resumed the waiting write with `ConcurrentIOException` ("Concurrent write attempts") instead.
- Ktor server: an HTTP/3 request whose call fails after Ktor committed its response but before any answer went out (an
  upgrade that fails before its `:status 200`) is reset with H3_REQUEST_CANCELLED, a response abandoned after partial
  processing (RFC 9114 section 4.1.1); before, the request stream stayed open
  and the client waited for an answer that never came.
- Tooling: `tools/interop/run-local.sh` makes every image a run needs present for a platform the host can run before it
  starts (`tools/interop/peer-images.sh`): a missing image is pulled, `--platform linux/amd64` (emulated) when its manifest
  list has none for the host, as `cloudflare/quiche-qns:latest` on arm64; an image that cannot be obtained fails the run up
  front, naming it. A required peer the runner finds "not compliant" is an error naming its image (also under
  `--check-required`), no longer only red cells (0.2.1 gate, 2026-11-04). Cases: `tools/interop/peer-images-test.sh`.
- QUIC server: a client that really rebinds during the handshake while an off-path observer races copies of its datagrams
  from the old address now completes the handshake on its new address. Each copy from the old address used to take the
  path back there and forget the PATH_CHALLENGE sent to the new one, so the client never got HANDSHAKE_DONE and the
  handshake timed out. The server now keeps the address its first handshake-time move left as a second, internal
  candidate path with its own anti-amplification budget and its own validation (RFC 9000 sections 8.1, 8.2 and 9.3.3); the
  two addresses keep their validations whichever of them the connection uses, the first to answer its own challenge data
  is kept, wherever the answer came from, and the candidate is never reported as a path. A third address never becomes a
  candidate. A client that rebinds before any ServerHello reached it gets the flight's retransmissions at its new address
  too, within that address's own budget, so that handshake completes as well.
- QUIC server: a handshake-time change of the client's address to another IP (following it, returning to the old one, or
  keeping the candidate) kept the congestion controller, RTT estimate and MTU of the old address; they now start over, with
  path MTU discovery restarted, as RFC 9000 section 9.4 requires (a port-only change, a NAT rebinding, keeps them).
- QUIC server: an observer racing copies of a client's datagrams from a second live address after the handshake could
  keep the server switching paths without end: every switch validated the previous path at once and retired its
  connection ID, and the client's answer and replacement ID were the next apparent migration, until the AEAD
  confidentiality limit closed the connection. A path is now challenged no more often than once per PTO (RFC 9000 section
  8.2.1) and keeps its connection ID while that revalidation waits.
- QUIC on Kotlin/Native: an `EndpointCore` whose construction fails (a refused key, a loop group's keys already
  released) frees the stateless buffer, the reset key, the address-token keys and the admission queue it had made
  instead of leaking them, and `EndpointCore.close` runs every release even when one of them throws.
- QUIC: a `QuicEndpoint.bind` that fails after opening its sockets (the endpoint loop cannot be built or started) closes
  the main and the preferred-address sockets instead of leaving them bound, and the loop frees the endpoint core and the
  datagram batches it had made. A loop group that fails to build or start (its shared token keys included) likewise
  closes every loop's sockets and frees the loops already built.
- QUIC: closing an endpoint frees its endpoint core, datagram batches and remaining sockets even when one release in
  the sequence throws (a socket whose close fails); before, the rest was skipped and leaked. The first failure is still
  counted as the loop's uncaught failure. The close also stops and waits for the timer and the preferred-address
  receivers before it frees the batches, and a flush after that does nothing: a timer resumed during the close could
  otherwise poll into a freed batch.
- QUIC on Kotlin/Native: a `PacketBatch` whose slot allocation fails part-way frees the slots it had already allocated,
  and its `close` frees every slot even when one of them fails to close.
- QUIC server: the Retry token key is freed when making the NEW_TOKEN key fails while a server endpoint is set up,
  instead of leaking.
- HTTP/3: a peer that sends `H3_DATAGRAM=1` with a transport `max_datagram_frame_size` of 1 or 2 is no longer refused
  with `H3_SETTINGS_ERROR`: only an absent or 0 parameter is (RFC 9221 section 3 makes any value above 0 support). An
  HTTP/3 datagram that such a limit does not fit is reported too large.
- QUIC datagrams: a peer whose `max_datagram_frame_size` is small (2 to 34 bytes) is no longer reported as not
  supporting datagrams. The 32 bytes kept free for an ACK beside a packet-sized datagram were taken from the peer's limit
  too, so `maxDatagramSize` came out 0 or below, nothing was ever sent and `sendDatagram` failed with
  `PeerDoesNotSupport`, although RFC 9221 section 3 makes any value above 0 support. The payload limit is now what the
  peer's frame size allows (8 bytes for a 10-byte limit, an empty datagram for 2), the reserve only shrinking the
  packet's bound; a peer limit below the packet's is no longer cut by 32 bytes either (497 instead of 465 bytes for a
  500-byte limit). A limit of 1, which no DATAGRAM frame with a Length field fits, is support too: every datagram, an
  empty one included, is `TooLarge(max = 0)` (`max` is never negative).
- QUIC BBR (experimental): after persistent congestion the window from before comes back only once the losses are
  repaired (draft-ietf-ccwg-bbr-06 section 5.6.4.4, "by repairing all losses"): a packet sent since must be acknowledged
  and every packet declared lost up to the congestion settled, acknowledged late or kept past the persistent congestion
  period; losses declared later do not hold it. Before, the first acknowledgement of a newer packet restored it about
  one round trip after the congestion, while most of the lost data was still being resent.
- QUIC: a local close puts its CONNECTION_CLOSE on the wire sooner. The endpoint loop now sends the frame before it fails
  the connection's streams, wakes its waiters and calls the listener's `onClosed`, and on the JVM and Android an
  endpoint loads the close exceptions' classes once when it starts instead of on the first close: on a cold JVM,
  close() to the first datagram went from about 8 ms to 1.3-2.7 ms (in-memory sockets, local measurement), which
  narrows the window in which a peer's packet can still reach an open connection (the interop closing-challenge race).
- TLS over TCP: every record ksl writes under the sending keys counts toward their record limit (RFC 9846 section 5.5),
  from the record after its switch to the application keys, not only the application data: alerts, a TLS 1.2 side's
  Finished and a TLS 1.3 server's tickets count too, and a read handles one non-application record at a time with the
  limit checked before and after each, so no read writes past it. A TLS 1.2 peer could make the client answer
  HelloRequest after HelloRequest with a `no_renegotiation` alert, none of them counted.
- TLS over TCP: a read that had to finish writing a handshake message first (a KeyUpdate whose write found ksl's buffer
  full) answered as if it needed more input, so records already received waited for the peer to send something else.
  `ksl_tcp_read` now answers `KSL_OK` with nothing read in that case, and the connection's reader reads again once the
  drain made room.
- HTTP/3: a peer that stops one of our critical streams (control, QPACK encoder or decoder) or closes one of its own
  now ends the connection with `H3_CLOSED_CRITICAL_STREAM` (RFC 9114 section 6.2.1, RFC 9204 section 4.2), as soon as
  its STOP_SENDING arrives rather than at our next write on that stream; before, a stop ended it with
  `H3_INTERNAL_ERROR`, or for the control stream not at all.
- Ktor server: a start that failed while setting up a later connector (for example HTTP/3 settings it refuses) left the
  connectors before it accepting connections until the server was stopped; they are now stopped with the failed start.
- Ktor server on Kotlin/Native: a connector that could not bind (a port in use, an HTTP/3 endpoint that refused its
  configuration) aborted the process: the failure was thrown out of the accept coroutine, where no handler took it. It
  now fails the start only, as on the JVM.
- Windows (mingwX64) TCP: a pending connect could wait for ever when the selector lost its `FD_CONNECT`, which Winsock
  posts once, like `FD_CLOSE`. The engines bound it with their connect timeout; a direct `connectTcp` had no bound. The
  wait now looks at the socket itself every second: `SO_ERROR`, and a zero-wait `select` for whether the connect
  completed (`getpeername`, the check on other systems, already answers on Windows while the SYN is unanswered).
- TLS, `ksl` C ABI (not reachable from Kotlin): a session keeps the verify mode of the ssl that first handed it out.
  A TLS 1.2 resumption from a server that renews no ticket hands out the very session that was set, and
  `ksl_ssl_get1_session` stamped it again: a client without verification resuming a verified session turned it, for
  every other holder, into one made without verification, which verifying clients then refused, and the stamp was
  written while another thread could read it.
- Ktor server, HTTP/1.1: a pipelined response that failed before any of its bytes went out (its handler failed while it
  waited behind an earlier response) ended the connection with a reset, which could destroy the earlier responses
  still on their way. The connection now ends cleanly: the responses before it are sent whole, then the close, and no
  later request is read or answered (KTOR-10037, as upstream Ktor). A response that fails after part of it went out
  still ends the connection with its failure, so the client cannot take that part for the whole response.
- ksl: `ksl_ctx_set_ciphers` holds a TLS 1.2 list to the RFC 10015 profile itself: a list with any suite that is not
  ECDHE with RSA or ECDSA and an AEAD of 128 bits or more (static RSA, FFDHE, CBC, CCM_8, anonymous, PSK) is refused
  with `KSL_E_BAD_ARG`, as the version bounds are. Kotlin never passed one; the C ABI accepted any. A refused list also
  no longer leaves the context without TLS 1.2 suites (OpenSSL replaces the list before it refuses one that matches
  none).
- Ktor client: at most one WebSocket connection is in the CONNECTING state per remote host (RFC 6455 section 4.1,
  step 2, MUST: "If multiple connections to the same IP address are attempted simultaneously, the client MUST
  serialize them"): a WebSocket over HTTP/1.1 to an IP address another one is still connecting to, on any port, waits
  until that handshake is answered or failed, also when it uses another name for the address (an IPv4-mapped IPv6
  address counts as its IPv4 address); through a proxy that resolves names the name counts as the host, compared
  without case and without a final dot. A WebSocket takes the address first, then a connection from the pool,
  and holds the address until the server answers the handshake (a WebSocket waiting for the address holds nothing of the
  pool); the pool wait, the connection and the answer must fit in the connect timeout (`HttpTimeout`'s, else
  `connectTimeout`, 10 s), counted from the moment it holds the address, or
  the WebSocket fails with `ConnectTimeoutException`: a server that accepts the connection and never answers holds up
  the next WebSocket to the address for at most that long. The wait for another WebSocket's handshake is not part of
  the connect timeout: WebSockets started together queue for as long as the call allows (its request timeout or
  cancellation), and each one's connect timeout starts once it holds the address. Before, any number connected at once.
- HTTP/3 client: any number of interim (1xx) responses is accepted before the final one, as RFC 9110 section 15.2
  requires ("A client MUST be able to parse one or more 1xx responses"); a request failed at the sixth. Endless 1xx
  still end: the decoded fields of all of a request's interim responses together are bounded by `maxFieldSectionSize`
  (64 KiB by default), past which the request fails with `H3_EXCESSIVE_LOAD` and its stream is reset, as the HTTP/1.1
  client's 64 KiB budget. `Http3Settings.maxInformationalResponses` was ignored from then on (removed in 0.3.0, see "Changed").
- QUIC with BBR (`QuicConfig.congestionController`): persistent congestion is BBR's retransmission timeout
  (draft-ietf-ccwg-bbr-06 section 5.6.4.4): the window still drops to max(bytes in flight + 1 datagram, 4 datagrams)
  (`OnEnterRTO`), and now the window from before comes back once a packet sent after it is acknowledged (`RestoreCwnd`,
  "Upon exiting loss recovery (RTO recovery or Fast Recovery)"). Before, it was never restored, except by a spurious-loss
  undo.
- QUIC on the portable JVM socket (`IoPreference.Portable`, or when the accelerated UDP cannot open): the Don't Fragment
  bit is set on all of the socket's traffic, as RFC 9000 section 14 requires. Each half of the socket is in probe mode
  where the system takes it (`IP_PMTUDISC_PROBE`, and `IPV6_PMTUDISC_PROBE` on a dual-stack socket), set through `ksl`
  on the JVM and Windows and `android.system.Os` on Android, so a forged ICMP Fragmentation Needed can neither make the
  system refuse sends nor fragment them (quic-go CVE-2024-53259; section 14.2.1). Where probe mode is refused, DF is in
  DO mode (Apple: `IP_DONTFRAG` / `IPV6_DONTFRAG` through `ksl`; without `ksl` the JDK's `IP_DONTFRAGMENT`, JDK 19 and
  later; an IPv4 bind without `ksl` gets an AF_INET channel when DF takes on it, since the JDK's option sets only the
  IPv6 half of a dual-stack one, so bound to 0.0.0.0 it reaches IPv4 peers only; where the system refused DF to `ksl` on
  the dual-stack channel's IPv4 traffic, Apple's `IPV6_DONTFRAG` included, `ksl` is tried on an AF_INET channel too, on
  any JDK). Android does the same with `android.system.Os`: an IPv4 bind whose dual-stack socket was refused DF on its
  IPv4 half tries an AF_INET socket, kept when DF takes on it, instead of refusing its IPv4 sends (or not opening, when
  neither half had DF). In DO mode such a message can make the system refuse sends to the peer (EMSGSIZE; on Windows
  WSAEMSGSIZE, checked on a Windows 11 VM against a non-loopback peer): a datagram of at most 1200 bytes refused twice
  in a row now closes that path, or on the active path ends the connection with a CONNECTION_CLOSE of NO_VIABLE_PATH (an
  HTTP/3 client falls back to TCP), instead of losing datagrams until the idle timeout; the accelerated socket does the
  same with its EMSGSIZE count, never charging a refusal of a stateless send to a connection. `open` loads `ksl` on the
  JVM. Datagrams there stay within 1200 bytes, so PMTUD stays off.
- QUIC server with 0-RTT: `QuicConfig.resetStreamAt` is part of the tickets' early-data context, so a server that turned
  it off no longer accepts the 0-RTT of tickets issued with it on (draft-ietf-quic-reliable-stream-reset section 3: the
  server "MUST NOT disable this extension" when it accepts 0-RTT; the client then closed with PROTOCOL_VIOLATION).
  Tickets issued before the upgrade refuse 0-RTT once.
- QUIC with `resetStreamAt`: a RESET_STREAM sent after our RESET_STREAM_AT (our own `reset`, or the answer to the
  peer's STOP_SENDING) carries the RESET_STREAM_AT's error code, not the new one; draft-ietf-quic-reliable-stream-reset
  section 5.2 says the initiator "MUST NOT change the Application Error Code", and a peer closed the connection with
  STREAM_STATE_ERROR.
- HTTP/3: a `priority` field or PRIORITY_UPDATE Priority Field Value that is not a valid Structured Fields
  dictionary is ignored as a whole, so the defaults (u=3, i=?0) apply, or the current values when a response's field
  is merged (RFC 8941 section 4.2, RFC 9218 section 4). The parser read it member by member before and kept the valid
  members of a broken value such as `u=1, i,`. A `u` that is not an Integer 0 to 7 or an `i` that is not a Boolean is
  still ignored on its own (RFC 9218 sections 4.1, 4.2), and several `priority` field lines are combined before
  parsing; only the first one was read before.
- HTTP/3 server with WebTransport: a WebTransport stream naming a Session ID beyond the bidirectional stream limit the
  server granted closes the connection with `H3_ID_ERROR` at once; the client could never open that session. Such a
  stream held one of the 16 buffer slots for 5 s before.
- HTTP/3: an HTTP/3 datagram for a request other than CONNECT (a GET, a POST: no datagram semantics) aborts that
  request's stream with `H3_DATAGRAM_ERROR` while its direction towards us is still open, as RFC 9297 section 2
  requires ("the receiver MUST terminate the request"); the request fails, the connection lives on. Such datagrams were
  dropped, and a WebTransport server kept them for up to 5 s in the 16 slots meant for sessions whose CONNECT is still on
  the way. Once that direction ended they are still dropped silently (section 2.1).
- HTTP/3: an HTTP/3 datagram whose quarter stream ID names a stream beyond the client-initiated bidirectional stream
  limit (the one the server granted; on a client, the one granted to it) closes the connection with `H3_ID_ERROR`, as
  RFC 9297 section 2.1 recommends ("SHOULD be treated as an HTTP/3 connection error of type H3_ID_ERROR"), the same
  rule PRIORITY_UPDATE and WebTransport streams follow. Such a datagram was dropped silently.
- HTTP/3 server with WebTransport: datagrams that arrive before their session's CONNECT HEADERS (reordering, or a
  client that sends right after its CONNECT) are kept and delivered once the session is accepted, at most 16 per
  connection (draft-ietf-webtrans-http3-16 section 4.6, "SHOULD buffer streams and datagrams until they can be associated
  with an established session"), each on the order of a round trip as RFC 9297 section 2.1 allows: one PTO plus one
  smoothed RTT of the connection, at least 50 ms and at most 5 s. They were dropped.
- HTTP/3 with WebTransport: a WebTransport `WT_STREAM` signal as the first frame of the peer's control stream now closes
  the connection with `H3_MISSING_SETTINGS`, as RFC 9114 section 6.2.1 requires of any first frame other than SETTINGS,
  instead of `H3_FRAME_ERROR`.
- TLS over TCP: a server now issues six session tickets after a full handshake (also the explicit post-verdict ones of a
  pinned-client server), and a client keeps up to six per origin, each used once, so up to six parallel HTTP/1.1
  connections to one origin each resume (RFC 9846 appendix C.4, SHOULD, whose example is a browser's six HTTP/1.1
  connections). Before, one ticket per connection and one per origin meant only one of them resumed. A QUIC origin still
  keeps its newest ticket only.
- TLS over TCP: a connection whose application stream failed (a handler that threw mid-response) now ends with the fatal
  alert internal_error after what was sent, then a FIN, where OpenSSL can send one: a TLS 1.3 server and a TLS 1.2 client
  (RFC 9846 section 6.1). Before, it ended with a reset and no alert; it still never ends with `close_notify`, so a peer
  never takes the cut stream for a whole one. A TLS 1.3 client and a TLS 1.2 server still reset the connection: OpenSSL
  3.5 offers no way to send an alert there. New internal `TlsConnection.abortOutput` and `ksl_tcp_abort` (additive, ABI 7).
  The alert also follows a KeyUpdate that was queued and not yet written, and a record write the transport had no room
  for: both go out first (OpenSSL started no alert behind them, so the connection was reset). `ksl_tcp_write` takes at
  most one record per call and accepts the retry of a pending write from another buffer with the same bytes.
- Ktor client, HTTP/1.1: a status code must be exactly three digits (RFC 9112 section 4); `HTTP/1.1 20` and
  `HTTP/1.1 2000` without a reason phrase were taken as statuses 20 and 2000, and now fail with `ParserException`.
  Three digits outside 100..599 (`HTTP/1.1 600 Six`, `HTTP/1.1 042`) are an invalid status code that a client SHOULD
  process as a 5xx (RFC 9110 section 15): the response is a 500 whose description is the code and reason sent
  (`600 Six`), so response validation and retries on server errors take it as one, and a 0xx is never skipped as an
  interim response. Before, it was passed on as is, 042 looking like a success. A response in `HTTP/1.2` or a later
  minor version is processed as HTTP/1.1 (RFC 9110 section 6.2) instead of failing.
- WebTransport: a session the peer closes with WT_CLOSE_SESSION and then, at once, its connection (Firefox does both
  in back-to-back packets) ends with the capsule's code and reason. Before, the server saw code 0 and an empty reason:
  the connection's end completed the session before its capsule reader had read the capsule. The capsule reader now
  reads on to what the peer sent, and the connection's reason is the session's only when no capsule came. A
  WebTransport stream whose pump the lost connection cancelled before it ran now ends instead of leaving the
  application waiting.
- TLS over TCP: a `TlsConnection` freed its native session (the OpenSSL object, its context reference and a cached
  session it took) only from `close()`. A connection ended by cancelling the job of the `context` it was started in,
  which the API documents as ending it, kept that native state for the rest of the process, as did one whose owner never
  got it (see the Ktor server's TLS handshake deadline below). The native session is now freed whenever the
  connection's job ends, and `input` and `output` fail as after `close()`; when the job ends during the handshake (the
  caller's context cancelled as the handshake completes), only once the handshake is over, since the handshake reads the
  peer's chain and the negotiated parameters from the native session outside its lock (freed under it, that was a use
  after free, and a cached session or SNI context taken meanwhile was never released). Such a handshake fails with
  `TlsException.Protocol` "connection closed during the TLS handshake", or the caller's own `CancellationException`,
  instead of an `IllegalStateException`. Two concurrent `close()` calls no longer both run the tear-down (the closed flag
  was a plain field read and written from several threads).
- TLS over TCP: a transport that failed (a reset, a socket error) during the handshake or under an established
  connection ended it with `TlsException.Protocol` "transport closed during the TLS handshake" or "transport closed
  without close_notify (truncation)" without a cause: ktor-io reads a channel failed with a cause as one that ended, and
  the failure was dropped. It is now the exception's cause, so the application and the Ktor server's
  `tlsHandshakeFailed` event see it.
- Ktor server: a TLS handshake that completed just as the request-head deadline (`requestHeaderTimeout`) fired,
  or as the engine stopped, was dropped by the deadline (kotlinx's `withTimeoutOrNull` discards a result that arrives
  with its timeout) and its TLS session was never closed: one native TLS session per occurrence for the rest of the
  process. That session is now aborted. And a connection accepted just before a hard stop (the grace period ran out)
  whose coroutine was launched on the already cancelled connection scope never ran: neither its handshake nor its close,
  so the socket stayed open and kept its `tcp { maxConnections }` and `tcp { maxConnectionsPerIp }` slot. Such a connection is now
  aborted, which releases the slot.
- Ktor server: a graceful stop with a grace period under about three seconds (Ktor's default `stop(500, 500)`,
  `stop(1000, 2000)`) never ended gracefully while a browser or curl kept an idle HTTP/3 connection open: after the stop's
  final GOAWAY the server waited three seconds for the client to close such a connection, so the stop always ran out its
  grace period and then cut what was left, aborting TCP connections that were still writing a response instead of
  draining them. During a stop the server now waits a quarter of the grace period (at most the three seconds, at least
  four smoothed RTTs); `stop(500, 500)` then ends gracefully on a low-latency path. The guide's
  [Graceful stop](docs/guide/ktor.md#graceful-stop) gives the timing and why `stop(500, 500)` may return before the
  sockets cut at the grace deadline are closed.
- Ktor client: a call made as the engine closed, which passed the engine's closed check just before `close()` and
  attached to the engine after its cleanup had started, went on against the closed pools and failed with
  `IllegalStateException` ("the client is closed") on HTTP/3, or an `IOException` from the closed selector on a TCP
  connect, instead of `ClientEngineClosedException`. The engine now checks again once the call is attached and fails it
  with `ClientEngineClosedException`.
- Ktor client: a WebSocket over HTTP/1.1 resolved its host under a connect timeout of its own and then started a fresh
  one for the wait for a pool slot and the TCP and TLS connect, so with a slow resolver it could take up to twice the
  connect timeout before the answer to its handshake was even awaited. Resolving and connecting now share one connect
  timeout, as for any other request; the answer to the handshake keeps its own, counted from the connection
  (documented in `connectTimeout` and the guide's WebSocket section).
- `ksl` C API: `ksl_udp_close` waited at most one second for a receiver still inside `ksl_udp_recv` and then freed the
  socket under it, and a receiver that had passed `ksl_udp_recv`'s closed check but was not yet counted was not waited
  for at all: a use after free for a direct C user (Kuicksilver's own Kotlin and Native layers never close while a
  receiver is inside). A receiver is now counted before it checks the closed flag again, and the close waits until every
  receiver inside has left, which the shutdown wakes at once.
- QUIC over `ksl_udp`: closing a socket while another thread was still inside a native call on it (a sender in a
  large batch, a descheduled receiver) spun the closing thread, usually an endpoint's loop thread, at full speed until
  the call returned. After a short spin it now sleeps a millisecond between looks.
- QUIC, `loops > 1` on macOS, iOS and Windows: the receiver of the socket a loop group shares held one `Dispatchers.IO`
  thread for the socket's whole life, so a process with many such endpoints could leave `Dispatchers.IO` (blocking file
  I/O, DNS) without a free thread. It now gives the thread back after a receive slice that brought nothing and after
  every 64 busy rounds, like the receive of a socket of its own.
- Ktor server on Kotlin/Native: a hard stop (the grace period ran out) cancels the listening socket's job and with it
  every accepted socket's; the close that followed launched its work inside that cancelled job, where nothing starts, so
  the descriptor of every connection open at the stop stayed open for the rest of the process (in-process restarts,
  tests, embedded servers). The close now runs in a cancelled job too and releases the descriptor.
- Kotlin/Native on Linux: TCP sockets (listening, connected, accepted) were made close-on-exec with an `fcntl` after
  `socket` or `accept`, so a fork and exec in another thread of the process in between inherited the descriptor (a
  connection or listening port kept open in the child). They are now created with `SOCK_NONBLOCK | SOCK_CLOEXEC`
  (`socket`, `accept4`). Apple has neither and keeps the `fcntl` right after the call.
- Ktor server: a request with content and `Expect: 100-continue` got its `100 Continue` only when the application first
  read the content (HTTP/1.1, HTTP/2), or never (HTTP/3), so a handler that waited before reading (an authentication
  round trip, a slow upstream) held the client's content back until the client's own wait ended. RFC 9110 §10.1.1 asks
  for "an immediate 100 (Continue) response" unless the head alone determines a final status: the 100 now goes out as
  the call is dispatched, on all three versions, and the statuses the engine decides from the head (400, 413, 425, 431,
  501) still go out without it. Content the handler then leaves unread is drained like any other unread body.
- Ktor server and client, HTTP/1.1: a field value with obs-text that is not valid UTF-8 (`filename="caf<E9>"` in
  Latin-1) reached the application with U+FFFD in place of those bytes, since Ktor's parser decodes field values as
  UTF-8; RFC 9110 §5.5 has a recipient treat obs-text as opaque data. Such a value now arrives byte for byte, each byte
  as the char of the same code (ISO-8859-1); a value that is valid UTF-8 is decoded as UTF-8 as before.
- Ktor engines, WebSockets (RFC 6455 sections 5.6 and 8.1): text messages and Close reasons were never checked as UTF-8,
  and 1007 was never sent; a Close reason of 123 invalid bytes failed Ktor's `CloseReason` check inside its session,
  which then ended with 1006 and sent no Close. A text message that is not UTF-8 as a whole (across fragments, after
  decompression) and a Close reason that is not now close the connection with 1007. The engines now decompress
  permessage-deflate themselves whichever extension negotiated it: with Ktor's `WebSocketDeflateExtension` too (by the
  parameters of the answer; Ktor's extension passes the plain frames on), so its messages are checked and limited as
  well (RFC 7692 section 6). A text message the application builds from bytes that is not UTF-8 is no longer sent: the
  session fails with `ProtocolViolationException` (by the engines, also for text Ktor's extension compressed, which they
  inflate on the side, and by `PerMessageDeflate` on any engine for a message it compresses). With an extension the
  application brings itself, text is not checked: its specification defines its payload. Migration: text messages
  reach Ktor's session in frames of at most 64 KiB, so a raw session (`webSocketRaw`) gets an uncompressed text message
  over 64 KiB as several fragments (`Frame.Text` with `fin = false`, then continuations), as it already did for
  compressed messages; Ktor's default sessions reassemble them.
- Ktor engines, WebSockets (RFC 6455 sections 5.5.1 and 7.4): a Close with 1005, 1015, a code below 1000, 1004 or one
  no specification defines was echoed with the same code, which no endpoint may send, and a Close with 1006 was not
  answered at all; a Close with a 1-byte body was answered with 1000. Each now closes the connection with 1002. A Close
  the application sends with such a code goes out without a code, and one whose reason is not UTF-8 without the reason.
- Ktor client, WebSockets over HTTP/3 (RFC 6455 section 4.1 step 2: "There MUST be no more than one connection in a
  CONNECTING state"): the per-host lock HTTP/1.1 WebSockets take was not taken over HTTP/3, so two Extended CONNECT
  handshakes to one host ran at once. A WebSocket over HTTP/3 now holds the lock (shared with HTTP/1.1, keyed by the
  URL's host name and the address of the QUIC connection it uses) from before its CONNECT until the server answered it or
  the attempt failed; over HTTP/1.1 the keys are the name, the addresses of the families the lookup answered with (one
  that stalls is not waited for past the 50 ms Resolution Delay) and, once the connection is up, its own address, so two
  WebSockets to one name, or to one address under any names, are never CONNECTING together; the
  answer must come within the connect timeout (`ConnectTimeoutException`), as over HTTP/1.1.
- Ktor engines, WebSockets (RFC 6455 section 5.2): a payload length not in its minimal encoding (126 with a 16-bit length
  below 126, 127 with a 64-bit length up to 65 535) was accepted; it now closes the connection with 1002.
- Ktor engines, WebSockets (RFC 6455 sections 5.4 and 5.5): a fragmented or oversized control frame and a data frame out
  of sequence were left to Ktor's readers, whose Kotlin/Native reader closes the session's `incoming` before it queues its
  1002, so an application closing at that moment sent 1000 first. The engines' guard now closes with 1002 itself.
- Ktor engines, WebSockets with Ktor's `WebSocketDeflateExtension` (RFC 7692 section 6.1): it compresses each fragment
  of a message on its own and sets RSV1 on every fragment, so a fragmented compressed message it sent was refused by a
  conforming peer. The engines now send such a message as an RFC 7692 one: each non-final fragment gets its
  0x00 0x00 0xff 0xff back, which makes the fragments one DEFLATE stream, and the continuations lose RSV1. A message in
  which Ktor's `compressCondition` left a fragment uncompressed cannot be sent so and fails with
  `ProtocolViolationException`; such a refusal before a frame's header ends the connection with a Close 1011 (RFC 6455
  section 7.1.7), one inside a frame already started resets it. The last piece of a text message is held back until
  the whole message is known to be UTF-8, so a peer never receives an invalid one whole.
- Ktor server, WebSockets: when the engine cannot read the `Sec-WebSocket-Extensions` of its own answer (an extension
  that answers to `permessage-deflate` with a parameter RFC 7692 does not define), the session cannot be checked; the
  client now gets a Close frame with 1011 and the application log a warning, instead of a connection that ends without a
  word.
- Ktor engines, WebSockets on Kotlin/Native (RFC 6455 section 5.4): Ktor 3.6.1's common writer sends every fragment of a
  message with the message's opcode, so a peer refused a fragmented message as a new message inside an unfinished one;
  the engines now send the later fragments as continuations.
- Ktor server, WebSockets (RFC 6455 section 5.1): `install(WebSockets) { masking = true }` made the server mask its
  frames, which a server must never do; its frames now always go out unmasked.
- Ktor engines, WebSockets (RFC 7692 section 6.1): RSV1 on a continuation or control frame was refused only when
  permessage-deflate was the one extension negotiated; with another extension next to it every bit passed. RSV1 is now
  checked whenever permessage-deflate is negotiated, and another extension implemented by an installed Ktor extension may
  use only the bits its factory declares.
- Ktor client, HTTPS records (new in this release): the A or AAAA records of one family alone in an answer no longer
  stand in for the whole address lookup of that name, which a resolver that omitted the other family's RRset (RFC 9460
  section 5.2) left without it, IPv6 on an IPv6-only network say. That family is still used at once (section 5), and
  the other family is looked up as well: its addresses join the Happy Eyeballs race whenever they come (RFC 8305
  section 3), all of them sorted by RFC 6724 (section 4: "the client MUST sort the addresses received up to this point
  using Destination Address Selection"). "No records" reached through a CNAME is cached no longer than the CNAME's TTL (it was kept for the
  SOA's negative TTL, RFC 2308 section 5, although the negative answer is about "the data field of the last CNAME", RFC
  2308 section 1, and a CNAME "may be cached" only for its TTL, RFC 1035 section 3.2.1). The record cache counts a TTL
  on both the monotonic and the wall clock and expires an entry once either has seen it pass: a wall clock stepped back
  no longer keeps a record, a forged one included, past its TTL, and neither does a device that slept (the monotonic
  clock stops in sleep on most platforms). A TTL with the top bit set in the record lists of Apple and Windows counts as
  0 (RFC 2181 section 8), as in a whole message; it was taken as 2^31 - 1. An alias target that is a CNAME is now
  resolved from the answer's own records (the RRset and addresses at the end of its chain), without a follow-up query;
  they were filed under the CNAME's target before, which resolution never asks for, and a TargetName on another
  TargetName's CNAME path was not filed at all. The KDoc of `HttpsRecordSource.Exchange` and the guide now say that the
  engine matches a response by its question, not its ID (the queries carry ID 0), so an exchange over plain UDP or TCP
  must set and check a random ID of its own.
- Interop tooling: the simulator's captures lost their last 0.1-0.25 s. `dumpcap` reads through libpcap with a 250 ms
  timeout, and on Linux packets reach it a block at a time; `tools/interop/sim-entrypoint.sh` forwarded the runner's
  SIGTERM (0.1-0.2 s after the client exits) at once, so the open block was never written. Most cells' captures ended
  18-72 ms before the client's last qlog event (the quic-go client's), and `kuicksilver-native->quic-go:zerortt` (the
  0.3.0 integration matrix) and `kuicksilver->quic-go:zerortt` went red when the whole second connection (about 55 ms)
  fell in that gap ("Expected exactly 2 handshakes. Got: 1"; 1 of 3 runs before the fix). The wrapper now waits 0.5 s
  before forwarding the signal, and a second signal neither shortens the wait nor is forwarded again: 8 of 8 runs of
  that cell green, every capture ending 8-628 ms after the quic-go client's last qlog event.

### Security

- TLS, CRLs (`AnchoredCa(roots, crls)`): a peer's certificate can no longer make the CRL check cost CPU in proportion to
  the configured CRLs times its distribution points (CVE-2026-121482). OpenSSL 4.1.0 built the full name of each relative
  CRL distribution point again for every CRL of the certificate's issuer that has an issuingDistributionPoint, before any
  signature on the path is checked, so an unsigned leaf under a configured issuer's name with about 4,400 of them (within
  the 100 KiB certificate list bound) took 27 ms of CPU per such CRL, 0.83 s against 32 (macos-arm64). The bundled
  OpenSSL carries an eleventh patch (`patch_11`, `openssl-4.1.0-crl-dp-dos.patch`; ADR-0019, owner decision
  2026-11-25), upstream's fix verbatim (openssl/openssl@54e14955ef, on openssl-4.1 as openssl/openssl@14a9f9ad6e; dropped
  when the pin moves to the first 4.1.x release that contains it, as soon as that ships): the names are built once per
  certificate, and a certificate with more than 16 relative distribution points fails verification when such a CRL of its
  issuer is configured (fail closed; no change without CRLs), with
  `VerifyReason.UnknownRevocationStatus` and the alert unknown_ca (48), as any configured CRL that cannot be used for the
  certificate: `ksl` reports OpenSSL's `X509_V_ERR_UNSPECIFIED` for that refusal, which would have been internal_error (80)
  and `VerifyReason.Custom`, as `X509_V_ERR_UNABLE_TO_GET_CRL` (`docs/guide/tls.md`, "Certificate revocation").
- HTTP/3, `content-length` as a framing value (RFC 9110 section 8.6, `Content-Length = 1*DIGIT`): the length the request
  and response streams frame by was read with Kotlin's `toLongOrNull` after a Unicode `trim()`, which takes `+5` as 5, `-5`
  as -5 and a value wrapped in no-break spaces as its digits, the parser differential of the request-smuggling class.
  The peer's fields were already refused unless `1*DIGIT` (`FieldValidator`), so no peer value reached it; the helper
  and the stream sites that read our own requests and responses now take ASCII digits only, and an application
  response with another value fails with `IllegalArgumentException` instead of being framed. The HTTP/2 and HTTP/1.1
  Content-Length parsers (`H2Fields`, both engines' `FramingFields`) were already strict; Ktor keeps applications from
  setting Content-Length as a header on the other engine paths.
- TLS client, must-staple on every trust path (breaking strictness, RFC 7633 sections 4.2.3.1 and 4.3.3, RFC 6066 section
  8): under every `RevocationPolicy` but `Off` the client now sends `status_request` and checks the stapled OCSP response
  on every trust path, not only where `ksl` verifies the chain: under `TrustConfig.Platform` on the JVM, Android, Apple and
  Windows, `Custom` and `Tofu` too, once that verifier said yes, against the issuer of the path it accepted (the platform's
  path, with an issuer it may have fetched), else the presented certificate whose key signed the leaf; a certificate that
  only copies the issuer's name and key identifier, or carries the leaf's own key, is never taken for the issuer. A certificate whose TLS feature extension lists `status_request` (must-staple) now fails there without a good
  staple (`VerifyReason.UnknownRevocationStatus`, alert 113), and a staple that says revoked or does not verify fails as
  on the `ksl` path (`Revoked`, `InvalidStatusResponse`). `RevocationPolicy.Off` turns both off. The ClientHello on those
  paths now carries `status_request`. A stapled OCSPResponse that only states an error (DER, one of the defined error
  statuses `tryLater`, `internalError`, `malformedRequest`, `sigRequired`, `unauthorized`, and no responseBytes; Apache's mod_ssl staples a made-up `tryLater` while
  its CA's responder is down) counts as no staple on every path, `ksl`'s verifier included (before 0.3.0 it failed there
  with `InvalidStatusResponse`): it carries no certificate status (RFC 6960 sections 2.3 and 4.2.1), as Firefox reads it.
  A normal certificate goes on under `StapledIfPresent`; a must-staple one, or any under `RequireStapled`, fails as without
  a staple (`UnknownRevocationStatus`). A successful response that is revoked, stale, foreign or forged, and any other
  staple (not DER, an undefined status, an error status with responseBytes), still fail; `RevocationPolicy.Off` is the way out for such a server.
- QUIC client: the server's Source Connection ID is fixed by its first Initial without exception (RFC 9000 section 7.2),
  and the peer's first connection ID is never replaced. Until now an Initial with nothing but ACK, PING and PADDING from
  the client's own DCID left the SCID open, so a later Initial from any other SCID, a forged one included (Initial keys
  are public), could still become the server's ID; the client now accepts fewer packets. The early end of a handshake
  whose ServerHello comes from another SCID sends nothing and needs a forger who saw the client's first Initial, who could
  already make the handshake fail (RFC 9000 sections 21.1.1.3 and 21.2), though it widens the window for that to the
  first CRYPTO when the server's first Initial carries none; through the Ktor client it suspends resumption to the host
  for a backoff, not HTTP/3 (`docs/spec/threat-model.md`, section 3.5).
- QUIC, receive memory (RFC 9000 section 21.7; the class of picoquic #2333, a receive bound that stops holding once the
  peer moved the window): the flow-control windows and the reassembly range limits were fixed ceilings, but a stream's
  reassembly buffer kept its allocation after the application read it: up to 1 MiB once drained, and its whole size,
  up to the 6 MiB stream window, when a gap was left and nothing more was readable, a stream nobody reads again. Flow
  control bounds what is unread at any one time, not what stays allocated, so a peer that pushed one stream window
  through each of its `max_streams` streams (one byte at the end of the window, then the rest) left the connection
  holding the sum of its stream windows: 50 MiB with the defaults against a 15 MiB connection window, and up to
  `max_streams` x 6 MiB with windows the auto-tuning grew. The bytes the reassembly buffers hold allocated are now
  counted per connection; above `maxConnectionWindow` a read leaves its stream's buffer no larger than twice what it
  still holds (twice, so that a stream read a little behind its window does not shrink and regrow on every read) and
  lets a drained one go, and a finished stream gives its buffer back. The allocation stays within the connection window
  plus twice what the streams hold unread (`stream.ReassemblyRetainedCapacityTest`); below that bound
  nothing changes. The fuzz invariant of every stream manager checks the count and the bound.
- TLS, `TrustConfig.Tofu` (the class of curl #23475, host verification where peer verification is off): Tofu validates
  no chain and the shared matcher refused a certificate for another name, but the key was stored for the host before
  that check: a server presenting another name's certificate on first contact (a default virtual host, or someone on
  the path) left its key pinned for the host, and the host's own key failed with `PinMismatch` from then on. The name
  is now checked before the store is touched (`VerificationNegativeTest.negative_tofuStillChecksTheNameOnFirstUse`). The
  store was also written when the chain was verified, before the server's CertificateVerify and Finished: a first contact
  that failed after its certificate still pinned the presented key. It is now written only once the handshake completed,
  over TCP and QUIC (`TofuCommitTest`), and before the connection is handed to the application: a connection closed at
  once still leaves its pin, a store that fails fails the connection over QUIC as over TCP, and one that does not answer
  is cancelled at the handshake timeout, which fails the connection (`api.TofuRuntimeTest`); a store that returns as the
  timeout fires counts as stored. A `put` that ends in `withContext` (or another scope builder) can still write the pin
  and end with the cancellation when the timeout fires as it completes: the connection then fails, and the next one
  finds the pin (`TofuStore.put`).
  A QUIC session reports what it holds through the new experimental `QuicTlsSession.trustCommitPending` and
  `commitTrust`, which the connection runtime calls; a transport that drives the session itself must call it after
  `HandshakeDone`, or a `Tofu` first contact is accepted and never remembered.
- QUIC client, compatible version negotiation (RFC 9369 section 4.1, RFC 9368): until it had Handshake keys the client
  switched its Initial keys to the version of every server Initial of another configured version, before the packet was
  authenticated, so one that did not decrypt left the switch in place (RFC 9000 section 12.2: such a packet is discarded),
  and a later Initial of the original version (from anyone who saw the client's first Initial) switched it back. A packet
  of another version now switches the keys only if it decrypts under them, and the version is fixed by the first such
  packet ("the first long header Version field that differs from the original version") or by a CRYPTO frame from the
  server; server Initials of any other version are dropped from then on (`core.ClientVersionLatchTest`). A Handshake
  packet of another version that comes before the server's first Initial switches nothing and waits for the Handshake
  keys, as before. One forged ACK-only Initial of another configured version from someone who saw the client's first
  Initial now fixes that version, as RFC 9369 section 4.1 reads (threat model 3.9).
- No Don't Fragment, no QUIC (RFC 9000 section 14). A UDP socket that cannot set DF on any of its traffic is not used:
  `DatagramIo.open` and `QuicEndpoint.bind` throw the new `QuicException.DontFragmentUnavailable` (its `family`, the new
  `IpFamily`, null for the whole socket: the JVM without `ksl` below JDK 19, Android or a system refusing both DF modes, the
  Kotlin/Native portable `ktor-network` socket, which used to send without DF, while a port in use there is still the
  accelerated socket's refused bind, an `IOException`, as is a bind address that does not resolve (naming it, not the
  stale errno `ktor-network` reports after `getaddrinfo` fails); an accelerated socket without DF is not
  used either, while one whose system refuses probe mode now gets DO mode, `KslUdpSocket.DF_DO`). On a socket with no DF
  for one address family (a dual-stack socket's IPv4 or IPv6 half, IPv6 on an AF_INET socket), datagrams to that family
  are not sent: that path closes, or on the active path the connection ends with a CONNECTION_CLOSE of NO_VIABLE_PATH
  caused by the refusal (such datagrams count in the new `EndpointStats.datagramsSkippedNoDf`, not in `datagramsSent`); a
  server drops datagrams from that family before any state or stateless answer, also with `loops > 1`, and
  `QuicEndpoint.noDontFragmentFamily` names it. `ConnectionLost.NoViablePath` can now carry a cause. The Ktor client
  sends such calls over TCP at once, with the new `FallbackReason.QuicUnavailable`; a server endpoint does not start; the
  Ktor server serves HTTP/1.1 and HTTP/2 only ("HTTP/3 is not served on port ..."), or HTTP/3 for one family without
  Alt-Svc for the other, and reports it in the new `KuicksilverApplicationEngine.http3Status`. There is no opt-out.
- Certificate revocation on OpenSSL 4: an `AnchoredCa` whose root is an intermediate CA is checked against its issuer's
  configured CRL again (OpenSSL 4 stops a partial chain's CRL checks below its trust anchor, where 3.5 checked the anchor
  as well): an intermediate that the root's CRL revokes fails with `VerifyReason.Revoked` (alert 44), and a configured
  CRL of an issuer that is not among the roots still fails closed (alert 51), as documented. A responder certificate
  whose validity time does not parse is refused (OpenSSL's `X509_cmp_time` reported it as neither before nor after).
- HTTP/3 server, Rapid Reset by STOP_SENDING (CVE-2023-44487; RFC 9114 section 10.5): the request-reset budget counted
  only the client's RESET_STREAM. A complete request whose response the client stopped at once with STOP_SENDING
  cancelled its handler in the Ktor engine and gave its stream back without spending anything, and a reset the client
  sent after our own STOP_SENDING was not counted either, so floods of either kind went on at full speed without end. A
  request the client abandons before our complete response, by RESET_STREAM or by STOP_SENDING, now spends one token of
  the budget, once per request whichever came first; a flood ends with `H3_EXCESSIVE_LOAD`. A request the server resets
  because the client made it malformed (MadeYouReset, CVE-2025-8671: a head without its pseudo-header fields, content
  that does not match its content-length, trailers too large) now spends a glitch token, as on HTTP/2; trailers cancelled
  at their deadline do not. The Ktor engine also ends a request whose handler it cancelled before the handler began its
  work (STOP_SENDING and a reset with `H3_REQUEST_CANCELLED`); before, such a request stayed open with its receive half
  for the connection's life and held off the GOAWAY idle close. Released 0.2.1 has no limit on HTTP/3 request resets at
  all (see the Rapid Reset entry below).
- Ktor client, CONNECT-UDP proxy (`proxies { connectUdp }`): the QUIC connection to the proxy itself was set up with the
  origin's TLS configuration. The origin's client certificate (`identity`) was presented to the proxy, a third party
  (CWE-200); the origin's pins (`TrustConfig.Pinned`) were applied to the proxy, which failed every request through a
  proxy with another key, and the origin's `TrustConfig.ExpectedName` replaced the proxy's name, so a proxy presenting
  the origin's certificate passed; `proxies { tls { } }` was ignored. The proxy hop now takes the proxy's own configuration exactly
  as the TCP hop to an `https://` proxy does (ADR-0023): the proxy's host as SNI and reference identifier, `proxies { tls { } }` or
  by default the origin's trust without its `ExpectedName` and pins, no client certificate unless `proxies { tls { } }` sets one,
  ALPN `h3`; a failed handshake with the proxy is `ProxyTlsException`, also when a later address of the proxy only timed
  out before any address completed its handshake. Its connections leave from endpoints of their own whose session cache is the proxies' (they resume no session, a
  full handshake each time). The origin's connection inside the tunnel keeps the
  origin's client certificate, trust and pins (threat model 3.29). 0.2.x is not affected: CONNECT-UDP is new in this
  release.
- Ktor client on Android: the Network Security Configuration was asked about the host of an `http://` or `ws://` URL
  as written, and it matches strings, so a rule for an address was passed by another spelling of it (`127.1` or
  `2130706433` for `127.0.0.1`, `[0:0:0:0:0:0:0:1]` for `::1`, `[::ffff:192.168.1.1]` for `192.168.1.1`). It is now
  asked about one spelling per address, which the refusal names too: an inet_aton-form IPv4 host as the dotted quad it
  names; an IPv4-mapped literal as its dotted quad, the address the connection goes to; another IPv6 literal in the text
  RFC 5952 recommends (lower case, no leading zeros, the longest run of zero groups as `::`), without its zone: the
  policy knows no interfaces, so a rule for `fe80::1` holds for `fe80::1%wlan0`. A host that has no such spelling now
  fails with an `IOException` before the policy is asked: a numeric host that platforms read differently (`010.0.0.1`,
  before a cleartext refusal), an IP literal that is no IPv6 address (before, the policy was asked about it as written),
  a host beginning with a dot (Android's policy threw `IllegalArgumentException` for it), and a name with non-ASCII
  characters, since the engine does not map an internationalised name to the A-label the rules name: the URL must carry
  the A-label. The [Ktor guide](docs/guide/ktor.md) lists the spellings. Pinned by `CleartextPolicyHostTest` and the
  `ClientH1Test` cleartext tests.
- HTTP/2 (RFC 9113 section 10.5; CVE-2019-9514, CVE-2019-9516, MadeYouReset CVE-2025-8671): two kinds of streams the
  peer makes us reset cost it nothing. A malformed request or response (section 8.1.1: missing or invalid pseudo-header
  fields, a zero-length field block, connection-specific fields, a content-length that does not match) is reset by the
  engine with PROTOCOL_ERROR, and that reset now takes from the glitch budget as the core's own stream errors do; and a
  request refused while the client's open and half-closed streams fill SETTINGS_MAX_CONCURRENT_STREAMS, once the
  SETTINGS carrying it were acknowledged (section 5.1.2: the peer knows the limit then), is a glitch too; one refused only
  because our handlers still hold streams the protocol has closed is not. Before, a client that read our RST_STREAM frames could send malformed requests
  without end, and one that let its 100 running requests finish between batches never had more than 4 x the limit
  refused in a row, so neither flood ended; both now end with ENHANCE_YOUR_CALM after the budget (10 000 by default).
  Refusals before our SETTINGS are acknowledged stay free. A driver's `reset` never throws when the budget runs out:
  the connection ends with the GOAWAY instead.
- HTTP/2 (RFC 9113 section 10.5, "Providing tiny increments to flow control in WINDOW_UPDATE frames"; "Implementations
  SHOULD track the use of these features and set limits on their use"): WINDOW_UPDATE frames were neither answered nor
  counted, so 100 000 increments of one byte went on without end. Each DATA frame we write on a window now allows one
  increment below 1024 bytes to it (at most 16 held); beyond those such an increment is a glitch. Readers that credit each
  frame they read, or what they read once their window is used up (Go's x/net/http2), stay free; larger increments stay
  uncounted, bounded by the 2^31 - 1 window.
- HTTP/3 server, Rapid Reset (CVE-2023-44487; RFC 9114 section 10.5): a request the client opened and reset at once (STOP_SENDING
  and RESET_STREAM) gave its stream's `MAX_STREAMS` credit back as soon as the transport was done with it, while the
  request's handler still ran, so a client kept any number of handlers running within a limit of 100 streams (measured
  against the Ktor engine before the fix: 101 handlers with 100 streams allowed, and growing). A request stream now
  counts toward the client's limit until the application is done with the request: in the Ktor engine until its handler
  returned; with `Http3Connection.acceptRequest` until the response ended (complete or abandoned), `reset` was called, an
  answer failed, or the application read the request body's failure. Every reset of a request stream by the client also
  spends a token of a reset budget of its own (1000, 33 a second; not for an H3_NO_ERROR reset after a complete response), so a reset flood ends
  the connection with `H3_EXCESSIVE_LOAD`. The Ktor engine cancels a handler once its client abandons the request
  (STOP_SENDING, a reset, or the connection lost) and its response was not yet sent in full. QUIC: a peer
  that reports `STREAMS_BLOCKED` at the limit we granted is told at once about streams that closed since our last
  `MAX_STREAMS`, or about the next one to close when none has, not only at the next half window.

- HTTP/3 (RFC 9114 section 10.5, RFC 9000 section 21.6): request heads that never completed were held without limit.
  Each request stream could park a HEADERS frame of up to 2 × `maxFieldSectionSize` read off the transport (its
  flow-control credit returned), with no cap per connection and no deadline before our own GOAWAY, so one client kept
  about 12.5 MiB and 100 readers for as long as it kept the connection alive. Now `Http3Settings.maxHeaderBlockTime`
  (new, 10 s, as `Http2Settings.maxHeaderBlockTime`) bounds every field section: a request head must be decoded within
  it of its stream's first byte or the stream is reset with `H3_REQUEST_REJECTED`, trailers and (on a client) response
  heads within it of their frame header or the request is cancelled with `H3_REQUEST_CANCELLED`; the connection lives
  on. A connection reads at most 8 × `maxFieldSectionSize` (512 KiB) of HEADERS frames at once: a frame's length is
  reserved before any of it is taken from the transport, and frames that do not fit wait with their bytes left in the
  stream's flow-control window. The client applies both to response heads. With WebTransport on, a server's
  WebTransport streams must send their signal and Session ID within the deadline too (else
  `WT_BUFFERED_STREAM_REJECTED`), and every peer's unidirectional stream its type (else `STOP_SENDING
  H3_STREAM_CREATION_ERROR`; spared only while its bytes so far can still be the type of a control or QPACK stream
  not seen yet, one such stream per missing type) and, for
  WebTransport, its Session ID. The Ktor server bounds `maxHeaderBlockTime` by `requestHeaderTimeout`.
- HTTP/3 (RFC 9114 section 10.5): reserved (GREASE) frames and empty DATA frames were free in any number, so 2 000 000
  two-byte frames in one request never ended the connection. The first 8 of a stream (and of the control stream) stay
  free; each further one spends a glitch token, as unknown frame types do, and a flood ends the connection with
  `H3_EXCESSIVE_LOAD`.
- Ktor server (RFC 9110 section 7.4): a request on a TLS connection (any scheme: the application sees it as https) whose
  host the certificate of its connection does not name was served like any other, so a browser that reuses a connection for another host of the same address (RFC 9113
  section 9.1.1, RFC 9114 section 3.3), or anyone who sends another `Host`, reached the application under the wrong
  identity. Such a request now gets `421 Misdirected Request` from the engine (with `Date`; neither routing nor the
  send pipeline runs), as does now the 425 for a non-replayable request a gateway forwarded from early data, which
  over HTTP/1.1 used to go through the application's send pipeline and over HTTP/3 lacked `Date` (RFC 9110 section
  6.6.1), over HTTP/1.1, HTTP/2 and
  HTTP/3; on HTTP/2 and HTTP/3 only its stream ends. The host is checked against the subjectAltName of the certificate
  that connection presented (the `sniSelector` choice, or the identity current at its handshake), as a client checks it:
  wildcards for one whole left-most label only, IP literals against iPAddress entries, never the subject CN, the port not
  at all. On a connector with an `sniSelector`, which may give each name its own client-certificate policy, a request
  must also be for the connection's SNI name (or an address when there was no SNI), else 421, so a request for a name
  that requires a client certificate cannot ride a connection that asked for none, nor the other way round (as nginx and
  Caddy do with client authentication). A plain connector answers 421 to an absolute-form `https://` target (no certificate secures it); origin-form
  requests are served as before. A connector whose every client is a trusted gateway turns the check off with the new
  `tlsConnector { allowMisdirectedHosts = true }`, or with the new `plainConnector { allowMisdirectedHosts = true }` in place of Ktor's
  `connector { }` (docs/guide/ktor.md, "Misdirected requests"). **Upgrading:** the check is on by default. A server whose
  certificate does not name every host and address its clients use (`localhost`, `127.0.0.1`, the server's IP) now
  answers those clients 421; the engine logs the reason at debug level (docs/guide/troubleshooting.md, "The server answers
  `421 Misdirected Request`"). Reissue the certificate; set `allowMisdirectedHosts` only on connectors that only a trusted
  gateway reaches. New for the check and for servers
  built on the libraries: `TlsConnection.localCertificates`, `QuicTlsSession.localCertificates`,
  `QuicConnection.localCertificates`, `TlsSocket.localCertificates` and `Certificate.matchesHost`.

- Ktor client, WebSockets (RFC 6455 section 4.1): the server's answer to the opening handshake was not checked beyond
  its status and its extensions, so a 101 from something that is no WebSocket server (a wrong or missing
  `Sec-WebSocket-Accept`, `Upgrade: h2c`, no `Connection: Upgrade`) or one choosing a subprotocol the client never
  offered opened a session; Ktor's plugin checks only the status and the engines never called its `verify()`. Over
  HTTP/1.1 the answer now needs `Upgrade: websocket`, a `Connection` with `Upgrade` and exactly one
  `Sec-WebSocket-Accept` that answers the key; over both protocols at most one `Sec-WebSocket-Extensions` and at most one
  `Sec-WebSocket-Protocol`, naming only what the request offered. Anything else fails the call with
  `WebSocketException` ("Handshake exception: …") before a session exists. The key is now the engine's own, 16 bytes from
  OpenSSL's CSPRNG and new for every connection: before, it was the key of Ktor's request body, sent again on every
  connection of the request (a followed redirect, a retry).
- Ktor engines, WebSockets (RFC 6455 section 10.4): uncompressed frames and messages had no size limit (Ktor's defaults:
  `Long.MAX_VALUE` on the server, `Int.MAX_VALUE` on the client), and Ktor's JVM reader allocates the whole length a
  frame header claims: a few 14-byte headers claiming 2 GiB each could exhaust a JVM or Android server's heap. Both
  engines now refuse a frame whose header claims more than `webSockets { maxMessageSize }` (new, 16 MiB by
  default), or that takes its message past it, with 1009 from the header, before any of its payload is read; a
  compressed message is held to the smaller of that and `PerMessageDeflate`'s `maxInflatedMessageSize` as it inflates,
  and a compressed frame whose header claims more than 8 times that plus 64 KiB is refused from its header too.
  Migration: an application that exchanges messages over 16 MiB must raise `webSockets { maxMessageSize }` (client engine and
  server engine configuration).
- Ktor client, WebSockets (RFC 6455 section 5.3): the masking keys came from `kotlin.random.Random` (Ktor's writers), which
  is not a CSPRNG on any platform, so an observer could predict the keys of later frames. Every frame the client sends is
  now masked with a new key from OpenSSL's CSPRNG.
- Ktor server, WebSockets (RFC 6455 sections 4.2.1, 4.2.2 and 11.3.1): a handshake without `Sec-WebSocket-Key` was
  answered 101 without `Sec-WebSocket-Accept`, and one with a key that is not 16 bytes, two keys, or a version other than
  13 was upgraded too. It now gets 400, or 426 with `Upgrade: websocket` for another version (400 over HTTP/3), with
  `Sec-WebSocket-Version: 13`, and the handler does not run; over HTTP/3 a missing `sec-websocket-version` is no longer
  made up as 13 (RFC 8441 section 5).
- Ktor client, proxy auto-configuration: a PAC script gets a `wss://` (and `https://`) URL as its origin only,
  `wss://host[:port]/`, on Apple platforms and Windows. A script found by WPAD, or fetched from a plain-`http` PAC URL,
  is code from the local network, and it can send what it is given out through `dnsResolve("<data>.attacker.example")`:
  a token in a WebSocket's path or query would leak (the class of CVE-2016-3763 in Android and CVE-2016-5134 in Chrome,
  which strip the same way since 2016; Firefox strips the path of every URL). This departs from RFC 6455 section 4.1,
  whose PAC rule asks for the resource name (an owner-approved security deviation; `ws://` URIs still reach the script
  whole). `engine { pacFullWebSocketUrl = true }` (*experimental*) gives the whole `wss` URI to the script the system
  settings name, given inline or by an `https://` or local `file:///` URL, never to one WPAD found or one fetched over plain
  `http://`
  ([Proxies](docs/guide/ktor.md#proxies), [RFC 6455 §4.1](docs/spec/rfc/6455.md#s4-1-connecting-through-a-proxy)).
  The development builds before this passed every script the whole `wss` URI.
- JVM: the native library extraction (`KslLoader`) no longer creates anything under the umask or an inherited ACL
  (CodeQL `java/local-temp-file-or-directory-information-disclosure`). The library was written through
  `File.createTempFile` (mode `0644` under the usual umask) and missing parents of `-Dkuicksilver.native.workdir` were
  created the same way; every file and directory is now owner-only in the creating call (`rw-------` for the library,
  `rwx------` for directories), and the library goes through a new `O_CREAT | O_EXCL` temp file and an atomic rename.
  A library is reused only when the process user owns it and nobody else may write it. No setup that loaded before is
  refused now; risks are mitigated or logged as warnings (`System.Logger` `io.kuicksilver.native`, by default
  `java.util.logging` on standard error)
  ([troubleshooting](docs/guide/troubleshooting.md#kslexceptionnativeload-or-kslloaderavailability-is-unavailable)):
  - Windows checked nothing beyond "is a directory": in a temp directory where other users may create files (a
    service's `C:\Windows\Temp`) another user could plant the library and change it between the hash check and
    `System.load`. The work directory now gets an ACL with one entry for the process user. A default directory with
    another owner, a junction or an ACL still granting others is replaced by a new private directory for the process;
    for `-Dkuicksilver.native.workdir` that is a warning. An elevated process uses `kuicksilver-native-<user>-admin`, so
    elevated and normal runs no longer share a directory whose files belong to the Administrators group. A library that
    cannot be replaced because another process has it loaded is written under a name with its hash.
  - When a directory above `<java.io.tmpdir>/kuicksilver-native-<user>` lets another user rename it (writable by others
    without the sticky bit, as an `emptyDir` at `/tmp` is, or owned by another user), the library goes to
    `$XDG_RUNTIME_DIR` or the user's cache directory instead, else stays in the temporary directory with a warning.
  - A default directory created first by another user, or a link there, gives a new private directory for the process
    instead of the `IntegrityMismatch` of 0.2; an explicit `-Dkuicksilver.native.workdir` is still refused. Such a
    directory is removed at exit, or on Windows (a loaded library cannot be deleted) by a later start.
  - The process user is now the owner of a file it creates, so a uid without a passwd entry (a container's
    `runAsUser`) no longer fails with "the user of this process cannot be determined" when `java.io.tmpdir` is
    read-only.
- C tests and the `ksl` fuzz harness write their files with mode `0600` and `O_NOFOLLOW`, and the fuzz driver checks
  a corpus file on its open descriptor instead of by name (CodeQL `cpp/world-writable-file-creation`,
  `cpp/toctou-race-condition`).
- Ktor client, HTTPS records (new in this release): reading a DNS answer took time cubic in the number of its records
  with distinct TargetNames, and nothing interrupted it: one answer of 64 KiB from a hostile or spoofed resolver (the
  system resolver over plain DNS, or an `HttpsRecordSource.Exchange` server, with no size limit there) held a thread
  for over a minute per lookup, and the lookup's timeout could not stop it. The read is now linear in the message: each
  TargetName is walked once and each owner's RRset parsed once, a message over 65535 bytes is refused (RFC 8484 section
  6: "This media type restricts the maximum size of the DNS message to 65535 bytes"), at most 16 CNAMEs per name and 16
  other HTTPS RRsets per answer are followed, a record's `mandatory` keys are checked in one merge pass, and the read
  checks the lookup's coroutine every 64 units of work, so the timeout and cancellation stop it. At most 32 ServiceMode
  endpoints of an RRset are tried, so a forged RRset cannot turn one request into thousands of connection attempts, and
  the record cache holds about 1 MiB at most each of records and addresses (an estimate of the objects' size), and no RRset or address list of over 64 entries.
  The `client.svcb` fuzz target checks the parse bounds.

## [0.2.1] - 2026-11-04

**Withdrawn.** Its Kotlin/Native artifacts contain a local build path; their removal from Maven Central has been
requested. Use 0.3.0.

### Added

- Supply chain (`docs/release.md`, "Supply chain: SBOM and provenance"): a CycloneDX 1.6 SBOM of every publication
  (64 documents: each platform publication, each module, the BOM), with the statically linked OpenSSL (version, tarball
  SHA-256, CPE, configure flags) and the `ksl` shim as components, checked against the CycloneDX schema; and an in-toto
  / SLSA provenance v1 statement (source commit, toolchain pins, OpenSSL tarball and configure flags, SHA-256 of every
  published file), signed with the release key. `local-release.sh` makes both, dry run included; they are attached to the GitHub release
  and not uploaded to Maven Central, so the deployment's file count is unchanged. The provenance reaches SLSA Build
  Level 1, not more: it is produced and signed on the machine that builds.
- Verifying a release (`docs/verifying.md`): `tools/verify/verify-release.sh <version>` downloads a version from Maven
  Central, checks every file's signature against the pinned release key and Central's `.sha1`, checks the GitHub
  release's SBOM and provenance when present (signatures, every subject digest, the source commit against the tag), and
  rebuilds from the signed tag the native libraries this host can build (on macOS: the two macOS JNI dylibs, the static
  archives of the Apple and Kotlin/Native Linux cinterop klibs, the three Android `libksl.so`), comparing them byte for
  byte with the published ones; `--offline <dir>` reads a local repository. The Linux and Windows JNI libraries and the
  Kotlin/Gradle outputs are reported as not rebuilt, with the reason. `tools/verify/verify-release-test.sh` (in the local
  gate) runs it on fixtures without network. The page also covers Gradle dependency verification for `io.kuicksilver`.
  The tag must be signed by the release key before anything is compared with it or built from it; from 0.2.1 a missing
  SBOM or provenance fails, and a file that does not download, a missing `.sha1` or a server-supplied name that is not
  a plain name (BOM, module file, directory listing, provenance subject) fails rather than being skipped.
- `context7.json`: the configuration of the Context7 documentation index (what it reads, a description, rules for coding
  agents, the 0.2.0 tag), and a release step that keeps it on the newest published version (`docs/release.md`).
- `docs/stability.md` and `SECURITY.md` state that Kuicksilver is not FIPS-certified and that the bundled OpenSSL is
  built without the FIPS provider; every release build checks the latter (`tools/check/openssl-no-fips.sh`).
- `docs/benchmarks.md`: a published benchmark table — the QUIC Interop Runner's goodput and crosstraffic, CPU time per
  transferred GB (cgroup accounting per container, over a plain router) and handshakes per second, for the JVM and
  Kotlin/Native interop images against quiche, quinn and msquic, with the method, the raw data (`docs/benchmarks/`) and
  the caveats (one Apple Silicon host; the amd64 peer images run under emulation, calibrated with an amd64 build of
  our own endpoint). `tools/bench/run-table.sh` regenerates it.
- Interop tooling: `KSL_INTEROP_TAG` makes `build-image.sh` and `run-local.sh` build and run
  `kuicksilver-interop[-native]:<tag>` instead of `:local`.
- Benchmark tooling: `KSL_BENCH_JAVA_OPTS` hands JAVA_OPTS to the JVM server of `tools/bench/cpu-transfer.sh` and
  `handshakes.sh` (a JFR recording into `/profile`, which is `$KSL_BENCH_WORK/profile`); `ksl-ctx-bench.sh` reports the
  server's share of a handshake with the hybrid X25519MLKEM768 key share and with X25519 alone; `kuicksilver-bench` has
  a `macosArm64` target and a `core` configuration (`CoreThroughputBenchmark` with the Null and the `ksl` crypto), and
  the interop endpoint a `macosArm64` executable, to profile Kotlin/Native with `sample` or Instruments
  (`docs/benchmarks.md`, "Profiling").

### Changed

- Ktor 3.6.1 (was 3.6.0). It fixes KTOR-9959, ktor-network's JVM socket writer spinning at 100 % CPU when a write
  answered 0, which the engines never used (their JVM sockets have their own writer, which stays). Applications on Ktor
  3.6.0 keep working: Kuicksilver supports Ktor 3.6.x.
- QUIC client (behaviour): when the server rejects a 0-RTT that carried anything (a stream opened before the handshake
  completed), the connection now closes with `QuicException.ConnectionLost.ZeroRttRejected`, which every such stream
  fails with, and nothing of them is sent again in 1-RTT. RFC 9001 section 4.6.2: "When 0-RTT is rejected, all
  connection characteristics that the client assumed might be incorrect ... The client therefore MUST reset the state of
  all streams". Before, the transport sent their data again in 1-RTT whenever the ALPN and the new limits allowed it. A
  connection that offered 0-RTT and opened nothing before the handshake goes on as before (except under
  `EarlyDataState.Required`), and `ConnectionEvent.EarlyDataRejected` is emitted only for it. The HTTP/3 layer reports
  the rejection as that `ZeroRttRejected`, never as a graceful end after a GOAWAY, and the Ktor client with
  `http3 { earlyData = true }` sends the requests of such a connection again once, on a new connection without 0-RTT,
  over HTTP/3 (`KuicksilverEventListener.retry`), a request with a streamed body that was waiting for the handshake
  too (its body was never touched); before, they fell back to HTTP/1.1 and the alternative was marked broken, which a
  rejected 0-RTT no longer does.
- Ktor client, HTTP/1.1: a response `Content-Length` with leading zeros (`0000000000000000000005`) is read as its value
  instead of failing as invalid when it has more than 18 characters (RFC 9110 section 8.6: "Any Content-Length field
  value greater than or equal to zero is valid"). A valid length of 10^18 bytes or more still fails the response, now
  with a `ParserException` that names it as this client's limit, not as an invalid length.
- Ktor server, HTTP/1.1 (behaviour): the engine answers `501 Not Implemented` (with `Connection: close` and the text
  "This server does not support CONNECT tunnels.") when the application answers a CONNECT with a 2xx, and logs a
  warning in the application log. A 2xx to CONNECT says the server "will switch to tunnel mode immediately after the
  response header section" (RFC 9110 section 9.3.6), and the engine cannot tunnel: the handler gets no connection.
  Before, the 2xx went out framed as an ordinary body and the connection served the next request, so the client's
  tunnel bytes were read as requests. The connection still closes after every CONNECT (RFC 9931 section 8).
  Tunnelling is planned for 0.3.0.
- QUIC: a lost connection no longer takes the bytes a peer sent before it (`QuicStream.input`): what was received is
  still read, up to the FIN when it came too (then the stream ends cleanly), and only then do reads fail with the
  `QuicException.ConnectionLost`. Before, every read failed at once, even with the whole stream received. A reset still
  fails the reads at once.
- HTTP/3 server: `QuicConfig.defaultStreamErrorCode` left at its default 0 (no HTTP/3 error code; a client reads it as
  H3_NO_ERROR, RFC 9114 section 9) becomes H3_REQUEST_REJECTED for `Http3Endpoint` and the Ktor engine's HTTP/3 side. It
  is the code of a request stream the QUIC layer gives up before the server saw it, which a client may then retry
  (sections 4.1.1 and 8.1); every stream the HTTP/3 layer handled is reset with a code of its own. A code set
  explicitly is kept.
- Ktor client: `Http3DiscoveryMode.H3Only` now fails an `http://` or `ws://` request with
  `UnsupportedOperationException` ("HTTP/3 needs an https URL") instead of sending it over cleartext HTTP/1.1. HTTP/3
  exists only for the `https` scheme (RFC 9114 section 3.1), and the mode promises HTTP/3 or a reported failure, never
  TCP.
- Ktor client: `Http3DiscoveryMode.H3Only` with a proxy configured now fails each `https` request with
  `UnsupportedOperationException` ("HTTP/3 cannot go through the configured proxy"), without contacting the proxy.
  It used to send the request over HTTP/1.1 through the proxy, silently breaking the mode's promise (HTTP/3 or a
  reported failure, never TCP); HTTP/3 cannot go through a proxy, as UDP through an HTTP CONNECT (CONNECT-UDP, RFC
  9298) or SOCKS5 proxy is not supported. `Auto` and `Preferred` with a proxy keep using HTTP/1.1 through it.
- QUIC performance, client and server (`docs/benchmarks.md`, "0.2.1: before and after"; `tools/bench`, 2026-10-21
  against the 2026-10-20 run of `c08bc57b`). Client CPU per GB: from quinn's interop server 18.2 → 8.4 s (JVM) and
  9.1 → 7.4 (Native), from quiche's 13.9 → 5.9 and 12.2 → 5.3, Kuicksilver against itself 6.7 → 4.9 and 5.4 → 3.6.
  Server CPU per GB 3.9 → 2.7 s (JVM) and 5.4 → 3.5 (Native); per handshake 1.06 → 0.95 ms and 0.92 → 0.79 ms (1390 →
  1524 handshakes per second on Native). No bulk transfer got slower, and the runner's goodput and crosstraffic
  cells are unchanged within their spread (one crosstraffic cell measured again, 16 interleaved rounds per image).
  - The receive path. A receive went to `Dispatchers.IO` to wait for the socket and came back to the endpoint loop:
    two thread hand-offs per receive batch, which cost more than the QUIC work when a batch holds a few datagrams (a
    sender whose datagrams arrive spread out, paced or one `sendmsg` each, as quinn's and quiche's interop servers
    send: 18 s of CPU per GB for the JVM client from quinn's server, half of it system time), and most on
    Kotlin/Native, whose IO dispatcher is a pool of its own. While datagrams keep coming, the loop now reads the
    accelerated socket on its own thread: what is queued, or what arrives within 1 ms and before the loop's next timer
    (not on Windows, whose 1 ms poll waits a 15.6 ms tick); the loop's queued work still runs after every 16 datagrams
    or 1 ms, and a multi-loop server's forward loop yields after every 16 forwarded datagrams too. The loop's own
    dispatcher can therefore block for up to 1 ms; on a caller-supplied `QuicEndpointConfig.dispatcher` the loop takes
    what is queued and never waits, as other work shares that thread (two endpoints on one dispatcher would otherwise
    each hold up the other's sends for 1 ms per quiet gap).
    `ksl_udp_recv` calls `recvmsg` before `poll` (Linux, Android, Apple; Windows still polls first), so a datagram
    costs one system call instead of two. The acknowledgement policy was not the cause and is unchanged: an ACK per
    receive batch of at least two ack-eliciting packets, at once after a gap; the packet numbers quiche and quinn skip
    on purpose cost at most one ACK each (`AckTrackerTest.skippedPacketNumbersCostAtMostOneAckEach`).
  - Kotlin/Native: `PacketBuffer`'s per-byte `get` and `set` check the index inline instead of calling the shared range
    check with a `String` argument, which Kotlin/Native compiled into a call per byte: the core benchmark
    (`CoreThroughputBenchmark`, in-memory loopback) moves 27 % more data per second with the Null crypto and 15 % more
    with AES-GCM. `WireReader` and `WireWriter` build their exceptions out of line for the same reason.
  - The endpoint's timer waits with `select { onTimeout }` instead of `withTimeoutOrNull`, whose expiry created and threw
    a `TimeoutCancellationException` (on Kotlin/Native a stack trace and a C++ unwind) at every timer.
  - A connection starts its DATAGRAM sender coroutine with its first datagram instead of at creation, so a connection
    that sends none does not throw a `CancellationException` through it when it ends.
- Interop endpoint (benchmark numbers): the hq server streams a file in 1 MiB writes instead of reading it whole (a
  1 GiB array and two copies per request, 0.9 s/GB of the JVM server's CPU), and forgets a connection when it ends
  instead of keeping every connection in a list it copied on each accept (a growing copy per handshake and 340 MB of
  heap after 13 000 connections on the JVM).
- POM: `<scm><connection>` is `scm:git:https://github.com/kuicksilver/kuicksilver.git` in every module's POM and the
  BOM's, was `scm:git:git://...`. GitHub turned the unauthenticated `git://` protocol off in 2022, so tools that read
  the POM's SCM connection (Maven's SCM plugins, dependency dashboards, source links) could not reach it.
- HTTP/3: a QUIC configuration that lets the peer open fewer than three unidirectional streams is refused with
  IllegalArgumentException instead of being used: by `Http3Endpoint.bind` (server), `connect` and `connectEarly`, by
  the Ktor server when it starts with `http3` on, and by the Ktor client engine when it is created (unless its discovery
  mode is `H1Only`). RFC 9114 section 6.2: the transport parameters "MUST allow the peer to create at least three
  unidirectional streams" (its control and QPACK streams); a peer of such a configuration could not start HTTP/3, and a
  Kuicksilver peer now closes the connection after three seconds. A configuration that used to start now fails fast;
  the value is not raised quietly.

### Fixed

- Ktor engines on Kotlin/Native: the TCP sockets they open and accept have `TCP_NODELAY` on, as on the JVM. With
  Nagle on, a request or response whose head and body went out in separate writes waited for the peer's delayed ACK
  (about 40 ms on Linux). ktor-network 3.6.1 fixed the same gap in its own accepted sockets (KTOR-10005).
- QUIC: an empty DATAGRAM (RFC 9221 section 4 allows a zero-length payload) queued behind one that filled the
  packet no longer overflows it. `DatagramPacketWriter.remaining` is 0 both when an empty payload fits and when no frame
  fits, and `write` wrote the 2-byte frame into the 0 or 1 byte left, which threw on the endpoint loop. `write` now returns
  false when the frame does not fit, and the datagram goes in the next packet. Found by the `connectionNull` fuzz target.
- Ktor server, HTTP/1.1: a request whose `Content-Length` has 19 or more significant digits (10^18 bytes or more)
  gets `413 Content Too Large` and the connection closes, instead of 400: RFC 9110 section 8.6 says "Any
  Content-Length field value greater than or equal to zero is valid", so such a length is too large to process
  (section 15.5.14), not invalid. Leading zeros no longer count towards the digits (`000000000000000000005` is 5).
- HTTP/3 client: a server that sends GOAWAY and closes with `H3_NO_ERROR` at once no longer fails `Http3Endpoint.connect`
  or `Http3Connection.client` now and then. When both arrived in one receive batch, the close could end the session before
  the control stream's GOAWAY was applied, and the start failed with "H3_NO_ERROR from Peer" instead of returning the
  connection with `goAwayReceived` set. The start now lets the control stream's reader finish what the server sent before
  its close (at most one second) before it decides (RFC 9114 section 5.2), also when the control stream came in the same
  batch and had not been accepted yet; a close before any control stream decides at once.
- QUIC on Kotlin/Native: a connection and an endpoint no longer each leak a small native buffer (the receive path's
  placeholder and the connection ID registry's key scratch were allocated outside the heap and never freed), which grew
  RSS by about 3 MB per hour under the soak's churn. `EndpointCore.close` also frees the endpoint's own buffers and keys
  when a connection's release throws.
- HTTP/3: a connection the peer closed (H3_NO_ERROR after GOAWAY, an idle timeout, a stateless reset, the client's own close on a rejected 0-RTT) is no longer
  reported now and then as a local `H3_INTERNAL_ERROR`. A session coroutine that failed with ktor-io's wrapper of the
  loss (a `ClosedWriteChannelException` whose cause is the `ConnectionLost`) could run before the session saw the
  transport's end and closed with `H3_INTERNAL_ERROR`, which the Ktor client also took as a reason to mark the
  alternative broken. A failure caused by the session's own lost transport now leaves the end to the transport's close;
  a `ConnectionLost` of another connection (a handler relaying elsewhere) is still an internal error.
- QUIC client: the server's first Initial fixes its Source Connection ID, an ACK-only one too (RFC 9000 section 7.2,
  "MUST discard any subsequent packet ... with a different Source Connection ID"); before, an Initial without CRYPTO
  left the SCID open and a later one with another SCID was still adopted. The one exception is msquic's: an Initial with
  nothing but ACK, PING and PADDING whose SCID is the client's own DCID (msquic's connection sends from it until it has
  the whole ClientHello) is processed, its ACK included, without fixing the SCID or recording its packet number.
- HTTP/3 client: a server that sends GOAWAY before the client's SETTINGS went out (it is stopping right after the
  handshake) no longer makes `Http3Endpoint.connect` and `Http3Connection.client` fail with "closed locally with
  H3_NO_ERROR" (the client's own idle close after GOAWAY, RFC 9114 section 5.2). The connection is returned with
  `goAwayReceived` set, and a request on it fails with the retry-safe `Http3Exception.RequestNotProcessed`; likewise when
  the server's own `H3_NO_ERROR` close after its GOAWAY comes first (RFC 9114 section 5.2 lets it close at once). Only
  these graceful ends are passed over: a protocol error after the GOAWAY (a second SETTINGS, `H3_FRAME_UNEXPECTED`) or
  the server's own error close still fails the start.
- HTTP/3: a response or request body whose stream came whole (its FIN and every byte before it) before the peer's
  CONNECTION_CLOSE is read whole however late its reader runs or the application reads it (RFC 9000 section 3.2, "Data
  Recvd"). The one-second drain grace after a lost connection cut such a reader too, and a response body reader started
  between the session's end and the cancellation of its scope was cancelled with it: the body ended with `H3_NO_ERROR`
  from the peer instead of the bytes (`ConnectionEndTest` on Linux, Windows, a loaded Android 7 emulator, macOS under
  memory pressure). The grace now applies only to readers of streams cut short, and a field section waiting for a
  dynamic-table insert fails once no insert can arrive any more instead of waiting. Whether a stream came whole is
  decided when the transport is gone, not at the HTTP/3 close: after a local close the last DATA and FIN may still
  arrive, and an unread body that came whole that way no longer kept the session waiting for the application.
- HTTP/3 client: a response stream that ends without HEADERS fails the request with `Http3Exception.MessageError` and
  aborts the stream with `H3_MESSAGE_ERROR` (a response without `:status` is malformed, RFC 9114 section 4.1.2). It
  was `Http3Exception.Protocol` with `H3_REQUEST_INCOMPLETE`, which section 8.1 defines for an incomplete request.
- HTTP/3: a request's `te: Trailers` (any case) is accepted; transfer coding names are case-insensitive (RFC 9110
  section 10.1.4), and only the exact lowercase `trailers` passed, so such a request was reset with `H3_MESSAGE_ERROR`.
- HTTP/3: the QPACK encoder-stream string ceiling follows the configuration: min(`qpackMaxTableCapacity`,
  `maxFieldSectionSize`), at least 64 KiB (at most 256 MiB), as RFC 9204 section 7.4 asks. It was a fixed 64 KiB, so with
  a raised table capacity and field-section limit a peer inserting a larger field into the dynamic table closed the
  connection with `QPACK_ENCODER_STREAM_ERROR`, though the same field sent as a literal was accepted.
- HTTP/3 server: a PRIORITY_UPDATE for a request stream the transport has opened but whose HEADERS have not arrived
  yet (a reordered stream 4 behind stream 8, or a request whose HEADERS are delayed) is now kept and applied when the
  request opens, as RFC 9218 section 7 asks; it was taken for a finished request and dropped. A PRIORITY_UPDATE naming a
  stream beyond the bidirectional stream limit the server granted closes the connection with `H3_ID_ERROR` (section
  7.2).
- HTTP/3 server: a client's MAX_PUSH_ID is now read instead of skipped. A value smaller than the previous one closes the
  connection with `H3_ID_ERROR` (RFC 9114 section 7.2.7), a payload that is not exactly one push ID with
  `H3_FRAME_ERROR` (section 7.1). The first valid one is free; since the server never pushes, every later one does no
  useful work and spends a glitch token, as an unknown frame does (section 10.5), so a flood of them, increasing values
  included, closes the connection with `H3_EXCESSIVE_LOAD`.
- HTTP/3: a field value with a control character other than HTAB (0x01–0x08, 0x0B, 0x0C, 0x0E–0x1F, 0x7F), in a
  regular field or a pseudo-header, makes the request or response malformed (RFC 9114 section 10.3): a received one is
  a stream error `H3_MESSAGE_ERROR`, and our own requests, responses and trailers with one fail locally with
  `IllegalArgumentException`. Only NUL, CR and LF were refused, so a value such as `a<ESC>b` reached the application
  and the Ktor engines.
- ksl: `KSL_OPT_MIN_VERSION` and `KSL_OPT_MAX_VERSION` accept only TLS 1.2 and TLS 1.3; TLS 1.0, TLS 1.1 or no bound are
  refused at the C level (RFC 9846 section 4.2.3 and appendix E.5: "MUST NOT be negotiated"). The Kotlin API never set
  them.
- TLS: a received `general_error` alert (117, RFC 9846 section 6.2) is reported by that name instead of `alert_117`, and
  in TLS 1.3 an error alert the peer sent at level warning is reported as `TlsException.AlertReceived` with its code
  instead of a generic protocol error (RFC 9846 section 6: error alerts count regardless of their level).
- TLS over TCP: `TlsConnection.keyUpdate(requestPeer = true)` called again before the peer answered the previous request
  now updates only our key (`update_not_requested`) instead of asking the peer again (RFC 9846 section 4.7.3, MUST).
- TLS over TCP: a connection never lets its key update epoch pass 2^48-1 (RFC 9846 section 4.7.3, MUST); the session
  that sent its last allowed KeyUpdate ends instead of sending another, also in answer to the peer. OpenSSL counts none.
- TLS: a ClientHello, or a TLS 1.3 ServerHello, whose `legacy_version` is not 0x0303 is refused with `protocol_version`
  (RFC 9846 sections 4.2.2 and 4.2.3, MUST); OpenSSL 3.5 accepted 0x0301 and 0x0302 next to `supported_versions`.
- TLS 1.2: a peer without Extended Master Secret is now refused during the handshake with a `handshake_failure` alert (the
  server on the ClientHello, the client on the ServerHello), instead of being dropped without an alert after both
  Finished messages (RFC 9846 appendix D, RFC 9325 section 3.6).
- TLS over TCP: a connection updates its sending key (TLS 1.3 KeyUpdate) every 2^23 records it wrote, before the AES-GCM
  record limit of RFC 9846 section 5.5 (MUST since RFC 9846; 2^24.5 records, about 384 GiB at full size). OpenSSL never does so by itself, so a
  very long-lived bulk connection kept one key for good.
- TLS over TCP on the JVM and Android: a write the transport had no room for is retried with the same bytes from
  another buffer (the JNI layer copies each call's bytes), and OpenSSL refused that retry with `bad write retry`
  (`SSL_R_BAD_WRITE_RETRY`), failing the connection with "ksl: TLS error". It took a full 16 KiB write behind a record
  that left the transport short of room, such as a server's session ticket after a pinned client certificate. TCP
  sessions now set `SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER`; `ksl_tcp_write` accepts the retry from any buffer holding the
  same bytes.
- TLS server: a server that used the client's server name now acknowledges it with an empty `server_name` extension
  (in EncryptedExtensions for TLS 1.3, in the ServerHello of a full TLS 1.2 handshake), as RFC 6066 section 3 requires;
  before, the extension was never sent. Also on an SNI override and on QUIC.
- Windows (mingwX64) TCP: a connect, send or receive no longer fails at random with "POSIX error 0: No error". The
  socket code read the Winsock error after Kotlin/Native had unpinned the buffer, which can reset it, so a pending
  connect or a would-block send/receive was taken for a failure. The error is now read right after each call (the POSIX
  code reads errno the same way).
- Windows (mingwX64) TCP: a connect to a listening local port could still fail with "POSIX error 0: No error" now and then.
  Kotlin/Native's return from a C call can itself reset the Winsock last error, so the error is now captured in C, in
  the same function as the Winsock call (a small cinterop shim); a failed connect without an error is taken as pending
  only when the socket's `SO_ERROR` shows none.
- Windows (mingwX64) TCP: a write waiting for room on a connection the peer reset could wait for ever. ktor-network's
  selector there wakes such a wait on `FD_WRITE`, and Winsock reports a reset as `FD_CLOSE` instead (POSIX `poll`
  reports the socket writable, so the send fails). The wait now ends when the read side sees the reset, and otherwise
  tries the send again every second, which fails on a reset connection; so the write fails with an IOException. On every
  Kotlin/Native platform, such a write also failed now and then with ktor's `ConcurrentIOException` instead of the
  connection's error.
- Windows (mingwX64) TCP: a connection closed while the peer was still sending could lose the response still being
  sent. The read loop's end (a graceful close, a stopped reader) shut the receiving direction down, and Winsock resets
  the connection when data arrives after `SD_RECEIVE`. On Windows the read loop now does so only at the end of the
  peer's stream; unread input stays buffered until the close, as on Linux.
- Windows (mingwX64) TCP: a read could wait for ever for data or an end of stream that had already arrived. `FD_CLOSE`
  (and, in some interleavings, `FD_READ`) can be lost by ktor-network's selector there, which re-issues `WSAEventSelect`
  every round and completes only the waits that match; Winsock records `FD_CLOSE` once. The wait for data now tries the
  receive again every second.
- Ktor server: with `port = 0` a TLS connector could start without HTTP/3 where the OS hands out TCP ports one after the
  other (Windows): each retry of the TCP + UDP pair took the next TCP number, and a run of UDP ports held by other
  sockets refused all 16 twins. The retries now alternate with pairs whose UDP port the OS picks first and TCP follows.
- HTTP/3 server: a client's PRIORITY_UPDATE now reaches the stream's scheduling before `ServerRequest.priority` shows it,
  so code that reacts to the new value finds the stream already scheduled by it (RFC 9218 section 7).
- HTTP/3 server: `goAway()` no longer throws when the client answers the GOAWAY by closing the connection at once (RFC 9114
  section 5.2). The transport's loss could reach the GOAWAY write before the session saw the close.
- Building from source on a clean machine (a fresh `GRADLE_USER_HOME`, as `docs/verifying.md` and a CI runner start):
  Gradle dependency verification failed, because an empty cache resolves other variants than a warm one (junit-bom
  `.module` files the Plugin Portal serves without a usable signature, JUnit, OpenTelemetry, protobuf and poko artifacts
  no trusted key covered). `gradle/verification-metadata.xml` now covers them (signature trust where the key verifies,
  a sha256 checked against Maven Central's `.sha1` and the Plugin Portal otherwise; the new keys are in the keyring).
  The keep-rule checks (`tools/check/android-keep-rules.sh`, `service-keep-rules.sh`) run the R8 pinned in
  `gradle/libs.versions.toml` (`./gradlew -q ksR8Jar`) instead of whichever one another build left in the cache.
- Ktor client, HTTP/1.1: a response whose `Content-Length` or `Transfer-Encoding` has whitespace other than SP and
  HTAB around a value (VT, FF, U+00A0) fails, and its connection is closed instead of reused (RFC 9110 sections 5.6.3
  and 8.6, RFC 9112 section 6.3 item 5). `Content-Length: 5<VT>` framed a 5-byte body and `Transfer-Encoding:
  chunked<U+00A0>` a chunked one, so with a proxy in front that framed the response otherwise the bytes behind it
  became the response to the next request (response splitting). A `Transfer-Encoding` that is not a list of transfer
  codings or that applies `chunked` twice (RFC 9112 section 6.1) fails the same way.
- Ktor server, HTTP/1.1: a response no longer carries both `Content-Length` and `Transfer-Encoding` (RFC 9112 section
  6.2: a sender MUST NOT). A `Content-Length` the application set on a streamed response, which Ktor frames with
  `Transfer-Encoding: chunked`, is dropped; before, both went out, and a client or proxy that framed the response by
  the length read the chunk framing as the body.
- Ktor server, HTTP/1.1: an application's status description with a character a reason phrase cannot hold (CR, LF,
  NUL; RFC 9112 section 4) is replaced by the registered reason of the code, or none. Before, it was written as it
  was: `HttpStatusCode(200, "OK\r\nX-Injected: 1")` split the response and added a field of its own.
- Ktor server, HTTP/1.0: the `Upgrade` field of an HTTP/1.0 request is ignored (RFC 9110 section 7.8: a server MUST
  ignore it), so a WebSocket route no longer answers an HTTP/1.0 client with `101 Switching Protocols`, a 1xx it
  MUST NOT get (section 15.2); the application does not see the field.
- Ktor server, HTTP/1.1: a pipelined request with an unsafe method (POST, PUT, DELETE, ...) now runs alone: its
  handler starts after the handlers of the requests before it have ended, and the next request is read only after it
  has ended (RFC 9112 section 9.3.2: pipelined requests may be processed in parallel only if they all have safe
  methods). Before, a pipelined DELETE could run while the PUT before it was still streaming its response. Pipelined
  GET, HEAD, OPTIONS and TRACE requests still overlap.
- Ktor server, HTTP/1.1: a request whose `Connection` field lists `close` (`close, TE`, `keep-alive, close`, or on a
  second `Connection` line) ends the connection after its response, which now says `Connection: close` (RFC 9112
  section 9.6); so does an HTTP/1.0 request without `keep-alive`. The `close` the engine announces (here, when the
  server stops, for a CONNECT, or for an HTTP/1.0 body the close delimits) is added to the options the application put
  in its `Connection` field (`Connection: X-Hop` becomes `X-Hop, close`; a contradicting `keep-alive` goes), so the
  hop-by-hop fields they name are still removed by an intermediary (RFC 9110 section 7.6.1). Before, only a field of
  exactly `close` was announced, `keep-alive, close` or HTTP/1.0 with `Connection: TE` kept the connection open and
  served the next pipelined request, and the engine's `close` replaced the application's options.
- Ktor server, HTTP/1.1: every final response carries a `Date` field unless the application set one (RFC 9110
  section 6.6.1: an origin server with a clock MUST send it), the engine's own 400, 408, 414, 431, 501 and 505
  included. Before, only the DefaultHeaders plugin added it.
- Ktor server, HTTP/1.1: what the application writes for a response to HEAD, or for a 1xx, 204 or 304 response, is
  dropped; the fields stay (RFC 9110 section 9.3.2: the server MUST NOT send content in the response to HEAD). Before,
  `head("/") { call.respondText("x") }` without the AutoHeadResponse plugin sent `x`, which a keep-alive client read
  as the start of the next response. The engine's own `400 Bad Request` refusing a HEAD request keeps its fields and
  carries no content either.
- Ktor server, HTTP/1.1: a 1xx or 204 response no longer carries `Content-Length` or `Transfer-Encoding`, and a 304
  no longer `Transfer-Encoding` or the `Content-Length: 0` Ktor adds for empty content (RFC 9110 section 8.6: a server
  MUST NOT send Content-Length in a 1xx or 204 response, nor in a 304 one other than the 200's length). Before,
  `call.respond(HttpStatusCode.NoContent)` said `Content-Length: 0`, and a streamed 204 or 304 said
  `Transfer-Encoding: chunked`.
- Ktor server, HTTP/1.1: after a 400, 501 or 505 refusal (and a 400 for a malformed chunked body) the server reads and
  drops what the client is still sending for up to 2 s before it closes, as it did after a 431 (RFC 9112 section
  9.6: close in stages). Before, it closed over the unread rest of the request, the kernel answered with a reset, and
  the client could lose the 400.
- Ktor server, HTTP/1.1: a Host field that is not `uri-host [":" port]` (`Host: a b`, `[::1`, `h:x`, `a%zz`) gets 400
  and the connection closes (RFC 9112 section 3.2: a server MUST respond with 400 to a Host with an invalid value); so
  does an absolute-form target with such an authority. Before, only `/?#@` and a trailing colon were refused, and the
  rest reached `serverHost` and `serverPort`. A trailing colon (`Host: a.example:`, an empty port, valid by RFC 3986's
  `port = *DIGIT`) is now accepted as the default port instead of refused; a port above 65535 (`Host: h:99999`), which
  names no TCP port (RFC 9110 sections 4.2.1 and 4.2.2), gets 400, in an absolute-form target too.
- Ktor server, HTTP/1.1: a request field name that is not a token (with DEL or a byte above 0x7F, RFC 9110 section
  5.1) gets 400. A field value that starts with a Unicode space (U+00A0, U+2000, ... sent as obs-text) now reaches
  the application as sent: OWS is only SP and HTAB (section 5.6.3) and obs-text is opaque field content (section
  5.5), but Ktor's parser skipped it, so `X-A: <U+00A0>a` arrived as `a`, and `Content-Length: <U+00A0>5` framed a
  5-byte body while a front proxy that finds the value invalid frames none (request smuggling); such a
  `Content-Length`, `Transfer-Encoding` or `Host` is now invalid and gets 400.
- Ktor server, HTTP/1.1: a request field value with a control character other than HTAB (NUL, VT, FF, DEL) gets 400
  and the connection closes (RFC 9110 section 5.5: a recipient of NUL in a field value MUST reject the message or
  replace it). Before, Ktor's parser refused only CR and LF, and a NUL reached the application.
- Ktor server, HTTP/1.1: the request-target must match its form (RFC 9112 section 3.2): an origin-form path and query
  of RFC 3986 characters, an absolute-URI, the authority-form for CONNECT only (with a host, not `CONNECT :443`, and
  a port from 1 to 65535, RFC 9110 section 9.3.6), `*` for OPTIONS only. Any other target is an invalid request line
  and gets 400 (section 3.2); a GET or HEAD whose path or query only has characters to encode (`|`, `{`, `^`, `[`,
  which browsers send unencoded, and non-ASCII bytes) gets `301 Moved Permanently` to the target properly encoded
  instead, the other answer section 3.2 names, once the rest of its head is valid (a missing, repeated or invalid Host
  or faulty framing gets its own 400 or 501). Before, any run of non-whitespace reached routing.
- Ktor server, HTTP/1.1: the request line is checked before Ktor's parser reads it. A method that is not a token
  (`G"ET`, RFC 9112 section 3.1), a control character other than the whitespace section 3 allows as a separator, or a
  Unicode space (U+00A0), which Ktor's parser took as a separator, gets 400. A request in a higher minor version
  (`HTTP/1.2`) is processed as HTTP/1.1 instead of refused (RFC 9110 section 6.2), and one in another major version
  (`HTTP/2.0`, `HTTP/0.9`) gets `505 HTTP Version Not Supported` instead of 400 (section 15.6.6).
- Ktor server, HTTP/1.1: a request line longer than 8 KiB (a request-target longer than the server parses) gets
  `414 URI Too Long` instead of 400 (RFC 9112 section 3: the server MUST respond with 414), and what follows is read and
  dropped for a while before the close, as after a 431. A field line over 8 KiB still gets 400, and a method longer
  than the line limit gets `501 Not Implemented` (section 3: a server SHOULD answer a method longer than any it
  implements with 501).
- Ktor server, HTTP/1.1: `Content-Length` and `Transfer-Encoding` values with whitespace other than SP and HTAB
  around them (VT, FF, U+00A0) are refused with 400 and the connection closed (RFC 9110 sections 5.6.3 and 8.6, RFC
  9112 section 6.3 items 4 and 5). They were trimmed as Unicode whitespace, so `Content-Length: 5<VT>` framed a 5-byte
  body and `Transfer-Encoding: chunked<U+00A0>` a chunked one, while a front proxy that ignores the invalid field
  forwards those bytes as the next request (request smuggling). `Transfer-Encoding` is now parsed as a list of transfer
  codings (RFC 9112 section 6.1): a value that is not one, or that applies `chunked` twice, gets 400, and a coding the
  server does not implement before the final `chunked` (`gzip, chunked`, also `identity, chunked`) gets 501 instead of
  400 (section 6.1); `identity` is no longer ignored, as it is no transfer coding since RFC 7230.
- Ktor client: a request through an HTTP proxy no longer sends the URL's userinfo and fragment in its absolute-form
  request line (RFC 9110 section 4.2.4: a sender MUST NOT generate userinfo in a target URI; section 7.1, RFC 9112
  section 3.2.2): `http://user:pass@host/p?q#frag` went out as `GET http://user:pass@host/p?q#frag`, the origin's
  credentials in clear text to the proxy and its logs; it is now `GET http://host/p?q`.
- Ktor server, HTTP/1.1: a request in absolute-form (`GET http://a.example/x HTTP/1.1`) is accepted and routed by its
  path and query, with the target's authority as the host and the Host field ignored (RFC 9112 section 3.2.2, two
  MUSTs); before, routing saw the whole URI (404) and the host came from Host. An "http" or "https" target with an empty
  host (RFC 9110 section 4.2.1) or with userinfo (section 4.2.4) gets 400.
- Ktor server, HTTP/1.1: a response the application marks `Connection: close` now ends the connection after it, and
  no further pipelined request is processed (RFC 9112 section 9.6); before, the next request ran and was answered and
  the connection stayed open. The next pipelined request is now read once the previous response's head is out.
- Ktor client, HTTP/1.1: a request body (a `ReadChannelContent`, `WriteChannelContent` or byte array) whose length
  differs from its Content-Length fails the request and closes the connection (RFC 9112 section 6.3: the server takes
  that many octets as the body). A shorter one went out as complete and its connection was kept, so the server waited
  for the rest or read the next request as it; a longer one sent its excess where the next request goes (section 11.2).
  The excess is no longer sent, and the producer of a longer streamed body is cancelled rather than left waiting.
- Ktor client, HTTP/1.1: the keep-alive connection of a response whose body was read to its end is back in the pool
  when the application sees that end, so the request it sends next reuses it. Before, the body ended first and the
  connection was released a moment later, when the body's reader completed: a request sent in between (a thread
  preempted there, as on a slow Android emulator) found no idle connection and opened another one. A streamed request
  body still being sent when the response has been read never delays the response's end: after a response that would
  keep the connection, it is not reused and closes once the upload ends or the call does (before, it went back to the
  pool only when its sender completed); after one that does not (`Connection: close`, HTTP/1.0, a close-delimited or
  failed body), it closes at once and the upload stops (RFC 9112 section 9.5).
- Ktor client, HTTP/1.1: a response head cut before its empty line (the server closed the connection in the middle of
  the header section) now fails the request with `ClosedReadChannelException` instead of passing for a complete
  response without fields (RFC 9112 section 8: the client MUST record it as incomplete); a redirect without its
  `Location` or a 200 with an empty body were the result. The proxy's response to `CONNECT` fails the same way. An
  idempotent request on a pooled connection is still retried once on a fresh one.
- Ktor client, HTTP/1.1: a response whose head holds a control character other than HTAB (NUL, a bare CR, 0x01-0x1F,
  0x7F) in a field value or the reason phrase now fails with `ParserException` and its connection is closed (RFC 9110
  section 5.5: NUL, CR and LF in a field value MUST be rejected or replaced, other control characters are invalid);
  before, `X-A: a<NUL>b` reached the application. The proxy's response to `CONNECT` is checked the same way.
- Ktor client, HTTP/1.1: a response field folded over several lines (obs-fold, a line that starts with SP or HTAB) is
  now unfolded into one value with a space, as RFC 9112 section 5.2 requires of a user agent; Ktor's parser failed
  such a response.
- Ktor client, HTTP/1.1: a status code must be exactly three digits in 100..599 (RFC 9112 section 4, RFC 9110 section
  15); `HTTP/1.1 20` and `HTTP/1.1 2000` without a reason phrase and `HTTP/1.1 600` were taken as statuses 20, 2000
  and 600, and now fail with `ParserException`. A response in `HTTP/1.2` or a later minor version is processed as
  HTTP/1.1 (RFC 9110 section 6.2) instead of failing.
- Ktor client: an HTTP proxy's interim 1xx responses (100 Continue, 103 Early Hints) before its answer to `CONNECT` are
  skipped, at most 5 as for a request, instead of failing the tunnel with an `IOException` (RFC 9110 section 15.2: a
  client MUST be able to parse 1xx responses it did not expect).
- Ktor client, HTTP/1.1: a request body with a transfer coding of its own (`Transfer-Encoding: gzip` in the request's or
  the content's headers) now goes out with `chunked` added as the final coding and without `Content-Length` (RFC 9112
  sections 6.1 and 6.2). The head said `Transfer-Encoding: gzip` over a chunk-encoded body, which a server reads until
  the connection closes, and a body with a length sent both fields.
- Ktor client, HTTP/1.1: an idle pooled connection on which the server sent something no request asked for (typically
  `408 Request Timeout` before closing it) is no longer reused; the next request goes on a fresh connection. Before,
  that 408 was returned as the answer to the next request.
- Ktor client: an `Alt-Svc` alternative whose `ma` is too large to represent (`ma=99999999999999999999`) is kept with a
  lifetime of 2147483648 seconds instead of being dropped (RFC 7838 section 3.1, RFC 9111 section 1.2.2); an `ma` with a
  sign (`ma=+5`) is no delta-seconds and makes its alternative invalid.
- Ktor client, HTTP/1.1: an HTTP/1.0 response with `Transfer-Encoding` is no longer chunk-decoded: its framing is
  faulty even with a `Content-Length` (RFC 9112 section 6.1), so the body is read as sent until the server closes the
  connection, which is then not reused.
- QUIC: a datagram carrying an Initial packet now always reaches 1200 bytes (RFC 9000 section 14.1: a client pads every
  such datagram, a server every one with an ack-eliciting Initial). When the packet expected to pad the datagram did not
  fit behind the Initial or Handshake packet (a ClientHello ending in the last 64 bytes before 1200 with 0-RTT data
  queued, or a server flight ending there with 1-RTT frames queued), the datagram left short, the peer dropped it, and
  every retransmission repeated the same layout. The packet with no room behind it now carries the PADDING frames.
- QUIC: a server whose anti-amplification budget is below 1200 bytes no longer sends an ack-eliciting Initial packet (a
  PTO probe or CRYPTO data) in a datagram of the budget's size, which RFC 9000 section 14.1 forbids and the client drops.
  The Initial data waits until the client's next datagram raises the budget (section 8.1); an Initial ACK and Handshake
  data still go out within the budget, and no PTO is armed while no probe can be sent (RFC 9002 section 6.2.2.1).
- QUIC: a server discards an Initial packet carried in a datagram below 1200 bytes wherever it sits in the datagram
  (RFC 9000 section 14.1). Only an Initial first in the datagram was checked; one coalesced behind another packet was
  processed.
- QUIC: a packet that is not built takes no packet number. A packet without room for its header and the 4 bytes after
  it, or for the bare CONNECTION_CLOSE of a closing connection, or with nothing to carry used up a number on every poll
  (gaps are legal, RFC 9000 section 12.3, but a closing server below its anti-amplification budget spent one per
  attempt). With 20-byte connection IDs (`connectionIdLength = 20`) and an anti-amplification budget of 64 to 70 bytes the
  long header did not even fit: writing it threw and the connection failed with an internal error.
- QUIC: the Stateless Reset check follows the first packet of a datagram (RFC 9000 section 10.3.1: "the comparison MUST
  be performed when the first packet in an incoming datagram either cannot be associated with a connection or cannot be
  decrypted"). A datagram whose first packet does not open is checked even when a later packet of it is processed; one
  whose first packet is an Initial the server discards for the datagram's size is not (it no longer counts in
  `ConnectionStats.invalidResets`). A datagram led by a duplicate is not checked either, and one led by a packet of a
  space whose keys were discarded is checked but not counted: `invalidResets` counts only datagrams whose first packet
  was not ours or did not authenticate.
- QUIC: a CONNECTION_CLOSE that does not fit the room left in its packet (a server closing below its anti-amplification
  budget with a long reason) now goes out with its reason cut to fit (RFC 9000 sections 10.2.1 and 10.2.3). The frame
  was skipped, and the packet, holding only padding, still counted as the close, so the peer never learned of it.
- QUIC: the reason phrase of a CONNECTION_CLOSE that is cut (to 1024 bytes, or to fit its packet) ends on a whole
  character, so the peer receives valid UTF-8 (RFC 9000 section 19.19). The encoded bytes were cut anywhere, which could
  leave half of a multi-byte character at the end.
- QUIC: the spin bit of every 1-RTT packet is now a random value instead of always 0 (RFC 9000 section 17.4 recommends
  this for an endpoint that does not spin, as kuicksilver never does), so the bit tells an on-path observer nothing.
- QUIC server: a client's 1-RTT packets that arrive before its TLS Finished is verified are held and processed only
  once the handshake completes (RFC 9001 section 5.7). Their frames, stream data included, were applied at once, even
  when they came in the same datagram as a Finished (or client certificate) that then failed verification. Up to 32
  such packets are held (`QuicLimits.undecryptablePackets`, shared with packets waiting for keys); the client resends
  what was dropped.
- QUIC: a peer's first key update no longer closes the connection with KEY_UPDATE_ERROR when it arrives before any
  1-RTT packet of the first key phase was processed (RFC 9001 section 6.2), for instance when the peer updates right
  after the handshake and its earlier 1-RTT packets were lost. The packet is now taken as the update.
- QUIC: sending a DATAGRAM (or an HTTP/3 datagram) no longer closes the connection with an internal error when the
  packet being built has exactly 66 bytes left. The room offered to the datagram was one byte too large there (a 64-byte
  payload, whose Length field takes 2 bytes), so the frame overflowed the packet (RFC 9221 section 5). The room is now
  the largest payload whose whole frame fits, for every size.
- QUIC: Initial packets that fail authentication now count toward the AEAD integrity limit with the rest (RFC 9001
  section 6.6: "across all keys"), and in `ConnectionStats.authenticationFailures`. The limit (2^52 for AES-128-GCM)
  stays out of reach, so this changes the count, not when a connection closes in practice.
- QUIC client: 0-RTT packets count toward the AEAD confidentiality limit of the 0-RTT key, and 0-RTT sending stops at
  the limit, the rest of the early data waiting for 1-RTT (RFC 9846 section 5.5, RFC 9001 section 6.6). The limit
  (2^23 packets for AES-GCM) is far above what a client sends before the server's answer, so in practice nothing
  changes.
- QUIC, Linux and Apple platforms: a UDP send interrupted by a signal (`EINTR`) is retried instead of failing the
  socket; on Linux an interrupted GSO send no longer withdraws GSO.
- TLS: a server context without session ticket keys (a QUIC server with tickets off, a keyless SNI override base) no
  longer falls back to OpenSSL's own random ticket keys: it sends no ticket (RFC 9846 section 4.7.1 allows none) and
  resumes none, also when a ticket is requested explicitly after the pin verdict. A keyed SNI override under a keyless
  base context now seals its tickets with its own keys instead of the base context's random ones.
- TLS: a session ticket now resumes only under the server name it was issued for (RFC 6066 section 3: a server "MUST
  NOT accept the request to resume the session if the server_name extension contains a different name"). Virtual hosts
  of one server (an `sniSelector` returning overrides with the same trust, hence the same session context, and the
  process-wide ticket keys) accepted each other's tickets: a client offering `a.test`'s ticket with the name `b.test`
  resumed `a.test`'s session and never saw `b.test`'s certificate. Such a ticket, or one without a server name when
  the connection has one (and the reverse), now runs a full handshake and gets a new ticket. Tickets issued before this
  release are not resumed (one full handshake each).
- Ktor client: an HTTP/3 connection whose handshake completed just as the connect timeout fired is closed. It was
  dropped by the timeout and stayed open with nobody holding it until its idle timeout.
- QUIC: a peer's RESET_STREAM never reads as the end of the stream. The core answers -1 both at a FIN and at a reset;
  when the reset's event had not reached the stream yet (the loop's flush waiting in a blocking send), a read that
  pulled the core took the -1 for a clean end, `readAvailable` answered -1 and `closedCause` stayed null. The input now
  asks the core which it was and fails with the reset.
- Ktor server, HTTP/1.1: an upgrade request (WebSocket) whose handler failed before any response started, its error
  response failing too, no longer takes the connection's coroutine down with it. The failure was rethrown out of the
  connection's pipeline: the connection was reset, the responses pipelined before it were lost, and the exception
  reached the thread's uncaught exception handler (a crash on Android). The connection now ends with a close after
  those responses, and any failure that still reaches an HTTP/1.1 connection's coroutine is logged, as for HTTP/3.
- Ktor server, HTTP/1.1: a pipelined request with `Expect: 100-continue` behind a slow response no longer gets a 408
  while its client correctly waits for the `100 Continue` (RFC 9110 section 10.1.1). The `100 Continue` waits behind
  the earlier responses, but the body deadline started when it was queued; it now starts once those responses are
  written.
- Ktor server, HTTP/1.1: a refused request (400 for a malformed head or framing, 431 for a head over the size limit)
  behind pipelined requests whose responses filled the response queue got no answer: the refusal was dropped and the
  connection closed after the earlier responses. It now waits its turn behind them
  (RFC 9112 sections 3.2 and 6.3 require the 400; RFC 6585 section 5 the 431).
- Ktor server, HTTP/1.1: the 400 for a malformed request said `HTTP/1.0`. It now says `HTTP/1.1`, the highest
  version the server conforms to, as every other response does (RFC 9110 section 6.2: a server SHOULD send it).
- Ktor server, HTTP/1.0: a response of unknown length (a streamed body) to an HTTP/1.0 request no longer carries
  `Transfer-Encoding: chunked`, which a server MUST NOT send unless the request indicates HTTP/1.1 (RFC 9112 section
  6.1). Its body now goes out as is, delimited by the close of the connection (section 6.3 item 8), and the response
  says `Connection: close` (section 9.6), also to a client that asked for keep-alive. Before, an HTTP/1.0 client read
  the chunk framing as part of the body. Responses of known length keep their Content-Length and keep-alive.
- HTTP/3: a peer that resets a stream while its trailers wait for the QPACK encoder stream now fails the body with
  the reset as an `Http3Exception`. Before, the reader got the runtime's internal "stream abandoned while blocked"
  exception, and the stream's Stream Cancellation went out twice (RFC 9204 section 4.4.2).
- HTTP/3 server: a CONNECT request (classic or Extended, WebTransport among them) carrying `content-length` no
  longer has its tunnel bytes checked against it. A CONNECT has no content and what follows its header section is the
  tunnel (RFC 9110 section 9.3.6, RFC 9114 section 4.1.2), so `content-length: 0` followed by tunnel DATA failed the
  stream with H3_MESSAGE_ERROR.
- Ktor client, HTTP/1.1: a request with `Expect: 100-continue` now waits for the server before sending its body (RFC
  9110 section 10.1.1). Before, the body followed the head at once, so a server that refuses it (417, 401) received it
  anyway. The body now goes out on a 100 Continue, or after 1 s without an answer (as Ktor's CIO engine and curl); a
  final response first is the answer, the body is never sent and that connection is not reused. A 417 is the exception:
  the request is repeated once without the expectation, as the RFC recommends and CIO does.
- Ktor client: a request that completes just as its socket timeout expires keeps its response. The inactivity
  watchdog could still act after the request had returned (a timer that already fired is not stopped by cancelling the
  watchdog, nor is one firing on another thread), so the response was replaced by a `SocketTimeoutException` and, over
  HTTP/1.1, the connection was closed under it. The request's end and the expiry now settle once: whichever comes
  first wins.
- Ktor client: a 421 (Misdirected Request) from the origin itself leaves the origin's cached alternatives. Only a 421
  from an alternative removes it (RFC 7838 section 6); before, a 421 received over HTTP/1.1 also dropped every
  alternative of the origin. A 421 is not authoritative for the origin (RFC 9110 section 15.5.20), so its `Alt-Svc` is
  not learned either.
- Ktor client: a 421 from an alternative removes only that alternative from the origin's cache (RFC 7838 section 6);
  the origin's other alternatives stay. Before, it removed all of them.
- Ktor client: `close()` lets the calls already made finish, as Ktor's CIO engine does: a request in flight or still
  queued for the connection limit gets its response, and the pools, sockets and selector close after the last call
  ends. Before, the cleanup ran at once and closed them under those calls, which failed with a bare
  `CancellationException` (one a caller could take for its own cancellation). A call made after `close()` fails with
  Ktor's `ClientEngineClosedException`, as does one the HTTP/1.1 pool turns away once shut down.
- HTTP/3: a body never waits forever when the connection ends under it. A response that arrived with the connection's
  close was returned with a body whose pump never ran (it was launched into the connection's already cancelled scope),
  so reading it hung; and when the connection ended while a response or a request body was being written, the
  application's writes hung once the channel's buffer was full. The body and trailers now fail with the connection's
  error, and so do those writes.
- HTTP/3: a response or request body whose last bytes came with the peer's CONNECTION_CLOSE is read whole. When the
  connection is lost, the readers of the peer's streams (message bodies, control and QPACK streams) now go on until
  their input ends, at most one second, before the connection's coroutines are cancelled; before, they were cancelled at
  once and the body failed with the connection's error. A reader the application does not keep up with is cut after
  that second. This holds for a response whose headers came with the close too: its body's reader started
  after the connection's coroutines were gone and never ran, and the body failed with H3_NO_ERROR, unread.
- QUIC: data and FIN received just before a CONNECTION_CLOSE are delivered. A peer that sends its last bytes and closes
  at once (Firefox closes its WebTransport connection right after the session's WT_CLOSE_SESSION and FIN) lost them when
  the close was processed before the application read: the reads failed with the connection's end.
- HTTP/3: an application that cancels a request body (server) or a response body (client) now stops the stream at
  once with STOP_SENDING (`H3_NO_ERROR` on the server, `H3_REQUEST_CANCELLED` on the client). Before, the stream was
  stopped only when the peer sent its next DATA, so a peer that paused kept the stream and its flow-control credit.
- QUIC server: Retry tokens are sealed with a counter nonce per key instead of 64 random bits, so AES-GCM never sees a
  nonce twice under one key. Random nonces crossed NIST's 2^-32 collision bound after about 92,000 tokens per hourly
  key (93 s at the default stateless rate limit of 1000 per second); a repeat an attacker observed among its own tokens
  would give away the key's GHASH key and let it forge Retry tokens for other addresses while that key lives.
- HTTP/3 scheduling: the control and QPACK streams are now sent before every request stream, whatever urgency the peer
  asks for. Before, they were urgency 0 like any other stream, so a request at u=0 (non-incremental) with a stream id
  below theirs had its whole response sent ahead of them: a QPACK insert that the response's own header or trailer
  section needed, or a GOAWAY, waited behind the body (only on that client's own connection).
- QUIC: `QuicPath.remoteAddress` reports each path's own peer address. Before, every path reported the connection's
  current one: on a server whose client migrated, the path the client left (in `PathEvent.Changed.old`,
  `QuicConnection.paths` and the path-change log line) showed the client's new address.
- TCP and TLS sockets of the engines (JVM, Android, Kotlin/Native): when the application's stream failed mid-response
  (a handler that threw) or a write loop failed, the connection ended as if the stream were complete: a FIN on a plain
  connection, `close_notify` and a FIN on a TLS one. The peer saw a clean end of a cut stream, and a response delimited
  by the connection's close passed for the whole one. Such a connection now ends with a reset (`SO_LINGER` 0; on TLS
  without `close_notify`), and the peer gets an error. An aborted connection (a client that stopped reading, a stop
  past its grace period) is reset without a FIN ahead of the reset: the JVM writer shut its output down first, and the
  Kotlin/Native socket shut both directions down instead of resetting, so the kernel kept the unsent bytes until TCP
  gave up on the peer.
- TLS sockets of the engines (`kuicksilver-ktor-network`): a TLS session that failed (a reset, a TLS error) could end
  the application's read channel cleanly instead of failing it. When the failure was there before the application
  opened its channel, or landed between two reads of the copy after the last bytes, ktor's `copyTo` returned normally
  and the channel closed without a cause, so a response delimited by the connection's close could pass cut for whole.
  The channel now fails with the session's error.
- Ktor server, HTTP/1.1 (slow POST, R.U.D.Y.): a request body had no deadline, so a client that announced a body and
  then sent it a byte at a time, or stopped, held its handler for ever. A body that sends no byte for
  `connectionIdleTimeoutSeconds` now fails the handler's read; when neither the application nor StatusPages answers the
  failure, the client gets `408 Request Timeout` (body "Request Timeout") with `Connection: close`, and the connection
  closes after the request. Each wait for body bytes has its own deadline (as nginx's `client_body_timeout`), so a
  slow but moving upload is read in full; after `Expect: 100-continue` the wait starts once `100 Continue` is sent;
  upgraded connections are not affected.
- Ktor server, HTTP/1.1: a request body the handler did not read was read to its end after the response, however
  large (Ktor's default engine phase discards it), and a large one could stall the connection. Now at most 256 KiB of
  it are read and dropped (as Go's net/http `maxPostHandlerReadBytes`); a larger rest, or a chunked one still
  incomplete when the response starts (its size is unknown), ends the connection after the response, which says
  `Connection: close`, and what the client still sends is read and dropped
  for up to 2 s before the close so that a client writing its whole body first is not reset before it reads the
  answer. A handler that starts its response before reading a body of more than 256 KiB therefore gets
  `Connection: close` on it (as with Go). A request with `Expect: 100-continue` answered without
  `100 Continue` is not waited for: its response says `Connection: close` and the connection ends (RFC 9110 section
  10.1.1, as Go).
- Ktor server, HTTP/1.1: a graceful stop cut responses that were still draining to a slow client. A connection ended
  as soon as its socket's `close()` was called, so once all of them had, the listener's job completed and closed its
  selector under sockets still sending their last bytes: a 4 MiB response written during `stopSuspend(8000, 10000)`
  ended after 3.5 MiB while the stop returned in 3.4 s. A connection now ends when its socket has closed (the close is
  bounded on progress, below), so responses in flight get the grace period, as with Ktor's other engines and Go's
  `Shutdown`; idle keep-alive connections still close at once.
- Ktor server, HTTP/1.1 (send-side slowloris): a client that requested a large response and never read it held the
  connection and its handler for ever: the response writer waited for the socket without a deadline, and so did the
  socket's close. A response write that makes no progress for the longer of `connectionIdleTimeoutSeconds` and
  5 minutes now ends the connection and its handler (upgraded WebSocket connections too) and aborts its socket, which
  releases its descriptor (on TLS connectors too). Every other close is graceful while its drain makes progress, so a
  slow reader's last `Connection: close` response is not cut, and aborted after the same deadline without progress.
  Progress counts, not the length of the response, as with nginx's `send_timeout`: the engine sees it about 1 MiB at a
  time, so the 5 minutes keep clients down to about 3.4 KiB/s (EDGE, throttled plans) served as before.
- Ktor server, HTTP/1.1: a pipelined response whose handler failed before the writer reached it (it waited behind an
  earlier response) was skipped: the writer took the failed channel for an ended one, wrote nothing for it and went on,
  so the client took the next request's response for the failed one's. Such a response now ends the connection with
  its failure, as one that fails while it is written does.
- Ktor server, HTTP/1.1: empty lines before a request line (RFC 9112 section 2.2) made a connection that then went
  quiet count as a started request, which got 408 at the header deadline; they are skipped, and such a connection is
  closed without a response like an idle one.
- Ktor server, HTTP/1.1: the request head had no size limit. Ktor's parser bounds each line at 8 KiB but not their
  number, so a request with megabytes of header fields was buffered and served, and one fast connection could push any
  amount of data into the heap. A request head (request line and header section) larger than 64 KiB, the default
  `maxFieldSectionSize` of the HTTP/3 server, now gets `431 Request Header Fields Too Large` and the connection closes
  (RFC 6585 section 5); a single line above 8 KiB still gets 400 as before.
- Ktor server, HTTP/1.1 (slowloris): a client that connected and sent nothing, or sent the request head a byte at a
  time inside the idle timeout, held its connection for ever. There was no deadline for the request head or the TLS
  handshake, and the 45 s idle timer closed only the output side while the reader kept waiting. Now a request head must
  be complete within `requestHeaderTimeoutSeconds` (new, *experimental*, default 30 s), counted from the accepted
  connection (TLS handshake included) or the end of the previous response; arriving bytes do not extend it. A partial
  head gets `408 Request Timeout` and the connection closes (RFC 9110 section 15.5.9); an idle connection is closed
  without a response (RFC 9112 section 9.5). `connectionIdleTimeoutSeconds` closes the whole connection. A keep-alive
  connection without requests now closes after the smaller of the two timeouts (30 s by default, was 45 s). Threat
  model section 3.22.
- Ktor server: a failing `accept()` (EMFILE/ENFILE with the descriptor table full) was retried at once, so the accept
  loop spun at 100 % CPU while the condition lasted. Failed accepts are now retried after 5 ms, doubling up to 1 s,
  back to 5 ms after a successful accept (as Go's `net/http` server), and logged at most once per 10 s with the number
  of failures left out; a closed listening socket and cancellation still end the loop at once.
- `docs/guide/ktor.md` said the HTTP/1.1 client tries each address a host name resolves to in turn. On the JVM and
  Android it connects to the one address `InetAddress.getByName` returns; on Kotlin/Native it moves to the next
  `getaddrinfo` address only when a connect fails with an error, and neither races addresses.
- QUIC: a stream at its reassembly limit (256 gaps; the CRYPTO streams, 1024) could stall until the idle timeout. A
  STREAM or CRYPTO frame at the read offset that did not reach the first buffered range opened a new range and was
  refused; nothing was readable, so nothing ever freed a range, and every retransmission of that frame was refused too.
  A frame at the read offset opens no gap and makes data readable: it is now always taken (a stream holds at most one
  range beyond the limit, the readable one), and the limit on gaps still holds.

- QUIC: a peer could make one connection buffer far more than its connection window. A STREAM frame refused for lack
  of reassembly room (the packet is dropped unacknowledged since 0.2.0) had already raised the stream's highest offset, and the
  refusal skipped the connection-level charge; data sent later below that offset merged into a buffered range and was
  stored uncharged. Three streams held 1.5 MiB against the default 768 KiB connection window, and with the default
  limits one connection could hold the sum of its stream windows (RFC 9000 section 4.1). A STREAM or RESET_STREAM frame
  is now checked against the final size, the stream window, the connection window and the reassembly room before
  anything is committed; abandoning a stream credits only bytes that were charged. CRYPTO frames likewise count toward
  their caps only once buffered.
- QUIC: a copy of a packet dropped for lack of reassembly room was processed again. The frames ahead of the refused
  STREAM frame had run (a DATAGRAM delivered, a PATH_CHALLENGE answered) and the packet number was not recorded, so a
  network duplicate or a replay delivered the DATAGRAM twice (RFC 9000 section 12.3). The packet number now counts as
  seen and is still never acknowledged, as not all of its frames were processed (section 13.1); the peer resends the
  data in a new packet.
- QUIC: RESET_STREAM (with STOP_SENDING on a bidirectional stream) returned MAX_STREAMS credit for streams the
  application never accepted: the runtime consumed the reset itself while the stream waited in the accept queue (about
  33 KiB each), so a peer could open streams without bound (500 against `maxBidiStreams = 10`) while the application
  did not call `acceptStream()`. The reset of a queued stream is now consumed when `acceptStream()` hands it out (as
  quic-go counts a reset stream completed only once the application read the error), for bidirectional and
  unidirectional streams. An `acceptStream()` caller cancelled while being resumed with a stream no longer loses it:
  the stream goes back to the queue for the next `acceptStream()` (once the connection is closed it is given up with
  STOP_SENDING and RESET_STREAM instead), where before it stayed open, unseen, until the connection closed.
- QUIC: a packet of MAX_STREAM_DATA frames could cost the endpoint loop about 250 ms. On a stream whose receiver
  acknowledged every other packet, each frame (even one that raises nothing, which spends no glitch token) compared
  every queued retransmission with every acknowledged range, and so did every packet built for the stream. Acknowledged
  bytes now leave the retransmission queue when the ACK arrives (as quic-go drops acknowledged frames from its queue),
  acknowledgements and losses are binary searches, and a MAX_STREAM_DATA that raises nothing does no work, like MAX_DATA.
  A range declared lost after part of it was acknowledged is resent without the acknowledged part.

- Ktor client, HTTP/1.1: a failure was taken for an end in both directions, because ktor's `copyTo` returns normally on
  a source closed with a cause. A response delimited by the connection's close, cut by a reset while the client waited
  for the application to read, ended cleanly, so a cut body passed for the whole; it now fails with the connection's
  error. A request body whose channel failed was sent as complete: chunked, with its last chunk (the server took the cut
  body for the whole); with a Content-Length, short, and the call waited for a response that could not come. Such a
  request now fails with the body's error and its connection is closed without the last chunk. A request body's
  failure also reached the uncaught-exception handler (printed on the JVM, fatal to an Android app); it now fails only
  its call.
- Ktor client, HTTP/1.1: a server could make the client buffer a response head of any size and hold a request with
  endless interim responses. Ktor's `parseResponse` bounds each line at 8 KiB but not their number, and the whole header
  section is buffered (2 bytes per character) before the call sees it; interim 1xx heads were skipped without a bound,
  so a server streaming 103 Early Hints held the request until a timeout, if any. A response head is now limited to
  64 KiB (the field section size our HTTP/3 client advertises, and the server's limit for request heads) and at most 5
  interim responses are skipped (Go's `net/http` stops at the same count); beyond either the request fails with Ktor's
  `ParserException` and the connection is closed.
- Ktor client: the proxy's response to `CONNECT` had no size limit either (the same Ktor parser). It is read with the
  same 64 KiB limit, one byte at a time so that no byte of the tunnel after the head is consumed; a larger head fails
  the request with `ParserException` and the connection to the proxy is closed.
- Ktor client: the socket timeout failed uploads that were still making progress. Over HTTP/1.1 (streamed bodies) and
  HTTP/3 (every body) the request body goes out while the response head is awaited, and the timeout covered that whole
  wait: with `socketTimeoutMillis = 1_000`, any upload longer than a second failed with `SocketTimeoutException`, however
  steadily it moved. Ktor defines the socket timeout as the "maximum time of inactivity between two data packets", and
  CIO applies it to each socket read and write. It now measures inactivity in both directions: every piece of the body
  the connection takes (an HTTP/1.1 flush, a chunk the HTTP/3 stream reads) and every byte of the response head that
  arrives restarts it, so a stalled upload (the server stops reading, the application stops writing) still fails one
  timeout after its last progress. HTTP/1.1 also no longer leaves the wait for the response head running past the
  timeout: the vendored response reader runs in the call's context, which the timeout's cancellation did not reach, so
  the timeout only took effect when the head arrived or the connection closed; the connection is now closed at the
  deadline. A byte-array body written before the response is awaited is under the same timer (it had none). A socket
  timeout on a pooled connection is not taken for a stale connection: the request is not repeated on a new one (as an
  `IOException`, it was, so a GET to a slow handler ran twice).
- Ktor client: shorthand IPv4 literals passed the Alt-Svc local-network filter (threat model 3.14). Only the dotted
  quad counted as an address, so `h3="127.1:443"`, `"2130706433:443"`, `"10.1:443"` or `"192.168.1:443"` were taken as
  DNS names, while the JVM's `InetAddress` and getaddrinfo/inet_aton map them to 127.0.0.1, 10.0.0.1 and 192.168.0.1
  without any lookup: a public origin could still aim clients' QUIC Initials at their own network. Every inet_aton form
  with decimal parts is now classified as the address it names, on every platform; a numeric host with an octal or hex
  part (`0177.0.0.1`, `0x7f.1`: octal or hex to inet_aton, decimal or refused by the JVM) or that is no address
  (`256.1.1.1`, `4294967296`) is never a destination.
- Ktor client, HTTP/3: a WebSocket call that ended with a cause (a caller cancelled during the closing handshake, an
  application that threw once its Close was out) reset the stream's send side even when the session had already
  queued its Close frame and FIN: the reset could overtake them, and the peer then saw a reset, not the Close. A send
  side the session finished is now left to deliver its Close and FIN; an unfinished one is still reset.
- Ktor server: a graceful `stop(gracePeriod, timeout)` took the whole grace period while any HTTP/1.1 keep-alive
  client was connected. The stop waits for every HTTP/1.1 connection, and an idle keep-alive connection sat in the
  request parser (until the idle timeout), so it was only cut at the grace deadline. Once accepting stops, an HTTP/1.1
  connection now reads no further request: an idle one closes at once (RFC 9112 section 9.5 lets a server close an
  idle connection at any time; Go's `Server.Shutdown` closes idle connections the same way), one with a request in
  flight, or whose request head has started to arrive, closes after that response, which says `Connection: close` (as
  Go's `Shutdown` makes in-flight responses do).
- HTTP/1.1 server: the 400 answer to a malformed request head echoed the header section. Its body was the parser's
  message (as in Ktor CIO), and Ktor's `ParserException` messages embed the whole header section read so far, so
  cookies, credentials and any field a front proxy added (internal authentication, client-certificate headers) were
  sent back to the client, the class of Apache's CVE-2012-0053. Every 400 the engine writes itself now has the fixed
  body `Bad Request`.
- HTTP/1.1 server: a request without Host, or with two Host fields, was served (the first value won). RFC 9112 section
  3.2: a server MUST respond with 400 to an HTTP/1.1 request that lacks Host and to any request with more than one Host
  field line; a front proxy that keys on the last line routed and cached by another host than the application saw. Both
  now get 400 and the connection closes; an HTTP/1.0 request without Host is still served. The HTTP/3 path already
  refused a second `host`.
- HTTP/1.1 server: `call.request.origin.serverHost` was `"[:"` for an IPv6 literal in the Host field
  (`Host: [::1]:8443`), and `serverPort` the local port for `Host: [::1]`, as the value was split at its last colon.
  The literal now keeps its brackets (`"[::1]"`, as over HTTP/3) and a Host without a port gives the scheme's default
  port.
- HTTP/1.1, server and client: a bare CR in a chunk-size line was skipped, a request smuggling vector. The parser (Ktor
  3.6.0's, KTOR-9263) ignored a CR anywhere in the line, so `1\r0\r\n` was read as size 0x10 where a recipient that
  ends the line at the CR reads 1, and `\r\r\n` was taken as the last chunk; a quote outside an extension switched on a
  quoted mode that swallowed the line end, and 16 hex digits from `8000000000000000` up became a negative size. RFC 9112
  section 2.2 makes a bare CR invalid, and section 7.1 defines the line as `1*HEXDIG [ chunk-ext ] CRLF`; a front proxy
  that reads such a line differently frames the body differently (the "funky chunks" class). Both engines now parse the
  line by that grammar: hex digits, extensions as `;` name `=` token or quoted-string with optional whitespace around
  the separators, whitespace tolerated before the CRLF (as nginx and Go accept it), CRLF only, a size that fits a
  signed 64-bit length, 128 bytes at most. A bare LF stays invalid on a chunk line (section 2.2 lets a recipient accept
  it in the start line and field lines only; the trailer section keeps accepting it). For a malformed chunked request body the engine writes no response itself: the handler's receive of
  the body fails with `BadRequestException`, which Ktor answers with 400 and a fixed text unless the application
  handles it (it was a plain IOException, answered with 500 and the parser's message), and the connection closes.
- JVM and Android HTTP/1.1 and TLS over TCP: a peer that read slower than we wrote kept a `Dispatchers.IO` thread at
  100 % CPU until its window opened, and that thread could not be cancelled. ktor-network 3.6.0's socket writer retries
  a write that answers 0 without reaching its select; about 64 such peers exhaust `Dispatchers.IO`. The engines'
  sockets now write through Kuicksilver's own writer, which waits in the selector. Closing a client connection lets
  the writer drain for at most 3 s and then drops the rest; a server's accepted socket has no bound of its own, so a
  slow reader still gets the last response whole (whoever accepted it sets the bound, `setCloseTimeout`); a writer that is cancelled or
  fails (a reset) closes the descriptor ([threat model 3.21](docs/spec/threat-model.md)).
- Kotlin/Native TCP sockets of the engines: a connection the peer reset, or whose wait for data failed, ended the read
  channel cleanly. The read loop closed the channel before the failure could fail it, and a failed select even left the
  loop as if at the end. A reader took the cut stream for a complete one, so over plain HTTP/1.1 a response delimited by
  the connection's close passed cut for whole. The channel now fails with the reset or the select's error.
- ktor-network: `TlsSocket.close()` could keep the raw socket, its coroutines and the native TLS session alive for as
  long as the peer kept the connection open without reading, since the flush, `close_notify` and the raw socket's last
  write all waited on it. A client's close (`Socket.tls`) is now bounded by 3 s in all; then what is queued is dropped
  and the socket closed. A server's (`Socket.tlsServer`) waits for the client to take the last response however slowly
  it reads: a fixed bound there cut such a response short with a clean EOF; whoever accepted the socket bounds it.
- TLS: a `TlsConnection` whose output the application failed (cancelled with a cause, a stream that failed midway) could
  still send `close_notify`, so the peer saw a clean end of a cut stream. ktor's `readAvailable` answers -1 for a failed
  channel as for a closed one when the failure is there before the call, and the writer pump, busy on a full transport
  when the failure came, took that for the end. A failed output now ends the session without `close_notify`.
- TLS: `TlsConnection.shutdown()` could wait forever when the peer stopped reading. Its 3 s bound covered only the
  wait for the peer's `close_notify`; before it, the wait for the writer to send the queued data and `close_notify`
  had none, and a full transport stops that writer. The 3 s now bound the whole shutdown, after which the connection
  closes, as the KDoc said; `TlsSocket` on a server leaves sending the last data unbounded (internally) and bounds only
  the wait for the peer's `close_notify`.
- Ktor client: an application shrunk with R8 in class-file mode (a JVM application) lost `KuicksilverEngineContainer`
  and its `META-INF/services` entry, so `HttpClient()` without an engine argument no longer found the Kuicksilver
  engine. The `kuicksilver-ktor-client` jar now carries a keep rule as `META-INF/proguard/kuicksilver-ktor-client.pro`,
  and the AAR the same rule as `proguard.txt` ([troubleshooting: Android](docs/guide/troubleshooting.md#android)). A
  new gate step, `tools/check/service-keep-rules.sh`, checks every class a published artifact names in
  `META-INF/services` with an R8 run and a negative control.
- Native UDP: the errno and text of a socket's last error (`KslUdpSocket`'s exception message) could mix two errors,
  or come out torn, when the sending and the receiving thread failed at the same time; the pair is now written and read
  under a short lock. Diagnostics only.
- Native UDP (Linux GSO, Windows USO): a run of equal datagrams was joined up to 65535 bytes, but one IPv4 datagram
  carries at most 65507 bytes of UDP payload (65527 over IPv6). The kernel refused such a send with `EMSGSIZE`, which
  for segments of at most 1200 bytes switched GSO off for the socket. A join now stops at the limit of the peer's
  family. The endpoint loop sends at most 32 datagrams per batch, so no 0.2.x caller reached it.
- Android: an app built with R8 (`isMinifyEnabled = true`, the usual release setup) could not load `libksl`, so TLS,
  QUIC and HTTP/3 were unavailable in release builds while debug builds worked. The 0.2.0 AAR shipped no consumer keep
  rules: R8 renamed `PacketBuffer.buffer` and removed the `KslNative` natives the app never reached, and `JNI_OnLoad`,
  which registers every native and reads that field by name, failed the load (`UnsatisfiedLinkError`, `KslLoader`
  `Unavailable`). The AAR now carries the rules as `proguard.txt`, and the JVM jar as
  `META-INF/proguard/kuicksilver-native.pro` for applications that shrink on the JVM ([troubleshooting:
  Android](docs/guide/troubleshooting.md#android)). A new gate step, `tools/check/android-keep-rules.sh`, checks the AAR's
  rules against the names `ksl_jni.c` looks up and runs R8 over the AAR's classes when R8 is in the Gradle cache.
- `Certificate`: a DER length of four bytes past `Int.MAX_VALUE` wrapped the minimal walker's bounds check, so reading
  `dnsNames`, `ipAddresses` or the validity of such bytes threw an index error instead of `TlsException.Config`, and a
  crafted negative length could make the walker revisit the same bytes without end. Certificates that came through a
  handshake were parsed by OpenSSL first and cannot carry such lengths.
- `PacketProtector` and `ResetKey` (`seal`, `open`, `headerMask`, `mac16`, through `Ksl`): an offset plus a length past
  `Int.MAX_VALUE` wrapped around the bounds check, and the native call then read or wrote about 2 GiB outside the buffer
  instead of throwing the documented `IndexOutOfBoundsException`. Not reachable from the QUIC codec, whose lengths come
  from datagrams of at most 64 KiB.
- `KslCrypto.verify` returns false for an ECDSA signature that is not DER-encoded, as its KDoc says of a bad signature;
  it threw `KslException.Internal` ("key does not match the algorithm") for such attacker-supplied bytes.
- Native UDP (Linux, Apple): a trickle of empty UDP datagrams could freeze an endpoint loop. `ksl_udp_recv` re-armed its
  full `poll` timeout after every datagram it dropped (empty, from a link-local IPv6 source, truncated, larger than the
  slot), so the timeout counted from the last dropped datagram rather than from the call. Since 0.2.1 the loop reads the
  socket on its own thread with a 1 ms wait while datagrams keep coming; an off-path sender of about 1,000 empty
  datagrams a second (spoofed sources are fine) kept that wait from ending, and every timer and application command of
  the loop's connections with it. The timeout is now one deadline for the call (as `ksl_udp_win.c` already did), and a
  run of 64 dropped datagrams in a row ends a call that may not wait or already holds datagrams, on Windows too.
- QUIC: a handshake could be held on a client address the client does not own until the handshake timeout. The
  datagram that completes the ClientHello moves the server's path at once (0.2.0), and an Initial may move it after the
  old address has been quiet for a PTO; neither move had a deadline. An off-path attacker that sees the client's
  datagrams and races a copy of each from a spoofed address (RFC 9000 sections 9.3.3 and 21.1.3.2) keeps that address
  fresh and the client's own looking quiet (every genuine datagram after a copy is a duplicate), so the flight went to
  the spoofed address within its 3x budget for as long as the attacker kept going. A move an Initial made is now undone
  when nothing validated the new address (see the next entry) within the validation period of RFC 9000 section
  8.2.4, max(3 x PTO, 6 x initial RTT) (section 9.3.2: revert to the address before it, with its state and budget); the
  handshake flight is resent there at once and the server follows no other address until the handshake completes, as
  quic-go, quiche, msquic and ngtcp2 never do during a handshake. A client that really rebound answers the flight with a
  Handshake packet well inside the period and keeps its new address.
- QUIC: one copied client Handshake packet could redirect a connection's whole downlink to an address of the attacker's
  choosing. A Handshake packet from a new address moved the server's path at once and was taken as validating that
  address (RFC 9000 section 8.1), and the path then settled as validated without a PATH_RESPONSE; an off-path attacker
  that races a copy of the client's Handshake packet from a spoofed address (section 9.3.3) gets its copy in first. A
  Handshake packet shows that the client read our flight where we sent it, not where it came from: it now validates the
  active address only when the whole handshake flight went there, an acknowledgement (Handshake or 1-RTT) of a packet
  sent to the current address validates it, and so does a PATH_RESPONSE. The move a Handshake packet makes is led by a
  PATH_CHALLENGE within the 3x budget and, like every handshake-time move, undone at the validation deadline when
  nothing validated the new address, also after the handshake completed (a raced copy can carry the Finished; the
  completion no longer validates an address the path was moved to). A client that rebinds after the server's flight left
  keeps its new address once it answers the challenge; one whose new address gets nothing through for a whole
  validation period ends the handshake on its old address, as with quic-go, quiche, msquic and ngtcp2, which never
  follow a new address during a handshake. Only the first restore of a connection by a newer packet from the old address
  resends the outstanding flight at once (later ones leave it to the PTO), so alternating raced copies with the client's
  own packets costs ACKs, not flights. Known limit: a client that really rebinds mid-handshake while an observer races
  copies of its packets from its old address keeps being taken back to the dead old address and the handshake fails at
  the handshake timeout, as it does with those implementations; challenging both candidates as separate paths is planned
  for 0.3.0.
- Soak harness: the flatness verdict of a long run ran out of memory after the run. The Theil–Sen slope held every
  pairwise slope as a boxed `Double`, n(n−1)/2 of them: a 72-hour soak at the default `sampleSeconds=15` has ~13,800
  samples after warm-up, ~95 M pairs, more than the 1 GiB test heap, so the whole run ended without a verdict. Up to
  2,048 samples (2²¹ pairs) the slope is still the exact median of every pair, now in a primitive array; beyond that it
  is the median of 2²¹ pairs drawn from a fixed seed, whose rank among all the slopes is within about 0.035 percentile
  (one standard deviation). A 7-day window (32,000 samples) is judged in about 25 ms.
- Interop tooling: the `rebind-port` cells' transfers ended on the simulator's rebind at 11 s. The clients started after
  the first rebind (0.2.0), and over the 10 Mbit/s link the transfer takes 9-10.5 s whatever the peer, so 92 of 110
  measured rebind cells closed within 0.5 s of that rebind, and a client's CONNECTION_CLOSE could open the new path
  (`msquic->kuicksilver-native:rebind-port`, 0.2.0 gate 6) or end the connection before it answered the server's
  PATH_CHALLENGE there. In `rebind-port` `tools/interop/sim-entrypoint.sh` now opens the clients' port 1.25 s after the
  first rebind: clients poll it once a second, so every client starts one second later and the transfers end between the
  rebinds at 11 s and 16 s, at least 0.56 s from either in 33 measured runs. Half a second would not do: the emulated
  peers' clients still start on the same poll as before. The poll phases (x.5 s for the arm64 clients, x.8-x.0 s for the
  emulated amd64 ones) were measured on an arm64 Docker Desktop host and may differ on an amd64 host, where no peer is
  emulated. `rebind-addr` keeps the 0.2.0 start: its binding from 11 s on is one ngtcp2's server never receives from,
  and with the later start all five `ngtcp2->kuicksilver[-native]:rebind-addr` runs stalled until the next rebind (one
  failed). `closing-rebind.py` stays as a backstop; `KSL_INTEROP_START_GATE` overrides the delay.
- Interop tooling: a cell the runner timed out was reported as `ENVIRONMENT` (an unflushed capture) and rerun up to five
  times (`kuicksilver->picoquic:v2`, the known picoquic defect, in every 0.2.0 gate run of the JVM image). The runner
  cuts the simulator's output off at its timeout, so the `dumpcap` summaries are missing whatever the capture did, and
  it fails the cell without reading a capture; `tools/interop/environment.sh` now leaves such a cell to the endpoints'
  verdict, also when it is required, so a hang is not rerun until it happens to pass. The trade-off: a host stall that
  times out a required cell is now a hard red, to be rerun by hand, instead of an automatic rerun.
- Release tooling: `tools/release/local-release.sh` released a patch version from `main` after its maintenance branch
  existed (`0.2.1` from `main` would ship 0.3.0-line code as 0.2.1), and never checked that the tree names the version
  it releases (a `0.2.2` from `release/0.2.x` without the version bump would ship README and iOS guide coordinates of
  0.2.1). It now refuses `main` once `release/<X.Y>.x` exists, locally or on origin, and refuses unless every version
  fallback of the tree is `<X.Y.Z>-SNAPSHOT` of the version and, for a final version, the README and `docs/guide/ios.md`
  name it (`docs/release.md`, "Every release", step 2). A release (not a dry run) now also fetches origin first, so a
  maintenance branch made elsewhere counts, refuses a local branch behind origin (it would release an older commit), and
  refuses a version that is already on Maven Central. `tools/release/local-release-test.sh` covers the refusals.
- HTTP/3: one client stopped an HTTP/3 server from accepting anyone else. `Http3Connection.server` opened the control
  and QPACK streams before returning, and opening a stream waits for the peer's stream credit; a client whose transport
  parameters allow fewer than the three unidirectional streams HTTP/3 needs (RFC 9114 section 6.2: they "MUST allow the
  peer to create at least three") and that keeps its connection alive held it forever. `Http3Endpoint.accept` and the
  Ktor server's HTTP/3 accept loop start connections one after another, so HTTP/3 was down for every later client.
  `Http3Connection.server` now returns at once and opens those streams in the background, as quic-go serves each
  connection in its own goroutine; when they cannot be opened within three seconds the connection closes with
  H3_GENERAL_PROTOCOL_ERROR (RFC 9114 names no more specific code for it). `Http3Connection.client` still returns once
  its SETTINGS went out, and against such a server it now fails with that error instead of hanging.
- HTTP/3: any peer could close a connection on demand by resetting a unidirectional stream before its type
  (RFC 9114 section 6.2: "A receiver MUST tolerate unidirectional streams being closed or reset prior to the reception of
  the unidirectional stream header"). Only a stream that ended cleanly was dropped; a RESET_STREAM inside the type
  reached the connection as an internal failure and closed it with H3_INTERNAL_ERROR, which also broke peers that
  abandon their GREASE streams. Such a stream is now dropped and spends a glitch token, like an empty one, as quic-go
  drops it; a critical stream reset after its type is still H3_CLOSED_CRITICAL_STREAM.
- HTTP/3: `:authority` and `host` were barely checked (NUL, CR, LF, whitespace at the ends, userinfo), so values such as
  `a.example/x?y`, `a b` or `x#y` reached the application, and the Ktor server made them the `Host` header that HTTP/1.1
  refuses. Both must now be an RFC 3986 authority, `host [":" port]` with a port up to 65535 and a host for http, https
  and CONNECT (RFC 9114 section 4.3.1, RFC 9110 sections 4.2.1 and 7.2); anything else is a malformed request
  (H3_MESSAGE_ERROR on its stream), and a client request carrying one fails locally with IllegalArgumentException.
  The Ktor server's `serverHost` and `serverPort` no longer take userinfo (allowed for other schemes) for the host.
- HTTP/3: with `maxFieldSectionSize` at its maximum of 2^30, a HEADERS frame declaring 2^31 bytes passed the size check
  (2 x `maxFieldSectionSize`) and its length became negative as an Int, closing the connection with H3_INTERNAL_ERROR.
  Such a frame is now refused unread as too large (431 on a server), as any other HEADERS frame above the bound.
- HTTP/3: a classic CONNECT whose `:authority` had no port, an empty one or port 0 (`proxy`, `proxy:`) was accepted.
  RFC 9114 section 4.4 makes it the host and port to connect to, and RFC 9110 section 9.3.6 its authority-form
  `uri-host ":" port`; such a request is now malformed (H3_MESSAGE_ERROR on its stream). Extended CONNECT (RFC 9220)
  keeps an optional port.
- Ktor server: an HTTP/3 call reported `call.request.local.scheme` as `https` and, without a port in `:authority`,
  `serverPort` as 443 whatever the request's `:scheme` said; an `http` request over HTTP/3 (RFC 9114 section 3.1.2) was
  seen as `https` on port 443. Both now follow `:scheme`: `http` with default port 80, `https` with 443.

### Security

- Ktor server, HTTP/1.1: the `301 Moved Permanently` for a GET or HEAD target with characters to encode was an open
  redirect. `GET //evil.example/^` got `Location: //evil.example/%5E`, a network-path reference (RFC 3986 section
  4.2) that a browser resolves to `http://evil.example/`, so a link to `http://victim.example//evil.example/^` left
  the site. A target whose Location could name another authority (it starts with `//`, also once `%2F`, `%5C` and
  `%2E` are decoded, `\` is read as `/` and dot segments are removed) now gets 400, as does a target with a raw `#`
  (redirected to `%23` it named another resource, RFC 3986 section 2.2). The redirect now never leaves the server;
  valid targets that start with `//` are still served as paths. The check removes dot segments in time linear in the
  target's length (a straight reading of RFC 3986 section 5.2.4 is quadratic, a CPU cost an unauthenticated client
  could raise with an 8 KiB target), and whether a head is for HEAD is decided once per head, not by rescanning the
  buffered request line on every read.
- TLS, `ksl` C ABI (not reachable from Kotlin, whose contexts and sessions are already used this way):
  `ksl_ssl_sni_resume` refuses an SNI override that is not a server context (`KSL_E_BAD_ARG`, the pause stays open for
  a valid answer), and the certificate callback takes its side from the SSL, not from the owning context; a session
  keeps the verify mode of the context it was made with, so switching an unfrozen context to `KSL_VERIFY_NONE`
  afterwards no longer drops the reference identifier rule (ADR-0011) for it; and every session `ksl_ssl_get1_session`
  hands out carries the verify mode it was made under, so `ksl_ssl_set_session` refuses (`KSL_E_BAD_ARG`) a session
  made under `KSL_VERIFY_NONE`, or one ksl did not hand out, on a session that verifies: a resumed handshake carries no
  certificate, so nothing would have verified the server.
- Ktor server, HTTP/1.1: a CONNECT request is now always the last on its connection. A CONNECT the application
  refused (a 407, a 502 or 504, Ktor's 404 or 405 for no route, a 500 from a failing handler) left the connection
  open, so the bytes behind it, which a proxy client may send optimistically as tunnel data, were read and executed as
  the client's next request, with the authority of the connection (request smuggling; RFC 9931 section 8, which
  updates RFC 9112: a server MUST close the connection when rejecting a CONNECT, without processing any further
  request on it). Every response to CONNECT now says `Connection: close`, and what follows is read and dropped, never
  parsed.

## [0.2.0] - 2026-10-18

**Withdrawn.** Its Kotlin/Native artifacts contain a local build path; their removal from Maven Central has been
requested. Use 0.3.0.

The first version published on Maven Central, made on top of the 0.1.0 candidate. That candidate, frozen on 2026-10-09,
was never published (no tag, no Central deployment); it is summarised in the last section, and its changes reach users
with 0.2.0.

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
  a server and the Ktor server engine over HTTP/3 run on `macosArm64` and on the iOS simulator, where every module's
  suite runs and `iosHostInteropTest` connects a host JVM client to a server on iOS; `iosArm64` is compiled and linked,
  not yet run on a device.
- QUIC server on Kotlin/Native Windows (`mingwX64`): `ksl_udp` over Winsock (`WSASendMsg`/`WSARecvMsg` with `WSAPoll` and
  a wake socket, ECN through `IP_ECN`/`IPV6_ECN` where Windows accepts them (probed when the socket opens; verified on Windows 11), USO/URO where the system grants them,
  DF, dual-stack IPv6 sockets, `SO_EXCLUSIVEADDRUSE`); the JVM on Windows uses the same socket through JNI. Winsock is
  started when the Kotlin/Native runtime starts (not from a C constructor, which in a `sharedLib` would run under the
  loader lock), so address lookups before the first socket do not fail with `WSANOTINITIALISED`. Verified in a local
  Windows 11 VM (Kotlin/Native and the JVM); the GitHub Actions workflows are disabled.
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
  kept a 2.3 ms mean queue where CUBIC queued 274 ms (`docs/guide/quic.md`). Loss detection now reports a packet declared
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
  failed runs; disabled like the other workflows, the measurements run locally). The floors warn instead of failing
  (`"blocking": false`) until they are measured on more hosts.
- Reproducible builds: base images pinned by digest, the Gradle wrapper by checksum, `-ffile-prefix-map` in the native
  builds, and `tools/check/double-build.sh` (builds the native libraries from two checkout paths and compares them) and
  `tools/check/pins.sh`; the CI scripts and OpenSSL tasks are written to run on fresh GitHub runners (not yet exercised:
  the gate runs locally through `tools/ci/local-matrix.sh`).
- Releases from a maintainer's Mac, no GitHub runner (`docs/release.md`): `tools/release/local-release.sh <version>`
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
  against quic-go, ngtcp2, quiche, picoquic, quinn and msquic in both roles with the JVM and native images; the 0.2.0
  matrix and its analysis are in `docs/spec/rfc-compliance.md` ("Interop matrix (0.2.0, QUIC Interop Runner 740c05a,
  2026-10-13)"), including BBR vs CUBIC
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

API shape before the first release (pre-release review, 2026-10-14; nothing was published, so no deprecation cycle):

- **Breaking:** `Http3Request` is built with `http3Request(method, authority, path) { ... }` or `Http3Request.Builder`
  (plus `toBuilder()`) instead of an 11-parameter constructor, so request options can be added later without breaking
  binaries; `allowEarlyData` is set in the builder under the experimental opt-in.
- **Breaking:** implementing `QuicCrypto`, `QuicTlsSession`, `PacketProtector`, `TokenKey` or `ResetKey` needs
  `@OptIn(ExperimentalKuicksilverApi::class)` (`@SubclassOptInRequired`), as do the constructors of the `TlsEvent` and
  `DriveResult` classes and of `IoCapabilities` that an implementation returns; using them is unchanged.
- The Ktor server engine's experimental `logger` is a `KuicksilverLogger?` defaulting to null (the QUIC endpoint's
  default, `Stderr`), like the client engine's.
- `QuicEndpoint.stats` and `Http3Endpoint.stats` are stable: the stable counters (`initialsDropped` to
  `connectionsCreated`) could only be read through these experimental accessors.
- `Certificate.der`, `SpkiSha256.bytes` and `QuicException.ConnectionLost.TransportClosed.reasonBytes` return a fresh
  copy on every read instead of the instance's own array, which a caller could change under `equals`, `hashCode` and
  the pin checks; a `ByteString` view can be added later without breaking these. `Datagram.data` stays the receiver's
  own array (one per datagram, never shared).
- `docs/stability.md` now states the minimum Kotlin of consumers (2.3 on the JVM and Android, 2.4 for klibs), that the
  QUIC, TLS and HTTP/3 modules expose Ktor 3.6 types and so require Ktor 3.6.x too, that sealed hierarchies and enums
  may gain members in a minor release, and the crypto SPI's opt-in.
- **Breaking:** library-produced values have internal constructors: `ConnectionAttempt`, the `PathEvent`,
  `ConnectionEvent` and `MigrationEvent` classes, `ClientHelloInfo`, `Http3PeerSettings`.

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
- A STREAM frame that would open more than the internal reassembly limit (256 gaps per stream, 4096 per connection) gaps in a stream is dropped unacknowledged (the peer
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

- `maxConnectionsPerHost` is renamed `maxIdleConnectionsPerRoute` (**breaking**, before the first release), the name of
  what it always was: the number of idle HTTP/1.1 connections kept per route, not a connection limit (that is the
  experimental `maxConnectionsPerRoute`); a Ktor or OkHttp user setting `maxConnectionsPerHost = 10` expected a cap. The idle map of the HTTP/1.1 pool, which grew by one entry per origin
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

Found by the 0.2.0 release gate (QUIC Interop Runner):

- QUIC: a PTO probe could repeat the same two oldest packets for the life of a connection. It took the oldest
  unacknowledged packets whatever they held, so when those were a PING and NEW_CONNECTION_ID frames and every
  acknowledgement from the peer was lost, each probe was ACK + PING and the data behind them (HANDSHAKE_DONE, a response)
  was never resent until the idle timeout (`kuicksilver->ngtcp2:handshakeloss`, one connection of 50). A probe now takes
  the oldest packets that hold something to resend and that no earlier probe took (RFC 9002 section 6.2.4).
- Interop tooling: the runner's simulator container exited right after forwarding SIGTERM to its two `dumpcap`
  processes, so Docker could tear it down while one was still writing: a pcap missing its last packets, and a runner
  check judged on it (`kuicksilver->ngtcp2:amplificationlimit` went red on a server-side trace holding 49 of 71 packets,
  about 1 in 70 cells of a gate lacked a flushed capture). `tools/interop/run-local.sh` now runs the simulator through
  `tools/interop/sim-entrypoint.sh` (a compose override), which waits for the captures to finish, and reports a cell
  whose simulator output still lacks a `dumpcap` summary as `ENVIRONMENT`, rerunning it once.
- QUIC: a server whose client's NAT mapping changed during the handshake answered the new address late and short. When the
  ClientHello completed from the new address inside a PTO of the client's last packet from the old one, the Initial
  anti-spoofing rule kept the whole ServerHello flight going to the dead old mapping until the client's next PTO (2 s in
  the gate's `kuicksilver->quiche:rebind-addr`); a repeat of the first half of a two-datagram ClientHello could move the
  path before the server had keys and send its Initial ACK there first; and the new address's 3x budget counted only the
  datagram that moved the path, so a 1200-byte probe the client could not read yet and the flight waited for ACKs. The
  datagram that completes the ClientHello now moves the path at once (an Initial that completes nothing still waits for
  a quiet PTO), the budget counts every datagram decrypted from the new address, and no PATH_CHALLENGE leads when the
  move comes with the ClientHello's completion (the client's Handshake packet validates the address, RFC 9000 section
  8.1).
- Interop tooling: in the rebind cases the client starts, polling the simulator once a second, within milliseconds of the
  simulator's first rebind at 1 s; when it starts first the handshake runs across the rebind and no server can pass the
  runner's check, because the PATH_CHALLENGE it wants first on the new path goes out before anyone can decrypt it
  (`kuicksilver->quiche:rebind-addr` red in the gate on a841e079 and in 16 of 23 runs on the same host that day, every
  green run one where the client started after the rebind). `sim-entrypoint.sh` now holds the simulator's ready port
  closed until the first rebind is over (the scenario is unchanged), and a cell failed that way anyway is reported as
  `ENVIRONMENT` (`tools/interop/handshake-challenge.py` proves it from both captures) and rerun, as is an unflushed
  capture, up to five times while the rerun hits the environment again.
  The rebind cells therefore no longer exercise a rebind in the middle of the handshake; `core.PathTest`'s
  rebind-during-handshake tests cover that case.
- QUIC: resent stream data no longer carries a FIN that is still in flight; a lost FIN goes again as an empty STREAM
  frame. quiche's receiver loses a FIN that arrives on a frame whose bytes it already read, and a request timed out
  (`kuicksilver->quiche:handshakeloss`, once probes carried data).
- QUIC: a peer that repeats `DATA_BLOCKED` in almost every packet, as quiche's server does during a download, no longer
  gets the connection closed with `PROTOCOL_VIOLATION` "excessive peer activity" after about a thousand repeats; a repeat
  within an RTT is still not answered (`quiche->kuicksilver:transfer`, `chacha20`, `keyupdate`, `blackhole`, and the
  native image's `transfer`).
- QUIC and HTTP/3: a stream that ended without the peer's FIN (a `RESET_STREAM`, a connection closed by either side, an
  idle timeout, a stateless reset) looked like a complete one: `QuicStream.input` and the HTTP/3 body channels kept the
  cause in `closedCause` but answered -1 from ktor-io's `readAvailable`, as after a FIN, and the interop client wrote a
  truncated download and exited 0. Only a FIN with all its data read is the end of a stream now; every other end fails
  the read (`readAvailable`, `readByte`, `readRemaining`, `copyTo`, …) with the `QuicException` or `Http3Exception`, and
  such a channel is not `isClosedForRead`. The Ktor engines inherit this for `rawContent` and the request body;
  `bodyAsChannel()` goes through Ktor's own copy, whose `readAvailable` keeps ktor-io's contract (-1 with the cause in
  `closedCause`) while `bodyAsText`, `readRemaining` and the other whole-body reads throw. The interop client checks
  `closedCause` as well.

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
  RTT per connection or stream; a faster repeat is not answered and spends no glitch token (a repeat of the same limit
  used to spend one: quiche reports `DATA_BLOCKED` in almost every packet of a download, about 750 times per 10 MB
  interop transfer). Simulated 50 Mbit/s, 40 ms upload with 75 % ACK-path loss, 20 seeds: mean goodput 7.2 → 18.5 Mbit/s
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

QUIC transport conformance (`kuicksilver-quic`; RFC 9000 review of 2026-10-14):

- Connection IDs: a retransmitted NEW_CONNECTION_ID for an ID we had retired ourselves came back as a fresh ID (one the
  peer's stateless reset could then match) or closed the connection with CONNECTION_ID_LIMIT_ERROR; retired sequence
  numbers are now remembered (bounded) and copies of a frame below retire_prior_to queue one RETIRE_CONNECTION_ID, not
  one each (§19.15). NEW_CONNECTION_ID from a peer using zero-length IDs and RETIRE_CONNECTION_ID for an ID whose
  NEW_CONNECTION_ID was never sent are PROTOCOL_VIOLATION (§19.15, §19.16). `preferred_address` is validated (no
  zero-length ID, a length that matches, not from a zero-length-ID server; §18.2), and its ID is kept as the server's
  sequence 1 and retired rather than forgotten (§5.1).
- Version Negotiation after a processed Retry is discarded (§6.2); a Stateless Reset is recognised in a long-header
  datagram too (§10.3), and the reset for a trigger of at most 43 bytes is one byte shorter than it (longer triggers
  get at least 43 bytes). A coalesced packet whose DCID differs from the first packet's is skipped (§12.2).
- Streams: STREAM, RESET_STREAM and STREAM_DATA_BLOCKED on a send-only stream and MAX_STREAM_DATA and STOP_SENDING on
  a receive-only one are STREAM_STATE_ERROR also once the stream was retired (§19.4-§19.13); no MAX_STREAM_DATA once
  the final size is known and no STOP_SENDING after RESET_STREAM or all data (§13.3, §3.2); CONNECTION_CLOSE carries
  the type of the frame that caused a stream or flow-control error instead of 0 or STREAM (§19.19).
- Paths: every PATH_CHALLENGE carries new data (§8.2.1, §13.3); a challenge the amplification limit kept below 1200
  bytes is followed by a second, full-size validation (§8.2.1); the validation timeout and new paths' RTT estimators
  use the configured initial RTT, not the RTT a client endpoint remembered for the first path, so a migration from a
  fast network to a slow one no longer times out (§8.2.4); a server never sends its current connection ID to a
  client address whose packets carry another of its IDs (it waits for a spare ID, as ngtcp2) and keeps the ID it
  answered a probe with for the switch that follows (§9.5); paths the client moves the server to run DPLPMTUD with
  black-hole detection, from the MTU a NAT rebinding inherited or from 1200 (RFC 8899 §4.3); the handshake-time
  rebinding follows only the highest packet number of its space (§9.3); `QuicConnection.addPath`/`migrate` refuse a
  server that uses zero-length connection IDs with IllegalStateException (§9.5).

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
- A session cache (TCP and QUIC tickets) owns what is put into it: a store cancelled while it waited for the cache lock,
  or made after the engine or endpoint had cleared the cache on close, lost the native session and never freed it (one
  per such race in a 40-minute Linux arm64 soak). Such an entry is now freed, and a closed cache refuses new entries
  (`SessionCacheTest.putCancelledWhileWaitingReleasesEntry`, `.putAfterCloseReleasesEntry`).
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
- QPACK with the dynamic table on: a request stream that the client reset before the server read its HEADERS, and a
  response stream that the server reset before the client read its HEADERS, sent no Stream Cancellation either, so the
  peer's encoder kept references to the entries those HEADERS used; both sides now send one
  (`QpackDynamicTest.resetBeforeHeadersSendsCancellation`, `QpackStreamCancellationTest.responseResetBeforeHeadersSendsCancellation`).
- QUIC: a connection kept the id of every stream its peer opened until it closed (a list only a test drained), one boxed
  `Long` per peer stream — about 36,000 on the soak's long-lived HTTP/3 connection. The list is removed
  (`StreamManagerRetentionJvmTest`).
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

- HTTP/1.1 over IPv6 binds and connects the address it is given on Linux, Apple and Windows Native. On Kotlin/Native
  the engines now use `kuicksilver-ktor-network`'s own TCP bind and connect (`bindTcp`, `connectTcp`) instead of
  `ktor-network`'s (`ktor-network` as before on the JVM and Android), because of a Ktor issue reported as KTOR-10017
  (security, under coordinated disclosure). The portable Native UDP socket, which still uses `ktor-network`, refuses a
  specific IPv6 bind address and IPv6 destinations.

Samples and testing:

- `samples/realtime-telemetry` reads control lines with a 1024-byte limit; a longer line closes the connection (code 2)
  instead of growing the server's buffer.
- The `NullCryptoProvider` test protection binds the packet number into its tag, so a misdecoded packet number fails to
  open as with real keys instead of being acknowledged.

Pre-release API and operations review (2026-10-14):

- QUIC: an application callback that throws a `CancellationException` (a `ConnectionListener`, a `KuicksilverLogger`,
  a `ConnectionAdmission` policy, a custom certificate verifier) no longer ends the endpoint loop's coroutine silently or
  leaves `closed`, the handshake and `accept()` waiting: it counts as that callback's failure like any other exception
  (`listenerFailures`, `admissionContractViolations`, a rejected peer). The listener's `onClosed` runs after `closed` has
  completed. Exceptions out of the logger are now counted in `listenerFailures`, and a failing qlog sink is logged at
  `Warn`, as their KDoc said.
- Ktor engines: a `KuicksilverEventListener` or `KuicksilverServerEventListener` callback that throws a
  `CancellationException` no longer fails the call (client) or ends HTTP/3 accepting and the connection's handler
  (server); it is logged like any other listener failure.
- HTTP/3: `Http3Connection.goAway()` runs on the connection's session dispatcher whatever thread calls it (the Ktor
  server calls it from `Dispatchers.IO`); it read and wrote the GOAWAY state unsynchronised, so a request racing the
  final GOAWAY could be processed above the announced id while the client retried it elsewhere.
- Ktor client: when the call setting up a shared HTTP/3 connection was cancelled, every other call waiting for that
  connection failed with a `CancellationException` (no retry, no HTTP/1.1 fallback); they now set up a connection of
  their own.
- HTTP/3 close paths send H3_NO_ERROR (RFC 9114 section 5.2) instead of QUIC application code 0, which HTTP/3 does not
  define: `Http3Endpoint.close()`, the Ktor client's `close()` and the Ktor server's stop at its grace deadline (which
  could close with code 0 when the endpoint's close overtook the connections' own).
- Ktor server stop: HTTP/3 accepting goes on until the endpoint closes, so a connection whose handshake completes after
  the stop began is served and gets GOAWAY at once instead of waiting in the accept queue, and the stop returns as soon
  as the connections are idle rather than always lasting the whole grace period. `docs/guide/ktor.md` describes the
  stop as it runs.
- QUIC counters: `datagramsDroppedQueue` now counts datagrams a loop could not forward to the loop that owns their
  connection (its queue full or closed), as its KDoc said; `connectionsCreated` no longer counts server connections
  for Initials that did not decrypt (forged or corrupted; they count in `datagramsDroppedUndecryptable`).
- Linux and macOS UDP: `ENOBUFS` from a full interface queue (Darwin) or qdisc (Linux) is backpressure like `EAGAIN`;
  the rest of the batch was counted as lost and thrown into the same full queue (f6d40586).
- Ktor client, HTTP/3 WebSockets on the JVM and Android: a session closed before the server's FIN arrived reset its
  stream and could discard its own Close reply on the way to the server; each direction now ends on its own (07b105a9).
- Kotlin/Native IP literals take ASCII digits only and no octets with leading zeros: `fe80::١` and `010.0.0.1` (which
  `inet_aton` reads as 8.0.0.1) could name different addresses for the loop and the socket (b3332a90).
- HTTP/3 client: a caller cancelled just as `request` (or `connect`) returned dropped the finished response without
  STOP_SENDING or RESET_STREAM, so the stream held flow-control credit until the connection ended; it is abandoned with
  H3_REQUEST_CANCELLED now.
- HTTP/3 graceful shutdown no longer cuts responses short: the server's idle close after GOAWAY waited a fixed
  max(4 RTT, 200 ms) after the last response was handed to QUIC, so a response still in flight or held back by flow
  control (a large body, a slow or loaded client) was lost to the CONNECTION_CLOSE (seen once as
  `ServerH3Test.stopSendsGoAwayToAllConnectionsAtOnce` failing under load). The server now waits until every answered
  request stream is finished at the QUIC level, and then for the client to close, which a client idle after GOAWAY does
  with H3_NO_ERROR once its responses are read (RFC 9114 section 5.2, as quic-go's server expects); a client that does
  not is closed three seconds later.
- Ktor client: `connectionReleased` follows every `connectionAcquired`, also for an exchange that failed before its
  response and for an HTTP/3 WebSocket; such calls reported no release.
- TLS: a `TlsConnection` that failed while being built (a client configuration without a reference identifier, a
  native error setting SNI) leaked its `SSL*` and its `SSL_CTX`; both are freed now.
- Linux Native trust store: a certificate directory without `c_rehash` links (`SSL_CERT_DIR`, `/etc/ssl/certs`) was
  accepted and then found no issuer at every handshake (`UnknownIssuer`); such a directory is now read file by file as Go
  does, and one without certificates fails with `TlsException.Config` naming the paths. The RHEL 7+ bundle
  `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` joins the searched files (Go's list).
- Windows Native TCP sockets (`kuicksilver-ktor-network`, used by both engines): every socket is created without
  handle inheritance (`WSA_FLAG_NO_HANDLE_INHERIT`; accepted ones are cleared too), so a child process no longer keeps
  a listener's port or a connection open, and listeners bind with `SO_EXCLUSIVEADDRUSE`, so no `SO_REUSEADDR` socket
  of another process can bind over them, as the UDP sockets, msquic and Go already did.
- Ktor client on Android: `http://` and `ws://` requests honour the app's Network Security Configuration
  (`NetworkSecurityPolicy.isCleartextTrafficPermitted(host)`, false by default from targetSdk 28) and are refused with an
  `IOException` before any connection, as OkHttp, `HttpURLConnection` and Cronet do; they were sent in cleartext.
- Ktor engines on Android: the Ktor version check read the version Android gives every package ("0.0") and refused to
  create a client or start a server ("ktor-server-core 0.0 is on the classpath"); on Android only a jar manifest counts
  now, so the check passes as documented.

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
- Kotlin/Native: a Ktor server connector bound to a specific IPv6 address (for example a loopback-only `::1` endpoint)
  listens on that address only, and a client request to an IPv6 address connects to exactly that address: the engines
  use their own TCP bind and connect instead of `ktor-network`'s, because of a Ktor issue reported as KTOR-10017
  (security, under coordinated disclosure; threat model section 3.19, `negative_ipv6ConnectorListensOnItsAddressOnly`,
  `negative_h1ToIpv6LiteralReachesThatAddressOnly`).
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
2026-10-14 0.2.0 was made the first Maven Central publication, and 0.2.0 contains everything below.

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

[Unreleased]: https://github.com/kuicksilver/kuicksilver/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/kuicksilver/kuicksilver/releases/tag/v0.2.1
[0.2.0]: https://github.com/kuicksilver/kuicksilver/releases/tag/v0.2.0
