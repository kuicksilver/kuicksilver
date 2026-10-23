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
- Ktor client: proxy resolution (experimental `proxyResolver`, `docs/guide/ktor.md`, "Proxies"):
  `ProxyResolvers.System` (the platform's settings: `ProxySelector` on the JVM and Android, CFNetwork on Apple
  platforms, WinHTTP's Internet settings on Windows, the environment on Linux), `ProxyResolvers.Environment` (curl's
  `https_proxy`, `http_proxy`, `all_proxy` and `no_proxy`, with `socks5://` and `socks5h://`), `ProxyResolvers.None`,
  or any `ProxyResolver` returning a `ResolvedProxy`. Answers are kept 30 seconds per route; `localhost` and loopback
  addresses always connect directly; a PAC or WPAD configuration on Apple platforms and Windows is not run (direct,
  one warning); a proxy the engine cannot use fails the request. `HttpClient.webTransport` refuses exactly the URLs a
  resolver sends through a proxy.
- Ktor client: SOCKS5 proxies (RFC 1928, CONNECT only) with username/password authentication (RFC 1929): a
  `ProxyBuilder.socks(host, port)` proxy now tunnels every request instead of being refused, the proxy resolving the
  origin's name. New experimental `proxyCredentials` for the explicit `proxy` (SOCKS5 username/password, sent only
  when the proxy picks that method; `Proxy-Authorization: Basic` with the first CONNECT or absolute-form request to an
  HTTP proxy) and `ProxyException` (a SOCKS5 reply or CONNECT status other than success, as `replyCode`). Off the JVM
  a proxy URL's user info is used as its credentials, and an `https://` proxy URL is refused instead of being spoken
  to in clear.
- QUIC: ICMP Packet Too Big (Linux, Android) and EMSGSIZE (every accelerated socket) speed up path MTU discovery as
  hints (experimental `QuicConfig.pmtudIcmpHints`, on by default; RFC 8899 section 4.6, RFC 9000 section 14.2.1). A
  Packet Too Big must quote one of the connection's packets on its active path and leave at least 1200 bytes of payload,
  and at most 64 a second per endpoint are looked at (`EndpointStats.ptbAccepted`, `ptbIgnored`). It ends larger probes
  at once; one below the size in use only triggers confirmation probes, and the MTU drops to the reported size only when
  three of them are lost, or when the black-hole detector fires meanwhile, which then falls to the reported size instead
  of 1200 and does not pause. EMSGSIZE on a probe settles that size at once.
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
  `MemoryTokenStore`). Tokens are keyed by server name and port, used once, replaced by a Retry token when a Retry comes,
  and bounded per connection (eight of at most 1024 bytes; more NEW_TOKEN frames spend glitch tokens).
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
- HTTP/3 (*experimental*): the Capsule Protocol of RFC 9297 section 3 on Extended CONNECT streams.
  `Http3Stream.useCapsuleProtocol(CapsuleConfig)` returns a `CapsuleStream`: `capsules` delivers the declared
  `knownTypes` (64 KiB each at most by default) and skips other types without buffering them, `send` writes whole
  capsules, `close()` writes what is queued and then FIN. A FIN inside a capsule, a known capsule above the limit, or a
  message that uses capsules with `content-length`, `content-type`, `transfer-encoding` or a 204/205/206 status resets
  the stream with `H3_MESSAGE_ERROR` and fails with `Http3Exception.MessageError`, as does any byte after a capsule of
  `terminalTypes` (for WebTransport's WT_CLOSE_SESSION); the connection lives on. DATAGRAM
  capsules are received together with QUIC datagrams, dropped unread above `maxDatagramLength`, and sent instead of QUIC
  datagrams when HTTP/3 datagrams are unsupported (`datagramFallback`). `CapsuleProtocol` reads and writes the
  `Capsule-Protocol` header field. See `docs/guide/http3.md`, "Capsules".
- WebTransport over HTTP/3, first part (experimental, `docs/guide/http3.md`, "WebTransport"): `Http3Settings.webTransport`
  advertises the SETTINGS of draft-ietf-webtrans-http3-16 and of the draft-02 and draft-14 codepoints browsers still
  use; WebTransport streams (`0x54` uni, `0x41` bidi) are routed to their session, those that arrive before it wait in
  a bounded buffer (16 per connection, 5 s each); `Http3Connection.webTransport` opens a session (the `:protocol`
  token follows the server's draft, `WT-Available-Protocols`/`WT-Protocol` negotiation, ten-second deadlines for the
  server's SETTINGS and for the answer) and
  `Http3ServerRequest.isWebTransport`, `availableProtocols` and `acceptWebTransport` accept one. One session per
  connection, no WebTransport flow control. A `WebTransportSession` opens and accepts bidirectional and
  unidirectional streams, sends and receives datagrams, closes with an application code and reason
  (WT_CLOSE_SESSION, then FIN) and drains; application error codes are mapped into the HTTP/3 space;
  `Http3ErrorCode` has the WebTransport codes.
- Ktor server (experimental): `webTransport = true` and `Route.webTransport(path, protocols, checkOrigin) { session -> }`
  serve WebTransport sessions over HTTP/3 (`docs/guide/ktor.md`, "WebTransport over HTTP/3"): the route matches only a
  WebTransport Extended CONNECT, refuses a foreign `origin` with 403 (`sameHostOrigin` by default), picks the
  protocol, and closes the session when the handler returns (code 0) or throws (`WEB_TRANSPORT_HANDLER_FAILED`).
- QUIC (experimental): RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset-11). `QuicConfig.resetStreamAt` advertises
  `reset_stream_at` (0x1d, and the pre-IANA codepoint Chrome and quiche use); `QuicStream.resetAt(code, reliableSize)` and `ConnectionCore.resetStreamAt` reset a stream while
  still delivering its first bytes when the peer advertised it too, and fall back to RESET_STREAM otherwise. WebTransport
  resets the streams it opened this way, keeping their header (draft-ietf-webtrans-http3-16 section 4.4), and the Ktor
  server advertises it with `webTransport`.
- Ktor client (experimental): `HttpClient.webTransport(url, protocols, headers)` opens a WebTransport session on a
  dedicated HTTP/3 connection of the Kuicksilver engine, outside the pool, closed with the session
  (`docs/guide/ktor.md`, "WebTransport on the client"); no fallback; refused under `H1Only` and through a proxy unless
  `http3 { webTransportIgnoresProxy = true }`; at most `http3 { maxWebTransportSessions }` (64) at once.
- WebTransport interop with a real browser: `ChromeWebTransportTest` (opt-in, `-Pkuicksilver.browserTests=true`)
  drives an installed Chrome headless through streams, datagrams and both closes against the Ktor server; results and
  a manual check for Firefox and Safari in `docs/spec/rfc-compliance.md`, "Interop WebTransport".
- Ktor client: Happy Eyeballs for HTTP/1.1's TCP connects, to the origin and to an HTTP proxy (RFC 8305 sections 4 to 6;
  `docs/guide/ktor.md`, "IPv6 over TCP on Kotlin/Native"). Every address of a host name is tried, IPv6 and IPv4
  alternating, a new attempt every `connectionAttemptDelay` (*experimental*, 250 ms; 10 ms to 2 s, or
  `Duration.INFINITE` for one address after another) or at once when the previous one failed; the first connection
  wins and the others are cancelled or closed. An address that drops connection attempts now costs 250 ms instead of
  the request's connect timeout, and the JVM and Android no longer connect only to the first address of a name. The
  name is resolved once per request for both sides of the h3/h1 race (HTTP/3 takes the first address), off the
  caller's thread and within the connect timeout.
- Ktor engines: WebSocket extension negotiation and frame checks (RFC 6455 sections 4.1, 5.2 and 9.1; RFC 7692
  section 6.1; `docs/guide/ktor.md`, "Client"). The client engine declares `WebSocketExtensionsCapability`, so Ktor's
  `WebSockets` plugin offers and negotiates the installed extensions over HTTP/1.1 and HTTP/3 (Ktor's JVM
  `WebSocketDeflateExtension` included); an answer that accepts an extension the client did not offer fails the call
  with `WebSocketException`. Both engines end a session whose peer sets an RSV bit no negotiated extension defines, or
  uses a reserved opcode, or masks its frames in the wrong direction (RFC 6455 section 5.1), with a Close frame with code
  1002 (threat model 3.20.1).
- Ktor server: RFC 9218 priorities (experimental). `call.request.priority` is the client's signal (the `priority`
  field, over HTTP/3 also its PRIORITY_UPDATE frames, which `call.request.priorityUpdates` follows as a `StateFlow`),
  and `call.response.priority(urgency, incremental)` sets the response's `Priority` field with only the given
  parameters; over HTTP/3 they are merged into the client's signal and schedule the response. Over HTTP/1.1 the field
  is read and sent only.
- Ktor client: RFC 9218 priorities (experimental). `priority(urgency, incremental)` in a request builder sends the
  `priority` field and, over HTTP/3, schedules the request's stream with it (a WebSocket over HTTP/3 included); it
  replaces a `Priority` header on the same request. `response.updatePriority(urgency, incremental)` sends a
  PRIORITY_UPDATE while the response is coming and returns false over HTTP/1.1 or once the call is over.

### Changed

- QUIC: a lost connection no longer takes the bytes a peer sent before it (`QuicStream.input`): what was received is
  still read, up to the FIN when it came too (then the stream ends cleanly), and only then do reads fail with the
  `QuicException.ConnectionLost`. Before, every read failed at once, even with the whole stream received. A reset still
  fails the reads at once.
- Ktor client: requests now follow the platform's proxy settings by default (`proxyResolver = ProxyResolvers.System`):
  where the system, the JVM's properties or (on Linux) the environment name a proxy, requests go through it over
  HTTP/1.1, without HTTP/3 or Alt-Svc. Before, only an explicit `proxy` was used. `proxyResolver = ProxyResolvers.None`
  restores direct connections.
- Ktor client: a `ws://` WebSocket through an HTTP proxy now goes in a CONNECT tunnel (RFC 6455 section 4.1), as
  browsers do, instead of an absolute-form Upgrade the proxy may not forward. A CONNECT the proxy refuses fails with
  `ProxyException` (`replyCode` 407 when it wants credentials) instead of a plain `IOException`. The
  `protocolSelected` reason for a request through a proxy is the new `ProtocolReason.Proxy` (was `NotSecure`).
- HTTP/3 scheduling: the control and QPACK streams are now sent before every request stream, whatever urgency the peer
  asks for. Before, they were urgency 0 like any other stream, so a request at u=0 (non-incremental) with a lower
  stream id had its whole response sent ahead of them: a QPACK insert that the response's own header or trailer
  section needed, or a GOAWAY, waited behind the body.
- HTTP/3 scheduling (RFC 9218): a CONNECT tunnel without a priority signal, a WebSocket over HTTP/3 among them, is now
  scheduled incremental on both sides, so it shares bandwidth with the other streams instead of holding back every
  response of the same urgency. A `priority` header on a request now schedules the client's own stream too, and a
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
  other. `connectionAttemptDelay = Duration.INFINITE` restores one address after another.
- Ktor client: name lookups run at most 8 at a time on their own share of `Dispatchers.IO`, one per name however many
  requests wait for it; an IP address literal is never looked up, and a dotted-decimal string with an octet above 255
  is a name, not an address (one with a leading-zero octet, octal to `inet_aton`, goes to the platform as before).
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
- WebTransport: a session the peer closes with WT_CLOSE_SESSION and then, at once, its connection (Firefox does both
  in back-to-back packets) ends with the capsule's code and reason. Before, the server saw code 0 and an empty reason:
  the connection's end completed the session before its capsule reader had read the capsule. The capsule reader now
  reads on to what the peer sent, and the connection's reason is the session's only when no capsule came. A
  WebTransport stream whose pump the lost connection cancelled before it ran now ends instead of leaving the
  application waiting.
- HTTP/3: a response or request body whose last bytes came with the peer's CONNECTION_CLOSE is read whole. When the
  connection is lost, the readers of the peer's streams (message bodies, control and QPACK streams) now go on until
  their input ends, at most one second, before the connection's coroutines are cancelled; before, they were cancelled at
  once and the body failed with the connection's error. A reader the application does not keep up with is cut after
  that second. This holds for a response whose headers came with the close too: its body's reader started
  after the connection's coroutines were gone and never ran, and the body failed with H3_NO_ERROR, unread.
- QUIC: data and FIN received just before a CONNECTION_CLOSE are delivered. A peer that sends its last bytes and closes
  at once (Firefox closes its WebTransport connection right after the session's WT_CLOSE_SESSION and FIN) lost them when
  the close was processed before the application read: the reads failed with the connection's end.
- QUIC: `QuicPath.remoteAddress` reports each path's own peer address. Before, every path reported the connection's
  current one: on a server whose client migrated, the path the client left (in `PathEvent.Changed.old` and
  `QuicConnection.paths`) showed the client's new address, and a client's probe toward a server's preferred address
  showed the original one.
- HTTP/3: an application that cancels a request body (server) or a response body (client) now stops the stream at
  once with STOP_SENDING (`H3_NO_ERROR` on the server, `H3_REQUEST_CANCELLED` on the client). Before, the stream was
  stopped only when the peer sent its next DATA, so a peer that paused kept the stream and its flow-control credit.
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

## [0.2.0] - 2026-10-18

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

[Unreleased]: https://github.com/kuicksilver/kuicksilver/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/kuicksilver/kuicksilver/releases/tag/v0.2.0
