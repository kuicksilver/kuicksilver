<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Ktor client engine

**What this page is for.** What `HttpClient(Kuicksilver)` does and how to tune it: the mobile first screen,
timeouts, HTTP/2, h2c, the connection pool and coalescing, Happy Eyeballs and name resolution.

**Before you start**

- The first client: [Quickstart](quickstart.md#2-a-client). The options most clients set:
  [configuration: first screen](configuration.md#first-screen-ktor-client).
- The imports of the code blocks: [Ktor engines: Imports](ktor.md#imports).
- Related pages: how the client finds and uses HTTP/3 in [HTTP/3 in the Ktor client](client-http3.md); pins and client
  certificates in [TLS in the Ktor engines](engine-tls.md); [proxies](client-proxies.md); why a request did not use HTTP/3
  in [Observability and diagnostics](observability.md).

The client's first screen for the most common case, configuring nothing, is in the [Minimal example](ktor.md#minimal-example).
A mobile app talking to its own API sets a handful of options, all stable but `migration`:

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // only for http3 { migration }

// guide:ktor:first-screen-mobile
val client = HttpClient(Kuicksilver) {
    engine {
        connectTimeout = 10.seconds
        http3 {
            hints = setOf(HostPort("api.example.com", 443))                         // HTTP/3 from the first request
            altSvcStore = FileAltSvcStore(File(context.cacheDir, "alt-svc"))        // remember HTTP/3 across restarts
            allowed = { remoteConfig.http3Enabled }                                  // remote kill switch
            migration = Http3ConnectionMigration.followDefaultNetwork(connectivity)  // Wi-Fi <-> LTE without a reset
        }
        tls { trust = TrustConfig.AnchoredCa(listOf(privateCa)) }                    // only for a private CA
        observability { logger = KuicksilverLogger.platform(LogLevel.Info) }         // while you debug "why not HTTP/3"
    }
}
```

The default logger, `KuicksilverLogger.Default`, is the platform's (SLF4J on the JVM, Logcat on Android, `NSLog` on Apple
platforms, standard error elsewhere) at warnings and up: the line per call that says why HTTP/3 was not used is Info
([Why did this request not use HTTP/3?](observability.md#why-did-this-request-not-use-http3)), hence the `LogLevel.Info` logger while you
debug. Every option, with its block, type, default and stability, is in the [configuration reference](configuration.md#ktor-client).
With Ktor's timeouts:

```kotlin
// guide:ktor:client
val client = HttpClient(Kuicksilver) {
    engine {
        http3 { discovery = Http3Discovery.Auto }    // the default: TCP first, HTTP/3 after Alt-Svc
    }
    install(HttpTimeout) { connectTimeoutMillis = 5_000; socketTimeoutMillis = 15_000 }
}
```

- `https://` and `wss://` go over TLS 1.3 with the same `tls { }` (trust, client certificate, versions, suites) whatever
  the protocol;
  SNI and verification use the URL's host. Over TCP, `https://` is HTTP/2 when the server picks `h2` in ALPN and
  HTTP/1.1 otherwise ([HTTP/2 on the client](#http2-on-the-client)). `http://` and `ws://` are plain HTTP/1.1 over TCP. On Android they follow
  the app's Network Security Configuration as OkHttp does: a host for which `NetworkSecurityPolicy.isCleartextTrafficPermitted`
  is false (every host by default from `targetSdk` 28) is refused before any connection with an `IOException`
  "CLEARTEXT communication to <host> not permitted by network security policy". The policy matches strings, so it is
  asked about one spelling per address, and `<host>` in that message is this spelling: an IPv4 address in any form
  inet_aton reads alike on every platform (`127.1`, `2130706433`) as its dotted quad (`127.0.0.1`); an IPv6 literal in
  the text RFC 5952 recommends (`[0:0:0:0:0:0:0:1]` as `::1`), without its zone, so a rule for `fe80::1` holds on every
  link and a `<domain>` written with a zone never matches; an IPv4-mapped literal (`[::ffff:192.0.2.1]`) as its dotted
  quad (`192.0.2.1`), the address the connection goes to; and a name as it is. Write `<domain>` entries in these
  spellings. A host that can be in none of them fails before the policy is asked, with an `IOException` of its own: an
  IP literal that is no IPv6 address ("not an IP address"), an IPv4 form that platforms read differently (`010.0.0.1`),
  a host beginning with a dot, and a name with non-ASCII characters: the engine does not map an internationalised name
  to its A-label, so the URL must carry the A-label (`xn--...`), as the `<domain>` entry does.
- HTTP/1.1 requests are written and responses parsed with Ktor's CIO code (vendored, see `docs/ktor-internal-api.md`):
  chunked bodies, `Expect: 100-continue`, keep-alive with at most `pool { maxIdleConnectionsPerRoute }` idle connections per route
  (a pooled connection the server already closed is replaced once, transparently, for idempotent requests; a POST
  that failed on one is reported, never sent again). Requests on one connection are
  sequential; `pipelining` is not used. Limits and idle cleanup: see "Connection pool" below. A response head (status
  line and header fields) is limited to 64 KiB, the same as the HTTP/3 field section, and the interim (1xx) responses
  skipped before the final one to 64 KiB in all, however many they are (RFC 9110 section 15.2); beyond either the
  request fails with Ktor's `ParserException` and the connection is closed. A chunked response body must follow RFC
  9112 section 7.1 exactly, as on the server: a chunk-size line with whitespace right before its CRLF (`5 \r\n`, which
  Go's net/http and nginx tolerate) fails the response with "Whitespace before the end of a chunk size line" since
  0.2.1. A proxy's response to `CONNECT` has the same
  limits.
- Requests go through a proxy when one applies (by default the platform's proxy settings): TCP only (HTTP/1.1, or HTTP/2
  inside the tunnel), see [Proxies](client-proxies.md#proxies).
- Timeouts come from `HttpTimeout`: the connect timeout (TCP + TLS, or the QUIC handshake; the name resolution and the
  wait for a pool slot share it) fails with Ktor's `ConnectTimeoutException`, whose message names the timeout that fired
  (`connect_timeout=500 ms`: `HttpTimeout`'s, else the engine's own `connectTimeout`), the socket timeout with `SocketTimeoutException`; the request timeout is the plugin's own.
  The socket timeout is an inactivity timeout, as Ktor defines it ("maximum time of inactivity between two data
  packets"): while the request body goes out and the response head is awaited, every piece of the body the connection
  takes and every byte of the response that arrives restarts it, so an upload that keeps moving never times out however
  long it takes, and one that stalls (the server stops reading, the application stops writing) fails that long after its
  last progress; every read of the response body then has it on its own. Without `HttpTimeout` the engine's `connectTimeout` (10 s) applies.
- Capabilities: `HttpTimeoutCapability`, `WebSocketCapability`, `WebSocketExtensionsCapability`, `SSECapability`; no
  Unix sockets. With `WebSocketExtensionsCapability` Ktor's `WebSockets` plugin offers the extensions installed with
  `extensions { install(...) }` in `Sec-WebSocket-Extensions` and negotiates them, over HTTP/1.1, HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220).
  permessage-deflate on every target is `PerMessageDeflate` ([WebSocket compression](realtime.md#websocket-compression-experimental));
  Ktor's own `WebSocketDeflateExtension` exists on the JVM and Android only. Both engines check the
  handshake and the frames (RFC 6455 sections 4.1, 5, 8.1 and 9.1). The client checks the server's answer before a
  session opens and fails the call with `WebSocketException` ("Handshake exception: …") unless, over HTTP/1.1, it has
  `Upgrade: websocket`, a `Connection` with `Upgrade` and exactly one `Sec-WebSocket-Accept` that answers the request's
  key, and, over every protocol, at most one `Sec-WebSocket-Extensions` with only offered extensions and at most
  one `Sec-WebSocket-Protocol` naming a subprotocol the request offered (Ktor's plugin checks only the status). The key
  is the engine's, from OpenSSL's CSPRNG and new for every connection, and every frame the client sends is masked with a
  new key from the same source. A frame with an RSV bit that no negotiated extension defines (RSV1 for
  permessage-deflate, on the first frame of a message only, RFC 7692 section 6.1), a reserved opcode, a mask bit in the
  wrong direction (RFC 6455 section 5.1: a server's frames are never masked, a client's always are), a malformed
  control frame, fragment, length or Close frame fails the connection with code 1002; a text message or a Close reason
  that is not UTF-8 with 1007, after permessage-deflate, which the engine decompresses itself whichever extension
  negotiated it; an uncompressed frame or message over the engine's `webSockets { maxMessageSize }` (16 MiB by default)
  with 1009, from the frame's header, before its payload is read, and a compressed one as it inflates
  past the limit. The engine hands the session a Close
  frame with that code in place of the bad frame, Ktor's session answers it, so the code goes on the wire and is the
  session's `closeReason`, and `incoming` ends without the bad frame (a raw `webSocketRaw` session sees the Close in
  `incoming` and answers it itself). An extension the engine does not know (the application's own) may use every RSV
  bit; one implemented by an installed Ktor extension the bits its factory declares. A text message the application
  builds from bytes (`Frame.Text(fin, ByteArray)`) that is not UTF-8 is not sent (also when Ktor's
  `WebSocketDeflateExtension` compresses it): the session fails with `ProtocolViolationException`. An extension the
  application brings with its own specification defines its payload: with one agreed, text is not checked.
- `HttpClient()` without an engine finds Kuicksilver through `ServiceLoader` on the JVM with priority 0.5 (below OkHttp
  and the platform engines at 1.0, above CIO at 0.0) and through Ktor's engine list on Kotlin/Native.

## HTTP/2 on the client

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:http2-client
val client = HttpClient(Kuicksilver) {
    engine {
        http2 {
            pingInterval = 30.seconds                           // a keep-alive PING; null (the default): none
            settings { initialStreamWindow = 1 shl 20 }  // our windows and limits (threat model 3.23)
        }
    }
}
```

Every `https://` connection over TCP offers `h2` and `http/1.1` in ALPN (RFC 9113 section 3.2); when the server picks
`h2` the responses report `HttpProtocolVersion.HTTP_2_0` and one connection per route carries the requests as streams.
This holds directly, through an HTTP CONNECT tunnel and through SOCKS5 (ALPN is inside the TLS session with the origin,
as with OkHttp), in every `http3 { discovery }` mode but `H3Only`, with `http3 { enabled = false }`, and whatever `http3 { allowed }` says: the HTTP/3 kill
switch does not turn HTTP/2 off. `http2 { enabled = false }` offers only `http/1.1`, as in 0.2. The `http2` block is stable; `priorKnowledge` (h2c) and
`settings { }` are experimental.

- **Not HTTP/2.** `http://`, unless its origin is listed for h2c ([h2c on the client](#h2c-on-the-client)). A WebSocket opens no HTTP/2 connection of its own: see
  WebSockets below. No server push (the client sends SETTINGS_ENABLE_PUSH = 0; a PUSH_PROMISE
  ends the connection), and no connection coalescing across origins unless turned on ([Connection
  coalescing](#connection-coalescing-experimental)). `priority(...)` goes as the end-to-end `priority`
  field, with an RFC 7540 weight in the HEADERS until the server says it ignores those (RFC 9218 section 2.1.1).
- **Repeats.** A request the server did not process, a stream above a GOAWAY's last stream or refused with
  REFUSED_STREAM (RFC 9113 section 8.7), goes again on another stream or connection, at most twice, whatever its
  method; a streamed body already consumed fails the call with `H3BodyConsumed` instead. A server that answers
  HTTP_1_1_REQUIRED makes its route offer only `http/1.1` for 5 minutes (doubling up to 2 days at each new refusal):
  `ProtocolDiagnostics.fallback` says `H2Refused`. The request itself goes again over HTTP/1.1 only when the server did
  not process it, or when it is idempotent with a body that can be sent again (a GET, say); a POST the server may have
  processed is not sent twice: that call fails with `Http11RequiredException`, and the application can send it again,
  which then goes over HTTP/1.1. Any other HTTP/2 failure fails
  the call with `Http2Exception` (`StreamReset`, `ConnectionClosed`, `MalformedMessage`, `FieldSectionTooLarge`); there
  is no silent repeat over HTTP/1.1.
- **Never-indexed fields** (RFC 7541 sections 6.2.3 and 7.1.3, experimental): `neverIndex("x-api-key")` in the request
  builder sends the named fields as literals never indexed (the engine does so on its own for every `authorization`
  and `proxy-authorization` value, and for `cookie` values under 20 bytes), and `response.neverIndexedHeaders` lists the response fields
  the server sent so. A proxy built on both engines keeps the representation by passing those names to `neverIndex` on
  the message it forwards. Over HTTP/3 the same API carries QPACK's 'N' bit (RFC 9204 section 4.5.4); over HTTP/1.1 the
  list is empty and `neverIndex` changes nothing.
- **Responses** are checked against RFC 9113 section 8: a malformed one (an invalid field, a content-length that does
  not match the content) fails with `Http2Exception.MalformedMessage`. A response field section above
  `settings { maxFieldSectionSize }` (64 KiB) fails its call, not the connection.
- **Flow control follows the application's reading**: the server gets window back as the body is read, so a body the
  application does not read stops the server at the stream window (512 KiB, growing to 6 MiB while the application
  keeps up) instead of filling memory.
- **No wait for the server's SETTINGS.** The request that opens a connection goes out right after our preface (RFC 9113
  §3.4), saving a round trip on every new connection. It is the only one before the server's SETTINGS: other requests for
  the route wait for them and then open streams within their SETTINGS_MAX_CONCURRENT_STREAMS, so a burst never meets a
  server's refusal (REFUSED_STREAM, or PROTOCOL_ERROR, which §5.1.2 also allows and which would fail the call).
- **Deadlines.** The server's SETTINGS (its preface) must arrive within what the connect timeout left after TCP and TLS,
  else the connection ends with SETTINGS_TIMEOUT: the call fails with `ConnectTimeoutException` when its request had no
  content or the content had not started, else with `Http2Exception.ConnectionClosed` (a request whose body went out is
  not one that never left). Ours must be acknowledged within `settings { settingsAckTimeout }` (10 s) of the server's
  preface. A connection quiet for 10 s is checked with a PING before it takes a
  request (half the connect timeout at most, 5 s; one PING per connection, shared by the requests that wait); one that
  does not answer takes no new request and the request goes to a new connection. Calls still running on it are not cut:
  the connection gets GOAWAY and closes once they are done (or closes at once when none run). With
  `pool { maxConnectionsPerRoute = 1 }` such a connection keeps the route's only slot until those calls end, and new requests
  wait for it within their connect timeout. Within an exchange, a response or a send window that stays shut is bounded by the socket timeout
  (`HttpTimeout`), and with `pingInterval` a connection whose PING is still unanswered at the next one is closed and its
  calls fail; with neither, a connection that dies mid-exchange holds the call until TCP gives up, as over HTTP/1.1.
- **TLS 1.2.** A client that allows TLS 1.2 (`tls { versions = TlsVersions.Tls12And13 }`) offers `h2` too, and a server
  without TLS 1.3 gets HTTP/2 over TLS 1.2 under RFC 9113 section 9.2: SNI from the URL's host, no TLS compression, and
  the TLS 1.2 suites of the profile, ECDHE with an AEAD (`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` with P-256 among them),
  none of which section 9.2.2 prohibits. Renegotiation stays refused: a server that asks for one (a HelloRequest) ends
  the connection with PROTOCOL_ERROR (section 9.2.1) and the calls on it fail with `Http2Exception.ConnectionClosed`
  (`code == PROTOCOL_ERROR`, `byPeer == false`); over HTTP/1.1 the renegotiation is refused and the connection goes on.
- **Events and diagnostics.** `protocolSelected` comes once the connection is in hand and names its protocol
  (`HTTP_2_0`), then `connectionAcquired(HTTP_2_0, reused)`; the race reports `raceEnded(winner = HTTP_2_0)`; and
  `ProtocolDiagnostics.protocol` is `HTTP_2_0` (its `fallback` still says why HTTP/3 was not used).
- **WebSockets** (RFC 8441). A `wss://` WebSocket goes over HTTP/2 when its origin has an HTTP/2 connection already
  (opened by an earlier request, as in Chromium) whose server enabled Extended CONNECT (SETTINGS_ENABLE_CONNECT_PROTOCOL
  = 1, section 3): an Extended CONNECT with `:protocol = websocket` on a new stream, without `Sec-WebSocket-Key`,
  `Connection` and `Upgrade` (section 5); the session's `call.response.version` is `HTTP_2_0`. A connection whose
  server's SETTINGS have not arrived yet is waited for, at most 1 s (within the connect timeout), before the WebSocket
  decides (section 3: the client "MUST NOT" use `:protocol` before the setting arrives); without them by then it goes
  over HTTP/1.1. Otherwise (no HTTP/2 connection, a server without
  the setting, a connection without a free stream, HTTP_1_1_REQUIRED) the WebSocket opens a connection of its own that
  offers `http/1.1` only and upgrades as in 0.2; a WebSocket never opens an HTTP/2 connection. A 2xx answer opens the
  session after its `Sec-WebSocket-Extensions` and `Sec-WebSocket-Protocol` were checked against the offer (an extension
  or a subprotocol not offered fails the handshake with `WebSocketException`, RFC 6455 section 4.1); any other answer
  fails it as an HTTP/1.1 answer without 101 does. The frames go within the server's flow-control windows (a send stall
  is bounded by the socket timeout) and come in through the stream's own window. A session that ends in order sends its
  END_STREAM only after the server's (at most 5 s after both Closes, then anyway; the stream is reset with CANCEL only
  when the server's END_STREAM has not come 5 s after that); a handshake refused here resets the stream with CANCEL, and a call that failed or
  was cancelled once the session was open closes it with a Close (1001 Going Away, or the application's own code) as one
  cancelled after its Close does (see [HTTP/3 on the client](client-http3.md#http3-on-the-client)). As over HTTP/1.1, one WebSocket per remote host
  is in its handshake at a time (RFC 6455 section 4.1).

## h2c on the client

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:h2c-client
val client = HttpClient(Kuicksilver) {
    engine {
        http2 {
            // these http:// origins speak HTTP/2 over cleartext TCP (h2c, prior knowledge); every other stays HTTP/1.1
            priorKnowledge = setOf(HostPort("backend.internal", 8080))
        }
    }
}
```

An `http://` request whose origin (host and port as in the URL) is in `http2 { priorKnowledge }` goes over HTTP/2 on
cleartext TCP (RFC 9113 section 3.3, experimental; [ADR-0018](../adr/0018-h2c-and-coalescing-in-030.md)): the client
connection preface right after the TCP connect, no TLS, no ALPN, never `Upgrade: h2c` (deprecated by section 3.1). The
list is per origin, where OkHttp's `Protocol.H2_PRIOR_KNOWLEDGE` turns a whole client to h2c: the application names the
servers it knows, and every other `http://` request stays HTTP/1.1. Nothing is learned (section 3.3: a server that once
spoke h2c may not again), and a listed origin does not have to be on loopback; the per-origin opt-in is the gate, as
grpc-go's `insecure.NewCredentials()` is per channel.

- **No fallback.** A listed server that speaks HTTP/1.1 only, or a TLS port, fails the call (its answer is no SETTINGS
  frame); only a server that ends the connection with HTTP_1_1_REQUIRED gets HTTP/1.1, as over TLS.
- **Never for `https://`** (section 3.3: HTTP/2 over TLS "MUST use protocol negotiation in TLS"), and never HTTP/3: an
  `http://` origin learns no alternative, neither from `Alt-Svc` fields nor from ALTSVC frames on an h2c connection.
  With `network { httpsRecords }` an HTTPS record still upgrades the request to `https://` first (RFC 9460 section 9.5).
- **Proxies.** Through an HTTP proxy the h2c connection goes in a CONNECT tunnel (an absolute-form request would be
  HTTP/1.1), as OkHttp does; through SOCKS5 as any other connection. The tunnel is a CONNECT to the origin's cleartext
  port (80, say), which many proxies refuse (squid's default `SSL_ports` allows CONNECT to 443 only): such a proxy fails
  the call with its answer to the CONNECT. `Proxy-Authorization` goes on the CONNECT only, never on the HTTP/2 stream. The pool keeps h2c connections per route (origin
  and proxy), apart from the `https://` ones of the same host.
- **The rest is HTTP/2 on the client**: one multiplexed connection per route, repeats, deadlines (the server's SETTINGS
  within the connect timeout), `pingInterval`, `settings` and diagnostics (`HTTP_2_0`; `fallback` says `NotSecure`,
  why not HTTP/3). A `ws://` WebSocket to a listed origin goes as an Extended CONNECT (`:scheme http`, RFC 8441 section
  5) on the origin's h2c connection; with none open, the WebSocket opens it (pooled for the requests after it) and waits
  for its SETTINGS (at most 1 s): an h2c-only server has no HTTP/1.1 Upgrade to offer. A server whose SETTINGS do not
  allow Extended CONNECT (section 3) gets the HTTP/1.1 Upgrade on a connection of its own, as over TLS.
- **Cleartext** (CWE-319): list only servers on a trusted network or behind a sidecar that protects the hop. On Android
  the app's cleartext policy applies as to any `http://` request.

## Connection pool

```kotlin
// guide:ktor:pool
val client = HttpClient(Kuicksilver) {
    engine {
        pool {
            maxConnections = 1000              // TCP connections (HTTP/1.1, HTTP/2) of the engine, idle ones included
            maxConnectionsPerRoute = 100       // ... to one route (scheme, host, port, proxy)
            maxIdleConnectionsPerRoute = 4     // idle keep-alive connections kept per route
            idleTimeout = 5.minutes            // idle HTTP/1.1, HTTP/2 and HTTP/3 connections are closed after this
            maxConnectionLifetime = null       // age after which a connection takes no new requests; null: none
        }
    }
}
```

| Setting | Default | Compared with |
|---|---|---|
| `maxConnections` | 1000 | CIO `maxConnectionsCount` 1000; OkHttp `Dispatcher.maxRequests` 64 (requests, not sockets) |
| `maxConnectionsPerRoute` | 100 | CIO `endpoint.maxConnectionsPerRoute` 100; OkHttp `maxRequestsPerHost` 5 |
| `maxIdleConnectionsPerRoute` (idle per route) | 4 | OkHttp `ConnectionPool` 5 idle in all |
| `idleTimeout` | 5 min | OkHttp keep-alive 5 min; CIO `keepAliveTime` 5 s |
| `maxConnectionLifetime` | null (none) | neither OkHttp nor CIO has one |

The limits are CIO's, so moving from CIO changes nothing; they guard against a runaway caller rather than shape traffic
(OkHttp's lower numbers limit requests, and HTTP/2 multiplexes behind them). The idle timeout is OkHttp's: long enough
to reuse a connection across bursts, short enough that a forgotten client does not hold sockets for long. A connection
the server closed meanwhile is detected when it is taken from the pool and replaced.

- **HTTP/1.1.** A request beyond `maxConnectionsPerRoute` or `maxConnections` waits, in arrival order, for a
  connection to come back or close; waiting and connecting share the connect timeout, so a request that waits too long
  fails with `ConnectTimeoutException`, as with CIO (`HttpTimeout`'s request timeout, if shorter, ends it first with
  `HttpRequestTimeoutException`). A full route does not hold up requests to other routes, and when only the total is
  exhausted the oldest idle connection of another route is closed to make room. A cancelled or timed-out waiter leaves
  the queue without taking or losing a slot. WebSocket connections hold their slot while open.
- **HTTP/2.** One connection per route while it has a free stream under the server's SETTINGS_MAX_CONCURRENT_STREAMS;
  it counts once toward `maxConnectionsPerRoute` and `maxConnections` however many requests it carries. When it is
  full a second one opens, within those limits; at the limits a request waits for a free stream within the connect
  timeout. Requests that start together toward a new origin open one connection: one connects while the others wait for
  it (ALPN is known only after the TLS handshake) and use it when it is HTTP/2, or connect on their own when it is
  HTTP/1.1; an origin last seen on HTTP/1.1 does not make them wait. A connection
  without requests for `idleTimeout`, or past `maxConnectionLifetime`, is sent GOAWAY and closes once its requests are
  done; a server's GOAWAY moves new requests to a new connection.
- **HTTP/3.** One QUIC connection per origin carries all requests, also when the origin is reached under several
  names (its host, an `Alt-Svc` alternative, an HTTPS-record target) that resolve to the same address and port: as RFC
  9114 section 3.3 asks, a second name finds the connection already there and shares it. Origins share one only with
  `pool { coalescing }` ([Connection coalescing](#connection-coalescing-experimental)). When the server's MAX_STREAMS
  credit is used up, a request waits for the next credit on that connection instead of failing or opening another
  connection; the request timeout bounds the wait (`HttpRequestTimeoutException`), and so does the socket timeout,
  which covers the time without progress until the response head. A connection without requests for `idleTimeout` is closed (QUIC's
  own idle timeout, `http3 { quic { maxIdleTimeout } }` (30 s) and the server's, may end it first: the effective idle time
  of an HTTP/3 connection is the smaller of the two unless `http3 { quic { keepAlive } }` is set); one past `maxConnectionLifetime` takes
  no new requests and closes once its requests are done.
- **Cleanup.** A background task of the engine closes expired connections; it sleeps until the next expiry, at most
  `idleTimeout` and at most a minute, and stops when the client closes. Per-origin bookkeeping lives only while an
  origin has connections or waiting requests, so a client that talks to many origins does not grow without bound.

## Connection coalescing (experimental)

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:coalescing
val client = HttpClient(Kuicksilver) {
    engine {
        // another origin's HTTP/2 or HTTP/3 connection may carry a request when its certificate passes every check
        // for the request's host and that host resolves to its address (off by default)
        pool { coalescing = true }
    }
}
```

With `pool { coalescing = true }` (off by default; [ADR-0018](../adr/0018-h2c-and-coalescing-in-030.md)) a request for
one `https` origin may go on an open HTTP/2 or HTTP/3 connection of another origin, as RFC 9113 section 9.1.1 and RFC 9114
section 3.3 allow: two names behind one wildcard certificate or one CDN certificate then share a connection, a handshake
and a congestion window. A request goes there only when both conditions of RFC 9110 section 4.3.3 hold:

- **The address.** The request's host resolves now (through `network { dns }`, NAT64 synthesis included) to the address and port the
  connection is connected to; over HTTP/3 the name is that of the request's own HTTP/3 endpoint (the origin, an
  `Alt-Svc` alternative or an HTTPS-record target). It is checked for every request, so a DNS answer that changed takes
  the next request elsewhere. Another port is another destination.
- **The certificate.** The chain the server presented passes every check a new connection to the request's host would
  make ("The certificate presented by the server MUST satisfy any checks that the client would perform when forming a
  new TLS connection for the host in the URI", RFC 9113 section 9.1.1): the `tls { trust }` (anchors, CRLs, validity now; the
  platform's verifier or a `Custom` verifier is asked about the new host), the pins, the name (a `*.example.com` covers
  one label, `example.com` and `a.b.example.com` not; an address literal needs an iPAddress entry), the security level
  and the staple (under `RequireStapled`, or for a must-staple certificate, the connection's server must have stapled an
  OCSP response that is still fresh). Checked once per connection and host; when the connection's ECH was accepted, or
  the host has an ECH configuration, the platform's verifier makes no network request about the host (RFC 9849 section
  10.7). A certificate that fails for the new host alone (it does not name it, a custom verifier refuses it) leaves the
  connection to its own origin; one that fails for the connection's own origin as well (expired, revoked, a stale staple)
  retires it: its requests finish, every origin's next request opens a new connection (RFC 9114 section 3.3), and one
  Warn line of the engine's `observability { logger }` per connection says why (the reason for the connection's own origin, and what the new
  host met). That line names both hosts, as an audit log needs (RFC 9110 section 4.3.4); filter it in your `logger` if
  host names must stay out of your logs.

A server that does not serve the host on that connection answers 421 (Misdirected Request; our server does for a host
its certificate does not name, and for any name but the SNI on a connection an `sniSelector` set up). The request then
goes once more, whatever its method, on a connection of its own origin (RFC 9110 section 15.5.20), and the connection
takes no further request of that host; a streamed body that the first attempt consumed fails the call with
`H3BodyConsumed` instead. A 421 on the origin's own connection is the call's answer. `ProtocolDiagnostics.attempts` counts
both attempts and the listener gets `retry`.

Never coalesced: requests through a proxy and connections through one (`proxy`, `proxies { resolver }`,
`proxies { connectUdp }`), so
a request the application routes through a proxy never takes a direct connection and the other way round; h2c; WebSockets
and WebTransport sessions; `TrustConfig.Tofu` (a key is remembered for a name only from a handshake with that name) and
`TrustConfig.ExpectedName`, also under `Pinned` (the certificate does not have to name the host; RFC 9110 section 4.3.3
attributes authority only to a certificate that does); an
HTTP/3 connection still in its handshake (0-RTT); an HTTP/2 connection without a free stream (the request opens its own
instead of waiting). Coalescing never brings HTTP/3 to a request that would not use it: over HTTP/3 it only spares the
handshake of a request that has an HTTP/3 endpoint of its own. Session tickets stay per origin (a coalesced request
resumes nothing and stores nothing), and the client certificate is the engine's `tls { identity }` for every origin. An ALTSVC
frame on a request stream of a connection that carried another origin is ignored (it does not say whose it is); each
response's `Alt-Svc` field is learned for its own origin. On an HTTP/2 connection other origins may share, `cookie` is
always sent as a literal HPACK never indexes (RFC 7541 section 7.1: a shared compression table lets one origin's
requests probe another's values), which costs the compression of longer cookies there. No ORIGIN frame (RFC 8336) is
used. `ProtocolDiagnostics.reason` says how HTTP/3 was chosen, not whether the connection is shared: a coalesced HTTP/3
request reports the path that led to HTTP/3 (`Race`, `HttpsRecord`, `Configuration`, ...), never `ExistingConnection`
(that one means a connection of the request's own origin), and its `connection` is the snapshot of the shared
connection.

Turn it on where the servers behind a shared certificate are one service, or answer 421 for the names they do not
serve: a TLS-terminating middlebox that picks the back end by SNI and does neither sends the request to the wrong back
end (RFC 9113 section 9.1.1), and a trust mistake then reaches every origin the connection carries. OkHttp and browsers
coalesce by default; Go's `net/http` and curl do not.

## Happy Eyeballs

Every connection the engine makes to a host name, HTTP/1.1 and HTTP/2 over TCP, HTTP/3 over QUIC, to the origin, to an
alternative and to an HTTP proxy, follows Happy Eyeballs version 2 (RFC 8305; details and the RFC text in
[RFC 8305](../spec/rfc/8305.md)):

- **Resolution.** With the system's resolver (the default; `network { dns }` sets [your own](#name-resolution-experimental)), the
  name's IPv6 (AAAA) and IPv4 (A) addresses are asked for separately, IPv6 first: one `getaddrinfo`
  per family on two threads, on the JVM and Android through Kuicksilver's native library, since `InetAddress` asks for
  both at once. The first IPv6 answer starts a connection at once; an IPv4 answer that comes first waits up to 50 ms for
  the IPv6 one (the Resolution Delay), and goes ahead at once when the IPv6 answer is empty or failed. An answer that
  comes while connections are being tried joins them. On the JVM, an application that installed its own resolver
  (`InetAddressResolverProvider`, `jdk.net.hosts.file`) keeps it: lookups go through `InetAddress` then, both families in
  one call. `java.net.preferIPv4Stack=true` leaves IPv6 out. At most 8 lookups of each family run at once, so a network
  that drops AAAA queries does not hold up the A lookups of other names.
- **Order.** The addresses are sorted by RFC 6724's destination address selection, the engine's own on every platform
  (also for the addresses of an [HTTPS record](client-http3.md#https-records-experimental)): an address without a usable source
  address (no IPv6 route, say) goes last, then matching scope and label, the policy table's precedence (native IPv6
  before IPv4 before 6to4 and Teredo), native transport before a tunnel, and the longest prefix shared with the source.
  The two families then alternate, starting with the first one in the sorted list. `java.net.preferIPv6Addresses` no
  longer decides the order.
- **Attempts.** One attempt at a time: the next one starts when `network { happyEyeballsDelay }` (250 ms) has passed since the
  last one started, or as soon as an attempt failed, but never within 10 ms of the last start. The first connection
  wins; the other attempts are cancelled, and one that connected anyway is closed. So an address that drops connection
  attempts silently costs 250 ms, not the request's connect timeout, which bounds all attempts together.
  `happyEyeballsDelay` takes 100 ms to 2 s, or null to try one address after another.
- **HTTP/3.** QUIC handshakes race over the addresses in the same way, so a family that drops UDP costs one attempt
  delay, also with `Http3Discovery.H3Only`; a cancelled handshake closes its connection. With `http3 { earlyData { enabled } }` and a
  session ticket for the server, the first address of the order can send 0-RTT at once and is used without a race:
  its requests go out early, and if its handshake then fails they fail and fall back as any HTTP/3 failure does; the
  other addresses are not tried for that setup. When every address fails, a server's CONNECTION_REFUSED counts as a
  refusal (no broken mark) only when every address refused. The [h3/h1 race](client-http3.md#racing-and-fallback) runs on top: each
  side races the addresses of the request's one resolution. An `Alt-Svc` alternative's host and an HTTPS record's
  endpoint are raced the same way, and [connection migration](client-http3.md#connection-migration) follows the connection that won.
- **IPv6-only networks (NAT64).** When the host has a global IPv6 address and no IPv4 route (464XLAT, as Android's
  clatd and iOS on cellular run it, gives one, and the engine then leaves IPv4 to the platform), an IPv4 address the
  host has no route to (an IPv4 literal, or a name with IPv4 addresses only) is reached through the network's NAT64:
  on Apple platforms with the system's own synthesis (`getaddrinfo` of the literal, Apple's documented way, so an iPhone
  on a NAT64 Wi-Fi uses the prefixes iOS knows), elsewhere with the prefix of an AAAA query for `ipv4only.arpa` (RFC
  7050), asked only once an address needs it, cached for its TTL (at least a minute, refreshed in the background before
  it ends, 30 s between failed queries) and forgotten on a new `network { networkId }` or a new IPv6 network. Addresses with a route
  (a LAN, a VPN, loopback) are used as they are, and the Well-Known Prefix `64:ff9b::/96` never carries a private
  address (RFC 6052). The engine then asks for a name's IPv4 addresses only when the IPv6 answer is empty, or 2 s after
  the last IPv6 attempt started without a connection (a broken AAAA record). On Android (API 30) the engine takes the
  prefix Android knows (`LinkProperties.getNat64Prefix`) when the application gave it a `ConnectivityManager` through
  `Http3ConnectionMigration.followDefaultNetwork(connectivity)` or `HttpsRecordSource.followingPrivateDns(connectivity)`;
  otherwise, where it runs no 464XLAT, the `ipv4only.arpa` query goes through its resolver.
- **Caching.** An answer is kept as long as the JDK's own cache would keep it (`networkaddress.cache.ttl`, 30 s, and
  `networkaddress.cache.negative.ttl`, 10 s by default; 2 s on Android), at most 1000 names and families; on
  Kotlin/Native the system resolver's cache does it.

## Name resolution (experimental)

The engine resolves host names with the system's resolver (`Dns.System`, the default, described under
[Happy Eyeballs](#happy-eyeballs)). `network { dns }` replaces it with a resolver of your own, as OkHttp's `Dns` does: another DNS
server (DNS over HTTPS through a client you trust), fixed addresses for some names, or a policy of your own. Whatever it
answers, the engine connects to with Happy Eyeballs over TCP (HTTP/1.1, HTTP/2) and QUIC (HTTP/3).

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:dns
// fixed addresses for some names, the system's resolver for the rest
val fixed = mapOf("api.example.test" to listOf(IpAddress.parse("192.0.2.10"), IpAddress.parse("2001:db8::10")))
val client = HttpClient(Kuicksilver) {
    engine {
        network { dns = Dns { name -> fixed[name] ?: Dns.System.lookup(name) } }
    }
}
// a blocking resolver (here the JDK's; an OkHttp Dns alike) runs on threads of its own
val blocking = HttpClient(Kuicksilver) {
    engine {
        network { dns = Dns.blocking { name -> java.net.InetAddress.getAllByName(name).map { IpAddress.of(it) } } }
    }
}
```

The contract (the KDoc of `Dns` has it in full):

- **Suspending, not blocking.** `lookup` is called in the call's coroutine on the engine's dispatcher and must not block
  it. `Dns.blocking { }` runs a blocking resolver on a pool of its own (8 threads by default, shared by all of them, or the
  dispatcher you give it): a lookup that never returns holds one of those threads, never the engine's. The default pool
  is shared by every `Dns.blocking` resolver of the process, every engine's: 8 lookups that hang hold it whole, and the
  others wait behind them until their calls time out. Give a resolver that may hang a dispatcher of its own. A call that
  gives up takes its lookup off the queue when it has not started.
- **Within the connect timeout.** The lookup is part of connecting: the connect timeout bounds it with the rest, and the
  call then fails with Ktor's `ConnectTimeoutException`; a cancelled call cancels its lookup. A blocking lookup cannot be
  interrupted: the call stops waiting and the lookup ends on its thread. A `CancellationException` your resolver throws
  on its own (its own `withTimeout`) counts as a failed lookup.
- **Failures.** An exception, an empty list, or a list without a usable address fails the connection as a name that does
  not resolve does (an `IOException`: "could not be resolved", with your exception as the cause, or "resolved to no
  address").
- **Order and families.** The engine sorts the answer by RFC 6724 and alternates the families (RFC 8305 section 4 makes
  the sort a MUST), as it does the system's: your order only breaks ties. A plain `Dns` answers both families in one
  call; implement `FamilyDns` to answer IPv6 and IPv4 separately, so that the race can start on the first answer
  (RFC 8305 section 3). Duplicates are dropped, an IPv4-mapped address counts as IPv4, and at most 32 addresses of each
  family are kept. On an IPv6-only network with NAT64 the IPv4 answers are synthesized as the system's are.
- **Never a destination.** 0.0.0.0/8, `::`, multicast and 255.255.255.255 in an answer, yours or the system's, are
  dropped: a connect to
  0.0.0.0 reaches the device's own listeners on Linux and macOS, and RFC 9293 makes a TCP open to a multicast address an
  error.
- **Literals.** An IP address in the URL is connected to as it is, unless no connection may go there (`0.0.0.0`,
  `[::]`, a multicast group, 255.255.255.255): that call fails with an `IOException`. Your resolver gets host names only.
  A host with the form of an IPv4 address that is not a dotted quad is not a host name (RFC 1123): `127.1` is 127.0.0.1,
  and one that platforms read differently (`010.0.0.1`, octal to some, decimal to others) fails the call without a
  lookup, with the system's resolver too.
- **Once per request.** Each name is asked once per request, both sides of the HTTP/3 and TCP race and a fallback
  included; the engine caches nothing across requests, so caching and TTLs are your resolver's.
- **Proxies.** Your resolver is asked for a proxy's name. Behind an HTTP proxy and `socks5h` the origin's name goes to
  the proxy and is never resolved here; through `socks5` it is resolved here and the proxy gets the addresses.
- **HTTP/3 and Alt-Svc.** An `Alt-Svc` alternative's host and an HTTPS record's target are resolved by it too; the A and
  AAAA records an HTTPS answer carries are used first, and your resolver is asked for the families they lack. HTTPS
  records themselves come from `network { httpsRecords }`; the NAT64 prefix discovery and a PAC script's `dnsResolve` stay with
  the system.
- **Identity.** Your answers decide where the engine connects, never whom it trusts there: TLS sends the URL's host
  name as SNI and verifies the certificate and the pins against that name over TCP and QUIC, whatever address your
  resolver gave. Connections are pooled per origin, never per address, and no connection is shared across origins.
