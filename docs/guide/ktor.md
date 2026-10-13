# Ktor engines

Kuicksilver plugs into Ktor 3.6 as a server engine (`io.kuicksilver:kuicksilver-ktor-server`) and a client engine
(`io.kuicksilver:kuicksilver-ktor-client`). Both speak HTTP/1.1 over TLS 1.3 (`kuicksilver-ktor-network`) and HTTP/3
(`kuicksilver-http3`); HTTP/2 is not implemented (ADR-0009). The code blocks below compile and run as `GuideSamplesTest`
(`kuicksilver-ktor-server/src/jvmTest` and `kuicksilver-ktor-client/src/jvmTest`); the engines' other tests run on every
target (see "Compatibility"). Every engine option with its default is in the [configuration
reference](configuration.md); common failures are in [troubleshooting](troubleshooting.md).

## Server

```kotlin
// guide:ktor:server
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector(TlsIdentity.fromPem(chainPem, keyPem.toCharArray())) {   // the key array is zeroed after import
        port = 443
        clientAuth = ClientAuth.Optional              // ask for a client certificate without requiring one
        trust = TrustConfig.AnchoredCa(listOf(clientCa))
    }
}) {
    routing {
        get("/") { call.respondText("hello, ${call.request.peerCertificates.size} certificates") }
    }
}
server.start(wait = true)
```

- A `tlsConnector` serves HTTP/1.1 over TLS on TCP; Ktor's HTTP/1.1 connection pipeline (from `ktor-server-cio`) parses
  requests, so keep-alive, pipelining, chunked bodies and `100-continue` behave as in the CIO engine. ALPN on TCP is
  `http/1.1`.
- `configuration.identity = ...` turns plain connectors into TLS ones, so `embeddedServer(Kuicksilver, port = 443,
  configure = { identity = ... })` works as expected. Without an identity a plain `connector { port = ... }` serves
  cleartext HTTP/1.1 (behind a TLS-terminating proxy, for tests).
- On the JVM, Ktor's `sslConnector(keyStore, alias, ...) {}` (and the `ktor.security.ssl.*` keys) is accepted: the key
  and chain under the alias become the identity, and a trust store makes client certificates required, as in Ktor's
  Netty and Jetty engines. Any other HTTPS connector type fails with `TlsException.Config` rather than serving cleartext.
- `call.request.peerCertificates` is the client certificate chain as the TLS layer validated it (empty without client
  authentication). Ktor has no equivalent.
- A TLS handshake failure closes only that connection. `resolvedConnectors()` reports the real ports when you bind port
  0; `stop(grace, timeout)` stops accepting, sends GOAWAY to every HTTP/3 connection at once, raises `ApplicationStopPreparing`
  and waits for running calls (HTTP/1.1 and HTTP/3) until the grace period, then cuts what is left at the timeout.
- Optional whitespace around a response header value is trimmed before the value goes out over HTTP/3 (field values
  carry none); a value HTTP/3 cannot carry (a character above U+00FF, CR, LF) fails the call and resets its stream.

### HTTP/3 on the server

Every TLS connector also serves HTTP/3 on UDP on the same port number; the UDP socket is opened after the TCP one, so
`port = 0` resolves first and both share the resolved port (`resolvedConnectors()` lists the TCP connectors). The OS
picks the TCP port only, so its UDP twin may be taken: the pair is then bound again on a new port, up to 16 times,
after which the connector serves HTTP/1.1 alone with a warning. A fixed port whose UDP side is taken fails the start. HTTP/1.1
responses then carry `Alt-Svc: h3=":<port>"; ma=86400` so clients can switch (RFC 7838) — unless the application set
its own `Alt-Svc`, or the response is a 421; `altSvc = false` turns the header off.

In an HTTP/3 call `call.request.httpVersion` is `"HTTP/3"`, `call.request.local.scheme` is `"https"`, the `:authority`
appears as the `Host` header, and `call.request.local.remoteAddress` follows the client when it migrates to another
network. Responses never carry `Transfer-Encoding` or other connection-specific headers: bodies of unknown length are
simply a sequence of DATA frames.

Knobs, named after Ktor's Netty engine where one exists: `http3` (on), `quic` (transport settings), `quicMaxIdleTimeout`
(applies while `quic` is not assigned), `udpSocketCount` (endpoint loops on `SO_REUSEPORT`, Linux and Android), `quicAdmission`
(Retry policy, Ktor-Netty's `quicTokenHandler`), `http3Settings`. UDP socket buffer sizes are not configurable yet.

The engine serves HTTP/3 on every target, Kotlin/Native Linux, Apple and Windows included (the accelerated `ksl` socket,
ADR-0006); `udpSocketCount > 1` needs Linux or Android. Where a QUIC server cannot run, the engine logs a warning and serves
HTTP/1.1 only, without `Alt-Svc`. The same applies to a `tlsConnector` with a `sniSelector`: QUIC cannot pick an
identity per SNI name in v1, so that connector skips HTTP/3 with a warning instead of failing to start.

### WebSockets over HTTP/3

With `webSocketsOverHttp3 = true` (the default) the HTTP/3 listener advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL` and
accepts Extended CONNECT with `:protocol = websocket` (RFC 9220). Such a request reaches Ktor's pipeline as the HTTP/1.1
upgrade request the `WebSockets` plugin knows — `GET` with `Connection: Upgrade`, `Upgrade: websocket` and a
`Sec-WebSocket-Key` — so ordinary `webSocket("/path") {}` routes serve it unchanged; the upgrade is answered with
`:status 200` and the frames travel on the request stream. Extended CONNECT with any other protocol is answered 501. A
plain HTTP/1.1 `Upgrade` on an HTTP/3 request is meaningless (RFC 9114 section 4.5) and gets 501 too.

### EngineMain and configuration keys

`io.kuicksilver.ktor.server.EngineMain` reads the usual `ktor.deployment.*` keys (and on the JVM `-sslPort` with
`ktor.security.ssl.*`). Its own keys work on every platform:

| Key | Meaning |
|---|---|
| `kuicksilver.tls.certificateChain`, `kuicksilver.tls.privateKey` | PEM files; the deployment port then serves TLS and HTTP/3 |
| `kuicksilver.http3` | serve HTTP/3 (`true`) |
| `kuicksilver.altSvc` | send `Alt-Svc` on HTTP/1.1 responses (`true`) |
| `kuicksilver.webSocketsOverHttp3` | accept RFC 9220 WebSockets (`true`) |
| `kuicksilver.udpSocketCount` | endpoint loops on the UDP port (`1`) |
| `ktor.deployment.connectionIdleTimeoutSeconds` | idle HTTP/1.1 keep-alive timeout (`45`) |

## Client

```kotlin
// guide:ktor:client
val client = HttpClient(Kuicksilver) {
    engine {
        trust = TrustConfig.Pinned(setOf(SpkiSha256.parse("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")), base = TrustConfig.Platform)
        http3 { discovery = Http3DiscoveryMode.Auto }    // the default: HTTP/1.1 first, HTTP/3 after Alt-Svc
    }
    install(HttpTimeout) { connectTimeoutMillis = 5_000; socketTimeoutMillis = 15_000 }
}
```

- `https://` and `wss://` go over TLS 1.3 with the same `trust`, `identity` and `tls {}` settings whatever the protocol;
  SNI and verification use the URL's host. `http://` and `ws://` are plain HTTP/1.1 over TCP.
- HTTP/1.1 requests are written and responses parsed with Ktor's CIO code (vendored, see `docs/ktor-internal-api.md`):
  chunked bodies, `Expect: 100-continue`, keep-alive with at most `maxConnectionsPerHost` idle connections per route
  (a pooled connection the server already closed is replaced once, transparently, for idempotent requests; a POST
  that failed on one is reported, never sent again). Requests on one connection are
  sequential; `pipelining` is not used. Limits and idle cleanup: see "Connection pool" below.
- A proxy (`proxy = ProxyBuilder.http(...)`) is used for HTTP/1.1 only: `CONNECT` tunnels for `https`, absolute-form
  requests for `http`; SOCKS proxies are refused with `UnsupportedOperationException`. HTTP/3 never goes through a proxy.
- Timeouts come from `HttpTimeout`: the connect timeout (TCP + TLS, or the QUIC handshake) fails with Ktor's
  `ConnectTimeoutException`, the socket timeout (any wait for data: the response head and every body read) with
  `SocketTimeoutException`; the request timeout is the plugin's own. Without `HttpTimeout` the engine's `connectTimeout` (10 s) applies.
- Capabilities: `HttpTimeoutCapability`, `WebSocketCapability`, `SSECapability`. `WebSocketExtensionsCapability` is not
  declared (no extension negotiation in v1), nor Unix sockets.
- `HttpClient()` without an engine finds Kuicksilver through `ServiceLoader` on the JVM with priority 0.5 (below OkHttp
  and the platform engines at 1.0, above CIO at 0.0) and through Ktor's engine list on Kotlin/Native.

### Connection pool

```kotlin
// guide:ktor:pool
val client = HttpClient(Kuicksilver) {
    engine {
        maxConnectionsCount = 1000                 // HTTP/1.1 connections of the engine, idle ones included
        maxConnectionsPerRoute = 100               // ... to one route (scheme, host, port, proxy)
        maxConnectionsPerHost = 4                  // idle keep-alive connections kept per route
        idleTimeout = 5.minutes                    // idle HTTP/1.1 and HTTP/3 connections are closed after this
        maxConnectionLifetime = Duration.INFINITE  // age after which a connection takes no new requests
    }
}
```

| Setting | Default | Compared with |
|---|---|---|
| `maxConnectionsCount` | 1000 | CIO `maxConnectionsCount` 1000; OkHttp `Dispatcher.maxRequests` 64 (requests, not sockets) |
| `maxConnectionsPerRoute` | 100 | CIO `endpoint.maxConnectionsPerRoute` 100; OkHttp `maxRequestsPerHost` 5 |
| `maxConnectionsPerHost` (idle per route) | 4 | OkHttp `ConnectionPool` 5 idle in all |
| `idleTimeout` | 5 min | OkHttp keep-alive 5 min; CIO `keepAliveTime` 5 s |
| `maxConnectionLifetime` | infinite | neither OkHttp nor CIO has one |

The limits are CIO's, so moving from CIO changes nothing; they guard against a runaway caller rather than shape traffic
(OkHttp's lower numbers limit requests, and HTTP/2 multiplexes behind them). The idle timeout is OkHttp's: long enough
to reuse a connection across bursts, short enough that a forgotten client does not hold sockets for long. A connection
the server closed meanwhile is detected when it is taken from the pool and replaced.

- **HTTP/1.1.** A request beyond `maxConnectionsPerRoute` or `maxConnectionsCount` waits, in arrival order, for a
  connection to come back or close; waiting and connecting share the connect timeout, so a request that waits too long
  fails with `ConnectTimeoutException`, as with CIO (`HttpTimeout`'s request timeout, if shorter, ends it first with
  `HttpRequestTimeoutException`). A full route does not hold up requests to other routes, and when only the total is
  exhausted the oldest idle connection of another route is closed to make room. A cancelled or timed-out waiter leaves
  the queue without taking or losing a slot. WebSocket connections hold their slot while open.
- **HTTP/3.** One QUIC connection per origin (and alternative) carries all requests. When the server's MAX_STREAMS
  credit is used up, a request waits for the next credit on that connection instead of failing or opening another
  connection; the request timeout bounds the wait (`HttpRequestTimeoutException`), and so does the socket timeout,
  which covers every wait until the response head. A connection without requests for `idleTimeout` is closed (QUIC's
  own idle timeout, `quic { idleTimeout }` and the server's, may end it first); one past `maxConnectionLifetime` takes
  no new requests and closes once its requests are done.
- **Cleanup.** A background task of the engine closes expired connections; it sleeps until the next expiry, at most
  `idleTimeout` and at most a minute, and stops when the client closes. Per-origin bookkeeping lives only while an
  origin has connections or waiting requests, so a client that talks to many origins does not grow without bound.

### HTTP/3 on the client

`http3 { discovery = ... }` decides when HTTP/3 is used for `https://` (never through a proxy):

| Mode | Behaviour |
|---|---|
| `Auto` (default) | HTTP/1.1 first; HTTP/3 once the origin announced it with `Alt-Svc` (see below) |
| `Preferred` | HTTP/3 by prior knowledge, falling back to HTTP/1.1 (like `curl --http3`); `quicHints` gives the same treatment to listed origins in `Auto` mode |
| `H3Only` | HTTP/3 only (like `curl --http3-only`): failures are reported, never retried over TCP |
| `H1Only` | HTTP/1.1 only |

HTTP/3 responses report `HttpProtocolVersion.HTTP_3_0`. One QUIC connection per origin carries all its requests; a
request the server did not process (GOAWAY above its stream, `H3_REQUEST_REJECTED`) is repeated on a new connection
without the application noticing. When HTTP/3 fails before the response headers, the request is repeated over HTTP/1.1
— always if it cannot have reached the server, otherwise only for idempotent methods whose body can be sent again
(bytes, a `WriteChannelContent` writer, or no body). A streamed `ReadChannelContent` body that HTTP/3 already consumed
is never replayed, neither on the fallback nor after a 421 or a `RequestNotProcessed`: the call fails with
`H3BodyConsumed` and the application decides. The fallback uses the same `trust`, pins and TLS 1.3 settings. When a call ends before its body was read, the rest of the stream is abandoned
with `STOP_SENDING`.

WebSockets use HTTP/1.1 `Upgrade` unless an HTTP/3 connection to the origin already allows Extended CONNECT (or the
mode is `H3Only`); over HTTP/3 the handshake is RFC 9220 and the plugin sees the usual 101.

### Discovery and Alt-Svc

In `Auto` mode the engine learns alternatives from `Alt-Svc` headers (RFC 7838) of HTTPS responses and sends the next
requests to the origin over HTTP/3, with an `Alt-Used` header; SNI and certificate verification still use the
origin's host. The rules:

- only responses over verified TLS count (an `http://` response can never redirect a client to an alternative);
- a new `Alt-Svc` replaces every entry of the origin, `clear` removes them, and so does a 421 response; this applies
  to every HTTP/1.1 response, including the ones served while a cached alternative is broken or lost the race;
- `ma` defaults to 86400 seconds and expired entries are ignored;
- an alternative on an unprivileged port (1024 and up) is refused for an origin on a privileged one, as Chromium does;
- only `h3` alternatives are used.

Entries live in `http3 { altSvcStore = ... }` — `InMemoryAltSvcStore` by default. `FileAltSvcStore(path)` keeps them
in one tab-separated text file (loaded once, rewritten atomically after every change, expired records dropped on load)
so the first request after a cold start can already use HTTP/3; implement `AltSvcStore` for any other backing store
(one engine per file: two engines sharing a file overwrite each other). Both built-in stores keep at most 8 alternatives
per origin (the first ones of the header) and 1000 origins, dropping the least recently used; `FileAltSvcStore` skips
the rewrite when a repeated header only refreshes the expiry, and the engine writes it after releasing its lock. With `clearOnNetworkChange = true`,
entries without `persist=1` are dropped when `networkId()` reports a new network.

### Racing and fallback

When HTTP/3 is an option (`Preferred`, a QUIC hint, or a live Alt-Svc alternative) and no HTTP/3 connection to it is
open yet, the engine races connection setups (RFC 8305 section 5, after Chromium and curl): QUIC starts at once and
TCP + TLS starts when QUIC fails, or after a head start of 1.5 x the host's smoothed RTT (250 ms without history,
clamped to 100 ms..2 s; `hardDelay` overrides it) — and with no head start at all on a network where QUIC was never
seen working. The request runs once, on the winner. A QUIC setup that loses the race keeps going in the background and
serves the next requests once it is up; a TCP connection that loses is closed. When both setups fail, the HTTP/1.1
failure is reported — the race was the one HTTP/1.1 attempt, there is no second one.

An alternative is marked broken only when HTTP/3 failed while HTTP/1.1 worked (a lost race, or a request that fell
back to HTTP/1.1 after the HTTP/3 connection failed as a whole: setup, QUIC transport, an HTTP/3 connection error; a
single stream reset or a malformed response falls back for that request only) — per origin and alternative, never "UDP is blocked" for everything: 5 minutes, doubling up to 2 days, and forgotten when `networkId()` reports a new
network. Broken alternatives are skipped (straight to HTTP/1.1).

## Observability (experimental)

Both engines report what they do without a logging dependency (the API is `@ExperimentalKuicksilverApi`). The QUIC side
is the one described in [QUIC: Observability](quic.md#observability): counters, a `KuicksilverLogger`, a
`ConnectionListener` and qlog.

**Server.** In the engine configuration, `logger` receives the HTTP/3 endpoints' diagnostics (warnings on standard error by
default; the engine's own messages keep going to the application's log), `connectionListener` hears every QUIC
connection, `qlog` adds a trace per HTTP/3 connection to `quic`, and `eventListener` takes a
`KuicksilverServerEventListener`: `connectionOpened` and `connectionClosed` with the protocol (`HTTP/1.1` after the TLS
handshake, `HTTP/3.0` once accepted) and the peer's address, `tlsHandshakeFailed`, and `requestStarted` / `requestEnded`
around the application's pipeline with the `ApplicationCall` (its response status) and the pipeline's failure, if any.

```kotlin
embeddedServer(Kuicksilver, configure = {
    tlsConnector(identity) { port = 443 }
    logger = KuicksilverLogger.stderr(LogLevel.Info)
    qlog = AsyncQlogSink(DirectoryQlogSink("/var/log/qlog"), sampleEvery = 100)
    eventListener = object : KuicksilverServerEventListener() {
        override fun requestEnded(protocol: HttpProtocolVersion, call: ApplicationCall, cause: Throwable?) {
            metrics.record(protocol, call.response.status()?.value)
        }
    }
}, module = Application::module)
```

**Client.** `engine { eventListener = ... }` takes a `KuicksilverEventListener`, an abstract class with an empty method
per event in the manner of OkHttp's `EventListener`: `callStart`, `callEnd` (protocol and status) or `callFailed`;
`protocolSelected` with a `ProtocolReason` (`Configuration`, `NotSecure`, `ExistingConnection`, `Race`, `NoAlternative`,
`BrokenAlternative`, `WebSocket`, `Fallback`); `raceEnded` (winner, head start, why HTTP/3 lost); `altSvcUsed` and
`altSvcMarkedBroken`; `fallback` from HTTP/3 to HTTP/1.1; `retry` (a request the server did not process after GOAWAY, a
stale pooled HTTP/1.1 connection); `connectionAcquired` (reused or new) and `connectionReleased` (kept for the next request
or closed). `logger` (null keeps `http3.endpoint.logger`) also receives the listener's own failures, and
`http3 { qlog = ...; connectionListener = ... }` reach the engine's QUIC endpoint.

```kotlin
HttpClient(Kuicksilver) {
    engine {
        eventListener = object : KuicksilverEventListener() {
            override fun protocolSelected(request: HttpRequestData, protocol: HttpProtocolVersion, reason: ProtocolReason) {
                println("${request.url}: $protocol ($reason)")
            }
        }
        http3 { qlog = AsyncQlogSink(DirectoryQlogSink("qlog")) }
    }
}
```

Callbacks of both listeners run on the engines' coroutines and must return quickly; an exception out of one is logged and
never fails a call.

### Graceful stop

`stop(gracePeriodMillis, timeoutMillis)` stops accepting TCP connections, sends GOAWAY on every live HTTP/3 connection at
once (RFC 9114 section 5.2) and shuts each HTTP/3 endpoint down with the same grace period
([QUIC: Graceful shutdown](quic.md#graceful-shutdown)): a new QUIC client is refused at its first Initial with
CONNECTION_REFUSED instead of waiting for a handshake timeout, a handshake already in flight still completes and its
connection gets GOAWAY at once, and the calls in flight finish. The stop returns as soon as they have: each HTTP/3
connection closes with H3_NO_ERROR once its last call is answered. At the end of the grace period the calls still
running are cancelled and the connections left are closed with H3_NO_ERROR; the stop then waits for those calls to end,
until `timeoutMillis` after it began at most.

## 0-RTT (opt-in, experimental)

Both engines can resume HTTP/3 connections with 0-RTT ([ADR-0015](../adr/0015-0rtt-implementation.md)). It is off by
default.

- **Server:** set `quicEarlyData = true` in the engine configuration. GET, HEAD and OPTIONS requests that arrive in
  0-RTT run before the handshake completes, and `call.request.receivedEarly` is true for them. Every other request
  waits for the handshake. `http3Settings { earlyData = Http3EarlyDataPolicy.Reject425() }` answers `425 Too Early`
  instead.
- **Client:** set `http3 { earlyData = true }`. The engine keeps the servers' session tickets for its lifetime, and
  on a new connection to a server it has a ticket for, it sends GET, HEAD and OPTIONS requests without a body in 0-RTT.
  Other requests wait for the handshake. A `425` is retried once.

> **Replay warning.** An attacker can replay a 0-RTT request (RFC 8446 section 8). Turn this on only when the handlers
> of GET, HEAD and OPTIONS have no side effects.

## Supported Ktor versions

Kuicksilver 0.x supports **Ktor 3.6.x** (built and tested against 3.6.0). The engines use a few Ktor internals and
vendor parts of Ktor CIO (`docs/ktor-internal-api.md`), which Ktor may change in any minor release, so another
major.minor is not supported even when it happens to link.

- **At startup.** Creating a client engine (`HttpClient(Kuicksilver)`, also through `ServiceLoader`) checks
  `ktor-client-core` and `ktor-http-cio`; starting a server engine checks `ktor-server-core` and `ktor-server-cio`. On the
  JVM and Android the version is the `Implementation-Version` in the manifest of the jar that holds each class; when the
  major.minor is not 3.6, the engine fails with an `IllegalStateException` naming the artifact, its version and the
  fix. Where no version can be read (Android after dexing, shaded or repackaged jars, classes from a directory) the check
  passes silently.
- **Opting out.** `-Dkuicksilver.ktor.versionCheck=false` (or `System.setProperty` before the engine is created) skips
  the check, for experts who verified their Ktor themselves; a mismatch then fails later, if at all, with
  `NoSuchMethodError` or `AbstractMethodError`.
- **Kotlin/Native.** klibs are resolved when the binary is linked: a Ktor whose ABI differs fails the link (unresolved
  symbols), so there is no runtime check. Keep every `io.ktor` dependency on the same 3.6.x, best with
  `platform("io.ktor:ktor-bom:3.6.0")`.
- **Upgrades.** A new Ktor minor is adopted in a Kuicksilver release: the version catalog moves, every entry of
  `docs/ktor-internal-api.md` is re-checked, the vendored CIO code and contract tests are re-vendored from the new tag,
  and `KtorVersionPolicy.SUPPORTED` moves with them. Ktor patch releases (3.6.x) need nothing and are accepted at once.

## Compatibility

Both engines run Ktor 3.6.0's own engine contract tests, vendored under `src/commonTest/kotlin/.../contract` (and
`src/jvmTest` for the JVM-only `ContentTestSuite`; attribution in `NOTICE`), over HTTP/1.1 and over HTTP/3, on every target:
the JVM, Android, Linux, macOS, iOS and Windows. The HTTP/3 runs, like the engines' own HTTP/3 tests in `commonTest`,
need a QUIC server peer and run where one can bind, which since 0.2.0 is every target with the accelerated socket: the
JVM, Android, Linux, macOS, the iOS simulator and Windows (where a probe finds no server, they pass without running). iOS
runs them on the simulator (`iosSimulatorArm64Test`), not yet on a device. Windows (Kotlin/Native and the JVM) was
verified in a local Windows 11 VM (Parallels); there is no CI run on Windows while GitHub Actions is paused.

**Client** (`kuicksilver-ktor-client`): `ContentTest`, `PostTest`, `UploadTest`, `DownloadTest`, `HttpRedirectTest`,
`HttpTimeoutTest` and `WebSocketTest` against Ktor's test-server routes hosted on the Kuicksilver server engine; every
test runs twice — `Kuicksilver-h1` (cleartext HTTP/1.1, `H1Only`) and `Kuicksilver-h3` (HTTPS, `H3Only`). 93 tests,
90 pass in both modes, 3 are `@Ignore`d upstream. Left out:

- tests that need modules this project does not depend on: JSON content negotiation (`testJsonPostWithEmptyBody`),
  `ktor-client-auth` (three bearer-token WebSocket tests), kotlinx-serialization (`testWebSocketHeaders`, which over
  HTTP/3 would also have no `Connection`/`Upgrade`/`Sec-WebSocket-Key` to compare — RFC 9220 drops them);
- `testWebsocketWithDefaultRequest` over HTTP/3 only: `defaultRequest` sets host and port, so the URL stays `ws://`;
- `ServerSentEventsTest` and `HeadersTest`: they need serialization, logging and auth plugins (SSE is covered by the
  engine's own tests over both protocols).

The contract found and fixed: a closed client kept its UDP socket (the engine's cleanup waited for its own parent
job), the socket timeout did not cover response bodies, an HTTP/3 body cancelled by the call reported the stream reset
instead of the call's cause (request timeout, caller's exception), and the `Sec-WebSocket-Protocol` of a WebSocket over
HTTP/3 did not reach the client.

**Server** (`kuicksilver-ktor-server`): `HttpServerCommonTestSuite` and `ContentTestSuite` run over HTTP/1.1
(`KuicksilverH1*`: each request once in cleartext and once over TLS, as Ktor's own engines do) and over HTTP/3
(`KuicksilverH3*`, `H3Only` client); `WebSocketEngineSuite` runs over HTTP/1.1 (`KuicksilverH1WebSocketTest`) — its
tests drive raw TCP sockets, so an HTTP/3 run would repeat them unchanged; WebSockets over HTTP/3 are covered by the
engine's tests and by the client contract's `WebSocketTest` in `Kuicksilver-h3` mode. The test client is
`HttpClient(Kuicksilver)` (a test-only dependency on `kuicksilver-ktor-client`), the plugins the suites install are
Ktor 3.6.0's (test scope only). On the JVM: 143 tests, 136 pass, 7 skip: `@Http2Only` (server push, no HTTP/2 in Kuicksilver),
`@Http1Only` over HTTP/3 (the two keep-alive tests and chunked encoding), and two tests `@Ignore`d upstream. The
multipart uploads (streamed bodies of unknown length, chunked over HTTP/1.1) run over HTTP/3 too. Adapted: the test base (ports from the engine's resolved
connectors, the TLS identity from the test CA, real time instead of virtual time), the paths of the local-file and
static-resource tests (this module's layout and package). Not vendored: `HttpServerJvmTestSuite`,
`SustainabilityTestSuite`, `ClientCertTestSuite` and the other JVM suites — they rely on `HttpURLConnection`, JKS key
stores and the Apache/OkHttp clients. Off the JVM, `PortableContentTestSuite` carries the 13 `ContentTestSuite` tests
that need no `java.io` (with `respondBytesWriter` and `ChannelWriterContent` for the JVM writers) in its place.

The suites found and fixed: a query parameter without a value (`?auto`) read as `null` instead of `""` over HTTP/3,
and the HTTP/1.1 client sent a streamed request body completely before reading the response (a server that answers
first, then reads the body, deadlocked). On Linux Native the client contract found that a failed HTTP/3 request (a peer
resetting a WebSocket stream) escaped as an uncaught coroutine exception, which aborts a Kotlin/Native process; each
request now contains its own failure.

### IPv6 over TCP on Kotlin/Native

Ktor 3.6.0's `ktor-network` sockets on Kotlin/Native (Linux, Apple, Windows) never copy the IPv6 address into the
`sockaddr_in6` they bind or connect with (`NativeIPv6SocketAddress.nativeAddress` sets family, port, flow label and scope
only), so every IPv6 bind and connect uses `::`. A connector on `::1` listened on every interface (and, dual-stack, on
IPv4); a request to an IPv6 address went to `::`, which Linux and Apple route to the local host and Windows refuses
(`WSAEADDRNOTAVAIL`, 10049). Details and the upstream report draft: [ktor-native-ipv6.md](../upstream/ktor-native-ipv6.md).

Both engines therefore open their HTTP/1.1 TCP sockets through `kuicksilver-ktor-network` (`bindTcp`, `connectTcp`): on
the JVM and Android that is `ktor-network` as before; on Kotlin/Native it is a TCP socket of Kuicksilver on Ktor's selector
that binds and connects the address `getaddrinfo` returned. So on every platform:

- a server connector with a specific `host` (`::1`, `127.0.0.1`, a global address) listens on that address only; `::` and
  `0.0.0.0` stay the wildcards;
- the client's HTTP/1.1 connection (and its connection to an HTTP proxy) goes to the address in the URL, trying each
  address a host name resolves to in turn; an IPv4-mapped literal (`[::ffff:127.0.0.1]`) is connected over IPv4, as the
  JVM does.

HTTP/3 uses the accelerated `ksl` UDP socket, which carries the full address on every platform (the Ktor client's endpoint
is dual-stack, ADR-0006). The portable Kotlin/Native UDP socket (`IoPreference.Portable`, or a sandbox that refuses the
accelerated one) still uses `ktor-network`: it refuses to bind a specific IPv6 address (`UnsupportedOperationException`)
and to send to an IPv6 address (`IOException`), instead of
using `::`. Tests: `ServerH1Test.negative_ipv6ConnectorListensOnItsAddressOnly`,
`ClientH1Test.negative_h1ToIpv6LiteralReachesThatAddressOnly`, `ClientH1Test.plainHttpToIpv6Literal`,
`ClientH3Test.h1ToIpv6Loopback`, `TcpSocketsTest`, `KtorDatagramIoTest`.
