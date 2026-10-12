# Ktor engines

Kuicksilver plugs into Ktor 3.6 as a server engine (`io.kuicksilver:kuicksilver-ktor-server`) and a client engine
(`io.kuicksilver:kuicksilver-ktor-client`). Both speak HTTP/1.1 over TLS 1.3 (`kuicksilver-ktor-network`) and HTTP/3
(`kuicksilver-http3`); HTTP/2 is not implemented (ADR-0009). The code blocks below compile and run as `GuideSamplesTest`
(`kuicksilver-ktor-server/src/jvmTest` and `kuicksilver-ktor-client/src/jvmTest`).

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
`port = 0` resolves first and both share the resolved port (`resolvedConnectors()` lists the TCP connectors). HTTP/1.1
responses then carry `Alt-Svc: h3=":<port>"; ma=86400` so clients can switch (RFC 7838) — unless the application set
its own `Alt-Svc`, or the response is a 421; `altSvc = false` turns the header off.

In an HTTP/3 call `call.request.httpVersion` is `"HTTP/3"`, `call.request.local.scheme` is `"https"`, the `:authority`
appears as the `Host` header, and `call.request.local.remoteAddress` follows the client when it migrates to another
network. Responses never carry `Transfer-Encoding` or other connection-specific headers: bodies of unknown length are
simply a sequence of DATA frames.

Knobs, named after Ktor's Netty engine where one exists: `http3` (on), `quic` (transport settings), `quicMaxIdleTimeout`
(applies when `quic` is the default), `udpSocketCount` (endpoint loops on `SO_REUSEPORT`, Linux), `quicAdmission`
(Retry policy, Ktor-Netty's `quicTokenHandler`), `http3Settings`. UDP socket buffer sizes are not configurable yet.

Where a QUIC server cannot run — Apple and Windows Kotlin/Native (ADR-0006) — the engine logs a warning and serves
HTTP/1.1 only, without `Alt-Svc`.

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
  chunked bodies, `Expect: 100-continue`, keep-alive with at most `maxConnectionsPerHost` idle connections per origin
  (a pooled connection the server already closed is replaced once, transparently, for idempotent requests; a POST
  that failed on one is reported, never sent again). Requests on one connection are
  sequential; `pipelining` is not used.
- A proxy (`proxy = ProxyBuilder.http(...)`) is used for HTTP/1.1 only: `CONNECT` tunnels for `https`, absolute-form
  requests for `http`; SOCKS proxies are refused with `UnsupportedOperationException`. HTTP/3 never goes through a proxy.
- Timeouts come from `HttpTimeout`: the connect timeout (TCP + TLS, or the QUIC handshake) fails with Ktor's
  `ConnectTimeoutException`, the socket timeout (any wait for data: the response head and every body read) with
  `SocketTimeoutException`; the request timeout is the plugin's own. Without `HttpTimeout` the engine's `connectTimeout` (10 s) applies.
- Capabilities: `HttpTimeoutCapability`, `WebSocketCapability`, `SSECapability`. `WebSocketExtensionsCapability` is not
  declared (no extension negotiation in v1), nor Unix sockets.
- `HttpClient()` without an engine finds Kuicksilver through `ServiceLoader` on the JVM with priority 0.5 (below OkHttp
  and the platform engines at 1.0, above CIO at 0.0) and through Ktor's engine list on Kotlin/Native.

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
(one engine per file: two engines sharing a file overwrite each other). With `clearOnNetworkChange = true`,
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
back to HTTP/1.1 after failing on an HTTP/3 connection) — per origin and alternative, never "UDP is blocked" for everything: 5 minutes, doubling up to 2 days, and forgotten when `networkId()` reports a new
network. Broken alternatives are skipped (straight to HTTP/1.1). The curl-style `softDelay` ("no UDP datagram from the
server yet") is accepted in the configuration but not acted on in v1: the QUIC API does not expose that signal.

## Compatibility

Both engines run Ktor 3.6.0's own engine contract tests, vendored under `src/jvmTest/kotlin/.../contract` (attribution
in `NOTICE`), over HTTP/1.1 and over HTTP/3.

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
Ktor 3.6.0's (test scope only). 143 tests, 134 pass, 9 skip: `@Http2Only` (server push, no HTTP/2 in Kuicksilver),
`@Http1Only` over HTTP/3 (keep-alive tests, chunked encoding and the two multipart uploads that set
`Transfer-Encoding`), and two tests `@Ignore`d upstream. Adapted: the test base (ports from the engine's resolved
connectors, the TLS identity from the test CA, real time instead of virtual time), the paths of the local-file and
static-resource tests (this module's layout and package). Not vendored: `HttpServerJvmTestSuite`,
`SustainabilityTestSuite`, `ClientCertTestSuite` and the other JVM suites — they rely on `HttpURLConnection`, JKS key
stores and the Apache/OkHttp clients.

The suites found and fixed: a query parameter without a value (`?auto`) read as `null` instead of `""` over HTTP/3,
and the HTTP/1.1 client sent a streamed request body completely before reading the response (a server that answers
first, then reads the body, deadlocked).
