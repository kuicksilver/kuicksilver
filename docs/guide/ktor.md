<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Ktor engines

**What this page is for.** It covers the Ktor server and client engines: starting a TLS and HTTP/3 server, making HTTP/3
requests with `HttpClient(Kuicksilver)`, and the options and behaviour around them (limits, fallback, proxies,
observability).

**Before you start**

- Dependencies: `io.kuicksilver:kuicksilver-ktor-server` and/or `io.kuicksilver:kuicksilver-ktor-client`, version
  `0.3.0` or newer. Ktor 3.6.x, with all `io.ktor` artifacts on the same version
  ([Supported Ktor versions](#supported-ktor-versions)).
- Built with Kotlin 2.4.20: JVM and Android need Kotlin 2.3 or newer, Kotlin/Native 2.4.x
  ([Kotlin version](../stability.md#kotlin-version)).
- Platforms: JVM 17 or newer, Android `minSdk` 24, iOS 15, macOS 12 (macOS 11 on the JVM), Linux, Windows
  ([Platforms](../stability.md#platforms)).
- A server needs a certificate chain and private key (PEM). A client needs none: it trusts the platform's store unless you
  set `trust`.

<a id="minimal-example"></a>
**Minimal example.** A server with one route, and a client that makes one request to it (run the client inside a coroutine, for example
`runBlocking { }`):

```kotlin
val chainPem = File("fullchain.pem").readText()
val keyPem = File("privkey.pem").readText()
// guide:ktor:minimal-server
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector(TlsIdentity.fromPem(chainPem, keyPem.toCharArray())) {
        port = 8443
    }
}) {
    routing {
        get("/") { call.respondText("hello") }
    }
}
server.start(wait = true)
```

```kotlin
val url = "https://example.com:8443/"   // the host name in the certificate
// guide:ktor:minimal-client
val client = HttpClient(Kuicksilver)
println(client.get(url).bodyAsText())
client.close()
```

The client trusts the platform's store, so the server's certificate must chain to a CA it knows and name the host in the URL. The complete server
is under [Server](#server), the complete client under [Client](#client), and both with client certificates under
[Mutual TLS](#mutual-tls-client-certificates).

<a id="imports"></a>
**Imports.** The code blocks on this page start after their imports; these are the imports they use, and the test that
compiles them fails when a name moves. The server engine and the client engine are two objects with the same name,
`Kuicksilver`: `io.kuicksilver.ktor.server.Kuicksilver` for `embeddedServer(Kuicksilver)` and
`io.kuicksilver.ktor.client.Kuicksilver` for `HttpClient(Kuicksilver)`. Experimental API (`@ExperimentalKuicksilverApi`)
needs an opt-in: `@file:OptIn(ExperimentalKuicksilverApi::class)` at the top of the file, as the blocks show, or
`languageSettings.optIn("io.kuicksilver.annotations.ExperimentalKuicksilverApi")` for the whole module
([stability](../stability.md#stability-levels)).

```kotlin
// guide:ktor:server-imports
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.utils.io.copyTo
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http3.Http3EarlyDataPolicy
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.ktor.server.Http3Advertising
import io.kuicksilver.ktor.server.Kuicksilver
import io.kuicksilver.ktor.server.KuicksilverServerEventListener
import io.kuicksilver.ktor.server.peerCertificates
import io.kuicksilver.ktor.server.priority
import io.kuicksilver.ktor.server.receivedEarly
import io.kuicksilver.ktor.server.webTransport
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.qlog.AsyncQlogSink
import io.kuicksilver.quic.qlog.DirectoryQlogSink
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.io.IOException
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
```

```kotlin
// guide:ktor:client-imports
import io.ktor.client.HttpClient
import io.ktor.client.engine.ProxyBuilder
import io.ktor.client.engine.http
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.api.createClientPlugin
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.get
import io.ktor.client.request.prepareGet
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.utils.io.discard
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.ktor.client.KuicksilverEventListener
import io.kuicksilver.ktor.client.ProtocolReason
import io.kuicksilver.ktor.client.ProxyCredentials
import io.kuicksilver.ktor.client.ProxyResolver
import io.kuicksilver.ktor.client.ResolvedProxy
import io.kuicksilver.ktor.client.closeHttp3Connections
import io.kuicksilver.ktor.client.kuicksilverDiagnostics
import io.kuicksilver.ktor.client.priority
import io.kuicksilver.ktor.client.updatePriority
import io.kuicksilver.ktor.client.webTransport
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.qlog.AsyncQlogSink
import io.kuicksilver.quic.qlog.DirectoryQlogSink
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.io.readString
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
```

The Android sample under [Connection migration](#connection-migration) also needs `android.net.ConnectivityManager`,
`io.kuicksilver.ktor.client.Http3ConnectionMigration` and `io.kuicksilver.ktor.client.followDefaultNetwork` (an
Android-only extension; the iOS and macOS one, without arguments, has the same name). A file that uses both engines (a
test, a gateway) imports at least one of them under another name:

```kotlin
// guide:ktor:both-engines-aliases
import io.kuicksilver.ktor.client.Kuicksilver as KuicksilverClient
import io.kuicksilver.ktor.server.Kuicksilver as KuicksilverServer
// guide:ktor:both-engines
val server = embeddedServer(KuicksilverServer, configure = {
    tlsConnector(identity) { port = 8443 }
}, module = Application::module)
val client = HttpClient(KuicksilverClient)
```

Kuicksilver plugs into Ktor 3.6 as a server engine (`io.kuicksilver:kuicksilver-ktor-server`) and a client engine
(`io.kuicksilver:kuicksilver-ktor-client`). Both speak HTTP/1.1 over TLS 1.3 (`kuicksilver-ktor-network`) and HTTP/3
(`kuicksilver-http3`); both also speak HTTP/2 over TLS (`kuicksilver-http2`, ADR-0017), opt-in on the server ([HTTP/2 on the server](#http2-on-the-server)). The code blocks below compile and run as `GuideSamplesTest`
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

- A `tlsConnector` serves HTTP/1.1 over TLS on TCP; Ktor's HTTP/1.1 parser (`ktor-http-cio`) and a copy of the CIO
  engine's connection pipeline handle requests, so keep-alive, pipelining, chunked bodies and `100-continue` behave as
  in the CIO engine. Request framing follows RFC 9112 section 6 more strictly than CIO: a request with both
  Content-Length and Transfer-Encoding is refused with 400 and the connection closed, a request with neither has no
  body (also with `Connection: close`), and a chunked trailer section is accepted (its fields are discarded). A
  chunk-size line must follow RFC 9112 section 7.1 exactly (hex digits, extensions by their grammar, no whitespace
  right before the CRLF, which 0.2.0 and Go's net/http tolerate): anything else, such as a bare CR or LF in it, makes the handler's receive of the body fail with
  `BadRequestException` (Ktor answers 400 unless the application handles it) and the connection closes. An HTTP/1.1
  request without a Host field, or any request with two, gets 400 and the connection closed (RFC 9112 section 3.2).
  The engine cannot act as a CONNECT proxy (not supported in 0.3.0): a CONNECT reaches the application, but a 2xx answer
  goes out as `501 Not Implemented` with a warning in the application log, since a 2xx would promise a tunnel; every
  CONNECT ends its connection (RFC 9931 section 8). The engine's own 400 has the fixed body `Bad Request`
  (Ktor CIO sends the parser's message, which can quote the request's header fields). ALPN on TCP is `http/1.1`.
- `configuration.identity = ...` turns plain connectors into TLS ones, so `embeddedServer(Kuicksilver, port = 443,
  configure = { identity = ... })` works as expected. Without an identity a plain `connector { port = ... }` serves
  cleartext HTTP/1.1 (behind a TLS-terminating proxy, for tests).
- On the JVM, Ktor's `sslConnector(keyStore, alias, ...) {}` (and the `ktor.security.ssl.*` keys) is accepted: the key
  and chain under the alias become the identity, and a trust store makes client certificates required, as in Ktor's
  Netty and Jetty engines. Any other HTTPS connector type fails with `TlsException.Config` rather than serving cleartext.
- `call.request.peerCertificates` is the client certificate chain as the TLS layer validated it (empty without client
  authentication). Ktor has no equivalent. Requiring client certificates, and presenting one from the client:
  [Mutual TLS](#mutual-tls-client-certificates).
- Slow and silent clients (slowloris): a client has `requestHeaderTimeoutSeconds` (*experimental*, 30 s) to send a
  complete request head, counted from the accepted TCP connection for the first request (the TLS handshake included)
  and from the end of the previous response on a keep-alive connection; header bytes trickling in do not extend it. One
  that sent part of a head by then gets `408 Request Timeout` with `Connection: close`; one that sent nothing (or never
  finished the TLS handshake) is closed without a response. `connectionIdleTimeoutSeconds` (45 s) closes a connection
  without requests in both directions, and a request body that sends no byte for that long gets `408 Request Timeout`
  and ends the connection, unless the application or StatusPages answers the failed read itself (a slow but moving
  upload is read in full; after `Expect: 100-continue` the wait starts once `100 Continue` is sent). `Expect:
  100-continue` with content gets `100 Continue` at once, as the handler starts (RFC 9110 §10.1.1), unless the head
  alone decides the final status (400, 413, 425, 431 go out without it); another expectation is answered 417 when the
  handler reads the body. A body the handler leaves unread is dropped up to 256 KiB; a larger rest, a chunked one still
  incomplete when the response starts, or a request answered without the `100 Continue` it asked for, ends the
  connection after a response that says `Connection: close`. One whose client stopped reading its response (the socket
  took nothing) is closed after the longer of that and 5 minutes: the engine sees progress about 1 MiB at a time, and 5 minutes serve
  clients down to about 3.4 KiB/s. A closing connection sends what is left for as long as the client takes it, and is
  aborted after the same deadline without progress, so a slow reader's last response is not cut short.
  Empty lines before a request line are skipped and do not count as a started request. A request head (request line
  and header fields) above 64 KiB, the HTTP/3 default `maxFieldSectionSize`, gets `431 Request Header Fields Too
  Large` and the connection closes; a single line above 8 KiB gets 400. A failing `accept()` (the descriptor table
  full: EMFILE, ENFILE) is retried after 5 ms, doubling up to 1 s, instead of at once, and logged at most once per
  10 s with the number of failures left out. How many connections a connector holds, in all and per client address,
  is bounded too: [Connection limits](#connection-limits).
- A TLS handshake failure closes only that connection. `resolvedConnectors()` reports the real ports when you bind port
  0; `stop(grace, timeout)` stops accepting, sends GOAWAY to every HTTP/3 connection at once, raises `ApplicationStopPreparing`
  and waits for running calls (HTTP/1.1 and HTTP/3) until the grace period, then cuts what is left at the timeout.
- Optional whitespace around a response header value is trimmed before the value goes out over HTTP/3 (field values
  carry none); a value HTTP/3 cannot carry (a character above U+00FF, or a control character other than tab) fails the call and resets its stream.

### Connection limits

Each TCP connector holds at most `maxTcpConnections` (*experimental*, 10,000) connections at once, and, when it is set,
at most `maxTcpConnectionsPerIp` (*experimental*, off by default) from one client address, HTTP/1.1 and HTTP/2 alike. A
connection counts from `accept` (its TLS handshake included) until its socket is released (a socket whose release hangs
is given up after the abort wait, so for that moment the descriptors in use can briefly exceed the limit).

- At `maxTcpConnections` the connector stops accepting, as Go's `netutil.LimitListener`, Jetty's `ConnectionLimit` and
  nginx's `worker_connections` do: new clients wait in the OS backlog (their connect succeeds, nothing is read from
  them) and are accepted as connections close; the server spends no descriptor or TLS work on them. Once the backlog is
  full too (511 on the JVM, 50 on Kotlin/Native), the OS drops further connection attempts (Linux by default, with
  `tcp_abort_on_overflow` 0: the client's TCP retries its SYN) or resets them. Waiting clients are not reported to the
  event listener.
- `maxTcpConnectionsPerIp` is off by default, as in nginx, Caddy, Go, Jetty, Netty, Envoy and HAProxy. Behind a reverse
  proxy, a load balancer, Kubernetes source NAT or any NAT every client shares one address, and an HTTP/1.1 proxy opens
  an upstream connection per request in flight (plus one per WebSocket or SSE stream). Enable it (256, say) only when
  the server faces its clients directly. Over it, a connection is reset right after `accept`, before its TLS handshake
  (an address is known only then), as nginx's stream `limit_conn` and Envoy's `connection_limit` filter do; a proxy in
  front reports that as 502 or 503, and its passive health checks may take the server out.
  `KuicksilverServerEventListener.connectionRefused` hears it with the reason `per-IP limit`; the application log gets
  one warning, then at most one per 10 s with a count. An address is its bytes, never looked up as a name: an
  IPv4-mapped client counts as its IPv4 address, an IPv6 client by its whole address, as QUIC's `maxConnectionsPerIp`
  counts HTTP/3 clients, so a client that holds a /64 gets around it.
- The checks run cheapest first: the connection slot before `accept`, the per-address count right after it, then
  `http2RepeatOffenderPenalty` (when on), and only then the TLS handshake.
- The default 10,000 does not protect a process whose descriptor limit is lower (`ulimit -n`: 256 in a macOS shell,
  often 1024 on Linux): raise that limit, or set `maxTcpConnections` below it, leaving room for the UDP sockets, files
  and outgoing connections the application opens. Above it `accept()` fails with EMFILE; the engine then backs off
  (5 ms doubling to 1 s) instead of spinning, but clients wait until descriptors free up.
- `EngineMain` keys `kuicksilver.maxTcpConnections` and `kuicksilver.maxTcpConnectionsPerIp` (`0` or absent is off).
- HTTP/3 has its own limits in the QUIC endpoint, `quicMaxConnections` and `quicMaxConnectionsPerIp` (the same 10,000
  and 256, but the per-address one on by default), and `quicAcceptQueue` (128): *experimental* since 0.3.0, `EngineMain`
  keys `kuicksilver.quicMaxConnections`, `kuicksilver.quicMaxConnectionsPerIp` (`0` is off) and
  `kuicksilver.quicAcceptQueue`. Behind a NAT or `kube-proxy` raise the per-address one
  ([deployment guide](deployment.md#quic-connection-limits)); `engine.http3Stats` counts the clients they refused.

### HTTP/3 on the server

Every TLS connector also serves HTTP/3 on UDP on the same port number; the two sockets are bound as a pair, so with
`port = 0` both share the resolved port (`resolvedConnectors()` lists the TCP connectors). The OS
picks the TCP port first, so its UDP twin may be taken: the pair is then bound again on a new port, up to 16 times,
every other time with the UDP port picked first and TCP taking the same number, after which the connector serves
HTTP/1.1 alone with a warning. A fixed port whose UDP side is taken fails the start. HTTP/1.1
responses then carry `Alt-Svc: h3=":<port>"; ma=86400` so clients can switch (RFC 7838) — unless the application set
its own `Alt-Svc`, or the response is a 421; `altSvc = false` turns the header off.

In an HTTP/3 call `call.request.httpVersion` is `"HTTP/3"`, `call.request.local.scheme` is the request's `:scheme`
(`"https"` from browsers and the Kuicksilver client; `"http"` when a client sends that), `serverPort` without a port in
`:authority` is that scheme's default (80 or 443), the `:authority` appears as the `Host` header, and `call.request.local.remoteAddress` follows the client when it migrates to another
network. Responses never carry `Transfer-Encoding` or other connection-specific headers: bodies of unknown length are
simply a sequence of DATA frames.

Knobs, named after Ktor's Netty engine where one exists: `http3` (on), `quic` (transport settings), `quicMaxIdleTimeout`
(applies while `quic` is not assigned), `udpSocketCount` (endpoint loops on the UDP port, every platform with a QUIC server), `quicAdmission`
(Retry policy, Ktor-Netty's `quicTokenHandler`), `quicLoadBalancer` (QUIC-LB connection IDs, experimental;
`engine.updateLoadBalancer` changes them, [QUIC: Behind a load balancer](quic.md#behind-a-load-balancer)), `http3Settings`. UDP socket buffer sizes are not configurable yet.

The engine serves HTTP/3 on every target, Kotlin/Native Linux, Apple and Windows included (the accelerated `ksl` socket,
ADR-0006); `udpSocketCount > 1` works wherever HTTP/3 does: a socket per loop with `SO_REUSEPORT` on Linux and Android,
one socket routed by connection ID in process on macOS, iOS and Windows ([QUIC: Several loops on one port](quic.md#several-loops-on-one-port)).
Where a QUIC server cannot run, the engine logs a warning and serves
HTTP/1.1 only, without `Alt-Svc`. The same applies to a `tlsConnector` with a `sniSelector`: QUIC cannot pick an
identity per SNI name (not supported for QUIC yet), so that connector skips HTTP/3 with a warning instead of failing to start.

Running it in production (UDP in firewalls, Docker and Kubernetes, load balancers, kernel buffers, checking that clients
arrive over HTTP/3): [Deploying the HTTP/3 server](deployment.md).

### HTTP/2 on the server

`http2 = true` (experimental; off by default in 0.3.0; `EngineMain` key `kuicksilver.http2`) makes every TLS connector
offer `h2` before `http/1.1` in ALPN, so a client that offers both gets HTTP/2 (RFC 9113) and one that offers only
`http/1.1` (WebSockets included) gets HTTP/1.1 on the same port, as before. Plain connectors never serve HTTP/2: there
is no h2c, and a client's `PRI * HTTP/2.0` preface is refused with `505 HTTP Version Not Supported`. HTTP/2 runs over
TLS 1.3 only, which is all the server engine negotiates (RFC 9113 section 9.2).

```kotlin
// guide:ktor:http2-server
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector(identity) { port = 443 }
    http2 = true                                              // offer h2 before http/1.1 in ALPN
    http2Settings = Http2Settings(maxConcurrentStreams = 50)  // windows and flood limits are Http2Settings'
}, module = Application::module)
```

Each stream is a Ktor call: `call.request.httpVersion` is `"HTTP/2"`, `call.request.local.scheme` is `"https"` (the
connection's, whatever the request's `:scheme`), `:authority` appears as the `Host` header and split `cookie` fields as one (RFC 9113 section 8.2.3). Responses
go out without connection-specific headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade` are dropped), a
response to HEAD, a 204 or a 304 without content, and every response carries the engine's `Alt-Svc` as on HTTP/1.1, so
a client on HTTP/2 learns HTTP/3 too. Requests are checked against RFC 9113 section 8 before the application sees them:
a malformed one (an uppercase or invalid field name, a connection-specific field, `te` other than `trailers`, a missing,
repeated or unknown pseudo-header field, `host` that differs from `:authority`, content that does not match
`content-length`) is reset with PROTOCOL_ERROR and the connection goes on; a field section above `maxHeaderListSize` is
answered 431. A CONNECT is answered 501 (the engine has no tunnels). WebSockets over HTTP/2 (RFC 8441) are not offered:
the engine never sends SETTINGS_ENABLE_CONNECT_PROTOCOL, so a request with `:protocol` is malformed. A request with
`Expect: 100-continue` gets an interim 100 as the handler starts (RFC 9110 §10.1.1: immediate), unless the request has no
content; another expectation is answered 417 when the handler reads the body. Content that does not match the
response's `Content-Length` is never sent as a complete response (the stream is reset); a 1xx as the final status goes
out as a 500. A call that ends without a response resets its stream; one stream's failure (a client's reset, a handler's
exception) never affects the others on the connection.

`http2Settings` (`Http2Settings`) holds the windows, SETTINGS_MAX_CONCURRENT_STREAMS (100) and the field-section and
flood limits of the core ([configuration reference](configuration.md#ktor-server-engine)). The engine's deadlines apply:
the client's connection preface must arrive within `requestHeaderTimeoutSeconds` of the accepted connection (TLS
included), else GOAWAY and close; each field block must arrive within it too (else GOAWAY with ENHANCE_YOUR_CALM); a
request body that sends no byte for `connectionIdleTimeoutSeconds` fails the handler's read and is answered 408 when
nothing else answered; a connection without requests for `connectionIdleTimeoutSeconds` gets GOAWAY and closes; a
response that gets no window from the client for the longer of that and 5 minutes resets its stream. Request content is
credited to the client only as the handler reads it. A client's RST_STREAM cancels the handler of that request; a
request still arriving when its handler is done with a complete response is stopped with RST_STREAM NO_ERROR (RFC 9113
section 8.1). `eventListener` reports these connections and calls with `HTTP_2_0`.

Flood defences (threat model, section 3.23): each connection is held to the core's limits (`http2Settings`: the reset
budget against Rapid Reset, the glitch budget against MadeYouReset and PING, SETTINGS or PRIORITY floods, 8 CONTINUATION
frames per field block, 10 000 queued control frames), and a broken limit ends it with GOAWAY ENHANCE_YOUR_CALM. A
stream the client reset cancels its handler and counts toward SETTINGS_MAX_CONCURRENT_STREAMS until the handler
returns, so no more handlers run at once than that limit. A connection that is over gets what it still has to write
sent for as long as the client takes it; after the send-stall deadline without progress its socket is aborted (3
seconds when it ended in an error, such as a broken flood limit: only its GOAWAY is left to deliver). These
per-connection limits are the defence by default.

`http2RepeatOffenderPenalty` (experimental, `EngineMain` key `kuicksilver.http2RepeatOffenderPenalty`, e.g. `30s`; off
by default) adds a backoff by address: one whose HTTP/2 connections end in a flood limit's ENHANCE_YOUR_CALM three
times within a minute has its TCP connections (HTTP/1.1 too) closed at accept, before the TLS handshake, for that long,
with a warning logged at most every 10 seconds per connector. An IPv4 client counts by its address (also when a
dual-stack listener reports it as `::ffff:a.b.c.d`), an IPv6 client by its /56; a slow field block is no strike. Turn it
on only where the server sees each client's real address (directly exposed, or behind an L4 load balancer that keeps
the source address). Never behind a NAT, CGNAT, an L4 load balancer or Kubernetes Service that rewrites source
addresses (`externalTrafficPolicy: Cluster`) or a TCP proxy such as HAProxy in TCP mode: every client there shares one
address, and one flooder would lock them all out.

The server passes h2spec 2.6.0 (all 146 cases, `tools/interop/h2spec.sh`). HTTP/2 on the server is still experimental and off by default in 0.3.0.

### Turning HTTP/3 off on the server

A running server can stop advertising HTTP/3, or take it out of service, without a restart: set
`engine.http3Advertising` (experimental) from wherever your remote configuration arrives — a config poll, an admin
endpoint, a feature flag.

```kotlin
// guide:ktor:http3-advertising
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector(identity) { port = 443 }
}, module = Application::module)
// later, when the remote configuration says so: clients fall back to HTTP/1.1 over TLS
server.engine.http3Advertising = Http3Advertising.Drain
// and when the incident is over
server.engine.http3Advertising = Http3Advertising.On
```

| Value | HTTP/1.1 responses | HTTP/3 responses | Live HTTP/3 connections | New QUIC connections |
|---|---|---|---|---|
| `On` (default) | `Alt-Svc: h3=":<port>"; ma=86400` | no `Alt-Svc` | served | accepted |
| `Clear` | `Alt-Svc: clear` | `Alt-Svc: clear` | served | accepted |
| `Drain` | `Alt-Svc: clear` | `Alt-Svc: clear` | GOAWAY (RFC 9114 section 5.2): requests in flight finish, then the connection closes | refused at the first Initial with CONNECTION_REFUSED |

RFC 7838 section 3: "A field value containing the special value "clear" indicates that the origin requests all
alternatives for that origin to be invalidated". An HTTP/3 response may send it too, since section 2.2 says
"Alternative services are fully authoritative for the origin in question, including the ability to clear or update
cached alternative service entries".

- Every response reads the value as its head goes out, so the next response on a keep-alive connection follows a
  change; every new client Initial is checked when the QUIC endpoint admits it. The setter returns at once.
- The header part applies where the engine sends `Alt-Svc` at all: on a TLS connector that serves HTTP/3, with
  `altSvc = true`. With `altSvc = false` no `Alt-Svc` is sent in any mode, but `Drain` still sends GOAWAY and refuses new
  QUIC connections. An `Alt-Svc` the application sets itself is left as it is in every mode, and a 421 gets none.
- `Clear` stops the advertising and withdraws it: a client drops the alternative at its next response, over HTTP/1.1 or
  HTTP/3. A connection it already has may go on serving it (RFC 7838 section 2.2 lets a client keep using one); to move
  those connections to TCP, use `Drain`.
- `Drain` sends GOAWAY to every live HTTP/3 connection at once, as a [graceful stop](#graceful-stop) does, and to every
  connection whose handshake completes while it is set. The requests in flight complete; once the last response is
  acknowledged the client closes the connection (a Kuicksilver client does), or the server three seconds later.
  **Not bounded in 0.3.0:** `Drain` has no grace deadline, so a long-lived stream (a WebSocket or WebTransport session
  over HTTP/3) keeps its connection until the application or the client ends it; a drain deadline is planned for 0.3.x.
  To cut such sessions, stop the server (its grace period applies) or end them in the application.
- A new client is refused with a stateless Initial CONNECTION_CLOSE carrying CONNECTION_REFUSED, as RFC 9000 section
  5.2.2 asks: "If a server refuses to accept a new connection, it SHOULD send an Initial packet containing a
  CONNECTION_CLOSE frame with error code CONNECTION_REFUSED" (sections 10.2.3 and 20.1). It is under the endpoint's
  stateless rate limit, runs before `quicAdmission` (which is not asked), unless a hard limit (`maxConnections`,
  `maxConnectionsPerIp`) drops the Initial first, and `EndpointStats.connectionsRefusedAdmission` counts it. A refused client falls back to TCP at once instead of waiting for
  its handshake timeout, and its next HTTP/1.1 response clears its cached alternative. A Kuicksilver client does not
  mark the alternative broken for the refusal ([Racing and fallback](#racing-and-fallback)), so once the instance (or
  another one) serves HTTP/3 and announces it again, the client is back on HTTP/3 with its next call.
- The UDP socket stays bound under `Drain`: releasing the port and binding it again on `On` would race other processes
  for it (and, with `udpSocketCount > 1` on Linux and Android, for each of its sockets), and a closed port answers with nothing or an ICMP
  error that clients only notice at their handshake timeout. To block UDP outright, use the firewall.
- Back to `On` (or `Clear`), new QUIC connections are accepted again. GOAWAY cannot be taken back (RFC 9114 section 5.2),
  so connections drained before keep closing; their clients open new ones.
- The value is per engine and is not kept across restarts: a new engine starts at `On`. Behind a load balancer set it on
  every instance.

Before maintenance, wait for the drained connections to go before you stop the server or block UDP. `engine.http3Stats`
counts them (`connectionsActive`, every HTTP/3 connection the listeners still hold, closing ones included); since `Drain`
has no deadline of its own, give the wait one:

```kotlin
// guide:ktor:drain-wait
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
server.engine.http3Advertising = Http3Advertising.Drain
// wait until the HTTP/3 connections are gone, or for 10 minutes at most (Drain has no deadline of its own)
withTimeoutOrNull(10.minutes) {
    while (server.engine.http3Stats.sumOf { it.connectionsActive } > 0) delay(1.seconds)
}
// now the maintenance; afterwards:
server.engine.http3Advertising = Http3Advertising.On
```

What is left when the deadline passes is a long-lived stream (a WebSocket or WebTransport session over HTTP/3): end it
in the application, or let the server's [graceful stop](#graceful-stop) cut it.

### WebSockets over HTTP/3

With `webSocketsOverHttp3 = true` (the default) the HTTP/3 listener advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL` and
accepts Extended CONNECT with `:protocol = websocket` (RFC 9220). Such a request reaches Ktor's pipeline as the HTTP/1.1
upgrade request the `WebSockets` plugin knows — `GET` with `Connection: Upgrade`, `Upgrade: websocket` and a
`Sec-WebSocket-Key` — so ordinary `webSocket("/path") {}` routes serve it unchanged; the upgrade is answered with
`:status 200` and the frames travel on the request stream. Extended CONNECT with any other protocol is answered 501 (WebTransport aside when it is on, below). A
plain HTTP/1.1 `Upgrade` on an HTTP/3 request is meaningless (RFC 9114 section 4.5) and gets 501 too.

### WebTransport over HTTP/3 (experimental)

With `webTransport = true` the HTTP/3 listener speaks WebTransport (draft-ietf-webtrans-http3-16, plus the SETTINGS of
draft-02 and draft-14 that browsers send; see the [HTTP/3 guide](http3.md#webtransport-experimental)), and a
`webTransport("/path") { session -> }` route serves the sessions. It matches only a WebTransport Extended CONNECT over
HTTP/3, never an HTTP/1.1 request (a request of another method to the path gets Ktor's 405); a WebTransport request
no route matches gets Ktor's 404, and one that another route answers with a 2xx gets 501 instead, since no session
was accepted. The route checks the
`origin` field first: `checkOrigin` refuses with 403, and its default, `sameHostOrigin`, admits the server's own
origin and clients that send none (browsers always send one; pass your own check for a page served elsewhere). The
server picks the first of the route's `protocols` the client offers. Then the session is accepted and the handler
runs; when it returns the session is closed with code 0, when it throws with `WEB_TRANSPORT_HANDLER_FAILED` (1) and
an empty reason. One session per connection: there is no WebTransport flow control yet.

```kotlin
// guide:ktor:webtransport-server
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector(identity) { port = 443 }
    webTransport = true
}) {
    routing {
        webTransport("/echo", protocols = listOf("echo-v1")) { session ->
            val stream = session.acceptBidi()
            stream.input.copyTo(stream.output)
            stream.output.flushAndClose()
        }                                          // returning closes the session with code 0
    }
}
```

A real browser is checked by `ChromeWebTransportTest` (`kuicksilver-ktor-server` jvmTest), which runs only on request
and only with an installed Chrome or Chromium:

```sh
./gradlew :kuicksilver-ktor-server:jvmTest --tests '*ChromeWebTransportTest*' -Pkuicksilver.browserTests=true
```

It starts Chrome headless with a throw-away profile, QUIC forced for the test origin and the test certificate admitted
by its SPKI hash, and the page `wt/index.html` from the test resources posts its results back. Firefox is checked by
hand with one command:

```sh
tools/interop/wt-firefox-manual.sh
```

It makes a P-256 certificate valid for 13 days (browsers pin only a certificate valid for at most 14 days and not RSA
by hash) and its SHA-256 hash, starts `ManualWebTransportServer` (`kuicksilver-ktor-server` jvmTest, opt-in with
`-Pkuicksilver.manualWebTransport=true`) with that page and the test's two routes on `127.0.0.1`, and opens
`https://localhost:<port>/wt/index.html?hash=<b64>` in Firefox with a throw-away profile. Accept Firefox's certificate
warning for the page once (`serverCertificateHashes` only covers the WebTransport sessions); the script then prints
PASS or FAIL with the page's JSON and stops Firefox and the server (variables in the script's header). On FAIL it keeps
its temporary directory and lists it: `server-events.txt` (how each session and connection ended, with the cause),
the server's qlog, Firefox's own qlog and MOZ_LOG. To check Safari
by hand, start the same server with a certificate such as `openssl req -x509 -newkey ec -pkeyopt
ec_paramgen_curve:P-256 -days 13 -nodes -subj /CN=localhost -addext subjectAltName=DNS:localhost -keyout wt.key -out
wt.pem` (OpenSSL 3, which writes the PKCS#8 key the server reads): `./gradlew :kuicksilver-ktor-server:jvmTest --tests
'*ManualWebTransportServer*' -Pkuicksilver.manualWebTransport=true -Pkuicksilver.manualWebTransport.cert=$PWD/wt.pem
-Pkuicksilver.manualWebTransport.key=$PWD/wt.key -Pkuicksilver.manualWebTransport.port=<port>`, open
`https://localhost:<port>/wt/index.html?hash=<b64>` with `<b64>` from `openssl x509 -in wt.pem -outform der | openssl
dgst -sha256 -binary | base64` (percent-encoded in the URL) and accept the certificate warning for the page; each step
prints `ok` on the page and the Gradle run passes once the page has posted its result. Record the result in
`docs/spec/interop.md`, "Interop WebTransport".

### Certificate rotation

A renewed certificate can be put in place without a restart (experimental). Give the connector a
`TlsIdentity.Reloadable` and call `reload` when the new files are there (from a deploy hook, an admin route, a timer):

```kotlin
// guide:ktor:certificate-rotation
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val identity = TlsIdentity.reloadable(TlsIdentity.fromPem(chainPem, keyChars)) // the key array is zeroed after import
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector(identity) { port = 443 }
}, module = Application::module)
// later, when the renewed files are in place: new TCP and QUIC handshakes present them, open connections keep theirs
identity.reload(TlsIdentity.fromPem(renewedChainPem, renewedKeyChars))
```

`keyChars` and `renewedKeyChars` are the key files read into `CharArray`s (not through a `String`, which would leave the
key on the heap). Every handshake whose ClientHello arrives after `reload` returns, HTTP/1.1 and HTTP/2 over TCP and
HTTP/3 over QUIC, presents the new chain and key (also on a TCP connection accepted before the reload); handshakes in
progress and open connections keep the old ones. A key that does not match its
certificate fails in `fromPem`, and `reload` refuses an expired leaf and one not valid yet (`TlsException.Config`): the
identity in use stays. Session tickets are bound to the certificate they were issued under, so after a reload clients
run one full handshake and see the new certificate (see [Rotating the server certificate](tls.md#rotating-the-server-certificate)
for ownership, resumption and key compromise). The same works for `identity` in the engine configuration (plain
connectors served over TLS); on the JVM, an `sslConnector` keystore is read once, so build the identity with
`TlsIdentity.fromKeyStore` and wrap it yourself instead.

With `embeddedServer` the application decides when to reload. A check of the files once an hour, from the application's
own coroutine scope (it ends when the server stops):

```kotlin
val chainFile = File("/etc/letsencrypt/live/example.com/fullchain.pem")
val keyFile = File("/etc/letsencrypt/live/example.com/privkey.pem")
// guide:ktor:reload-from-files
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
/** A PEM key file as a CharArray without a String of it (PEM is ASCII); the bytes are wiped. */
fun readKeyChars(file: File): CharArray {
    val bytes = file.readBytes()
    try {
        return CharArray(bytes.size) { bytes[it].toInt().toChar() }
    } finally {
        bytes.fill(0)
    }
}

/** Reloads [identity] when the chain file changed since [served] (its modification time); returns the time now served. */
fun reloadIfChanged(identity: TlsIdentity.Reloadable, chainFile: File, keyFile: File, served: Long): Long {
    val modified = chainFile.lastModified()
    if (modified == served) return served
    return try {
        val next = TlsIdentity.fromPem(chainFile.readText(), readKeyChars(keyFile))   // fails while the key does not match yet
        try {
            identity.reload(next)                          // refuses an expired certificate, or one not valid yet
        } catch (e: TlsException) {
            next.close()                                   // a refused identity is still ours to close
            throw e
        }
        modified
    } catch (e: TlsException) {
        served                                             // the old identity keeps serving; tried again at the next check
    } catch (e: IOException) {
        served
    }
}

val identity = TlsIdentity.reloadable(TlsIdentity.fromPem(chainFile.readText(), readKeyChars(keyFile)))
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector(identity) { port = 443 }
}) {
    launch {
        var served = chainFile.lastModified()
        while (true) {
            delay(1.hours)
            served = reloadIfChanged(identity, chainFile, keyFile, served)
        }
    }
    module()
}
```

`reload` itself writes nothing to a log: log the outcome where `reloadIfChanged` returns (with `EngineMain` the engine
logs it, below). To see from outside which certificate a server presents, `openssl s_client -connect <host>:443
-servername <host> </dev/null | openssl x509 -noout -dates -serial` shows the dates and serial of the leaf served over TCP.

With `EngineMain`, set `kuicksilver.tls.reloadInterval` (`1h`, `30m`, ...; off by default) and the engine checks the
PEM files of `kuicksilver.tls.certificateChain` and `kuicksilver.tls.privateKey` that often (the configuration's
`identityReloadInterval`). It reloads when the chain file holds other certificates than those served: a chain read
twice a second apart with the same content, and a key that matches it. Tools that write the chain before the key
(certbot) or swap a symlinked directory (Kubernetes secrets) are covered: a pair that does not match yet keeps the old
identity and is tried again after 1 s, then 2 s, 4 s and so on up to the interval. Failures are logged as warnings
(once per distinct failure, never with key material); a successful reload is logged at info level, and the files are
read once more a second later, so a chain whose writer paused longer than that is corrected then. Each file is read
whole on every check and refused above 1 MiB; a chain file that also holds a private key is refused, at startup too (keep
the key in its own file). The stop waits at most a second for a check in progress (a read on a hung network file system
cannot be interrupted). Polling once an hour means a renewed certificate may wait an hour to be served; certbot's `--deploy-hook`
(or a restart) is the alternative when it must take effect at once. With `kuicksilver.tls.reloadInterval` set, the
files at startup get the same checks as a reload, so an expired or not yet valid certificate fails the start; without
it, `EngineMain` serves the files as they are, as before. The identity `EngineMain` made is closed when the server stops.

**The client CA.** A connector that asks for client certificates ([Mutual TLS](#mutual-tls-client-certificates)) can
rotate the CA bundle it verifies them with in the same way: give it `trust = TrustConfig.reloadable(TrustConfig.AnchoredCa(roots))`
(alone or as the `base` of `Pinned`) and call `reload(TrustConfig.AnchoredCa(newRoots))`. Handshakes whose ClientHello
arrives after `reload` returns, HTTP/1.1 and HTTP/2 over TCP and HTTP/3 over QUIC, verify client certificates against the
new bundle, also on a TCP connection accepted before the reload; handshakes in progress and open connections keep the old
one, and a session ticket from before the reload is not resumed, so a client whose CA was dropped gets in neither with a
new handshake nor with a ticket. `reload` refuses a bundle in which no certificate is
valid now ([Rotating the client CA](tls.md#rotating-the-client-ca)).

```kotlin
// guide:ktor:client-ca-rotation
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val clientCa = TrustConfig.reloadable(TrustConfig.AnchoredCa(Certificate.parsePem(caBundlePem)))
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector(identity) {
        port = 443
        clientAuth = ClientAuth.Required
        trust = clientCa
    }
}, module = Application::module)
// later: new TCP and QUIC handshakes verify client certificates against the new bundle
clientCa.reload(TrustConfig.AnchoredCa(Certificate.parsePem(renewedBundlePem)))
```

With `EngineMain`, `kuicksilver.tls.clientAuth` (`optional` or `required`) and `kuicksilver.tls.clientCa` (a PEM file of
CA certificates) ask for client certificates on the deployment port. With `kuicksilver.tls.reloadInterval` set, the CA
file is watched at that interval with the rules above: a changed bundle is used once two reads a second apart agree. A
file holding a private key, a damaged file and a bundle with no certificate valid now keep the bundle in use, and so do
they at startup (where they fail the start). A reload is logged at info level, a failure as a warning, and so is a bundle
holding certificates that are not CA certificates (each is an anchor: a client presenting exactly it is accepted). The
keys apply to the port of `kuicksilver.tls.certificateChain`; on the JVM, a `-sslPort` connector (`ktor.security.ssl.*`)
takes client certificates from its `trustStore` instead, and the start is refused when both are configured.

### EngineMain and configuration keys

`io.kuicksilver.ktor.server.EngineMain` reads the usual `ktor.deployment.*` keys (and on the JVM `-sslPort` with
`ktor.security.ssl.*`). Its own keys work on every platform:

| Key | Meaning |
|---|---|
| `kuicksilver.tls.certificateChain`, `kuicksilver.tls.privateKey` | PEM files; the deployment port then serves TLS and HTTP/3 |
| `kuicksilver.tls.reloadInterval` | how often those PEM files, and the `kuicksilver.tls.clientCa` file, are checked for a renewed certificate or CA bundle (`30m`, `1h`; `0` or unset: never; at least `1s`); see [Certificate rotation](#certificate-rotation) |
| `kuicksilver.tls.clientAuth` | ask for a client certificate on the deployment port: `none` (unset), `optional` or `required`; anything but `none` needs `kuicksilver.tls.clientCa` |
| `kuicksilver.tls.clientCa` | PEM file of the CA certificates client certificates are verified against; needs the identity files and `kuicksilver.tls.clientAuth` `optional` or `required` |
| `kuicksilver.http3` | serve HTTP/3 (`true`) |
| `kuicksilver.http2` | serve HTTP/2 on TLS connectors (`false`); see [HTTP/2 on the server](#http2-on-the-server) |
| `kuicksilver.http2RepeatOffenderPenalty` | refuse an address that keeps flooding HTTP/2 for this long (`0`, off; e.g. `30s`); see [HTTP/2 on the server](#http2-on-the-server) |
| `kuicksilver.maxTcpConnections` | TCP connections a connector holds at once (`10000`); see [Connection limits](#connection-limits) |
| `kuicksilver.maxTcpConnectionsPerIp` | TCP connections of one client address on a connector (`0` or unset: off; e.g. `256` for a server that faces clients directly); see [Connection limits](#connection-limits) |
| `kuicksilver.altSvc` | send `Alt-Svc` on HTTP/1.1 responses (`true`) |
| `kuicksilver.webSocketsOverHttp3` | accept RFC 9220 WebSockets (`true`) |
| `kuicksilver.udpSocketCount` | endpoint loops on the UDP port (`1`) |
| `ktor.deployment.connectionIdleTimeoutSeconds` | idle HTTP/1.1 keep-alive timeout (`45`) |

An `application.conf` (HOCON) for a TLS and HTTP/3 server on port 443 whose certificate certbot renews; every key not
set keeps the default of the table above. The `kuicksilver-ktor-server` tests load this block as it stands (with their
own paths, port and module), so its keys stay current:

```hocon
ktor {
    deployment {
        port = 443                     # TCP for HTTP/1.1 over TLS and UDP for HTTP/3, the same number
    }
    application {
        modules = [ com.example.ApplicationKt.module ]
    }
}
kuicksilver {
    tls {
        certificateChain = "/etc/letsencrypt/live/example.com/fullchain.pem"
        privateKey = "/etc/letsencrypt/live/example.com/privkey.pem"
        reloadInterval = 1h
    }
    quicMaxConnectionsPerIp = 4096     # behind a NAT or kube-proxy; see deployment.md
}
```

The application's main class is `io.kuicksilver.ktor.server.EngineMain` (in Gradle: `application { mainClass.set("io.kuicksilver.ktor.server.EngineMain") }`),
and `-config=<file>` picks another file, as with Ktor's own engines. The private key must be an unencrypted PKCS#8 file
(`-----BEGIN PRIVATE KEY-----`, which certbot writes); convert an older `BEGIN RSA PRIVATE KEY` or `BEGIN EC PRIVATE KEY`
file with `openssl pkcs8 -topk8 -nocrypt -in old.pem -out privkey.pem`. `TlsIdentity.fromPem` has a `password`
parameter, but encrypted keys are refused with `TlsException.Config` whatever it holds: decrypt the key before.

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
  SNI and verification use the URL's host. Over TCP, `https://` is HTTP/2 when the server picks `h2` in ALPN and
  HTTP/1.1 otherwise ([HTTP/2 on the client](#http2-on-the-client)). `http://` and `ws://` are plain HTTP/1.1 over TCP. On Android they follow
  the app's Network Security Configuration as OkHttp does: a host for which `NetworkSecurityPolicy.isCleartextTrafficPermitted`
  is false (every host by default from `targetSdk` 28) is refused before any connection with an `IOException`
  "CLEARTEXT communication to <host> not permitted by network security policy".
- HTTP/1.1 requests are written and responses parsed with Ktor's CIO code (vendored, see `docs/ktor-internal-api.md`):
  chunked bodies, `Expect: 100-continue`, keep-alive with at most `maxIdleConnectionsPerRoute` idle connections per route
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
  inside the tunnel), see [Proxies](#proxies).
- Timeouts come from `HttpTimeout`: the connect timeout (TCP + TLS, or the QUIC handshake) fails with Ktor's
  `ConnectTimeoutException`, the socket timeout with `SocketTimeoutException`; the request timeout is the plugin's own.
  The socket timeout is an inactivity timeout, as Ktor defines it ("maximum time of inactivity between two data
  packets"): while the request body goes out and the response head is awaited, every piece of the body the connection
  takes and every byte of the response that arrives restarts it, so an upload that keeps moving never times out however
  long it takes, and one that stalls (the server stops reading, the application stops writing) fails that long after its
  last progress; every read of the response body then has it on its own. Without `HttpTimeout` the engine's `connectTimeout` (10 s) applies.
- Capabilities: `HttpTimeoutCapability`, `WebSocketCapability`, `WebSocketExtensionsCapability`, `SSECapability`; no
  Unix sockets. With `WebSocketExtensionsCapability` Ktor's `WebSockets` plugin offers the extensions installed with
  `extensions { install(...) }` in `Sec-WebSocket-Extensions` and negotiates them, over HTTP/1.1 and HTTP/3 (RFC 9220).
  permessage-deflate on every target is `PerMessageDeflate` ([WebSocket compression](#websocket-compression-experimental));
  Ktor's own `WebSocketDeflateExtension` exists on the JVM and Android only. Both engines check the
  handshake and the frames (RFC 6455 sections 4.1, 5.2 and 9.1): an answer that accepts an extension the client did not
  offer fails the call with `WebSocketException` before a session opens, and a frame with an RSV bit that no negotiated
  extension defines (RSV1 for permessage-deflate, on the first frame of a message only, RFC 7692 section 6.1), a
  reserved opcode, or a mask bit in the wrong direction (RFC 6455 section 5.1: a server's frames are never masked, a
  client's always are) fails the connection with code 1002: the engine hands the session a Close frame with 1002 in place
  of the bad frame, Ktor's session answers it, so 1002 goes on the wire and is the session's `closeReason`, and
  `incoming` ends without the bad frame (a raw `webSocketRaw` session sees the Close in `incoming` and answers it
  itself). An extension the engine does not know (the application's own) may use every RSV bit.
- `HttpClient()` without an engine finds Kuicksilver through `ServiceLoader` on the JVM with priority 0.5 (below OkHttp
  and the platform engines at 1.0, above CIO at 0.0) and through Ktor's engine list on Kotlin/Native.

### HTTP/2 on the client

```kotlin
// guide:ktor:http2-client
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val client = HttpClient(Kuicksilver) {
    engine {
        http2 {
            enabled = true                                      // the default: offer h2 on every TLS connection over TCP
            pingInterval = 30.seconds                           // a keep-alive PING; Duration.INFINITE (the default): none
            settings = Http2Settings(initialStreamWindow = 1 shl 20)  // our windows and limits (threat model 3.23)
        }
    }
}
```

Every `https://` connection over TCP offers `h2` and `http/1.1` in ALPN (RFC 9113 section 3.2); when the server picks
`h2` the responses report `HttpProtocolVersion.HTTP_2_0` and one connection per route carries the requests as streams.
This holds directly, through an HTTP CONNECT tunnel and through SOCKS5 (ALPN is inside the TLS session with the origin,
as with OkHttp), in every `http3 { discovery }` mode but `H3Only`, and whatever `http3Allowed` says: the HTTP/3 kill
switch does not turn HTTP/2 off. `http2 { enabled = false }` offers only `http/1.1`, as in 0.2.

- **Not HTTP/2.** `http://` (no cleartext HTTP/2, h2c) and WebSockets, which offer `http/1.1` only (WebSockets over
  HTTP/2, RFC 8441, are not supported yet). No server push (the client sends SETTINGS_ENABLE_PUSH = 0; a PUSH_PROMISE
  ends the connection), no RFC 7540 priorities (`priority(...)` goes as the end-to-end `priority` field), and no
  connection coalescing across origins.
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
- **Responses** are checked against RFC 9113 section 8: a malformed one (an invalid field, a content-length that does
  not match the content) fails with `Http2Exception.MalformedMessage`. A response field section above
  `settings.maxHeaderListSize` (64 KiB) fails its call, not the connection.
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
  not one that never left). Ours must be acknowledged within `settings.settingsAckTimeout` (10 s) of the server's
  preface. A connection quiet for 10 s is checked with a PING before it takes a
  request (half the connect timeout at most, 5 s; one PING per connection, shared by the requests that wait); one that
  does not answer takes no new request and the request goes to a new connection. Calls still running on it are not cut:
  the connection gets GOAWAY and closes once they are done (or closes at once when none run). With
  `maxConnectionsPerRoute = 1` such a connection keeps the route's only slot until those calls end, and new requests
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

### Connection pool

```kotlin
// guide:ktor:pool
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val client = HttpClient(Kuicksilver) {
    engine {
        maxConnectionsCount = 1000                 // TCP connections (HTTP/1.1, HTTP/2) of the engine, idle ones included
        maxConnectionsPerRoute = 100               // ... to one route (scheme, host, port, proxy)
        maxIdleConnectionsPerRoute = 4             // idle keep-alive connections kept per route
        idleTimeout = 5.minutes                    // idle HTTP/1.1, HTTP/2 and HTTP/3 connections are closed after this
        maxConnectionLifetime = Duration.INFINITE  // age after which a connection takes no new requests
    }
}
```

| Setting | Default | Compared with |
|---|---|---|
| `maxConnectionsCount` | 1000 | CIO `maxConnectionsCount` 1000; OkHttp `Dispatcher.maxRequests` 64 (requests, not sockets) |
| `maxConnectionsPerRoute` | 100 | CIO `endpoint.maxConnectionsPerRoute` 100; OkHttp `maxRequestsPerHost` 5 |
| `maxIdleConnectionsPerRoute` (idle per route) | 4 | OkHttp `ConnectionPool` 5 idle in all |
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
- **HTTP/2.** One connection per route while it has a free stream under the server's SETTINGS_MAX_CONCURRENT_STREAMS;
  it counts once toward `maxConnectionsPerRoute` and `maxConnectionsCount` however many requests it carries. When it is
  full a second one opens, within those limits; at the limits a request waits for a free stream within the connect
  timeout. Requests that start together toward a new origin open one connection: one connects while the others wait for
  it (ALPN is known only after the TLS handshake) and use it when it is HTTP/2, or connect on their own when it is
  HTTP/1.1; an origin last seen on HTTP/1.1 does not make them wait. A connection
  without requests for `idleTimeout`, or past `maxConnectionLifetime`, is sent GOAWAY and closes once its requests are
  done; a server's GOAWAY moves new requests to a new connection.
- **HTTP/3.** One QUIC connection per origin (and alternative) carries all requests. When the server's MAX_STREAMS
  credit is used up, a request waits for the next credit on that connection instead of failing or opening another
  connection; the request timeout bounds the wait (`HttpRequestTimeoutException`), and so does the socket timeout,
  which covers the time without progress until the response head. A connection without requests for `idleTimeout` is closed (QUIC's
  own idle timeout, `quic = quicConfig { maxIdleTimeout = ... }` and the server's, may end it first); one past `maxConnectionLifetime` takes
  no new requests and closes once its requests are done.
- **Cleanup.** A background task of the engine closes expired connections; it sleeps until the next expiry, at most
  `idleTimeout` and at most a minute, and stops when the client closes. Per-origin bookkeeping lives only while an
  origin has connections or waiting requests, so a client that talks to many origins does not grow without bound.

### HTTP/3 on the client

`http3 { discovery = ... }` decides when HTTP/3 is used for `https://` (never through a proxy):

| Mode | Behaviour |
|---|---|
| `Auto` (default) | HTTP/1.1 first; HTTP/3 once the origin announced it with `Alt-Svc` ([Discovery and Alt-Svc](#discovery-and-alt-svc)) |
| `Preferred` | HTTP/3 by prior knowledge, falling back to HTTP/1.1 (like `curl --http3`); `quicHints` gives the same treatment to listed origins in `Auto` mode |
| `H3Only` | HTTP/3 only (like `curl --http3-only`): failures are reported, never retried over TCP; an `http://` or `ws://` request (HTTP/3 needs `https`, RFC 9114 section 3.1), and with a proxy configured every request, fails with `UnsupportedOperationException` |
| `H1Only` | no HTTP/3: TCP only, which is HTTP/1.1, or HTTP/2 when the server offers it ([HTTP/2 on the client](#http2-on-the-client)) |

HTTP/3 responses report `HttpProtocolVersion.HTTP_3_0`. One QUIC connection per origin carries all its requests; a
request the server did not process (GOAWAY above its stream, `H3_REQUEST_REJECTED`) is repeated on a new connection
without the application noticing. When HTTP/3 fails before the response headers, the request is repeated over HTTP/1.1
— always if it cannot have reached the server, otherwise only for idempotent methods whose body can be sent again
(bytes, a `WriteChannelContent` writer, or no body). A streamed `ReadChannelContent` body that HTTP/3 already consumed
is never replayed, neither on the fallback nor after a 421 or a `RequestNotProcessed`: the call fails with
`H3BodyConsumed` and the application decides. The fallback uses the same `trust`, pins and TLS 1.3 settings. When a call ends before its body was read, the rest of the stream is abandoned
with `STOP_SENDING`. A response body the connection cut short (a reset, a lost connection) never looks complete:
`bodyAsText`, `bodyAsBytes`, `readRemaining` and the other whole-body reads throw the cause, and the engine's own channel
(`rawContent`, the server's request body) throws it from `readAvailable` instead of answering -1. `bodyAsChannel()`
hands out Ktor's copy of the body, which keeps ktor-io's contract: its `readAvailable` answers -1 with the cause in
`closedCause`, so a loop over that channel checks `closedCause` after -1 (or reads the rest with `readRemaining`).

WebSockets use HTTP/1.1 `Upgrade` unless an HTTP/3 connection to the origin already allows Extended CONNECT (or the
mode is `H3Only`); over HTTP/3 the handshake is RFC 9220 and the plugin sees the usual 101. Over HTTP/1.1 at most one
WebSocket is connecting to an address and port at a time (RFC 6455 section 4.1): another one to the same address, under
any name, opens its connection once the first handshake was answered or failed; through a proxy that resolves names,
the name counts as the host. The connect timeout applies twice to such a WebSocket, in two phases: resolving the name,
waiting for a pool slot and connecting (TCP and TLS) share one, as for any request; the answer to the handshake must then
arrive within the same timeout again, counted from the moment the connection is in hand. The wait for another WebSocket
to the address is in neither: only the call (its request timeout or cancellation) bounds it.

### Discovery and Alt-Svc

In `Auto` mode the engine learns alternatives from `Alt-Svc` headers (RFC 7838) of HTTPS responses and sends the next
requests to the origin over HTTP/3, with an `Alt-Used` header; SNI and certificate verification still use the
origin's host. The rules:

- only responses over verified TLS count (an `http://` response can never redirect a client to an alternative);
- a new `Alt-Svc` replaces every entry of the origin, `clear` removes them, and so does a 421 response; this applies
  to every HTTP/1.1 response, including the ones served while a cached alternative is broken or lost the race;
- `ma` defaults to 86400 seconds and expired entries are ignored;
- an alternative on an unprivileged port (1024 and up) is refused for an origin on a privileged one, as Chromium does;
- an alternative on a loopback, link-local or private address, or a `localhost` name, is refused unless the origin is
  on such an address too, and one on an unspecified, multicast or broadcast address always; an IPv4 address counts in
  every form the resolvers accept without DNS (`127.1`, `2130706433`), and a numeric host in octal or hex (`0177.0.0.1`,
  `0x7f.1`, which platforms read differently) or that is no address (`256.1.1.1`) is always refused. A DNS name is not
  resolved for this check;
- only `h3` alternatives are used.

Entries live in `http3 { altSvcStore = ... }` — `InMemoryAltSvcStore` by default. `FileAltSvcStore(path)` keeps them
in one tab-separated text file (loaded once, rewritten atomically after every change, expired records dropped on load)
so the first request after a cold start can already use HTTP/3; implement `AltSvcStore` for any other backing store
(one engine per file: two engines sharing a file overwrite each other). Both built-in stores keep at most 8 alternatives
per origin (the first ones of the header) and 1000 origins, dropping the least recently used; `FileAltSvcStore` skips
the rewrite when a repeated header only refreshes the expiry, and the engine writes it after releasing its lock. Entries
without `persist=1` are dropped when `networkId()` reports a new network (RFC 7838 section 2.2); `clearOnNetworkChange =
false` keeps them.

`FileAltSvcStore(path)` takes a `kotlinx.io.files.Path`; on the JVM and Android `FileAltSvcStore(file)` (experimental,
0.3.0) takes a `java.io.File`. On Android keep the file in the app's private files directory. Do not write
`File(...).toPath()`: that is a `java.nio.file.Path`, which this API does not take, and `File.toPath()` and
`java.nio.file` only exist from API 26, while the library supports API 24. The `File` form uses no `java.nio.file`,
so it works on API 24 and 25 too (there a write replaces the file with `File.renameTo`, which is atomic on one file
system):

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val filesDir = context.filesDir                  // android.content.Context
// guide:ktor:altsvc-store-android
HttpClient(Kuicksilver) {
    engine {
        http3 { altSvcStore = FileAltSvcStore(File(filesDir, "altsvc.tsv")) }
    }
}
```

### HTTPS records (experimental)

`http3 { httpsRecords = HttpsRecordSource.System }` (or `HttpsRecordSource.Exchange { query -> ... }` for your own
DNS-over-HTTPS client) makes the engine an HTTPS-record client (RFC 9460) in `Auto` mode: the origin's records say where
to connect, so the first request to an origin that publishes one with `alpn=h3` races HTTP/3 at once instead of waiting
for an `Alt-Svc` header, as browsers do. Off by default. The rules:

- for an `https://` request to a host name; never for `Preferred`, `H3Only`, `quicHints`, IP addresses, requests
  through a proxy, or while `http3Allowed` says no;
- the name asked is the host for port 443, `_<port>._https.<host>` otherwise (section 9.1); AliasMode records are
  followed (one at random among several; at most 8 steps; a loop or a longer chain is treated as no record; an AliasMode
  "." is ignored); the ServiceMode records of the final name, by ascending priority and shuffled within a priority, are
  the endpoints, each at its target (the record's own name for ".") and `port` (the origin's when absent); after an
  AliasMode chain the last name with the origin's port is one more endpoint, last (section 3);
- an endpoint is tried over the transports its ALPN set allows (section 7.1.2; the default set is `http/1.1`, so
  `alpn=h3` means QUIC and TCP, `alpn=h2` TCP, and `no-default-alpn` with `alpn=h3` QUIC only); QUIC and TCP race as for
  an `Alt-Svc` alternative ([Racing and fallback](#racing-and-fallback)), TCP connecting to the endpoint's target and
  port, both offering the engine's usual ALPN lists. An endpoint that cannot be connected to is followed by the next one,
  and after the last by the origin as without records. TLS and the request still name the origin, and the certificate is
  checked against the origin's name whatever the record says; a QUIC endpoint that fails is marked broken like an
  alternative (`httpsRecordUsed` and `altSvcMarkedBroken` report both). The address hints are not used, `ech` is not (a
  record that requires it is skipped), and a malformed record makes the whole answer unusable (section 2.2);
- a cached `Alt-Svc` alternative is tried first, its TCP side going to the origin's first TCP endpoint; the
  alternative's own HTTPS records are looked up too (RFC 9460 section 9.3), and when it has some, HTTP/3 goes to their
  targets and ports that offer `h3`, and not to the alternative at all when none does (`Alt-Used` still names the
  alternative);
- the request waits for the records while the origin's addresses resolve and at most `httpsRecordExtraWait` (50 ms)
  longer; a lookup that answers later, fails or times out leaves the request on the origin as without records, and a
  late answer is cached for the next request (`httpsRecordExtraWait` is 50 ms to 1 s: RFC 9460 section 5.1 asks for at
  least 50 ms before connecting without the records). While an AliasMode chain is followed, the addresses of each
  alias target are looked up in parallel (section 5). A malformed answer always counts as "no records". With
  `HttpsRecordSource.Exchange(secure = true) { ... }` (an exchange whose answers are protected: DNS over HTTPS or TLS, or
  validated DNSSEC) the request waits for the records instead, up to the connect timeout, and a failed lookup (an error
  answer such as SERVFAIL, a transport error, a timeout) abandons it with an `IOException`, so an attacker who drops the
  answers cannot downgrade the connection (RFC 9460 section 3.1). `HttpsRecordSource.ProtectedSystem { ... }` does the
  same for the system resolver when your check says its answers are protected; on Android
  `HttpsRecordSource.followingPrivateDns(connectivity)` says so while strict Private DNS is on (the engine has no
  `Context`: with plain `System` strict Private DNS is not taken into account, so opt in with this builder). Elsewhere no public API
  tells whether the system's DNS is encrypted, so `System` treats failures as "no records";
- answers are cached for their TTL, never longer (at most a day; "no records" for the negative TTL of the answer's SOA
  record, RFC 2308, and not at all without one; at most 1000 names), together with the other HTTPS records and the
  A/AAAA records the answer carried, which spare follow-up queries (RFC 9460 section 5), and forgotten when
  `networkId()` reports a new network; without `networkId` the engine cannot see a network change and keeps no answers
  of its own (RFC 9460 section 12: a forged record must not follow the device to the next network), so every request
  asks the source (the system resolver keeps its own cache); a failed lookup is not cached, and one lookup per name runs at a time, for at
  most the connect timeout (30 s at most); closing the client cancels the lookups still running.

`HttpsRecordSource.System` asks the operating system's resolver, so lookups follow the system's DNS settings:
`res_nquery` on Linux (JVM and Kotlin/Native), `DNSServiceQueryRecord` on macOS and iOS, `DnsQuery_W` on Windows, and
`DnsResolver.rawQuery` on the default network (Private DNS included) on Android from API 29. On Android API 24 to 28 there
is no public way to ask for a record type (and a resolver of the engine's own would bypass Private DNS), so every lookup
counts as failed there and requests behave as without records. At most four system lookups run at once per process.
`HttpsRecordSource.Exchange` works everywhere.

An `http://` request (not `ws://`, not through a proxy, not to an IP address) first looks up the records of the same URL
with `https` (port 80 becomes 443), waiting for the answer as an `https` request does (while the origin's addresses
resolve and `httpsRecordExtraWait` longer; the whole lookup with a secure source); when the origin
has an AliasMode record or a ServiceMode record the engine could use, the engine answers `307 Temporary Redirect` to the
`https` URL itself, without connecting (RFC 9460 section 9.5). Ktor's `HttpRedirect` (on by default) follows it like any
307; with `followRedirects = false` the call sees the 307, and so does a POST, PUT or other unsafe request while
`HttpRedirect`'s `checkHttpMethod` is on (its default follows GET and HEAD only): set `checkHttpMethod = false` to have
those repeated over `https` too. An AliasMode record whose target is no host name counts as "." and does not upgrade. The upgrade is no more trusted than a 307 over cleartext:
nothing is remembered for the origin beyond the records' TTL. An origin that publishes HTTPS records but serves
different content on `http://` cannot be reached over `http://` by such a client.

### Racing and fallback

When HTTP/3 is an option (`Preferred`, a QUIC hint, or a live Alt-Svc alternative) and no HTTP/3 connection to it is
open yet, the engine races connection setups (RFC 8305 section 5, after Chromium and curl): QUIC starts at once and
TCP + TLS starts when QUIC fails, or after a head start of 1.5 x the host's smoothed RTT (250 ms without history,
clamped to 100 ms..2 s; `hardDelay` overrides it) — and after 10 ms, the least RFC 8305 section 5 allows between two
attempts, on a network where QUIC was never seen working (`hardDelay = Duration.INFINITE` starts TCP only once QUIC
failed, on any network). The TCP side is HTTP/2 when the server offers it (`raceEnded` reports `HTTP_2_0`), and an
HTTP/2 connection to the origin that is already open serves it at once. The request runs once, on the winner. A QUIC
setup that loses the race keeps going in the background and serves the next requests once it is up; a TCP connection
that loses goes back to the pool. When both setups fail, the HTTP/1.1
failure is reported — the race was the one HTTP/1.1 attempt, there is no second one.

An alternative is marked broken only when HTTP/3 failed while HTTP/1.1 worked (a lost race, or a request that fell
back to HTTP/1.1 after the HTTP/3 connection failed as a whole: setup, QUIC transport, an HTTP/3 connection error; a
single stream reset or a malformed response falls back for that request only) — per origin and alternative, never "UDP is blocked" for everything: 5 minutes, doubling up to 2 days, and forgotten when `networkId()` reports a new
network. Broken alternatives are skipped (straight to HTTP/1.1). A server that refuses the QUIC setup with
`CONNECTION_REFUSED` (it is in `Drain`, stopping, or its accept queue is full: RFC 9000 section 5.2.2) has not shown the
alternative broken: that call falls back to HTTP/1.1 once (`fallback = Refused`), the alternative stays cached and
unmarked (RFC 7838 sections 2.2 and 3), and the next call tries HTTP/3 again. Any other close of the setup by the
server still marks it broken. Likewise a connection the server closes with H3_NO_ERROR after it sent GOAWAY (a graceful
stop whose grace period ended with requests still open: RFC 9114 section 5.2) ended in order: a request in flight on it
falls back to HTTP/1.1 when it may (idempotent, before its response), and the alternative is not marked broken; a close
with an error code after GOAWAY, or with H3_NO_ERROR but without a GOAWAY first, still marks it. So during a rolling restart the calls that meet a stopping instance fall back once each,
and the next calls use HTTP/3 again, instead of minutes to days of HTTP/1.1 for the whole origin.

### Turning HTTP/3 off remotely

`http3 { http3Allowed = { ... } }` (experimental) is a kill switch an application can flip from its remote
configuration (Firebase Remote Config, LaunchDarkly, its own config endpoint) when QUIC misbehaves on some network or
release, in the manner of Chrome's `QuicAllowed` policy or Cronet's `enableQuic(false)`, but per request and without a
restart. The engine calls it once per `https://` request, on the call's coroutine, before anything connects; it must
answer at once without blocking, so read a value your configuration keeps up to date:

```kotlin
val remoteConfig = MutableStateFlow(true)
// guide:ktor:http3-switch
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val quicAllowed: StateFlow<Boolean> = remoteConfig // updated by your remote configuration
val client =
    HttpClient(Kuicksilver) {
        engine { http3 { http3Allowed = { quicAllowed.value } } }
    }
// to take HTTP/3 off at once, not only for the next requests:
client.closeHttp3Connections()
```

What it does while it returns false:

- requests go over HTTP/1.1, as with `H1Only`; `protocolSelected` and the response's diagnostics say
  `Http3Disabled` ([Why did this request not use HTTP/3?](#why-did-this-request-not-use-http3));
- with `discovery = H3Only` a request fails with `UnsupportedOperationException` before it opens any TCP or UDP
  connection: that mode promises never to use TCP;
- `HttpClient.webTransport` fails the same way: WebTransport has no TCP fallback;
- open HTTP/3 connections take no new requests; calls already running on them finish, and idle connections close after
  `idleTimeout`;
- `Alt-Svc` is still learned in `Auto` mode, so when the switch returns true again the next request goes to the known
  alternative without a warm-up.

`HttpClient.closeHttp3Connections()` takes HTTP/3 out of use at once, whatever the switch says: every established
pooled connection gets a GOAWAY and no further request (a request that had just been handed one, before its stream
opened, goes again on a new connection or, switched off, the next call goes over HTTP/1.1), calls running on them
finish, and each closes when its last call is done; a connection still being set up serves the requests already
waiting for it and then closes; a race's own HTTP/3 setup still serves the request it was made for. A request refused
by that GOAWAY before anything of it went out is repeated on a new connection, a streamed body included (it was never
read). Every WebTransport connection gets a GOAWAY and every open session `WT_DRAIN_SESSION`: the server is asked to
wind the session down, the session's own `drainRequested` turns true so the application winds down too, and the
session stays open until either side closes it. A `webTransport` call whose CONNECT had not gone out yet fails with
`IllegalStateException` naming `closeHttp3Connections()`; one whose CONNECT completes after the call is drained as soon
as it opens. The call returns once
those frames are written, waiting at most 5 seconds for each.

The switch is not called for `http://` requests or `H1Only`. A switch that throws an exception counts as true (HTTP/3
allowed), so a broken configuration cannot take down traffic; the engine logs that at `Warn`, at most once per 5
minutes. A `CancellationException` or an `Error` out of it fails the call instead.

### Connection migration

`http3 { connectionMigration = ... }` (experimental, off by default) lets the engine's pooled HTTP/3 connections follow
the device's network (RFC 9000 section 9): when the default network changes, say from Wi-Fi to the mobile network,
each connection opens a socket on the new network, validates the path to the server and moves there, so a download
and the requests in flight carry on. Without it, as in 0.2, the outcome depends on the system: the engine's socket is
bound to no network, so the system may send its datagrams over the new default network from a new address, which the
server then takes as a NAT rebinding (RFC 9000 section 9.3; that is what an Android emulator does when its default
network goes away), or keep them on an interface that is gone, and then the connection ends at its idle timeout (an
idempotent request still waiting for its response falls back to HTTP/1.1). What the option adds over such a rebinding:

- the move is the client's decision, made when the system reports a new default network, not whenever the system
  happens to route a datagram elsewhere, and it does not depend on which network the system picks for an unbound socket
  (the new socket is bound to the new network: `Network.bindSocket`, `IP_BOUND_IF`);
- the new path is validated before the connection sends on it, and the connection stays where it was when it fails;
- the new path uses a fresh connection ID from the server, so the two networks' traffic cannot be linked by it (RFC
  9000 section 9.5); a rebinding keeps the old one;
- on iOS a socket the system reclaimed while the app was suspended is replaced.

On Android:

```kotlin
val connectivity = context.getSystemService(ConnectivityManager::class.java)
// inside HttpClient(Kuicksilver) { engine { http3 { ... } } }:
// guide:ktor:android-migration
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
connectionMigration = Http3ConnectionMigration.followDefaultNetwork(connectivity)
networkId = { connectivity.activeNetwork?.toString() }
```

On iOS and macOS, `Http3ConnectionMigration.followDefaultNetwork()` does the same with the Network framework
(`NWPathMonitor`, sockets bound to the new interface; it also replaces a socket iOS reclaimed while the app was
suspended). These are the `NetworkMigrator`s of [QUIC: Network changes](quic.md#network-changes), one per
connection over one shared system callback. The JVM, Linux and Windows have no network source of their own: pass
`Http3ConnectionMigration { connection, scope -> NetworkMigrator(connection, yourNetworks, yourOpenIo, scope) }`.

What the engine does:

- it starts the migrator once the connection's handshake has completed (a 0-RTT connection serves early requests
  first) and closes it when the connection closes (idle, lifetime, `closeHttp3Connections()`) or the client closes;
- the QUIC rules hold whatever the source says: no new path before the handshake is confirmed, none towards a server
  that sent `disable_active_migration` or uses zero-length connection IDs (RFC 9000 sections 9 and 9.5; no packet leaves
  the new socket), and every new path is validated before the connection sends on it. A refused or failed move leaves
  the connection where it was;
- every step reaches `KuicksilverEventListener.connectionMigrated(origin, event)`: `Migrated`, `Failed` (also logged at
  `Info`, or at `Debug` when the server does not allow migration), `NetworkLost` (the connection waits; its idle
  timeout decides if no network comes back) and `SourceFailed`;
- a migration neither marks the alternative broken nor forgets marks; `networkId` is separate, which is why the sample
  gives it the same source, so that a new network also gets a fresh chance at alternatives marked broken on the old one.

What does not survive a network change: HTTP/1.1 and HTTP/2 run over TCP, which cannot move, and so do WebSockets over
HTTP/1.1; a call on such a connection fails and the application repeats it. The dedicated connections of WebTransport
sessions do not follow the network either.

### Proxies

Where a request's proxy comes from:

1. `engine { proxy = ... }` (Ktor's `ProxyConfig`) when set: it applies to every request, `localhost` and loopback
   addresses included (as `curl -x` does; `java.net.Proxy.NO_PROXY` means none).
2. Otherwise `engine { proxyResolver = ... }` (*experimental*), asked per request and remembered for 30 seconds per
   scheme, host and port. The default is **`ProxyResolvers.System`**, the platform's settings:

| Target | `ProxyResolvers.System` | PAC / WPAD |
|---|---|---|
| JVM | `java.net.ProxySelector.getDefault()`: `https.proxyHost`/`http.proxyHost`, `socksProxyHost`, `http.nonProxyHosts`, and with `-Djava.net.useSystemProxies=true` the OS settings | as the JDK does |
| Android | the same: the active network's proxy, PAC through the system | yes (by the system) |
| macOS, iOS | the system proxy settings via `CFNetworkCopyProxiesForURL` (HTTP, HTTPS, SOCKS; the exceptions list) | not run: direct and one warning |
| Windows | the user's Internet settings via `WinHttpGetIEProxyConfigForCurrentUser` (`host:port` or `http=…;https=…;socks=…`, the bypass list with `<local>`) | not run: a fixed proxy next to it is used, else direct; one warning |
| Linux | `ProxyResolvers.Environment` (there is no system API; desktop settings are not read) | — |

`ProxyResolvers.Environment` reads the variables as curl does: `https_proxy`/`HTTPS_PROXY` for `https` and `wss`,
`http_proxy` (lower case only) for `http` and `ws`, then `all_proxy`/`ALL_PROXY`; `no_proxy`/`NO_PROXY` exempts `*`,
names with their subdomains (`example.com` covers `a.example.com`, not `badexample.com`), IP addresses and CIDR ranges;
an entry with a port (`example.com:8080`, `[2001:db8::1]:443`) exempts that port only, as Go does. On Windows
environment names are case-insensitive, so there an `HTTP_PROXY` variable is read as `http_proxy` (curl has the same
caveat).
A value is `http://host:port`, `socks5://` (names resolved by the client), `socks5h://` (by the proxy) or a bare
`host:port`; user info in it becomes the credentials. `ProxyResolvers.None` connects directly, as 0.2 did without
`proxy`; any `ProxyResolver { url -> ... }` of your own works too. Both built-in resolvers send `localhost`,
`*.localhost` and loopback addresses directly whatever the settings say.

A proxy the engine cannot use (`socks4://`, an `https://` proxy, an unknown type) fails the request with
`UnsupportedOperationException`: it is never bypassed.

How a proxy is used. An HTTP proxy gets `CONNECT` tunnels for `https` and for WebSockets, `ws://` included (RFC 6455
section 4.1, as browsers), and absolute-form requests for plain `http`; a SOCKS proxy is SOCKS5 (RFC 1928, CONNECT only;
no SOCKS4), every request tunneled, the proxy resolving the origin's name unless `socks5://` asked otherwise.
Credentials authenticate to either: SOCKS5 username/password (RFC 1929), offered and sent only when the proxy picks
that method, or `Proxy-Authorization: Basic` with the first CONNECT or absolute-form request unless the request sets
its own. `proxyCredentials` (*experimental*) are for the explicit `proxy` only (off the JVM a proxy URL's user info,
`http://user:password@proxy:3128`, wins); a resolver's proxy carries its own: the user info of `https_proxy` and the
like with `ProxyResolvers.Environment`, or the `credentials` of the `ResolvedProxy` your resolver returns. Both go in
clear to the proxy, never to the origin. Through `socks5://` (names resolved here) the engine tries the origin's
addresses in turn while the proxy answers "network unreachable" or "host unreachable", within the connect timeout. A
resolver that does not answer within the engine's `connectTimeout` (not a per-request `HttpTimeout`) fails the request with
`ProxyException`. A proxy that refuses fails the request with `ProxyException` (*experimental*):
`replyCode` is the SOCKS5 reply or the CONNECT status (407: credentials wanted; not retried).

**Through a proxy there is no HTTP/3.** QUIC is UDP, which neither CONNECT nor SOCKS5 CONNECT carries (no CONNECT-UDP,
RFC 9298, or SOCKS5 UDP ASSOCIATE), as with Chrome and curl. A proxied request uses HTTP/1.1 (`ProtocolReason.Proxy`),
`Alt-Svc` is neither used nor learned and `quicHints` are ignored; `H3Only` fails it with `UnsupportedOperationException`
without contacting the proxy, and `HttpClient.webTransport` refuses the URL unless `webTransportIgnoresProxy`. To use
HTTP/3 to a host, exempt it from the proxy (`no_proxy`, the OS bypass list), or connect directly everywhere with
`proxyResolver = ProxyResolvers.None`.

```kotlin
// guide:ktor:proxy
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val password = System.getenv("PROXY_PASSWORD") ?: ""
// one proxy for everything, with credentials for it
val viaProxy = HttpClient(Kuicksilver) {
    engine {
        proxy = ProxyBuilder.http("http://proxy.corp.test:3128")
        proxyCredentials = ProxyCredentials("user", password) // for `proxy` only
    }
}
// a resolver of your own: its proxy carries its own credentials (ProxyResolvers.Environment takes them from https_proxy)
val perHost = HttpClient(Kuicksilver) {
    engine {
        proxyResolver = ProxyResolver { url ->
            if (url.host.endsWith(".internal.test")) null // direct
            else ResolvedProxy.http("proxy.corp.test", 3128, ProxyCredentials("user", password))
        }
    }
}
```

### WebTransport on the client (experimental)

`HttpClient.webTransport(url)` opens a WebTransport session (draft-ietf-webtrans-http3-16) to an `https` URL and
returns the `WebTransportSession` of `kuicksilver-http3` (streams, datagrams, close; see the
[HTTP/3 guide](http3.md#webtransport-experimental)). Like a browser, each session gets a QUIC connection of its own,
outside the pool: without WebTransport flow control a connection carries one session, and the connection closes once
the session ended in both directions (after its close reached the server). The engine's trust, identity and QUIC
settings apply, with WebTransport, Extended CONNECT and `reset_stream_at` turned on for that connection;
`connectTimeout` bounds the setup, then the server's SETTINGS and its answer to the CONNECT get ten seconds each.
There is no fallback: a server without WebTransport fails with `Http3Exception.Settings`. Refused with
`UnsupportedOperationException`: `discovery = H1Only` (HTTP/3 is off), and a proxy that applies to the URL —
WebTransport runs over UDP, which an HTTP proxy does not carry — unless the host is exempt from the proxy or
`http3 { webTransportIgnoresProxy = true }` asks to connect directly. At most `http3 { maxWebTransportSessions }` (64)
sessions are open at once; one more fails at once with `IllegalStateException`, nothing waits. The connection goes
straight to the URL's host and port: Alt-Svc is not consulted and 0-RTT is never used; the resolved addresses are tried
in order within `connectTimeout`, so one whose handshake fails or stalls gives way to the next. Closing the client ends
the sessions still open with their connections, without a close capsule, and a call after `close()` fails with
`IllegalStateException`. Only the Kuicksilver engine supports it.

```kotlin
val client = HttpClient(Kuicksilver)
val url = "https://example.com/echo"
// guide:ktor:webtransport-client
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val session = client.webTransport(url, protocols = listOf("echo-v1"))
val stream = session.openBidi()
stream.output.writeFully("ping".encodeToByteArray())
stream.output.flushAndClose()
println(stream.input.readBuffer().readString())
session.close(0, "done")                           // the session's own connection closes with it
```

## Mutual TLS (client certificates)

A server that admits only clients with a certificate from its own CA sets `clientAuth = ClientAuth.Required` and an
`AnchoredCa` trust on the TLS connector:

```kotlin
val clientCaPem = File("client-ca.pem").readText()
// guide:ktor:mtls-server
val clientCa = Certificate.parsePem(clientCaPem)   // the CA that issues the client certificates
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector(TlsIdentity.fromPem(chainPem, keyPem.toCharArray())) {
        port = 443
        clientAuth = ClientAuth.Required           // no handshake without a client certificate that chains to clientCa
        trust = TrustConfig.AnchoredCa(clientCa)
    }
}) {
    routing {
        get("/whoami") { call.respondText("client ${call.request.peerCertificates.first().dnsNames}") }
    }
}
server.start(wait = true)
```

The client presents its certificate with `identity`, for HTTP/3, HTTP/2 and HTTP/1.1 alike:

```kotlin
// guide:ktor:mtls-client
val identity = TlsIdentity.fromPem(clientChainPem, clientKeyPem.toCharArray())   // every target; the key array is zeroed
val client = HttpClient(Kuicksilver) {
    engine {
        this.identity = identity                                            // presented over HTTP/3, HTTP/2 and HTTP/1.1 alike
        trust = TrustConfig.AnchoredCa(Certificate.parsePem(serverCaPem))   // or keep Platform for a public server certificate
    }
}
```

- **The server.** `clientAuth` is `None` (the default), `Optional` (a certificate is asked for; a client without one
  still connects, and `peerCertificates` is empty) or `Required` (the handshake fails without one). Any value but `None`
  needs `trust = TrustConfig.AnchoredCa(...)`, optionally inside `TrustConfig.Pinned`, the only trust for client
  certificates; without it the start fails with `TlsException.Config`. The setting applies to the TCP side and the HTTP/3
  side of the connector. `call.request.peerCertificates` is the client's chain as it was validated, leaf first, over
  TCP or QUIC. On the JVM, an `sslConnector` with a trust store requires client certificates the same way.
- **The client's key.** `TlsIdentity.fromPem(chain, key)` works on every target: the chain in PEM, leaf first, and the
  private key as one unencrypted PKCS#8 block (`-----BEGIN PRIVATE KEY-----`) in a `CharArray`. On the JVM (not
  Android) `TlsIdentity.fromPkcs12(bytes, password)` and `TlsIdentity.fromKeyStore(keyStore, alias, password)` read a
  `.p12` file or a `KeyStore` directly. Elsewhere convert a `.p12` once:
  `openssl pkcs12 -in client.p12 -nokeys -out client-chain.pem` and
  `openssl pkcs12 -in client.p12 -nocerts -nodes | openssl pkcs8 -topk8 -nocrypt -out client-key.pem`. The key has to
  be importable: a key that never leaves Android Keystore or the Apple Keychain cannot be used.
- **The client certificate.** One that carries an extended key usage must list `clientAuth` (TLS Web Client
  Authentication); otherwise the server refuses it with `InvalidPurpose` (alert 43). One without that extension is
  accepted.
- **A client without a certificate**, against `Required`: the server ends the handshake with the TLS alert
  `certificate_required` (116). Over TCP (`H1Only`) the call fails with an
  `IOException` (Ktor's `ClosedByteChannelException`) whose message is "TLS alert received from the peer:
  certificate_required (116)" and whose root cause is a `TlsException.AlertReceived`; the client's side of the TLS
  handshake has completed by then, so the alert ends the request. Over QUIC (`H3Only`) the call fails with
  `QuicException.ConnectionLost.TransportClosed`, `code` 0x174 (0x0100 + 116), with a `TlsException.AlertReceived` as
  its cause. In `Preferred` mode HTTP/3 fails that way first (the event listener's `raceEnded` or `fallback` gets that
  `TransportClosed`), the call goes on over TCP and fails there as over TCP, with no `suppressed` exceptions: the TCP
  setup did not fail. The server counts the failure by transport: over QUIC in
  `handshakesFailedTls` (`engine.http3Stats`), over TCP in its event listener's `tlsHandshakeFailed`.
- **0-RTT.** A server that asks for client certificates cannot accept 0-RTT: `quicEarlyData = true` together with a
  `clientAuth` other than `None` fails the start with `IllegalArgumentException` "earlyData cannot be combined with client
  certificates" ([0-RTT](#0-rtt-opt-in-experimental)). A client with an `identity` may keep `earlyData` on; such a
  server never offers it 0-RTT, so its connections use full handshakes.
- **Rotation.** The server's own identity can be a `TlsIdentity.Reloadable` ([Certificate rotation](#certificate-rotation)).
  The client CA in `trust` is read when the server starts; a new client CA takes a restart (put the old and the new CA in
  the bundle during the change).

## Priorities (experimental)

Both engines read and write RFC 9218 extensible priorities (the API is `@ExperimentalKuicksilverApi`). Over HTTP/3 the
priority decides the order in which response streams of one connection are sent: lower urgency first, streams of the
same urgency one after another, or interleaved when incremental. Over HTTP/1.1 a connection carries one response at a
time, so there the field is only read and sent, never used for scheduling.

On the server, `call.request.priority` is the client's current signal (urgency 3, not incremental, when it sent none; a
malformed parameter reads as its default), and `call.request.priorityUpdates` is the same as a `StateFlow` that follows
the client's PRIORITY_UPDATE frames over HTTP/3 (over HTTP/1.1 it never changes). `call.response.priority(urgency,
incremental)` sets the response's `Priority` field with only the parameters given: over HTTP/3 the engine merges them
into the client's signal (a parameter left out keeps the client's value, RFC 9218 section 8) and schedules the response
with the result, and later updates from the client no longer change it.

```kotlin
// guide:ktor:priority-server
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
get("/report") {
    if (call.request.priority.urgency < 4) call.response.priority(urgency = 4) // bulk: never ahead of the pages
    call.respondText(buildReport())
}
```

On the client, `priority(urgency, incremental)` in a request builder gives the request its priority: over HTTP/3 it is
sent as the `priority` field (no field for the default, u=3 non-incremental) and the request's own stream is scheduled
with it, a WebSocket over HTTP/3 included; over HTTP/1.1 only the `Priority` field is sent. It replaces a `Priority`
header set on the same request, so the server sees one signal. `response.updatePriority(urgency, incremental)` sends a
PRIORITY_UPDATE while the response is still coming (RFC 9218 section 7) and returns true; it returns false over
HTTP/1.1, which has no such signal (also when a 421 or a failure sent the request again over HTTP/1.1), once the call
is over or the body was read to the end, and when the connection is gone. The server reschedules
the rest of the response unless it set a priority of its own.

```kotlin
// guide:ktor:priority-client
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val page = client.get("$origin/index.html") { priority(urgency = 1) }
client.prepareGet("$origin/video.mp4") { priority(urgency = 5, incremental = true) }.execute { response ->
    response.updatePriority(urgency = 2, incremental = true) // now in view: more urgent
    response.bodyAsChannel().discard()
}
```

## WebSocket compression (experimental)

`PerMessageDeflate` (`kuicksilver-ktor-network`, `@ExperimentalKuicksilverApi`) is permessage-deflate (RFC 7692) for
Ktor's `WebSockets` plugins on every target: java.util.zip on the JVM and Android, the platform's zlib on Kotlin/Native.
Install it in the client plugin, the server plugin, or both; it works on any Ktor engine, and on Kuicksilver's engines
over HTTP/1.1 and HTTP/3 (RFC 9220) alike.

```kotlin
// guide:ktor:websocket-deflate-client
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val client =
    HttpClient(Kuicksilver) {
        install(WebSockets) { extensions { install(PerMessageDeflate) } }
    }
```

```kotlin
// guide:ktor:websocket-deflate-server
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
install(WebSockets) {
    extensions { install(PerMessageDeflate) { maxInflatedMessageSize = 1024 * 1024 } }
}
```

| `PerMessageDeflate.Config` | Default | |
|---|---|---|
| `compressionLevel` | 6 | zlib level of outgoing messages, 0..9 |
| `clientNoContextTakeover` | false | the client compresses each message on its own: a client offers it (and keeps to it whatever the answer), a server asks it of the client |
| `serverNoContextTakeover` | false | the server compresses each message on its own: a client requires it (an answer without it fails the handshake), a server announces it |
| `maxInflatedMessageSize` | 16 MiB | the largest size an incoming compressed message may inflate to |
| `minSizeToCompress` | 0 | smaller messages go uncompressed; a fragmented message is always compressed |
| `compressIf { frame -> ... }` | every message | compresses a message only when every predicate agrees (decided on its first frame) |

Only Text and Binary messages are compressed, with RSV1 on a message's first frame only (RFC 7692 section 6.1); a
fragmented message is one DEFLATE stream across its frames. As a client the extension does not offer
`client_max_window_bits`, so it compresses with a 32 KiB window; a server answer that is not a valid acceptance of its
offer (an unknown, repeated or malformed parameter, `client_max_window_bits`, `permessage-deflate` twice, or a requested
`server_no_context_takeover` left out) fails the call: Kuicksilver's client engine fails it with `WebSocketException`
before a session opens, other engines with the `ProtocolViolationException` the extension throws. As a server it
accepts the first offer it can keep to and declines the others (RFC 7692 section 7): an offered
`server_max_window_bits` is answered with the same value when the deflater can keep to it (9 to 15 on Kotlin/Native;
only 15 on the JVM and Android, whose `Deflater` has a fixed 32 KiB window: a smaller one is declined, and a client that
offered nothing else gets an uncompressed session), `client_max_window_bits` is a hint it leaves unanswered. Install one extension per RSV bit: Kuicksilver's server engine
refuses an upgrade that negotiated two extensions claiming the same bit (Ktor's own `WebSocketDeflateExtension` next
to `PerMessageDeflate`, say) with 500, and its client engine fails such an answer, as RFC 7692 section 5 requires. Incoming
messages are always inflated with a 32 KiB window, which reads every smaller one.

Decompression bombs. A compressed message may inflate to at most `maxInflatedMessageSize` bytes. Kuicksilver's engines
decompress the frames as they arrive, in pieces of 64 KiB, and close the connection with 1009 (message too big, RFC 6455
section 7.4.1) once a message passes the limit, after at most one piece more; malformed compressed data closes it with
1002 ("Invalid compressed data"). On Kuicksilver's engines Ktor's `maxFrameSize` sees only the decompressed pieces, so
the compressed bytes of a message have a bound of their own: 8 times the limit plus 64 KiB, past which the message
fails as too big as well (data that inflates to nothing, such as empty blocks, cannot stream on). On another engine the
extension decompresses each message Ktor's session has reassembled (Ktor's `maxFrameSize` bounds that compressed size)
and fails it with `FrameTooBigException`; what goes on the wire then is Ktor's choice (its session sends no 1009 for an
extension's exception). DEFLATE cannot expand more than about 1032 times, so the time spent on a message is bounded by
its compressed size as well; there is no separate ratio limit, which would only refuse legitimate, very repetitive
messages.

Compression and secrets. A message compressed in a window shared with data an attacker can choose leaks, through its
size, how much of a secret the attacker guessed (CRIME, BREACH; RFC 7692 section 8). Do not put secrets (tokens,
session ids) into messages that also carry attacker-influenced data, or keep such messages out of the shared window:
`compressIf { }` sends them uncompressed, and `serverNoContextTakeover` / `clientNoContextTakeover` stop one message
from sharing a window with the next (a secret and attacker data within one message still share one).

Memory per connection with permessage-deflate: the deflater's zlib state (about 256 KiB with a 32 KiB window, made on
the first outgoing compressed message), the inflater's (about 40 KiB, on the first incoming one), 32 KiB of output
history with context takeover on the JVM and Android and 80 KiB of buffers, plus the message being reassembled (at most the limit).
Kuicksilver's engines free the zlib state when the session ends. On another engine only a cleaner frees it, once the
garbage collector finds the extension unreachable: zlib's memory is native and does not press the collector, so many
short sessions can hold some 300 KiB each until it runs.

Linux Kotlin/Native binaries that use `kuicksilver-ktor-network` link the system's zlib dynamically (`libz.so.1`, in
every glibc distribution, though a distroless or scratch image may need it added); on Windows zlib is linked statically,
on Apple platforms it is the system's.

## Observability (experimental)

Both engines report what they do without a logging dependency (the API is `@ExperimentalKuicksilverApi`). The QUIC side
is the one described in [QUIC: Observability](quic.md#observability): counters, a `KuicksilverLogger`, a
`ConnectionListener` and qlog.

**Server.** In the engine configuration, `logger` receives the HTTP/3 endpoints' diagnostics (warnings on standard error by
default; the engine's own messages keep going to the application's log), `connectionListener` hears every QUIC
connection, `qlog` adds a trace per HTTP/3 connection to `quic`, and `eventListener` takes a
`KuicksilverServerEventListener`: `connectionOpened` and `connectionClosed` with the protocol (`HTTP/1.1` or `HTTP/2.0`
after the TLS handshake, `HTTP/3.0` once accepted) and the peer's address, `tlsHandshakeFailed`, `connectionRefused` (a
TCP client closed at accept, before TLS, with the reason: `per-IP limit` or `HTTP/2 repeat offender`; see [Connection
limits](#connection-limits)), and `requestStarted` / `requestEnded`
around the application's pipeline with the `ApplicationCall` (its response status) and the pipeline's failure, if any.
On the running engine, `engine.http3Stats` (0.3.0) gives the QUIC endpoint counters (`EndpointStats`) of every HTTP/3
listener, one per connector serving HTTP/3: datagrams, drops, refusals by the admission policy, the connection limits
and the accept queue, handshakes ([Deploying: Observability](deployment.md#observability)).

```kotlin
// guide:ktor:server-observability
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
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
`BrokenAlternative`, `WebSocket`, `Fallback`, `Proxy`, `Http3Disabled`, `HttpsRecord`; on the TCP path it comes once the
connection is in hand, with `HTTP_2_0` when the server picked `h2`, since 0.3.0); `raceEnded` (winner, head start, why HTTP/3 lost); `altSvcUsed`,
`httpsRecordUsed` (an endpoint of the origin's HTTPS record) and `altSvcMarkedBroken`; `fallback` from HTTP/3 to TCP,
with the HTTP/3 failure itself (not the `FallbackReason`, which is on the response, below); `retry` (a request the server
did not process after GOAWAY, HTTP_1_1_REQUIRED over HTTP/2, a stale pooled HTTP/1.1 connection, a 417); `connectionAcquired`
(reused or new) and `connectionReleased` (kept for the next request or closed); `connectionMigrated` (an HTTP/3 connection
followed the network, [Connection migration](#connection-migration)). `logger` (null keeps `http3.endpoint.logger`) also receives the listener's own failures, and
`http3 { qlog = ...; connectionListener = ... }` reach the engine's QUIC endpoint.

```kotlin
// guide:ktor:client-observability
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
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

On Android, `http3 { qlog = AsyncQlogSink(qlogDirectory(context)) }` writes the traces to a directory in the app's
cache directory, created owner-only (API 26 and up; [QUIC: qlog](quic.md#qlog)). It is the counterpart of
`keylogFile(context)`.

Callbacks of both listeners run on the engines' coroutines and must return quickly; an exception out of one is logged and
never fails a call.

### Why did this request not use HTTP/3?

Every response of the client engine carries a `ProtocolDiagnostics` (experimental): `response.kuicksilverDiagnostics`
(the call attribute `KuicksilverDiagnosticsKey`) says which `protocol` served the call, the `reason` that
`protocolSelected` heard last, and, when the call did not go over HTTP/3, why (`fallback`, a `FallbackReason`), with
the HTTP/3 `alternative` (`host:port`) and its `alternativeSource` (`AltSvc`, `QuicHint`, `Preferred`, `H3Only`),
whether the setups `raced` and HTTP/3's `headStart`, the HTTP/3 failure itself (`h3Failure`) when there was one, and
the number of `attempts`: the first, plus one per repeat by the engine (a request the server did not process after
GOAWAY or `H3_REQUEST_REJECTED`, or that `closeHttp3Connections()` stopped before it went out; a stale pooled HTTP/1.1
connection; a 417 to `Expect: 100-continue`; a 421 from the alternative), plus one for the fallback to HTTP/1.1 when
HTTP/3 had tried the request. The HTTP/3 layer's own repeats of a 0-RTT request on the same connection (early data
rejected, 425 Too Early) are not counted.

```kotlin
val url = "https://example.com/"
// guide:ktor:client-diagnostics
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val response = client.get(url)
val d = response.kuicksilverDiagnostics
if (d != null && d.protocol != HttpProtocolVersion.HTTP_3_0) {
    println("HTTP/3 not used: ${d.fallback} (alternative ${d.alternative} via ${d.alternativeSource})")
}
```

| `fallback` | Meaning | What to check |
|---|---|---|
| `NotSecure` | an `http://` or `ws://` URL | HTTP/3 needs `https` |
| `Proxy` | a proxy applies to the URL | `proxy` and `proxyResolver` ([Proxies](#proxies)) |
| `Configuration` | `discovery = H1Only` | the discovery mode |
| `Http3Disabled` | `http3 { http3Allowed }` returned false | your remote configuration ([Turning HTTP/3 off remotely](#turning-http3-off-remotely)) |
| `NoAlternative` | `Auto` and no `Alt-Svc` from the origin yet: the first call always goes over HTTP/1.1 | the server's `Alt-Svc`; `quicHints`, `FileAltSvcStore` |
| `MisdirectedRequest` | the alternative answered 421; it was dropped and the origin answered over HTTP/1.1 | the alternative's certificate and virtual hosts |
| `BrokenAlternative` | HTTP/3 to this alternative failed recently on this network | the log line's `broken since:` names why |
| `WebSocket` | a WebSocket without an HTTP/3 connection that allows Extended CONNECT | expected for the first WebSocket |
| `HandshakeTimeout` | no QUIC answer within the handshake or connect timeout | UDP to the port: a firewall, a VPN, a cloud security group open for TCP only |
| `UdpUnreachable` | ICMP unreachable for the UDP port | not reported yet: such calls show `HandshakeTimeout` |
| `H3NotReady` | HTTP/1.1 was ready before HTTP/3 answered (HTTP/3 had not failed) | nothing; the QUIC setup goes on and serves later calls |
| `Refused` | the server closed the QUIC connection without a TLS alert (`CONNECTION_REFUSED`), or no common QUIC version | `CONNECTION_REFUSED`: nothing, the server is draining, stopping or full, and the next call tries HTTP/3 again (the alternative is not marked broken); otherwise the server's QUIC listener and its limits |
| `TlsFailure` | a TLS alert in the QUIC handshake, or a local certificate failure | the UDP side's certificate and its `h3` ALPN |
| `Http3Error` | the HTTP/3 connection failed as a whole (an HTTP/3 or QPACK error, a stateless reset, an idle timeout) | `h3Failure`, a qlog trace |
| `ZeroRttRejected` | the server rejected 0-RTT | nothing |
| `GoAway` | the server refused the request with GOAWAY on every attempt | the server is stopping |
| `StreamFailed` | one HTTP/3 stream failed and the idempotent request went again over HTTP/1.1 | `h3Failure` |
| `Other` | any other HTTP/3 failure | `h3Failure` |
| `H2Refused` | the server answered HTTP/2 with HTTP_1_1_REQUIRED (RFC 9113 section 7), on this call or lately (the route offers only `http/1.1` for 5 minutes, doubling up to 2 days), so the call went over HTTP/1.1; why HTTP/3 was not used is in the log line as `h3Fallback=` | the server's HTTP/2 support for that route ([HTTP/2 on the client](#http2-on-the-client)) |

The engine's `logger` gets one line per call that HTTP/3 could have served but did not (a lost race, a fallback, a
broken alternative, a proxy) at `http3 { diagnosticsLogLevel }`, `Info` by default — which the default logger, warnings
and up, leaves out: set `logger = KuicksilverLogger.stderr(LogLevel.Info)` to see them. Calls over HTTP/3, and calls
HTTP/3 was never a candidate for (`http://`, `H1Only`, `Auto` without `Alt-Svc`), are logged at `Debug`; `null` turns
the lines off. The line is built only when the logger wants its level, and its format stays the same within 0.3.x:

```text
kuicksilver: GET https://example.com/path -> HTTP/1.1 (fallback=HandshakeTimeout, alt=example.com:443 via AltSvc, raced, headStart=10ms, h3Failure=Timeout, marked broken)
```

It names the method, scheme, host, port (when not the default) and path — never the query or the user info, which
often carry tokens — and the HTTP/3 failure by its type only (a peer's reason phrase is not logged). `broken since: <reason>`
says why a broken alternative was marked, `marked broken` that this call's failure marked it, `attempts=<n>` appears
from two attempts on.

**Logging every request.** The protocol and the reason come from three places, and one client can feed all three into
one log: the response's diagnostics (protocol, `reason`, `fallback`, `h3Failure`) for every call that got a response,
the event listener's `fallback` for the HTTP/3 failure as it happens (it has the exception, not the `FallbackReason`),
and the engine's own line through a `KuicksilverLogger` (an interface of two methods; here into the application's log,
on Android `android.util.Log` is the usual target):

```kotlin
fun logLine(line: String) = println(line)   // your logging library
// guide:ktor:protocol-log
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val client = HttpClient(Kuicksilver) {
    engine {
        // the engine's own line per call that HTTP/3 could have served, into your logging
        logger = object : KuicksilverLogger {
            override fun isEnabled(level: LogLevel) = level >= LogLevel.Info
            override fun log(level: LogLevel, message: String, cause: Throwable?) = logLine("$level $message")
        }
        // the HTTP/3 failure itself, when it happens; why the call did not use HTTP/3 is on the response
        eventListener = object : KuicksilverEventListener() {
            override fun fallback(request: HttpRequestData, cause: Throwable) = logLine("HTTP/3 failed for ${request.url.host}: $cause")
        }
    }
    // one line per response: the protocol and why
    install(createClientPlugin("ProtocolLog") {
        onResponse { response ->
            val d = response.kuicksilverDiagnostics ?: return@onResponse
            logLine("${response.call.request.url} -> ${d.protocol} (${d.reason}, fallback=${d.fallback}, h3Failure=${d.h3Failure})")
        }
    })
}
```

The first call to a new origin in `Auto` mode logs `https://example.com/ -> HTTP/1.1 (NoAlternative, fallback=NoAlternative,
h3Failure=null)`; a later one over HTTP/3 `-> HTTP/3 (...)` with `fallback=null`. `response.call.request.url` carries
the query: log `encodedPath` instead when queries hold tokens.

A call that fails has no response and so no diagnostics: its exception says what happened. When both the HTTP/3 and the
HTTP/1.1 setups failed, the HTTP/1.1 failure is thrown with the HTTP/3 one in `suppressed`. The diagnostics live as long
as the response (they are one of its call's attributes); the engine keeps no copy of the HTTP/3 failure, and a broken
mark remembers only its `FallbackReason`. Read them from the response: the engine puts a new object into the request's
attributes when the call reaches it and fills it as the call goes, so code that looks at the request earlier (a listener
during the call, a plugin running after a redirect copied the previous request's attributes) sees incomplete or stale
ones; when an interceptor sends one request builder through the engine twice, each engine call gets its own object.

### Graceful stop

`stop(gracePeriodMillis, timeoutMillis)` stops accepting TCP connections, sends GOAWAY on every live HTTP/3 connection at
once (RFC 9114 section 5.2) and shuts each HTTP/3 endpoint down with the same grace period
([QUIC: Graceful shutdown](quic.md#graceful-shutdown)): a new QUIC client is refused at its first Initial with
CONNECTION_REFUSED instead of waiting for a handshake timeout, a handshake already in flight still completes and its
connection gets GOAWAY at once, and the calls in flight finish. An HTTP/1.1 connection reads no further request: one
idle between requests (keep-alive) closes at once, one with a request in flight (or whose request head has started to
arrive) closes after that response, which says `Connection: close`. An HTTP/2 connection gets GOAWAY in two steps (RFC 9113
section 6.8: first with the largest stream identifier and a PING, then with the last stream it took, once the PING comes
back) and closes when those requests are done; streams the client opens after that are not processed. The stop returns
as soon as they have: each HTTP/3
connection closes with H3_NO_ERROR once its last response is acknowledged and read — the client closes it (a
Kuicksilver client does), or the server a quarter of the grace period later (three seconds at most; at least four
smoothed round trips). A browser or curl keeps an idle connection open, so that wait is what a stop takes with one
connected; with the quarter, Ktor's default `stop(500, 500)` ends gracefully on a low-latency path (a few milliseconds of
RTT). Where the round trip is longer, the GOAWAY round (two RTTs, at least 50 ms), that wait and the QUIC closing period
(three PTOs, RFC 9000 section 10.2) can exceed a short grace period: give it a second or more. At the end of the grace
period the calls still running are cancelled and the connections left are closed with H3_NO_ERROR (TCP connections still
writing a response are aborted instead of drained); the stop then waits for those calls to end, until `timeoutMillis`
after it began at most. As in Ktor's CIO engine, `stop(500, 500)` leaves no time for that last step: the stop may return
while the sockets cut at the grace deadline are still closing, so pass a `timeoutMillis` above the grace period where a
restart binds the same port at once.

## 0-RTT (opt-in, experimental)

Both engines can resume HTTP/3 connections with 0-RTT ([ADR-0015](../adr/0015-0rtt-implementation.md)): a returning
client sends its first requests with its first flight, one round trip earlier. It is off by default on both sides, it
exists only over QUIC (HTTP/1.1 and HTTP/2 over TCP never send or accept early data), and the price is that an early
request can be **replayed**: an attacker who recorded the client's first flight can send it to the server again
(RFC 9846 section 8). This section is everything an application needs to decide whether to turn it on.

- **Server:** set `quicEarlyData = true` in the engine configuration. Requests the early-data policy calls replayable
  (GET, HEAD and OPTIONS by default) that arrive in 0-RTT run before the handshake completes, and
  `call.request.receivedEarly` is true for them. Every other early request waits for the handshake (the default policy,
  `Http3EarlyDataPolicy.WaitForHandshake()`): a replayed copy never completes the handshake, so it never runs.
  `http3Settings = http3Settings { earlyData = Http3EarlyDataPolicy.Reject425() }` answers those with `425 Too Early`
  instead, without running the handler, and the client repeats them after its handshake (RFC 8470 section 5.2);
  replayable requests still run early under both policies. Assign it (a bare `http3Settings { ... }` inside `configure`
  only builds a value and changes nothing). Without `quicEarlyData` the server issues no session tickets for QUIC, so
  HTTP/3 clients run a full handshake every time.
- **Behind a gateway** (with or without `quicEarlyData`): a CDN or reverse proxy that forwards a request it received in
  early data marks it `Early-Data: 1` (RFC 8470 section 5.1), and such a request may be a replay whatever the state of
  the connection it arrives on. Over HTTP/1.1 and HTTP/3 the server engine sets `call.request.receivedEarly` for it and
  answers `425 Too Early` to any such request the early-data policy does not declare replayable (over HTTP/1.1: anything
  but GET, HEAD and OPTIONS), without running the handler; the gateway forwards the 425 and its client retries after
  its handshake. Gate side effects on `receivedEarly`, not on the TLS state of your own connection.
- **Client:** set `http3 { earlyData = true }`. On a new connection to a server it has a ticket for, the engine sends
  GET, HEAD and OPTIONS requests without a body in 0-RTT; other requests wait for the handshake. A `425` is retried
  once; when the server rejects 0-RTT as a whole, the early requests are repeated once on the same connection after its
  handshake (neither counts in `attempts`). 0-RTT keeps the h3/h1 race and the fallback intact:
  - A 0-RTT connection wins the race at once only on a network where QUIC was already seen working; elsewhere it must
    complete its handshake first, as in Chromium, so a network that drops UDP loses nothing over HTTP/1.1.
  - QUIC counts as working on the network, the alternative as working, and the connection's RTT is remembered only
    once the handshake completed, never on the 0-RTT start alone.
  - The connect timeout bounds the handshake of a 0-RTT connection (its handshake timer is cut to it): a GET sent early
    on a path that went dark fails then and falls back to HTTP/1.1, not after `handshakeTimeout`.
  - A request that waits for the handshake (POST, or anything with a body) has not been sent when the handshake fails:
    it goes over HTTP/1.1 like any request whose HTTP/3 connection could not be set up.
- **Tickets on the client** live in memory, in the engine's QUIC endpoint, for as long as the `HttpClient` lives: each
  is used once, checked against the current `trust` before use, and dropped when the client closes. Nothing is
  persisted, so after an app restart (or a new `HttpClient`) the first connection to each server is a full handshake,
  and 0-RTT starts from the next one.
- **Client certificates:** a server that asks for them cannot accept 0-RTT, and `quicEarlyData = true` with a
  `clientAuth` other than `None` fails the start ([Mutual TLS](#mutual-tls-client-certificates)).

```kotlin
// guide:ktor:zero-rtt-server
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector(identity) { port = 443 }
    quicEarlyData = true
    http3Settings = http3Settings { earlyData = Http3EarlyDataPolicy.Reject425() }   // or keep the default: unsafe requests wait
}, module = Application::module)
// guide:ktor:zero-rtt-client
val client = HttpClient(Kuicksilver) {
    engine { http3 { earlyData = true } }
}
```

### What must not run early

Turn 0-RTT on only when every request the policy calls replayable is safe to execute twice. Check the handlers of
GET, HEAD and OPTIONS (and of anything you add to `replayable`) for:

- state they change: counters, rate limits and quotas, "mark as read", a cart, a vote;
- one-time things a GET consumes: a sign-in or password-reset link, an e-mail confirmation, a download token, a nonce;
- actions behind a GET: sign-in or sign-out, sending a message or a push notification, starting a job, a payment;
- records that must be exact: billing or audit entries written per request.

An early request carries the same cookies and `Authorization` header as the original, so a replay is authorized too:
authentication does not make a state-changing request safe. Reads are fine. When some GETs change state, narrow the
policy instead of turning 0-RTT off, and keep `receivedEarly` checks in handlers that cannot be moved:

```kotlin
// guide:ktor:zero-rtt-replayable
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val policy = Http3EarlyDataPolicy.WaitForHandshake(replayable = { request ->
    request.method == "GET" && request.path.orEmpty().startsWith("/static/")   // only these may run before the handshake
})
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector(identity) { port = 443 }
    quicEarlyData = true
    http3Settings = http3Settings { earlyData = policy }
}) {
    routing {
        get("/feed") {
            if (call.request.receivedEarly) { /* a replay is possible here: no side effects */ }
            call.respondText("feed")
        }
    }
}
```

### How the server limits replays

A replay can only repeat requests the policy runs early; the server also limits how often and where:

1. **A short window.** A ticket's 0-RTT is accepted only while the ticket's age by the server's clock lies within
   [claimed − 1 s, claimed + 9 s] of the age the client claims (OpenSSL's fixed window, 10 s wide; RFC 9846 section 8.3),
   so a recorded flight is useless at most 10 s after the original.
2. **Once per ticket, per process.** A process-wide replay register remembers every ticket whose 0-RTT it accepted,
   for at least 20 seconds (longer than the window), and refuses that ticket's 0-RTT a second time. Every listener and
   every `udpSocketCount` loop of the process shares it. When it is full (it uses at most 1 MiB), 0-RTT is refused
   and the handshake goes on in 1-RTT: it fails closed.
3. **The configuration that issued the ticket.** A ticket allows 0-RTT only for the same ALPN, transport parameters and
   HTTP/3 SETTINGS; any change costs one 1-RTT handshake. A ticket is also bound to the certificate it was issued
   under, so after a [certificate reload](#certificate-rotation) old tickets resume nothing.
4. **The handshake.** A replayed flight never completes the handshake (the attacker lacks the key), so what waits for
   it, or got a 425, never runs from a replay.

**Several processes.** The register is per process. Session ticket keys are generated per process by default, so a
ticket issued by one instance resumes nothing on another (the client just runs a full handshake there), and a replay
sent to another instance gets no 0-RTT. With ticket keys shared between processes (`SessionTicketConfig.keys` in a `TlsConfig` of
the QUIC API; the Ktor server engine always uses the keys its process generated), or a server restarted within the
10-second window with the same keys, a replayed flight
can be accepted once per process: a replayable request may then run once more on each. Keep that in mind before
calling a request replayable on a multi-instance deployment. The threat model lists this residue
([threat model 3.8](../spec/threat-model.md#38-0-rtt-and-replay)).

## Supported Ktor versions

Kuicksilver 0.x supports **Ktor 3.6.x** (built and tested against 3.6.1). The engines use a few Ktor internals and
vendor parts of Ktor CIO (`docs/ktor-internal-api.md`), which Ktor may change in any minor release, so another
major.minor is not supported even when it happens to link.

- **At startup.** Creating a client engine (`HttpClient(Kuicksilver)`, also through `ServiceLoader`) checks
  `ktor-client-core`, `ktor-http-cio`, `ktor-network`, `ktor-io` and `ktor-websockets`; starting a server engine checks
  `ktor-server-core`, `ktor-http-cio`, `ktor-network` and `ktor-io` (every artifact whose internals the engines use or
  whose code they adapt). On the JVM and Android the version is the `Implementation-Version` in the manifest of the jar
  that holds each class; when the major.minor is not 3.6, the engine fails with an `IllegalStateException` naming the
  artifact, its version and the fix. Where no version can be read (Android after dexing, shaded or repackaged jars, classes from a directory) the check
  passes silently.
- **Opting out.** `-Dkuicksilver.ktor.versionCheck=false` (or `System.setProperty` before the engine is created) skips
  the check, for experts who verified their Ktor themselves; a mismatch then fails later, if at all, with
  `NoSuchMethodError` or `AbstractMethodError`.
- **Kotlin/Native.** klibs are resolved when the binary is linked: a Ktor whose ABI differs fails the link (unresolved
  symbols), so there is no runtime check. Keep every `io.ktor` dependency on the same 3.6.x, best with
  `platform("io.ktor:ktor-bom:3.6.1")`.
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
verified in a local Windows 11 VM (Parallels) and runs in the hosted CI's Windows jobs; the release gate runs locally
(`tools/ci/local-matrix.sh --with-windows`).

**Client** (`kuicksilver-ktor-client`): `ContentTest`, `PostTest`, `UploadTest`, `DownloadTest`, `HttpRedirectTest`,
`HttpTimeoutTest` and `WebSocketTest` against Ktor's test-server routes hosted on the Kuicksilver server engine; every
test runs twice — `Kuicksilver-h1` (cleartext HTTP/1.1, `H1Only`) and `Kuicksilver-h3` (HTTPS, `H3Only`). 93 tests,
90 pass in both modes, 3 are `@Ignore`d upstream. Adapted: the `HttpTimeoutTest` success budgets are widened, room
for a fresh client's handshake on a loaded host (comments in the file). Left out:

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
Ktor 3.6.0's (test scope only). On the JVM: 143 tests, 135 pass, 8 skip: `@Http2Only` (HTTP/2 server push, which Kuicksilver does not implement),
`@Http1Only` over HTTP/3 (the two keep-alive tests and chunked encoding), two tests `@Ignore`d upstream, and `testFragmentedFlagsFromTheFirstFrame` (it sends RSV1 without a negotiated extension, which the engine refuses with 1002). The
multipart uploads (streamed bodies of unknown length, chunked over HTTP/1.1) run over HTTP/3 too. Adapted: the test base (ports from the engine's resolved
connectors, the TLS identity from the test CA, real time instead of virtual time), the paths of the local-file and
static-resource tests (this module's layout and package), and `funkyChunked`, which expects a CRLF inside a quoted
chunk extension to be part of it: RFC 9110 section 5.6.4 allows neither CR nor LF in a quoted-string, so the server
answers 400. The WebSocket suite's test client masks its frames (RFC 6455 section 5.1; the engine fails an unmasked
one), and `testFragmentedFlagsFromTheFirstFrame` is `@Ignore`d: it sends RSV1 without negotiating an extension and
expects the server to take it, which the engine refuses with 1002 (threat model 3.20.1). Not vendored: `HttpServerJvmTestSuite`,
`SustainabilityTestSuite`, `ClientCertTestSuite` and the other JVM suites — they rely on `HttpURLConnection`, JKS key
stores and the Apache/OkHttp clients. Off the JVM, `PortableContentTestSuite` carries the 13 `ContentTestSuite` tests
that need no `java.io` (with `respondBytesWriter` and `ChannelWriterContent` for the JVM writers) in its place.

The suites found and fixed: a query parameter without a value (`?auto`) read as `null` instead of `""` over HTTP/3,
and the HTTP/1.1 client sent a streamed request body completely before reading the response (a server that answers
first, then reads the body, deadlocked). On Linux Native the client contract found that a failed HTTP/3 request (a peer
resetting a WebSocket stream) escaped as an uncaught coroutine exception, which aborts a Kotlin/Native process; each
request now contains its own failure.

**Other WebSocket peers.** The engines check every frame against the handshake (RFC 6455 sections 5.1 and 5.2, RFC
7692 section 6.1), stricter than Ktor's own engines:

- Ktor's `WebSocketDeflateExtension` sets RSV1 on every fragment of a compressed message, not only the first. A peer
  that uses it and fragments a compressed message (a message larger than its frame size) is closed with 1002; unfragmented
  messages, the common case, pass.
- A client that does not mask its frames, or a server that masks them, is closed with 1002, as the RFC requires; Ktor's
  own frame readers accept either.
- Ktor 3.6.1's WebSocket writer on Kotlin/Native (its common `RawWebSocket`) sends every fragment of a message with the
  message's opcode instead of 0 (continuation), so a fragmented message sent from Kotlin/Native, through any engine, is
  refused by the peer as a new message inside an unfinished one; send whole messages there. Its JVM writer is right.
- Ktor 3.6.1's `WebSocketDeflateExtension` fails (`IllegalArgumentException: byteCount: -5 < 0`, the session closes
  with 1011) when it compresses an empty message after an earlier one; it reads an empty message from
  `PerMessageDeflate` (a single 0x00 byte, RFC 7692 section 7.2.3.6) correctly. Otherwise the two interoperate in both
  directions over HTTP/1.1 and HTTP/3, context takeover included (`ClientDeflateKtorTest`).

### IPv6 over TCP on Kotlin/Native

On Kotlin/Native (Linux, Apple, Windows) Kuicksilver binds and connects its TCP sockets itself instead of through Ktor
3.6's `ktor-network`, because of a Ktor issue reported as
[KTOR-10017](https://youtrack.jetbrains.com/issue/KTOR-10017) (security, under coordinated disclosure).

Both engines therefore open their HTTP/1.1 TCP sockets through `kuicksilver-ktor-network` (`bindTcp`, `connectTcp`): on
the JVM and Android that is `ktor-network` as before; on Kotlin/Native it is a TCP socket of Kuicksilver on Ktor's selector
that binds and connects the address `getaddrinfo` returned. So on every platform:

- a server connector with a specific `host` (`::1`, `127.0.0.1`, a global address) listens on that address only; `::` and
  `0.0.0.0` stay the wildcards;
- the client's HTTP/1.1 connection (and its connection to an HTTP proxy) goes to the address in the URL; an
  IPv4-mapped literal (`[::ffff:127.0.0.1]`) is connected over IPv4, as the JVM does. A host name is resolved to all its
  addresses (`InetAddress.getAllByName` on the JVM and Android, `getaddrinfo` on Kotlin/Native, off the caller's thread
  and within the connect timeout) and connected with Happy Eyeballs (RFC 8305): IPv6 and IPv4 addresses alternate,
  starting with the family the resolver listed first (on the JVM `java.net.preferIPv6Addresses` decides, IPv4 first by
  default); a new attempt starts every `connectionAttemptDelay` (250 ms) or as soon as the previous one failed, the first
  connection wins and the other attempts are cancelled or closed. So an address that drops connection attempts silently
  costs 250 ms, not the request's connect timeout, which bounds all attempts together. `connectionAttemptDelay =
  Duration.INFINITE` tries one address after another, as 0.2 did on Kotlin/Native.
- HTTP/3 connects to the first address of the same resolution (one lookup per request for both sides of the h3/h1
  race); it does not race addresses: a family that drops UDP loses the h3/h1 race instead. With `H3Only` there is no
  race, so when the first address's family is broken (UDP dropped on it) the request fails at the connect timeout.
- Name lookups block a thread (`getaddrinfo`, `getAllByName`): at most 8 run at once, on their own share of
  `Dispatchers.IO`, and a name has one lookup in flight however many requests wait for it, so a stalled resolver cannot
  take the threads the sockets run on (threat model 3.21). An address literal is never looked up.

HTTP/3 uses the accelerated `ksl` UDP socket, which carries the full address on every platform (the Ktor client's endpoint
is dual-stack, ADR-0006). The portable Kotlin/Native UDP socket (`IoPreference.Portable`, or a sandbox that refuses the
accelerated one) still uses `ktor-network`: it refuses to bind a specific IPv6 address (`UnsupportedOperationException`)
and to send to an IPv6 address (`IOException`), for the same reason. Tests:
`ServerH1Test.negative_ipv6ConnectorListensOnItsAddressOnly`,
`ClientH1Test.negative_h1ToIpv6LiteralReachesThatAddressOnly`, `ClientH1Test.plainHttpToIpv6Literal`,
`ClientH3Test.h1ToIpv6Loopback`, `TcpSocketsTest`, `KtorDatagramIoTest`.
