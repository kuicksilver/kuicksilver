<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Ktor server engine

**What this page is for.** What `embeddedServer(Kuicksilver)` serves and how: the TLS connector, connection
limits, HTTP/3 and HTTP/2 on the server, h2c, turning HTTP/3 off, the CONNECT-UDP proxy and a graceful stop.

**Before you start**

- Words such as origin, alternative, route or race: the [glossary](glossary.md).
- The first server, with a local test certificate: [Quickstart](quickstart.md#2-a-server). The options most servers set:
  [configuration: first screen](configuration.md#first-screen-ktor-server).
- The imports of the code blocks: [Ktor engines: Imports](ktor.md#imports).
- Related pages: certificates, client certificates and reload in [TLS in the Ktor engines](engine-tls.md); a load balancer
  or proxy in front in [Behind a proxy or load balancer](server-proxies.md); `application.conf` in [Configuration file
  (EngineMain)](server-config-file.md); ports, firewalls, Docker and Kubernetes in [Deploying the HTTP/3
  server](deployment.md); WebSockets and WebTransport in [WebSockets, WebTransport and priorities](realtime.md).

The server's first screen is the [Minimal example](ktor.md#minimal-example): `tls { pemFiles(…) }` and one
`tlsConnector { port = 443 }`. Its second line, the recipes for common deployments, is stable too:

```kotlin
// guide:ktor:first-screen-server-recipes
embeddedServer(Kuicksilver, configure = {
    http3 { endpoint { maxConnectionsPerIp = null } } // behind a NAT or kube-proxy
    tcp { maxConnectionsPerIp = 256 } // facing the internet directly
    tlsConnector { proxyProtocol { trust("10.0.0.0/8") } } // behind an L4 load balancer
    tls { versions = TlsVersions.Tls12And13 } // old clients without TLS 1.3
}, module = Application::module)
```

With the certificate in memory and a route of its own:

```kotlin
// guide:ktor:server
val server = embeddedServer(Kuicksilver, configure = {
    tls { identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray()) }   // the key array is zeroed after import
    tlsConnector {
        port = 443   // no host: every interface, IPv6 and IPv4
    }
}) {
    routing {
        get("/") { call.respondText("hello") }
    }
}
server.start(wait = true)
```

- A `tlsConnector` serves HTTP/2 and HTTP/1.1 over TLS on TCP; for HTTP/1.1 Ktor's HTTP/1.1 parser (`ktor-http-cio`) and a copy of the CIO
  engine's connection pipeline handle requests, so keep-alive, pipelining, chunked bodies and `100-continue` behave as
  in the CIO engine. Request framing follows RFC 9112 section 6 more strictly than CIO: a request with both
  Content-Length and Transfer-Encoding is refused with 400 and the connection closed, a request with neither has no
  body (also with `Connection: close`), and a chunked trailer section is accepted when each line is a field line (its
  fields are discarded). Lines of the request head and of a trailer section end with CRLF: a bare LF gets 400 and the
  connection closed, unless `http1 { allowBareLf }` (*delicate*) is on (RFC 9112 section 2.2 lets a server take it; leave
  it off behind a proxy that forwards a bare LF, which would read the head otherwise). A
  chunk-size line must follow RFC 9112 section 7.1 exactly (hex digits, extensions by their grammar, no whitespace
  right before the CRLF, which 0.2.0 and Go's net/http tolerate): anything else, such as a bare CR or LF in it, makes the handler's receive of the body fail with
  `BadRequestException` (Ktor answers 400 unless the application handles it) and the connection closes. An HTTP/1.1
  request without a Host field, or any request with two, gets 400 and the connection closed (RFC 9112 section 3.2).
  The engine cannot act as a CONNECT proxy (not supported in 0.3.0): a CONNECT reaches the application, but a 2xx answer
  goes out as `501 Not Implemented` with a warning in the application log, since a 2xx would promise a tunnel; every
  CONNECT ends its connection (RFC 9931 section 8). The engine's own 400 has the fixed body `Bad Request`
  (Ktor CIO sends the parser's message, which can quote the request's header fields). ALPN on TCP offers `h2`, then
  `http/1.1`: HTTP/2 is on by default since 0.3.0 ([HTTP/2 on the server](#http2-on-the-server)). A connector speaks TLS 1.3 only unless it allows TLS 1.2: [TLS 1.2 on the server](engine-tls.md#tls-12-on-the-server).
- An identity in the engine's `tls { }` (`identity`, or `pemFiles(…)`) turns Ktor's own connectors into TLS ones, so
  `embeddedServer(Kuicksilver, port = 443, configure = { tls { identity = ... } })` works as expected; a `tlsConnector`
  takes the engine's `tls { }` and may override any of it with a `tls { }` of its own (another identity on another
  port, client certificates on one port). Without an identity a plain `connector { port = ... }` or `plainConnector { }`
  serves cleartext HTTP/1.1 (behind a TLS-terminating proxy, for tests). A `tlsConnector` or `plainConnector` without a
  `host` binds every interface, IPv6 and IPv4, with one dual-stack socket on `::` (Ktor logs `Responding at
  https://:::443`, which is `[::]:443`: `resolvedConnectors()` reports the bare `::`, which socket APIs take back), or
  `0.0.0.0` where the host has no IPv6 (logged at Info); so does the deployment port of `EngineMain` without
  `ktor.deployment.host`. Ktor's own `connector { }` keeps Ktor's default, `0.0.0.0`, and so does an explicit
  `ktor.deployment.host = "0.0.0.0"`.
- On the JVM, Ktor's `sslConnector(keyStore, alias, ...) {}` (and the `ktor.security.ssl.*` keys) is accepted: the key
  and chain under the alias become the identity, and a trust store makes client certificates required, as in Ktor's
  Netty and Jetty engines. Its `enabledProtocols` (`ktor.security.ssl.enabledProtocols`) choose the TLS versions:
  unset or `TLSv1.3` alone is TLS 1.3 only, `TLSv1.2` with `TLSv1.3` allows TLS 1.2 as well ([TLS 1.2 on the
  server](engine-tls.md#tls-12-on-the-server)); anything else (TLS 1.2 alone, TLS 1.0 or 1.1) fails the start with
  `TlsException.Config`. Ktor's connector cannot express a stapled OCSP response or a trusted gateway: it staples
  nothing and answers `421 Misdirected Request` for hosts its certificate does not name; for either, set
  `tls { ocspStapling }` or `tlsConnector { allowMisdirectedHosts }` in code, or serve the port with the `kuicksilver.tls.*` keys of
  `EngineMain` ([below](server-config-file.md#enginemain-and-configuration-keys)). Any other HTTPS connector type fails with
  `TlsException.Config` rather than serving cleartext.
- `call.request.local.remoteAddress` and `remoteHost` (and `localAddress`, `localHost`) are IP literals over HTTP/1.1,
  HTTP/2 and HTTP/3: the engine makes no reverse DNS lookup for a connection. `remoteAddress` and `localAddress` are
  literals in Ktor's Netty and CIO engines as well; their `remoteHost` and `localHost` are host names looked up on first
  use (`InetSocketAddress.getHostName()`), which this engine does not do.
- `call.request.peerCertificates` is the client certificate chain as the TLS layer validated it (empty without client
  authentication). Ktor has no equivalent. Requiring client certificates, and presenting one from the client:
  [Mutual TLS](engine-tls.md#mutual-tls-client-certificates).
- Slow and silent clients (slowloris): a client has `requestHeaderTimeout` (30 s) to send a
  complete request head, counted from the accepted TCP connection for the first request (the TLS handshake included)
  and from the end of the previous response on a keep-alive connection; header bytes trickling in do not extend it. One
  that sent part of a head by then gets `408 Request Timeout` with `Connection: close`; one that sent nothing (or never
  finished the TLS handshake) is closed without a response. Over HTTP/2 and HTTP/3 the same deadline bounds each
  request head (`maxHeaderBlockTime` of `http2 { settings { } }` and `http3 { settings { } }`, 10 s by default): an
  HTTP/3 head that misses it is reset with `H3_REQUEST_REJECTED`. `tcp { idleTimeout }` (45 s) closes a connection
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

## Connection limits

Each TCP connector holds at most `tcp { maxConnections }` (10,000) connections at once, and, when it is set, at most
`tcp { maxConnectionsPerIp }` (null, off, by default) from one client address, HTTP/1.1 and HTTP/2 alike. A
connection counts from `accept` (its TLS handshake included) until its socket is released (a socket whose release hangs
is given up after the abort wait, so for that moment the descriptors in use can briefly exceed the limit).

- At `maxConnections` the connector stops accepting, as Go's `netutil.LimitListener`, Jetty's `ConnectionLimit` and
  nginx's `worker_connections` do: new clients wait in the OS backlog (their connect succeeds, nothing is read from
  them) and are accepted as connections close; the server spends no descriptor or TLS work on them. Once the backlog is
  full too (511 on the JVM, 50 on Kotlin/Native), the OS drops further connection attempts (Linux by default, with
  `tcp_abort_on_overflow` 0: the client's TCP retries its SYN) or resets them. Waiting clients are not reported to the
  event listener.
- `maxConnectionsPerIp` is off by default, as in nginx, Caddy, Go, Jetty, Netty, Envoy and HAProxy. Behind a reverse
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
  `http2 { repeatOffenderPenalty }` (when on), and only then the TLS handshake.
- The default 10,000 does not protect a process whose descriptor limit is lower (`ulimit -n`: 256 in a macOS shell,
  often 1024 on Linux): raise that limit, or set `tcp { maxConnections }` below it, leaving room for the UDP sockets, files
  and outgoing connections the application opens. Above it `accept()` fails with EMFILE; the engine then backs off
  (5 ms doubling to 1 s) instead of spinning, but clients wait until descriptors free up.
- `EngineMain` keys `kuicksilver.tcp.maxConnections` and `kuicksilver.tcp.maxConnectionsPerIp` (`off` is off, `0` is
  refused).
- HTTP/3 has its own limits in the QUIC endpoint, `http3 { endpoint { maxConnections } }` and
  `http3 { endpoint { maxConnectionsPerIp } }` (the same 10,000 and 256, but the per-address one on by default), and
  `http3 { endpoint { acceptQueue } }` (128); `EngineMain` keys `kuicksilver.http3.endpoint.maxConnections`,
  `kuicksilver.http3.endpoint.maxConnectionsPerIp` (`off` is off) and `kuicksilver.http3.endpoint.acceptQueue`. Behind a
  NAT or `kube-proxy` turn the per-address one off (`maxConnectionsPerIp = null`): the first refusal by it logs a
  warning that says so, then one at most every 5 minutes ([deployment guide](deployment.md#quic-connection-limits));
  `engine.http3Stats` counts the clients they refused.

## HTTP/3 on the server

Every TLS connector also serves HTTP/3 on UDP on the same port number; the two sockets are bound as a pair, so with
`port = 0` both share the resolved port (`resolvedConnectors()` lists the TCP connectors). The OS
picks the TCP port first, so its UDP twin may be taken: the pair is then bound again on a new port, up to 16 times,
every other time with the UDP port picked first and TCP taking the same number, after which the connector serves
HTTP/1.1 alone with a warning. A fixed port whose UDP side is taken fails the start. HTTP/1.1
responses then carry `Alt-Svc: h3=":<port>"; ma=86400` so clients can switch (RFC 7838) — unless the application set
its own `Alt-Svc`, or the response is a 421; HTTP/2 responses carry it too, with an ALTSVC frame besides (see
[HTTP/2 on the server](#http2-on-the-server)); `http3 { altSvc = false }` turns both off. At the start the engine logs
at Info that HTTP/3 is advertised for the UDP port, which must be open.

In an HTTP/3 call `call.request.httpVersion` is `"HTTP/3"`, `call.request.local.scheme` is the request's `:scheme`
(`"https"` from browsers and the Kuicksilver client; `"http"` when a client sends that), `serverPort` without a port in
`:authority` is that scheme's default (80 or 443), the `:authority` appears as the `Host` header, and `call.request.local.remoteAddress` follows the client when it migrates to another
network. `call.request.local.localAddress` is the address the client sent to, on a connector without a host too (an IPv4
client of the dual-stack socket as IPv4), as the UDP socket reports it, the same on the JVM and Kotlin/Native; only a
socket that cannot report it (the portable one) gives the connector's own address. Responses never carry `Transfer-Encoding` or other connection-specific headers: bodies of unknown length are
simply a sequence of DATA frames.

The options are in the `http3 { }` block: `enabled` (true), `altSvc` (true), `quic { }` (the transport, `QuicConfig.Builder`:
idle timeout, streams, windows, path MTU), `settings { }` (`Http3Settings.Builder`: QPACK, field sections) and
`endpoint { }` for each listener's QUIC endpoint: `loops` (endpoint loops on the UDP port, every platform with a QUIC
server), `maxConnections`, `maxConnectionsPerIp`, `acceptQueue`, `admission` (Retry policy, Ktor-Netty's
`quicTokenHandler`), `maxConnectionLifetime`, `loadBalancer` (QUIC-LB connection IDs, experimental;
`engine.updateLoadBalancer` changes them, [QUIC: Behind a load balancer](quic.md#behind-a-load-balancer); the connection
ID length follows it) and `expert { }` (`connectionIdLength`, 8 bytes by default and refused next to `loadBalancer`, and
the admission internals). The engine derives what follows from other options (`expert { resetStreamAt }`
and `cancelErrorCode` in `quic { }`; `enableConnectProtocol`, `h3Datagram`, `webTransport`, `earlyData` in
`settings { }`) and refuses them when assigned, naming the option. UDP socket buffer sizes are not configurable yet.

The engine serves HTTP/3 on every target, Kotlin/Native Linux, Apple and Windows included (the accelerated `ksl` socket,
ADR-0006); `http3 { endpoint { loops } }` above 1 works wherever HTTP/3 does: a socket per loop with `SO_REUSEPORT` on Linux and Android,
one socket routed by connection ID in process on macOS, iOS and Windows ([QUIC: Several loops on one port](quic.md#several-loops-on-one-port)).
Where a QUIC server cannot run, the engine logs a warning and serves
HTTP/1.1 only, without `Alt-Svc`. A `tlsConnector` with an `sniSelector` serves HTTP/3 too: the same selector picks the
identity of each QUIC handshake ([Certificate per name](engine-tls.md#certificate-per-name-sni)).

Running it in production (UDP in firewalls, Docker and Kubernetes, load balancers, kernel buffers, checking that clients
arrive over HTTP/3): [Deploying the HTTP/3 server](deployment.md).

## HTTP/2 on the server

On by default; turn it off with `http2 { enabled = false }` for a middlebox that breaks it (`EngineMain` key
`kuicksilver.http2.enabled = false`). Every TLS connector offers `h2` before `http/1.1` in ALPN, so a client that offers
both (browsers, OkHttp, the JDK's client, curl, the Kuicksilver client) gets HTTP/2 (RFC 9113), where 0.2 gave it
HTTP/1.1, and one that offers only `http/1.1` gets HTTP/1.1 on the same port. `http2 { enabled }` is stable; the
tuning in `http2 { settings { } }` and `repeatOffenderPenalty` are experimental. Plain connectors serve HTTP/2 only with
their own opt-in ([h2c on the server](#h2c-on-the-server)); without it a client's `PRI * HTTP/2.0` preface is refused with
`505 HTTP Version Not Supported`. HTTP/2 runs over
TLS 1.3, and over TLS 1.2 on a connector that allows it ([TLS 1.2 on the server](engine-tls.md#tls-12-on-the-server); RFC 9113
section 9.2).

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:http2-server
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector {
        tls { this.identity = identity }
        port = 443
    }
    http2 {
        settings { maxConcurrentStreams = 50 }  // windows and flood limits are Http2Settings.Builder's
    }
}, module = Application::module)
```

Each stream is a Ktor call: `call.request.httpVersion` is `"HTTP/2"`, `call.request.local.scheme` is `"https"` (the
connection's, whatever the request's `:scheme`), `:authority` appears as the `Host` header and split `cookie` fields as one (RFC 9113 section 8.2.3). Responses
go out without connection-specific headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade` are dropped), a
response to HEAD, a 204 or a 304 without content. The engine's `Alt-Svc` goes out both ways: as the field on every
response, as on HTTP/1.1, and as an ALTSVC frame (RFC 7838 section 4) on the request stream ahead of the response, once
per origin and value on the connection and again 12 hours (half the advertised `ma`) after the last one, so a client on a
long-lived connection learns it again. Section 3 recommends the frame ("When using HTTP/2 ([RFC7540]), servers SHOULD
instead send an ALTSVC frame") and keeps the field valid ("Note that, despite this recommendation, Alt-Svc header fields
remain valid in responses delivered over HTTP/2"): the frame serves the clients that read it (the Kuicksilver client
does), the field those that read only the header (curl, Kuicksilver clients before 0.3.0, other stacks), and both carry
the same reading of the value. An application's own `Alt-Svc` header, and a 421, are left as they are. Requests are checked against RFC 9113 section 8 before the application sees them:
a malformed one (an uppercase or invalid field name, a connection-specific field, `te` other than `trailers`, a missing,
repeated or unknown pseudo-header field, `host` that differs from `:authority`, content that does not match
`content-length`) is reset with PROTOCOL_ERROR and the connection goes on; a field section above `maxFieldSectionSize` is
answered 431. A CONNECT is answered 501 (the engine has no tunnels), and so is an Extended CONNECT for a protocol other
than `websocket`; WebSockets come over HTTP/2 too ([WebSockets over HTTP/2](realtime.md#websockets-over-http2)). A request with
`Expect: 100-continue` gets an interim 100 as the handler starts (RFC 9110 §10.1.1: immediate), unless the request has no
content; another expectation is answered 417 when the handler reads the body. Content that does not match the
response's `Content-Length` is never sent as a complete response (the stream is reset); a 1xx as the final status goes
out as a 500. A call that ends without a response resets its stream; one stream's failure (a client's reset, a handler's
exception) never affects the others on the connection.

Never-indexed fields (RFC 7541 sections 6.2.3 and 7.1.3, experimental): `call.request.neverIndexedHeaders` lists the
request fields the client sent as literals never indexed, and `call.response.neverIndex("x-api-key")` sends the named
response fields so (neither into the HPACK table nor from it). An application that forwards a field it received never
indexed must keep that representation: pass its name to `neverIndex` on the message it sends on, as the client's
`neverIndex` and `neverIndexedHeaders` allow the other way. The engine sends `set-cookie` never indexed on its own.
Over HTTP/3 the same API carries QPACK's 'N' bit (RFC 9204 section 4.5.4); over HTTP/1.1 the list is empty and
`neverIndex` changes nothing.

`http2 { settings { } }` (`Http2Settings.Builder`) holds the windows, `maxConcurrentStreams` (100), the field-section
limit and, in `floodLimits { }`, the flood limits of the core ([configuration reference](configuration.md#ktor-server)).
The engine's deadlines apply: the client's connection preface must arrive within `requestHeaderTimeout` of the accepted
connection (TLS included), else GOAWAY and close; each field block must arrive within it too (else GOAWAY with
ENHANCE_YOUR_CALM); a request body that sends no byte for `tcp { idleTimeout }` fails the handler's read and is
answered 408 when nothing else answered; a connection without requests for that long gets GOAWAY and closes; a
response that gets no window from the client for the longer of that and 5 minutes resets its stream. Request content is
credited to the client only as the handler reads it. A client's RST_STREAM cancels the handler of that request; a
request still arriving when its handler is done with a complete response is stopped with RST_STREAM NO_ERROR (RFC 9113
section 8.1). `eventListener` reports these connections and calls with `HTTP_2_0`.

Flood defences (threat model, section 3.23): each connection is held to the core's limits (`http2 { settings {
floodLimits { } } }`: the reset budget `resets` against Rapid Reset, the glitch budget `glitches` against MadeYouReset and PING, SETTINGS or PRIORITY floods, 8 CONTINUATION
frames per field block, 10 000 queued control frames), and a broken limit ends it with GOAWAY ENHANCE_YOUR_CALM. A
stream the client reset cancels its handler and counts toward SETTINGS_MAX_CONCURRENT_STREAMS until the handler
returns, so no more handlers run at once than that limit. A connection that is over gets what it still has to write
sent for as long as the client takes it; after the send-stall deadline without progress its socket is aborted (3
seconds when it ended in an error, such as a broken flood limit: only its GOAWAY is left to deliver). These
per-connection limits are the defence by default.

`http2 { repeatOffenderPenalty }` (experimental, a `Duration?`; `EngineMain` key `kuicksilver.http2.repeatOffenderPenalty`,
e.g. `30s`; null, `off` in the file, by default) adds a backoff by address: one whose HTTP/2 connections end in a flood limit's ENHANCE_YOUR_CALM three
times within a minute has its TCP connections (HTTP/1.1 too) closed at accept, before the TLS handshake, for that long,
with a warning logged at most every 10 seconds per connector. An IPv4 client counts by its address (also when a
dual-stack listener reports it as `::ffff:a.b.c.d`), an IPv6 client by its /56; a slow field block is no strike. Turn it
on only where the server sees each client's real address (directly exposed, or behind an L4 load balancer that keeps
the source address). Never behind a NAT, CGNAT, an L4 load balancer or Kubernetes Service that rewrites source
addresses (`externalTrafficPolicy: Cluster`) or a TCP proxy such as HAProxy in TCP mode: every client there shares one
address, and one flooder would lock them all out.

The server passes h2spec 2.6.0 (all 146 cases, `tools/interop/h2spec.sh`, over TLS and over h2c), with its default
configuration. HTTP/2 is on by default since 0.3.0; its tuning API is experimental.

## h2c on the server

HTTP/2 over cleartext TCP with prior knowledge (h2c, RFC 9113 section 3.3; experimental, off by default; [ADR-0018](../adr/0018-h2c-and-coalescing-in-030.md))
is for a server behind a TLS-terminating proxy or load balancer, inside a service mesh whose sidecar does the TLS, and
for gRPC between services: the hop from the proxy to the server keeps HTTP/2's multiplexing instead of falling back to
HTTP/1.1. It is turned on per plain connector:

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:h2c-server
val server = embeddedServer(Kuicksilver, configure = {
    plainConnector {
        port = 8080
        h2c = H2cMode.WithHttp11      // HTTP/1.1 and h2c (prior knowledge) on this cleartext port; H2cMode.Only: h2c alone
    }
}, module = Application::module)
```

`EngineMain` takes `kuicksilver.connector.h2c = off | withHttp11 | only` for the cleartext deployment port (not
together with the `kuicksilver.tls.*` identity files: a TLS port negotiates `h2` by ALPN, `kuicksilver.http2.enabled`).
A connector that an identity in the engine's `tls { }` turns into a TLS one refuses h2c at the start
(IllegalArgumentException).

- **One port or two.** `WithHttp11` tells the two apart by the client connection preface (`PRI * HTTP/2.0

SM

`,
  RFC 9113 section 3.4), as Go's `golang.org/x/net/http2/h2c` handler and Netty's `CleartextHttp2ServerUpgradeHandler`
  do: the first octets are looked at as they arrive, none is consumed, and the first one that differs from the preface
  hands the connection to HTTP/1.1 at once, so a request shorter than the 24 octets is never held back. The wait is part
  of the first request head's deadline (`requestHeaderTimeout`): a client that sends part of the preface and
  stops is closed then, as a slow HTTP/1.1 head is. When the server stops during that wait, a connection
  that has sent nothing is closed at once, and one that has started is treated as a request head that started on
  HTTP/1.1: waited for within the request-head deadline and the stop's grace period. A whole preface is HTTP/2, which
  serves the requests that came with it and ends with the graceful two-step GOAWAY (RFC 9113 section 6.8); the first
  octet that differs hands the connection to HTTP/1.1, which answers that request with `Connection: close`; a client
  that stops part way is closed at the deadline with HTTP/1.1's 408. "Arrived" means read by the server from the socket:
  bytes still in the kernel's buffer, or a TLS record not yet decrypted, when the stop begins are not seen, and such a
  connection counts as one that has sent nothing. `Only` (a gRPC port) skips the check: a client that sends anything
  else, an HTTP/1.1 request included, gets the connection error of an invalid preface (GOAWAY with PROTOCOL_ERROR, then
  the close), never an HTTP/1.1 answer. A dedicated port per protocol is two connectors.
- **`Upgrade: h2c` is not taken.** RFC 9113 section 3.1 deprecates the HTTP/1.1 upgrade to h2c; a request that offers
  it is served as HTTP/1.1, as any `Upgrade` the server does not take (RFC 9110 section 7.8), never answered 101.
- **Everything else is HTTP/2 on the server, unchanged**: `http2 { settings { } }`, the deadlines, the flood defences
  and `http2 { repeatOffenderPenalty }`, RFC 9218 priorities, WebSockets over HTTP/2 (`ws://`, RFC 8441, with
  `webSockets { overHttp2 }`), the two-step GOAWAY at a stop, `tcp { maxConnections }`, the event listener and the probe. The
  call's `request.local.scheme` is `http`. No `Alt-Svc` and no ALTSVC frame: HTTP/3 is for `https` origins.
- **`:scheme https` over h2c** (a proxy that terminated TLS and forwards the original scheme) is a misdirected request
  on a plain connection (RFC 9110 section 7.4): 421, unless the connector's clients are trusted gateways
  (`plainConnector { allowMisdirectedHosts = true }`, [Misdirected requests](server-proxies.md#misdirected-requests)).

**Cleartext.** Nothing authenticates the client or protects the bytes (CWE-319): serve h2c only behind a trusted network
or proxy (a loopback hop, a private network, a sidecar that does mTLS), never on a port the internet reaches. When the
front is an HTTP/1.1 proxy that turns requests into h2c, the server's HTTP/2 message checks (connection-specific fields,
`content-length` against the content) reject what would smuggle a second request ([threat model 3.23.1](../spec/threat-model.md#3-23-1-h2c)).

## Turning HTTP/3 off on the server

A running server can stop advertising HTTP/3, or take it out of service, without a restart: set
`engine.http3Advertising` (experimental) from wherever your remote configuration arrives — a config poll, an admin
endpoint, a feature flag.

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:http3-advertising
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector {
        tls { this.identity = identity }
        port = 443
    }
}, module = Application::module)
// later, when the remote configuration says so: clients fall back to HTTP/2 or HTTP/1.1 over TLS
server.engine.http3Advertising = Http3Advertising.Drain
// and when the incident is over
server.engine.http3Advertising = Http3Advertising.On
```

| Value | HTTP/1.1 responses | HTTP/2 connections | HTTP/3 responses | Live HTTP/3 connections | New QUIC connections |
|---|---|---|---|---|---|
| `On` (default) | `Alt-Svc: h3=":<port>"; ma=86400` | the same field, and an ALTSVC frame with it | no `Alt-Svc` | served | accepted |
| `Clear` | `Alt-Svc: clear` | the same field, and an ALTSVC frame with it | `Alt-Svc: clear` | served | accepted |
| `Drain` | `Alt-Svc: clear` | the same field, and an ALTSVC frame with it | `Alt-Svc: clear` | GOAWAY (RFC 9114 section 5.2): requests in flight finish, then the connection closes | refused at the first Initial with CONNECTION_REFUSED |

RFC 7838 section 3: "A field value containing the special value "clear" indicates that the origin requests all
alternatives for that origin to be invalidated". An HTTP/3 response may send it too, since section 2.2 says
"Alternative services are fully authoritative for the origin in question, including the ability to clear or update
cached alternative service entries".

- Every response reads the value as its head goes out, so the next response on a keep-alive connection follows a
  change; every new client Initial is checked when the QUIC endpoint admits it. The setter returns at once.
- The `Alt-Svc` part (header or HTTP/2 frame) applies where the engine sends `Alt-Svc` at all: on a TLS connector that serves HTTP/3, with
  `http3 { altSvc = true }`. With `altSvc = false` no `Alt-Svc` is sent in any mode, but `Drain` still sends GOAWAY and refuses new
  QUIC connections. An `Alt-Svc` the application sets itself is left as it is in every mode, and a 421 gets none.
- `Clear` stops the advertising and withdraws it: a client drops the alternative at its next response, over HTTP/1.1 or
  HTTP/3. A connection it already has may go on serving it (RFC 7838 section 2.2 lets a client keep using one); to move
  those connections to TCP, use `Drain`.
- `Drain` sends GOAWAY to every live HTTP/3 connection at once, as a [graceful stop](#graceful-stop) does, and to every
  connection whose handshake completes while it is set. The requests in flight complete; once the last response is
  acknowledged the client closes the connection (a Kuicksilver client does), or the server three seconds later.
  **Not bounded:** `Drain` has no grace deadline (RFC 9114 section 5.2 sets none), so a long-lived stream (a WebSocket
  or WebTransport session over HTTP/3) keeps its connection until the application or the client ends it.
  To cut such sessions, stop the server (its grace period applies) or end them in the application.
- A new client is refused with a stateless Initial CONNECTION_CLOSE carrying CONNECTION_REFUSED, as RFC 9000 section
  5.2.2 asks: "If a server refuses to accept a new connection, it SHOULD send an Initial packet containing a
  CONNECTION_CLOSE frame with error code CONNECTION_REFUSED" (sections 10.2.3 and 20.1). It is under the endpoint's
  stateless rate limit, runs before `http3 { endpoint { admission } }` (which is not asked), unless a hard limit
  (`maxConnections`, `maxConnectionsPerIp`) drops the Initial first, and `EndpointStats.connectionsRefusedAdmission` counts it. A refused client falls back to TCP at once instead of waiting for
  its handshake timeout, and its next HTTP/2 or HTTP/1.1 response clears its cached alternative. A Kuicksilver client does not
  mark the alternative broken for the refusal ([Racing and fallback](client-http3.md#racing-and-fallback)), so once the instance (or
  another one) serves HTTP/3 and announces it again, the client is back on HTTP/3 with its next call.
- The UDP socket stays bound under `Drain`: releasing the port and binding it again on `On` would race other processes
  for it (and, with `endpoint { loops }` above 1 on Linux and Android, for each of its sockets), and a closed port answers with nothing or an ICMP
  error that clients only notice at their handshake timeout. To block UDP outright, use the firewall.
- Back to `On` (or `Clear`), new QUIC connections are accepted again. GOAWAY cannot be taken back (RFC 9114 section 5.2),
  so connections drained before keep closing; their clients open new ones.
- The value is per engine and is not kept across restarts: a new engine starts at `On`. Behind a load balancer set it on
  every instance.

Before maintenance, wait for the drained connections to go before you stop the server or block UDP. `engine.http3Stats`
counts them (`connectionsActive`, every HTTP/3 connection the listeners still hold, closing ones included); since `Drain`
has no deadline of its own, give the wait one:

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:drain-wait
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

## CONNECT-UDP over HTTP/3 (experimental)

With `http3 { connectUdp = true }` the HTTP/3 listener takes CONNECT-UDP requests (RFC 9298, MASQUE: an Extended CONNECT with
`:protocol` `connect-udp`) into Ktor's pipeline, and a `connectUdp(proxy)` route serves them with a `UdpProxy` of
`kuicksilver-http3` ([HTTP/3, CONNECT-UDP](http3.md#connect-udp-experimental)): the proxy reads the target from the path
with its `pathTemplate`, checks it with its `targetFilter` (`UdpTargetFilter.PublicOnly` by default: loopback, private,
link-local, multicast and broadcast targets are refused with 403) and its limits, answers and relays the tunnel; the call
ends with the tunnel. The route matches only such a request, at any path, over HTTP/3; HTTP/1.1 and HTTP/2 do not carry
CONNECT-UDP (ADR-0024). Without `connectUdp = true` the engine answers CONNECT-UDP with 501; a CONNECT-UDP request no route
takes gets Ktor's 404, and one another route answers with a 2xx gets 501, since no tunnel was opened. Give the route one
`UdpProxy` (its limits count the tunnels of every request) and put it behind authentication: "HTTP servers that support
UDP proxying ought to restrict its use to authenticated users" (RFC 9298 section 7); a 401 or 407 from a check in front
of it goes out as it is. The proxy's configuration is code (a filter, a resolver), so it has no configuration-file key.

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:connect-udp-server
val proxyServer = embeddedServer(Kuicksilver, configure = {
    tlsConnector {
        tls { this.identity = identity }
        port = 443
    }
    http3 { connectUdp = true }
}) {
    routing {
        connectUdp(UdpProxy())                     // behind your authentication; public targets only by default
    }
}
```

## Graceful stop

`stop(gracePeriodMillis, timeoutMillis)` stops accepting TCP connections, sends GOAWAY on every live HTTP/3 connection at
once (RFC 9114 section 5.2) and shuts each HTTP/3 endpoint down with the same grace period
([QUIC: Graceful shutdown](quic.md#graceful-shutdown)): a new QUIC client is refused at its first Initial with
CONNECTION_REFUSED instead of waiting for a handshake timeout, a handshake already in flight still completes and its
connection gets GOAWAY at once, and the calls in flight finish. An HTTP/1.1 connection reads no further request: one
idle between requests (keep-alive) closes at once, one with a request in flight (or whose request head has started to
arrive) closes after that response, which says `Connection: close`. A connection that has received nothing yet is new,
not idle: its first request may be on its way, and a client whose new connection closes without an answer cannot tell
whether a non-idempotent request was processed (RFC 9112 section 9.3.1). Its first byte is waited for until 2 s after the
connection was accepted (within the request-head deadline and the grace period; Go's `Server.Shutdown` waits 5 s), so a
silent new connection can hold the stop that long. An HTTP/2 connection gets GOAWAY in two steps (RFC 9113
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
