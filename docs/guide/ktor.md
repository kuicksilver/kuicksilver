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
  set `tls { trust }`.

<a id="minimal-example"></a>
**Minimal example.** The first screen of each engine: the few options most applications set, every one of them stable
(no opt-in; the [configuration reference](configuration.md#first-screen) lists them). A server with a certificate from
files, renewals picked up, on one port for TCP and UDP:

```kotlin
// guide:ktor:first-screen-server
fun main() {
    embeddedServer(Kuicksilver, configure = {
        tls {
            pemFiles(
                "/etc/letsencrypt/live/example.com/fullchain.pem", // the key must be unencrypted PKCS#8
                "/etc/letsencrypt/live/example.com/privkey.pem", // (-----BEGIN PRIVATE KEY-----)
            )
            reloadInterval = 1.hours // pick up certbot renewals
        }
        tlsConnector { port = 443 } // TCP 443: HTTP/2 and HTTP/1.1; UDP 443: HTTP/3, announced with Alt-Svc
    }, module = Application::module).start(wait = true)
}
// Open 443/tcp AND 443/udp. Check: curl -sI https://example.com | grep -i alt-svc; curl --http3-only -sI https://example.com
```

The same server from `application.conf`, with `mainClass = io.kuicksilver.ktor.server.EngineMain` (the keys follow the
DSL: [EngineMain and configuration keys](#enginemain-and-configuration-keys)):

```hocon
ktor.deployment.port = 443
ktor.application.modules = [ com.example.ApplicationKt.module ]
kuicksilver.tls {
    certificateChain = "/etc/letsencrypt/live/example.com/fullchain.pem"
    privateKey       = "/etc/letsencrypt/live/example.com/privkey.pem"
    reloadInterval   = 1h
}
```

The most common client configures nothing; the first request to a host goes over TCP (HTTP/2 or HTTP/1.1), HTTP/3 from
the next one once the server sent `Alt-Svc` (run it inside a coroutine, for example `runBlocking { }`):

```kotlin
// guide:ktor:first-screen-client
val client = HttpClient(Kuicksilver) // explicit engine: HttpClient() may pick OkHttp/Android first (ServiceLoader)
println(client.get("https://example.com/").bodyAsText())
client.close()
```

A mobile app with its own API (HTTP/3 from the first request, a remote kill switch, connection migration) is the first
screen of [Client](#client); recipes for common deployments open [Server](#server). Client certificates on both sides are
under [Mutual TLS](#mutual-tls-client-certificates), pinning under [Certificate pinning](#certificate-pinning).

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
import io.kuicksilver.http2.http2Settings
import io.kuicksilver.http3.Http3EarlyDataPolicy
import io.kuicksilver.http3.UdpProxy
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.ktor.network.websocket.PerMessageDeflate
import io.kuicksilver.ktor.server.H2cMode
import io.kuicksilver.ktor.server.Http3Advertising
import io.kuicksilver.ktor.server.Kuicksilver
import io.kuicksilver.ktor.server.KuicksilverServerEventListener
import io.kuicksilver.ktor.server.connectUdp
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
import io.kuicksilver.tls.EchKey
import io.kuicksilver.tls.EchServerKeys
import io.kuicksilver.tls.ServerTlsOverride
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsVersions
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
import io.kuicksilver.http2.http2Settings
import io.kuicksilver.http3.UdpProxyTemplate
import io.kuicksilver.ktor.client.ConnectFailure
import io.kuicksilver.ktor.client.ConnectUdpProxy
import io.kuicksilver.ktor.client.Dns
import io.kuicksilver.ktor.client.FileAltSvcStore
import io.kuicksilver.ktor.client.HostPort
import io.kuicksilver.ktor.client.Http3ConnectionMigration
import io.kuicksilver.ktor.client.Http3Discovery
import io.kuicksilver.ktor.client.HttpsRecordSource
import io.kuicksilver.ktor.client.IpAddress
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.ktor.client.KuicksilverEventListener
import io.kuicksilver.ktor.client.ProtocolReason
import io.kuicksilver.ktor.client.ProxyCredentials
import io.kuicksilver.ktor.client.ProxyResolver
import io.kuicksilver.ktor.client.ProxyResolvers
import io.kuicksilver.ktor.client.QuicConnectionSnapshot
import io.kuicksilver.ktor.client.ResolvedProxy
import io.kuicksilver.ktor.client.TcpConnectionSnapshot
import io.kuicksilver.ktor.client.Transport
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
import io.kuicksilver.tls.EchConfigList
import io.kuicksilver.tls.SpkiSha256
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.io.readString
import java.io.File
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
```

The Android samples (the mobile first screen, [Connection migration](#connection-migration)) also need
`android.net.ConnectivityManager` and `io.kuicksilver.ktor.client.followDefaultNetwork` (an Android-only extension; the
iOS and macOS one, without arguments, has the same name). A file that uses both engines (a
test, a gateway) imports at least one of them under another name:

```kotlin
// guide:ktor:both-engines-aliases
import io.kuicksilver.ktor.client.Kuicksilver as KuicksilverClient
import io.kuicksilver.ktor.server.Kuicksilver as KuicksilverServer
// guide:ktor:both-engines
val server = embeddedServer(KuicksilverServer, configure = {
    tlsConnector {
        tls { this.identity = identity }
        port = 8443
    }
}, module = Application::module)
val client = HttpClient(KuicksilverClient)
```

Kuicksilver plugs into Ktor 3.6 as a server engine (`io.kuicksilver:kuicksilver-ktor-server`) and a client engine
(`io.kuicksilver:kuicksilver-ktor-client`). Both speak HTTP/1.1 over TLS 1.3 (`kuicksilver-ktor-network`) and HTTP/3
(`kuicksilver-http3`); both also speak HTTP/2 over TLS (`kuicksilver-http2`, ADR-0017), on by default on both since
0.3.0 ([HTTP/2 on the server](#http2-on-the-server)): one port serves HTTP/1.1, HTTP/2 and HTTP/3. The code blocks below compile and run as `GuideSamplesTest`
(`kuicksilver-ktor-server/src/jvmTest` and `kuicksilver-ktor-client/src/jvmTest`), and the first screens compile in a
source set that opts in to nothing and fails on a warning (`src/jvmFirstScreenTest`), so they stay free of experimental
API; the engines' other tests run on every
target (see "Compatibility"). Every engine option with its default is in the [configuration
reference](configuration.md); common failures are in [troubleshooting](troubleshooting.md).

## Server

The server's first screen is the [Minimal example](#minimal-example): `tls { pemFiles(…) }` and one
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
  `http/1.1`: HTTP/2 is on by default since 0.3.0 ([HTTP/2 on the server](#http2-on-the-server)). A connector speaks TLS 1.3 only unless it allows TLS 1.2: [TLS 1.2 on the server](#tls-12-on-the-server).
- An identity in the engine's `tls { }` (`identity`, or `pemFiles(…)`) turns Ktor's own connectors into TLS ones, so
  `embeddedServer(Kuicksilver, port = 443, configure = { tls { identity = ... } })` works as expected; a `tlsConnector`
  takes the engine's `tls { }` and may override any of it with a `tls { }` of its own (another identity on another
  port, client certificates on one port). Without an identity a plain `connector { port = ... }` or `plainConnector { }`
  serves cleartext HTTP/1.1 (behind a TLS-terminating proxy, for tests). A `tlsConnector` or `plainConnector` without a
  `host` binds every interface, IPv6 and IPv4, with one dual-stack socket on `::` (Ktor logs `Responding at
  https://:::443`), or `0.0.0.0` where the host has no IPv6 (logged at Info); Ktor's own `connector { }` and
  `ktor.deployment.host` keep Ktor's default, `0.0.0.0`.
- On the JVM, Ktor's `sslConnector(keyStore, alias, ...) {}` (and the `ktor.security.ssl.*` keys) is accepted: the key
  and chain under the alias become the identity, and a trust store makes client certificates required, as in Ktor's
  Netty and Jetty engines. Its `enabledProtocols` (`ktor.security.ssl.enabledProtocols`) choose the TLS versions:
  unset or `TLSv1.3` alone is TLS 1.3 only, `TLSv1.2` with `TLSv1.3` allows TLS 1.2 as well ([TLS 1.2 on the
  server](#tls-12-on-the-server)); anything else (TLS 1.2 alone, TLS 1.0 or 1.1) fails the start with
  `TlsException.Config`. Ktor's connector cannot express a stapled OCSP response or a trusted gateway: it staples
  nothing and answers `421 Misdirected Request` for hosts its certificate does not name; for either, set
  `tls { ocspStapling }` or `tlsConnector { allowMisdirectedHosts }` in code, or serve the port with the `kuicksilver.tls.*` keys of
  `EngineMain` ([below](#enginemain-and-configuration-keys)). Any other HTTPS connector type fails with
  `TlsException.Config` rather than serving cleartext.
- `call.request.local.remoteAddress` and `remoteHost` (and `localAddress`, `localHost`) are IP literals over HTTP/1.1,
  HTTP/2 and HTTP/3: the engine makes no reverse DNS lookup for a connection. `remoteAddress` and `localAddress` are
  literals in Ktor's Netty and CIO engines as well; their `remoteHost` and `localHost` are host names looked up on first
  use (`InetSocketAddress.getHostName()`), which this engine does not do.
- `call.request.peerCertificates` is the client certificate chain as the TLS layer validated it (empty without client
  authentication). Ktor has no equivalent. Requiring client certificates, and presenting one from the client:
  [Mutual TLS](#mutual-tls-client-certificates).
- Slow and silent clients (slowloris): a client has `requestHeaderTimeout` (30 s) to send a
  complete request head, counted from the accepted TCP connection for the first request (the TLS handshake included)
  and from the end of the previous response on a keep-alive connection; header bytes trickling in do not extend it. One
  that sent part of a head by then gets `408 Request Timeout` with `Connection: close`; one that sent nothing (or never
  finished the TLS handshake) is closed without a response. Over HTTP/2 and HTTP/3 the same deadline bounds each
  request head (`maxHeaderBlockTime` of `http2 { settings { } }` and `http3 { settings { } }`, 10 s by default): an
  HTTP/3 head that misses it is reset with `H3_REQUEST_REJECTED`. `http1 { idleTimeout }` (45 s) closes a connection
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

### TLS 1.2 on the server

A TLS connector speaks TLS 1.3 only by default: a client without it is refused with a `protocol_version` alert.
`tls { versions = TlsVersions.Tls12And13 }` (on the engine, or in one `tlsConnector`'s `tls { }`), the `EngineMain`
key `kuicksilver.tls.versions = tls12And13` for the deployment port, or `enabledProtocols = listOf("TLSv1.2",
"TLSv1.3")` on Ktor's `sslConnector` (JVM) serves TLS 1.2 clients too (RFC 9325 section 3.1.1: "Implementations MUST
support TLS 1.2"). Turn it on only for clients that have no TLS 1.3 (older devices, embedded HTTP stacks, some
proxies and scanners): any client can then end up on TLS 1.2.

- A client that offers TLS 1.3 still gets it; a TLS 1.2 ServerHello carries the RFC 9846 downgrade sentinel, so a
  TLS 1.3 client notices an attacker who removed 1.3 from its offer.
- TLS 1.2 runs under the RFC 9325 profile: ECDHE with AES-GCM or ChaCha20-Poly1305 only (no static RSA, no CBC, no
  SHA-1 MAC, no finite-field DHE), Extended Master Secret required (a client without it is refused with
  `handshake_failure`), no renegotiation, no compression. Among the suites a client offers, the server picks AES-256-GCM
  first, then ChaCha20-Poly1305 (first when the client prefers it), then AES-128-GCM.
- An ECDSA certificate serves the TLS 1.2 clients that offer an ECDHE-ECDSA suite (most do); a client that offers only
  RSA suites needs a connector with an RSA certificate (2048 bits or more).
- With HTTP/2 on (the default), HTTP/2 is offered over TLS 1.2 too (RFC 9113 section 9.2), where the handshake can
  support `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` with P-256, the suite section 9.2.2 makes mandatory for such
  deployments: with an rsaEncryption certificate and `secp256r1` among the key-exchange groups. A TLS 1.2 handshake
  whose certificate has no rsaEncryption key (an EC or an RSA-PSS key, an `sniSelector`'s answer included) or whose
  groups leave P-256 out gets `http/1.1` instead (a client that offers `h2` alone gets `no_application_protocol`); the
  start says so at Info for the connector's own certificate, and fails for a connector whose `keyExchangeGroups` leave
  `secp256r1` out. TLS 1.3 clients get HTTP/2 either way. A client's attempt to renegotiate ends an HTTP/2 connection
  with GOAWAY PROTOCOL_ERROR, an HTTP/1.1 one goes on with the renegotiation refused.
- Client certificates, `sniSelector` and tickets work as over TLS 1.3. A TLS 1.2 session resumes for at most
  `SessionTicketConfig.ticketLifetime` after its full handshake (12 hours by default, at most half of `rotateEvery`),
  however often its ticket is renewed (TLS 1.2 has no fresh key exchange on resumption; RFC 9325 section 3.4). With
  explicit ticket keys the library does not rotate them: replace them at least every `rotateEvery`, as that option
  promises.
- HTTP/3 on the same port stays TLS 1.3 (QUIC allows nothing else).

### HTTP/3 on the server

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
network. Responses never carry `Transfer-Encoding` or other connection-specific headers: bodies of unknown length are
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
identity of each QUIC handshake ([Certificate per name](#certificate-per-name-sni)).

Running it in production (UDP in firewalls, Docker and Kubernetes, load balancers, kernel buffers, checking that clients
arrive over HTTP/3): [Deploying the HTTP/3 server](deployment.md).

### Encrypted Client Hello on the server

*Experimental.* With `tls { echKeys }` the TLS connectors decrypt Encrypted Client Hello (RFC 9849, shared mode) on TCP and HTTP/3
alike, so the name a client asks for never crosses the network in the clear. Make a key with OpenSSL 4 and publish its
ECHConfigList in the `ech` parameter of the HTTPS record of every name the connector serves (RFC 9848):

```shell
openssl ech -public_name cover.example.com -out ech-1.pem   # the PEM: the private key and an ECHCONFIG block
```

```kotlin
val ech1 = File("/etc/kuicksilver/ech-1.pem")
val ech2 = File("/etc/kuicksilver/ech-2.pem")
// guide:ktor:ech-server
val keys = EchServerKeys(listOf(EchKey(ech1.readBytes())))
val server =
    embeddedServer(Kuicksilver, configure = {
        tls {
            this.identity = identity
            echKeys = keys
        }
        tlsConnector { port = 443 }
    }) { routing { get("/") { call.respondText("hidden") } } }
// later: a new key; the old one still decrypts for clients that hold it, but is not sent in retry configurations
keys.rotate(listOf(EchKey(ech2.readBytes()), EchKey(ech1.readBytes(), inRetryConfigs = false)))
```

- **The public name.** A client whose configuration the server cannot decrypt (an old key, or GREASE) gets the keys' retry
  configurations, but only after it authenticated the server for the configuration's `public_name` (RFC 9849 section
  6.1.7): the connector's certificate must cover that name. With an `sniSelector` the selector is asked for the
  `public_name` then (the outer ClientHello's name), and its answer is the certificate the client checks; after an
  accepted ECH it is asked for the inner name, as without ECH.
- **Key material.** `EchKey` takes the PEM as a `ByteArray` or `CharArray` and zeroes it; its own copy is zeroed once
  `EchServerKeys` (or `rotate`) has read it into native memory, so such a key is used once. A `String` cannot be wiped and
  stays in memory as long as the key. `kuicksilver.tls.echKeys` reads its files without making a `String`.
- **Rotation.** `rotate` replaces the whole set for handshakes that start afterwards, on TCP and QUIC; handshakes in
  progress keep the set they started with. Keep a replaced key (`inRetryConfigs = false`) until the DNS TTL of the old
  record has run out. The keys of a set need distinct config_ids: one sharing a config_id with another (1 case in 256
  for keys made apart) is refused with "two ECH keys share a config_id"; make the new key again with `openssl ech`
  before publishing it.
- **Shared mode only.** The connector is both the client-facing and the backend server; split mode (a front end that
  forwards to a backend) is not supported.
- `EngineMain`: `kuicksilver.tls.echKeys` (above).

### HTTP/2 on the server

On by default; turn it off with `http2 { enabled = false }` for a middlebox that breaks it (`EngineMain` key
`kuicksilver.http2.enabled = false`). Every TLS connector offers `h2` before `http/1.1` in ALPN, so a client that offers
both (browsers, OkHttp, the JDK's client, curl, the Kuicksilver client) gets HTTP/2 (RFC 9113), where 0.2 gave it
HTTP/1.1, and one that offers only `http/1.1` gets HTTP/1.1 on the same port. `http2 { enabled }` is stable; the
tuning in `http2 { settings { } }` and `repeatOffenderPenalty` are experimental. Plain connectors serve HTTP/2 only with
their own opt-in ([h2c on the server](#h2c-on-the-server)); without it a client's `PRI * HTTP/2.0` preface is refused with
`505 HTTP Version Not Supported`. HTTP/2 runs over
TLS 1.3, and over TLS 1.2 on a connector that allows it ([TLS 1.2 on the server](#tls-12-on-the-server); RFC 9113
section 9.2).

```kotlin
// guide:ktor:http2-server
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
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
than `websocket`; WebSockets come over HTTP/2 too ([WebSockets over HTTP/2](#websockets-over-http2)). A request with
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
ENHANCE_YOUR_CALM); a request body that sends no byte for `http1 { idleTimeout }` fails the handler's read and is
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

### h2c on the server

HTTP/2 over cleartext TCP with prior knowledge (h2c, RFC 9113 section 3.3; experimental, off by default; [ADR-0018](../adr/0018-h2c-and-coalescing-in-030.md))
is for a server behind a TLS-terminating proxy or load balancer, inside a service mesh whose sidecar does the TLS, and
for gRPC between services: the hop from the proxy to the server keeps HTTP/2's multiplexing instead of falling back to
HTTP/1.1. It is turned on per plain connector:

```kotlin
// guide:ktor:h2c-server
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
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
  (`plainConnector { allowMisdirectedHosts = true }`, [Misdirected requests](#misdirected-requests)).

**Cleartext.** Nothing authenticates the client or protects the bytes (CWE-319): serve h2c only behind a trusted network
or proxy (a loopback hop, a private network, a sidecar that does mTLS), never on a port the internet reaches. When the
front is an HTTP/1.1 proxy that turns requests into h2c, the server's HTTP/2 message checks (connection-specific fields,
`content-length` against the content) reject what would smuggle a second request ([threat model 3.23.1](../spec/threat-model.md#3-23-1-h2c)).

### Turning HTTP/3 off on the server

A running server can stop advertising HTTP/3, or take it out of service, without a restart: set
`engine.http3Advertising` (experimental) from wherever your remote configuration arrives — a config poll, an admin
endpoint, a feature flag.

```kotlin
// guide:ktor:http3-advertising
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
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
  mark the alternative broken for the refusal ([Racing and fallback](#racing-and-fallback)), so once the instance (or
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

### WebSockets on the server

Ktor's `WebSockets` plugin and `webSocket("/path") {}` routes work as on Ktor's own engines, over HTTP/1.1, HTTP/2
(RFC 8441) and HTTP/3, with the checks RFC 6455 asks of a server that Ktor leaves out:

- A handshake is upgraded only when it is one (section 4.2.1): over HTTP/1.1 exactly one `Sec-WebSocket-Key` that is 16
  bytes in base64, and on every protocol exactly one `Sec-WebSocket-Version: 13`. Otherwise the route's answer becomes
  `400 Bad Request`, or for another version `426 Upgrade Required` over HTTP/1.1 (400 over HTTP/2 and HTTP/3), with
  `Sec-WebSocket-Version: 13`; the handler does not run.
- A client's uncompressed frame or message larger than the engine's `webSockets { maxMessageSize }` (16 MiB by default)
  closes the connection with 1009 from the frame's header, before its payload is read (section 10.4);
  a compressed one closes it as it inflates past the limit (and a compressed frame claiming more than 8 times the limit
  plus 64 KiB, from its header). Ktor's own `maxFrameSize` (unlimited on the server by default) applies on top. The
  engine decompresses permessage-deflate itself, whichever extension negotiated it (`PerMessageDeflate` or Ktor's
  `WebSocketDeflateExtension`). A text message or a Close reason that is not UTF-8 closes it with 1007 (section 8.1),
  and a malformed control frame, fragment, length or Close frame with 1002.
- The server's frames are never masked (section 5.1), whatever `WebSockets { masking }` says, and a Close the
  application sends with a code no endpoint may send (1005, 1006, 1015, below 1000, …) goes out without a code.
- Once the session ended (both Closes), the server closes the connection at once (section 5.5.1: "The server MUST close
  the underlying TCP connection immediately"): over HTTP/1.1 its FIN, right after close_notify over TLS, without
  waiting for the client to close first; over HTTP/2 and HTTP/3 its END_STREAM or FIN, after which it waits up to 5 s
  for the client's, reading what still comes, and only then stops a client that did not end its side (RST_STREAM
  NO_ERROR, STOP_SENDING H3_NO_ERROR).

The client engine applies the same rules to what servers send ([Client](#client)).

### WebSockets over HTTP/3

With `webSockets { overHttp3 = true }` (the default) the HTTP/3 listener advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL` and
accepts Extended CONNECT with `:protocol = websocket` (RFC 9220). Such a request reaches Ktor's pipeline as the HTTP/1.1
upgrade request the `WebSockets` plugin knows — `GET` with `Connection: Upgrade`, `Upgrade: websocket` and a
`Sec-WebSocket-Key` — so ordinary `webSocket("/path") {}` routes serve it unchanged; the upgrade is answered with
`:status 200` and the frames travel on the request stream. The protocol name matches in any case (RFC 9110 section 7.8).
Extended CONNECT with any other protocol is answered 501 (WebTransport aside when it is on, below), and so is a WebSocket
with `overHttp3 = false`, also when `http3 { webTransport { enabled = true } }` advertises Extended CONNECT. A route other than
`webSocket` that answers the WebSocket CONNECT with a 2xx (a `get` on the same path) gets 501 instead: a 2xx would open a
tunnel nobody accepted (RFC 9110 section 9.3.6), and `call.response.status()` reports the 501. An accepted upgrade
reports 101, as on HTTP/1.1, while `:status 200` goes out. A plain HTTP/1.1 `Upgrade` on an HTTP/3 request is meaningless (RFC 9114
section 4.5) and gets 501 too.

### WebSockets over HTTP/2

With HTTP/2 on (the default), `webSockets { overHttp2 = true }` (the default too) has the HTTP/2 connections advertise
`SETTINGS_ENABLE_CONNECT_PROTOCOL` and accept Extended CONNECT with `:protocol = websocket` (RFC 8441), as over HTTP/3:
the request reaches Ktor's pipeline as the HTTP/1.1 upgrade request the `WebSockets` plugin knows, ordinary
`webSocket("/path") {}` routes serve it unchanged (`call.request.httpVersion` is `"HTTP/2"`), and the upgrade is answered
with `:status 200` (no `Sec-WebSocket-Accept`, RFC 8441 section 5). The frames travel as DATA on the stream, within the
client's flow-control windows (a client that takes none for the send-stall deadline has its stream reset), and the
session's frames are checked against the negotiated extensions as over HTTP/1.1. The session's end is the stream's
END_STREAM, after which the server waits up to 5 s for the client's (an orderly close has no RST_STREAM); a call
cancelled or failed meanwhile resets the stream with CANCEL (RFC 8441 section 5), and a client's RST_STREAM ends the
session. The request must carry one `sec-websocket-version: 13` (RFC 6455 section 4.2.1): otherwise the answer is 400
with `sec-websocket-version: 13` (not 426, which needs an Upgrade field that HTTP/2 does not have). A route that is not a WebSocket one answering
the CONNECT with a 2xx gets 501 instead (no session was accepted), an Extended CONNECT for another protocol 501, and
a HEADERS frame on the stream after its request (RFC 9113 section 8.5) a stream error PROTOCOL_ERROR. A WebSocket stream
counts toward `http2 { settings { maxConcurrentStreams } }` while it is open, and keeps its connection from being idle.
With `webSockets { overHttp2 = false }` the parameter is not sent and a `:protocol` request is malformed: clients keep opening their
WebSockets over HTTP/1.1 on the same port.

### WebTransport over HTTP/3 (experimental)

With `http3 { webTransport { enabled = true } }` the HTTP/3 listener speaks WebTransport (draft-ietf-webtrans-http3-17, plus the SETTINGS of
draft-16, which other libraries send, and of draft-02 and draft-14, which browsers send; see the [HTTP/3 guide](http3.md#webtransport-experimental)), and a
`webTransport("/path") { session -> }` route serves the sessions. It matches only a WebTransport Extended CONNECT over
HTTP/3, never an HTTP/1.1 request (a request of another method to the path gets Ktor's 405); a WebTransport request
no route matches gets Ktor's 404, and one that another route answers with a 2xx gets 501 instead, since no session
was accepted. The route checks the
`origin` field first: `checkOrigin` refuses with 403, and its default, `sameHostOrigin`, admits the server's own
origin and clients that send none (browsers always send one; pass your own check for a page served elsewhere). The
server picks the first of the route's `protocols` the client offers. Then the session is accepted and the handler
runs; when it returns the session is closed with code 0, when it throws with `WEB_TRANSPORT_HANDLER_FAILED` (1) and
an empty reason. With WebTransport flow control (on by default, see the [HTTP/3 guide](http3.md#webtransport-experimental))
a connection carries up to `http3 { webTransport { maxSessionsPerConnection } }` (4) sessions; one more, or one beyond the rate a
connection takes new sessions at (a burst of 32, then 8 a second), is refused before any route runs. A draft-14 client that leaves a session without flow-control credit for ten seconds is logged once, as a warning,
through the application's log.

```kotlin
// guide:ktor:webtransport-server
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector {
        tls { this.identity = identity }
        port = 443
    }
    http3 { webTransport { enabled = true } }
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

A whole application on this route and on the client's `webTransport` is
[samples/webtransport-chat](../../samples/webtransport-chat/README.md): a chat room with a bidirectional stream per
member for the messages and datagrams for the typing indicators, its refusals as session close codes, and a test that
runs the server and its clients in one JVM.

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

### CONNECT-UDP over HTTP/3 (experimental)

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
// guide:ktor:connect-udp-server
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
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

### Misdirected requests

A TLS connector answers `421 Misdirected Request` to a request whose host the certificate of its connection does not
name (whatever scheme the request names: the application would see it as https), over HTTP/1.1, HTTP/2 and HTTP/3. The
engine answers it itself: neither routing nor plugins such as StatusPages or CallLogging see that request (RFC 9110
section 7.4: such a request "MUST be rejected"). Browsers send these: they reuse an HTTP/2 or HTTP/3 connection for another host at
the same address, and a 421 makes them retry on a connection of its own. On HTTP/2 and HTTP/3 only that request's stream
ends; the connection serves the others.

The host is checked as a client checks it: against the subjectAltName of the certificate that connection presented (the
`sniSelector`'s choice, or the identity current at its handshake when a `TlsIdentity.Reloadable` rotates), a wildcard
`*.example.com` for one whole left-most label, an IP literal against the certificate's IP addresses, never the subject CN.
The port is not checked: a certificate names none. On a connector with an `sniSelector`, which may give each name its own
certificate, client-certificate requirement and trust, a request must also be for the name the connection was set up for
(its SNI name, or an IP address when the client sent no SNI), so a request cannot reach a name that requires a client
certificate over a connection that asked for none. So a certificate must name every host the server is reached under,
`localhost` and the addresses included where clients use them.

Behind a gateway that terminates TLS and forwards requests for names the certificate here does not carry (it re-encrypts
with an internal certificate), turn the check off for that connector only. RFC 9110 allows it for connections "from a
trusted gateway", so the connector must accept no other clients:

```kotlin
// guide:ktor:trusted-gateway
tlsConnector {
    tls { identity = internalIdentity }
    port = 8443
    allowMisdirectedHosts = true // every client of this port is the gateway
}
```

A plain connector has no certificate at all, so a request whose target is an absolute `https://` URI
(`GET https://example.com/ HTTP/1.1`) gets 421 there too. Origin-form requests (`GET / HTTP/1.1` with any `Host`), which
a gateway in front of the server sends, are served as before. A gateway that forwards absolute `https` targets to a plain
port needs `plainConnector { allowMisdirectedHosts = true }` (delicate) instead of Ktor's `connector { }`.

### PROXY protocol

Behind an L4 load balancer or a TCP proxy (HAProxy, AWS NLB, Envoy, nginx `stream`) the server's TCP peer is the proxy.
A proxy that speaks the PROXY protocol (HAProxy's, versions 1 and 2) sends the client's address first on each
connection, and a connector with `proxyProtocol { }` reports that client as `call.request.origin`:

```kotlin
// guide:ktor:proxy-protocol
plainConnector {
    port = 8080
    proxyProtocol {
        trust("10.0.0.0/8", "2001:db8:1::/48") // the load balancers' addresses
    }
}
```

```kotlin
// guide:ktor:proxy-protocol-origin
get("/") {
    val client = call.request.origin.remoteAddress // the client the header names
    val proxy = call.request.local.remoteAddress // the TCP peer: the load balancer
    val sni = call.request.proxyHeader?.authority // a TLV, when the proxy sends one
    call.respondText("$client via $proxy for $sni")
}
```

`tlsConnector { proxyProtocol { … } }` takes the header before the TLS handshake (HAProxy `send-proxy-v2`
on a TCP-mode backend). The rules ([ADR-0022](../adr/0022-proxy-protocol.md), the details in
[spec-haproxy-proxy-protocol.md](../spec/rfc/spec-haproxy-proxy-protocol.md)):

- Only the sources given to `trust(…)` may send the header, and every connection to the connector must come from one of them: any
  other peer is closed at accept, before a byte is read (an event `connectionRefused` with the reason
  `PROXY protocol untrusted source`, and a warning at most every 10 s). A client that reaches the port around the proxy
  can therefore not choose its own address. List the proxies' own addresses, as the server sees them; an IPv4 proxy
  matches an IPv4 entry also on a dual-stack listener. Where a firewall alone decides who reaches the port, list
  `0.0.0.0/0` and `::/0`: every peer must then send a header.
- Every connection must start with a valid version 1 or 2 header, complete within `headerTimeout` (5 s, at least 3 s, the
  spec's bound for a TCP retransmit; `requestHeaderTimeout` must then be at least 3 s too, or the start fails); otherwise it is reset (reason `PROXY protocol header`). Health checks of the proxy
  must send one too (HAProxy sends LOCAL with `send-proxy-v2`); a LOCAL header, whatever family and length it carries, or
  an `UNKNOWN` one leaves the origin as the connection's.
- `call.request.local` stays the TCP connection, for logs that need the real hop. `XForwardedHeaders` and
  `ForwardedHeaders` overwrite the origin whenever their fields are present, and behind an L4 proxy those fields come
  from the client: install them only when an HTTP proxy in front of the server sets or strips them. `call.request.proxyHeader` gives the whole header:
  version, command, family, both addresses and ports, and the version 2 TLVs (`alpn`, `authority`, `uniqueId`, `ssl`,
  `netns`, any other by type); a CRC32c TLV is verified before the connection is served.
- `http2 { repeatOffenderPenalty }` counts the client the header names and never the proxy (a flood behind a header that
  names no client strikes nobody); `tcp { maxConnectionsPerIp }` counts TCP peers, so on such a connector it limits each proxy's
  connections: leave it off there, or size it for a proxy.
- HTTP/3 on a TLS connector's port takes no header (UDP): its requests report their UDP peer. Set `http3 { altSvc = false }`
  unless the proxy forwards UDP on the same port number.
- `EngineMain`: `kuicksilver.connector.proxyProtocol.trustedSources` (a list or a comma-separated string),
  `kuicksilver.connector.proxyProtocol.headerTimeout` and `kuicksilver.connector.proxyProtocol.maxHeaderSize` turn it on
  for the deployment port; next to Ktor's `-sslPort` connector the start fails.

### Certificate per name (SNI)

One connector can serve several names, each with its own certificate (RFC 6066 section 3): its `sniSelector` sees the
ClientHello's server name and answers with the identity, and optionally the client-certificate policy, trust and OCSP
response, for it:

```kotlin
// guide:ktor:sni-server
tlsConnector {
    port = 443
    tls {
        identity = defaultIdentity
        sniSelector = { hello ->
            when (hello.serverName) {
                "api.example.com" -> ServerTlsOverride(apiIdentity)
                "admin.example.com" -> ServerTlsOverride(adminIdentity, clientAuth = ClientAuth.Required, trust = adminCa)
                else -> null // a name not served here: the handshake ends with unrecognized_name
            }
        }
    }
}
```

The selector answers for TCP (HTTP/1.1, HTTP/2) and HTTP/3 alike, so a name gets the same certificate and policy on every
protocol, and the `Alt-Svc` its TCP responses carry leads to a QUIC endpoint that presents it. It is a suspending
function: it may look the identity up (a cache, a store); on QUIC it runs off the connection's loop while that handshake
waits, and a handshake that times out meanwhile cancels it. On QUIC it runs for each new connection's ClientHello, before
the client's address is validated (as RFC 9001 section 4.3 notes, a server that parses the ClientHello to decide can
require a Retry first): keep it cheap, or let `http3 { endpoint { admission } }` ask unvalidated clients for a Retry. A ClientHello without a server name (a client that connected
to an address) reaches it with `serverName == null`, and `null` from it then means the connector's own identity
(`defaultIdentity`). An answer's `alpn` restricts its name: without one the name gets every protocol of the connector;
with one TCP negotiates from that list without `h3` (which identifies HTTP/3 over QUIC only, RFC 9114 section 3.1; a list
of `h3` alone serves the name over HTTP/3 only, and its TCP handshake ends with `no_application_protocol`), and the name is
served over HTTP/3, and advertised with `Alt-Svc` on its TCP responses, only when the list names `h3`
(`listOf("h3", "h2", "http/1.1")`); a TCP client without ALPN speaks HTTP/1.1 (RFC 9113 section 3.3: "HTTP/2 connections
over TLS MUST use protocol negotiation in TLS"), so a list without `http/1.1` refuses it with `no_application_protocol`
(the connector's `alpnFallback`, [TLS guide](tls.md#configuration)); otherwise its QUIC handshake ends with
`no_application_protocol` (CRYPTO_ERROR 0x178, RFC 7301 section 3.2) and its TCP responses carry no `Alt-Svc` (RFC 7838
section 2.1: an alternative must serve the origin). Return the same `TrustConfig` and `OcspStapling` objects for a name,
so that its handshakes share one TLS context. A selector
that throws ends that handshake (on QUIC with `internal_error`; the exception's text is not sent to the client).

Session tickets resume only under the name and the certificate they were issued under: a client that comes back with a
ticket of another name, or after the selector started answering with another certificate, runs one full handshake (no
0-RTT) and gets a new ticket. A name whose answer asks for client certificates gets no 0-RTT and no tickets on HTTP/3
(`http3 { earlyData { enabled } }` applies to the other names). Requests on a connection must be for the name its identity was chosen for:
see [Misdirected requests](#misdirected-requests).

### Certificate rotation

A renewed certificate can be put in place without a restart (experimental). Give the connector a
`TlsIdentity.Reloadable` and call `reload` when the new files are there (from a deploy hook, an admin route, a timer):

```kotlin
// guide:ktor:certificate-rotation
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val identity = TlsIdentity.reloadable(TlsIdentity.fromPem(chainPem, keyChars)) // the key array is zeroed after import
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector {
        tls { this.identity = identity }
        port = 443
    }
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
for ownership, resumption and key compromise). The same works for the engine's `tls { identity }` (Ktor's own
connectors served over TLS); on the JVM, an `sslConnector` keystore is read once, so build the identity with
`TlsIdentity.fromKeyStore` and wrap it yourself instead.

PEM files need no code of yours: `tls { pemFiles(chain, key); reloadInterval = 1.hours }` (the [first
screen](#minimal-example)) has the engine watch them, with the rules of `EngineMain` below. For a source of your own the
application decides when to reload; a check of the files once an hour, from the application's own coroutine scope (it
ends when the server stops):

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
    tlsConnector {
        tls { this.identity = identity }
        port = 443
    }
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

With `tls { pemFiles(…) }` and `reloadInterval` in code, or `kuicksilver.tls.reloadInterval` (`1h`, `30m`, ...; `off`
by default) with `EngineMain`, the engine checks the PEM files (`kuicksilver.tls.certificateChain` and
`kuicksilver.tls.privateKey`) that often. It reloads when the chain file holds other certificates than those served: a chain read
twice a second apart with the same content, and a key that matches it. Tools that write the chain before the key
(certbot) or swap a symlinked directory (Kubernetes secrets) are covered: a pair that does not match yet keeps the old
identity and is tried again after 1 s, then 2 s, 4 s and so on up to the interval. Failures are logged as warnings
(once per distinct failure, never with key material); a successful reload is logged at info level, and the files are
read once more a second later, so a chain whose writer paused longer than that is corrected then. Each file is read
whole on every check and refused above 1 MiB; a chain file that also holds a private key is refused, at startup too (keep
the key in its own file). The stop waits at most a second for a check in progress (a read on a hung network file system
cannot be interrupted). Polling once an hour means a renewed certificate may wait an hour to be served; certbot's `--deploy-hook`
(or a restart) is the alternative when it must take effect at once. With `reloadInterval` set, the files at startup get the same checks as a reload, so an expired or not yet valid
certificate fails the start; without it, the engine serves the files as they are, as before. The identity the engine
read from files is closed when the server stops.

**The client CA.** A connector that asks for client certificates ([Mutual TLS](#mutual-tls-client-certificates)) can
rotate the CA bundle it verifies them with in the same way: give it `tls { clientTrust = TrustConfig.reloadable(TrustConfig.AnchoredCa(roots)) }`
(alone or as the `base` of `Pinned`) and call `reload(TrustConfig.AnchoredCa(newRoots))`. Handshakes whose ClientHello
arrives after `reload` returns, HTTP/1.1 and HTTP/2 over TCP and HTTP/3 over QUIC, verify client certificates against the
new bundle. After `reload` returns, no handshake accepts a certificate that only a removed CA vouches for: one in progress
is checked again against the new bundle when it completes, a TCP connection accepted before the reload is no way around
it, and a session ticket from before the reload is not resumed. Open connections are not affected. `reload` refuses a bundle in which no certificate is
valid now ([Rotating the client CA](tls.md#rotating-the-client-ca)).

```kotlin
// guide:ktor:client-ca-rotation
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val clientCa = TrustConfig.reloadable(TrustConfig.AnchoredCa(Certificate.parsePem(caBundlePem)))
val server = embeddedServer(Kuicksilver, configure = {
    tls {
        this.identity = identity
        clientAuth = ClientAuth.Required
        clientTrust = clientCa
    }
    tlsConnector { port = 443 }
}, module = Application::module)
// later: new TCP and QUIC handshakes verify client certificates against the new bundle
clientCa.reload(TrustConfig.AnchoredCa(Certificate.parsePem(renewedBundlePem)))
```

In code, `tls { clientCaFile(path) }` reads a PEM file of CA certificates as `clientTrust`; with `EngineMain`,
`kuicksilver.tls.clientAuth` (`optional` or `required`) and `kuicksilver.tls.clientCa` ask for client certificates on
the deployment port. With `reloadInterval` (`kuicksilver.tls.reloadInterval`) set, the CA file is watched at that interval with the rules above: a changed bundle is used once two reads a second apart agree. A
file holding a private key, a damaged file and a bundle with no certificate valid now keep the bundle in use, and so do
they at startup (where they fail the start). A reload is logged at info level, a failure as a warning, and so is a bundle
holding certificates that are not CA certificates (each is an anchor: a client presenting exactly it is accepted). The
keys apply to the port of `kuicksilver.tls.certificateChain`; on the JVM, a `-sslPort` connector (`ktor.security.ssl.*`)
takes client certificates from its `trustStore` instead, and the start is refused when both are configured.

### EngineMain and configuration keys

`io.kuicksilver.ktor.server.EngineMain` reads the usual `ktor.deployment.*` keys (and on the JVM `-sslPort` with
`ktor.security.ssl.*`). Its own keys work on every platform, and in `application.yaml` as in `application.conf`. A key is
the path of its option in the engine's DSL under `kuicksilver.` (`kuicksilver.http3.endpoint.maxConnections` is
`http3 { endpoint { maxConnections } }`), except the TLS files under `kuicksilver.tls` (the DSL reads them with
`pemFiles`, `clientCaFile` and `ocspStaplingFile`), the `kuicksilver.connector` block for the deployment port (a Ktor
connector, which has no DSL block) and Ktor's own `ktor.deployment.connectionIdleTimeoutSeconds`.

- **Strict.** Every key under `kuicksilver.` must be one of the table's: any other fails the start with an
  `IllegalArgumentException` that names it and the key to use, `kuicksilver.http3.quic.maxConnections is not a Kuicksilver
  key; did you mean kuicksilver.http3.endpoint.maxConnections?`. A key of 0.2.x or of an earlier 0.3.0 snapshot is never
  read: `kuicksilver.altSvc was replaced in 0.3.0 by kuicksilver.http3.altSvc`, and the 0.2.x switch
  `kuicksilver.http3 = true` gives `kuicksilver.http3 = true|false was replaced in 0.3.0 by kuicksilver.http3.enabled`
  (the old and new keys: [configuration reference](configuration.md#migrating-from-02x)). HOCON keeps the last of two
  definitions of one path, so a file with both `kuicksilver.http3 = true` and a `kuicksilver.http3 { }` block is read
  as whichever comes last: write the block only.
- **Values.** A switch is `true` or `false`, nothing else; a duration is what `kotlin.time.Duration.parse` reads (`30s`,
  `1h`, `PT30S`); an enumeration's name in any case (`required`, `tls12And13`, `withHttp11`). "None" or "no limit" is
  `off` for the keys that have one, where `0` is refused with "use off instead of 0". A value the option refuses fails
  the start with the key in front of the option's message.

| Key | Meaning |
|---|---|
| `kuicksilver.requestHeaderTimeout` | `requestHeaderTimeout`: the time for a complete request head on every protocol (`30s`); see [Server](#server) |
| `kuicksilver.tls.certificateChain`, `kuicksilver.tls.privateKey` | PEM files (`tls { pemFiles(…) }`); the deployment port then serves TLS, HTTP/2 and HTTP/3 |
| `kuicksilver.tls.reloadInterval` | `tls { reloadInterval }`: how often those PEM files, and the `kuicksilver.tls.clientCa` and `kuicksilver.tls.ocspStapling` files, are checked for a renewed certificate, CA bundle or response (`30m`, `1h`; `off` or unset: never; at least `1s`); see [Certificate rotation](#certificate-rotation) |
| `kuicksilver.tls.clientAuth` | `tls { clientAuth }`: ask for a client certificate on the deployment port: `none` (unset), `optional` or `required`; anything but `none` needs `kuicksilver.tls.clientCa` |
| `kuicksilver.tls.clientCa` | `tls { clientCaFile(…) }`: PEM file of the CA certificates client certificates are verified against; needs the identity files and `kuicksilver.tls.clientAuth` `optional` or `required` |
| `kuicksilver.tls.versions` | `tls { versions }`: the TLS versions of the deployment port: `tls13` (unset) or `tls12And13`; needs the identity files, and is refused next to `-sslPort`, whose key is `ktor.security.ssl.enabledProtocols`; see [TLS 1.2 on the server](#tls-12-on-the-server) |
| `kuicksilver.tls.keyExchangeGroups` | `tls { keyExchangeGroups }`: the key-exchange groups of the deployment port, the server's most preferred first: a list of `KeyExchangeGroups` names (`["X25519MLKEM768", "x25519", "secp256r1"]`, case ignored), or one string of them separated by `:` or `,` (`-P:` keys, `${?ENV}`); unset: the default list; needs the identity files, and is refused next to `-sslPort`; an unknown name or a duplicate fails the start; see [TLS: Key exchange groups](tls.md#key-exchange-groups) |
| `kuicksilver.tls.ocspStapling` | `tls { ocspStaplingFile(…) }`: a file with a DER OCSP response (RFC 6960) for the identity's certificate, stapled on TCP and QUIC when it is fresh and for the certificate sent; read again every `kuicksilver.tls.reloadInterval` (put a fresh response in place before nextUpdate; without the interval, a restart reads it); a response that is not stapled is logged as a warning at startup, and so is one that stops being stapled (expired, or for a certificate that was reloaded); needs the identity files, and is refused next to `-sslPort`; see [Certificate revocation](tls.md#certificate-revocation) |
| `kuicksilver.tls.echKeys` | `tls { echKeys }`: Encrypted Client Hello keys of the deployment port: a list of PEM files, each what `openssl ech -public_name <name>` writes (the private key and its ECHConfigList; every one is sent in retry configurations), or one comma-separated string; read once at startup (rotate in code with `EchServerKeys.rotate`); needs the identity files, and is refused next to `-sslPort`; see [Encrypted Client Hello on the server](#encrypted-client-hello-on-the-server) |
| `kuicksilver.connector.allowMisdirectedHosts` | `true`: every client of the deployment port is a trusted gateway (RFC 9110 section 7.4), so no request is answered `421 Misdirected Request`: with the identity files, for a host the certificate does not name; without them, for an absolute-form `https` target on the cleartext port behind a TLS-terminating proxy (`false`); with the identity files it is refused next to `-sslPort`, and without them it is accepted there but exempts only the cleartext port, never Ktor's `-sslPort` connector; see [Misdirected requests](#misdirected-requests) |
| `kuicksilver.connector.h2c` | HTTP/2 over cleartext TCP with prior knowledge on the plain deployment port: `off` (unset), `withHttp11` (both on one port, told apart by the preface) or `only`; refused with the identity files; see [h2c on the server](#h2c-on-the-server) |
| `kuicksilver.connector.proxyProtocol.trustedSources`, `.headerTimeout`, `.maxHeaderSize` | the PROXY protocol on the deployment port: the proxies allowed to send the header (a list, or one comma-separated string; unset: off), how long it may take (`5s`) and its largest size in bytes (`4096`); the other two need `trustedSources`; refused next to `-sslPort`; see [PROXY protocol](#proxy-protocol) |
| `kuicksilver.http1.allowBareLf` | `http1 { allowBareLf }`: let a bare LF end a line of an HTTP/1.1 request head or trailer section (`false`: 400); see [Server](#server) |
| `kuicksilver.http2.enabled` | `http2 { enabled }`: serve HTTP/2 on TLS connectors (`true`); see [HTTP/2 on the server](#http2-on-the-server) |
| `kuicksilver.http2.repeatOffenderPenalty` | `http2 { repeatOffenderPenalty }`: refuse an address that keeps flooding HTTP/2 for this long (`off`; e.g. `30s`); see [HTTP/2 on the server](#http2-on-the-server) |
| `kuicksilver.http3.enabled` | `http3 { enabled }`: serve HTTP/3 (`true`) |
| `kuicksilver.http3.altSvc` | `http3 { altSvc }`: announce HTTP/3: `Alt-Svc` on HTTP/1.1 and HTTP/2 responses, plus ALTSVC frames on HTTP/2 (`true`) |
| `kuicksilver.http3.earlyData.enabled` | `http3 { earlyData { enabled } }`: accept 0-RTT (`false`); the policy (`replayable`, a predicate) is code only; see [0-RTT](#0-rtt-opt-in-experimental) |
| `kuicksilver.http3.endpoint.loops` | `http3 { endpoint { loops } }`: endpoint loops on the UDP port (`1`) |
| `kuicksilver.http3.endpoint.maxConnections` | `http3 { endpoint { maxConnections } }`: QUIC connections each HTTP/3 listener holds (`10000`); see [Connection limits](#connection-limits) |
| `kuicksilver.http3.endpoint.maxConnectionsPerIp` | `http3 { endpoint { maxConnectionsPerIp } }`: QUIC connections of one client IP (`256`; `off` behind a NAT or kube-proxy) |
| `kuicksilver.http3.endpoint.acceptQueue` | `http3 { endpoint { acceptQueue } }`: handshaken connections waiting for the accept loop (`128`) |
| `kuicksilver.http3.endpoint.expert.connectionIdLength` | `http3 { endpoint { expert { connectionIdLength } } }`: the length of the listeners' connection IDs, 4..20 (`8`) |
| `kuicksilver.http3.quic.maxIdleTimeout`, `.handshakeTimeout`, `.keepAlive`, `.maxBidiStreams` | `http3 { quic { … } }`: the idle timeout (`30s`; `off` advertises none), the handshake deadline (`10s`), the PING interval of a quiet connection (`off`) and the request streams a client may have open (`100`) |
| `kuicksilver.http3.quic.pathMtu.maxReceive`, `.initial`, `.maxSend`, `.discovery` | `http3 { quic { pathMtu { … } } }`: the advertised `max_udp_payload_size` (1200..1500, the endpoint's datagram slots), the datagram size a connection starts with, the largest datagram sent and DPLPMTUD; see [Tunnels and NAT paths](quic.md#tunnels-and-nat-paths-wireguard) |
| `kuicksilver.http3.quic.migration.allow` | `http3 { quic { migration { allow } } }`: follow a client to a new address (`true`) |
| `kuicksilver.http3.quic.expert.maxUniStreams` | `http3 { quic { expert { maxUniStreams } } }`: unidirectional streams a client may open, at least 3 (`100`, raised to fit WebTransport) |
| `kuicksilver.webSockets.overHttp2`, `.overHttp3` | `webSockets { overHttp2, overHttp3 }`: accept RFC 8441 and RFC 9220 WebSockets (`true`); see [WebSockets over HTTP/2](#websockets-over-http2) |
| `kuicksilver.webSockets.maxMessageSize` | `webSockets { maxMessageSize }`: the largest WebSocket message a client may send, in bytes (`16777216`) |
| `kuicksilver.tcp.maxConnections` | `tcp { maxConnections }`: TCP connections a connector holds at once (`10000`); see [Connection limits](#connection-limits) |
| `kuicksilver.tcp.maxConnectionsPerIp` | `tcp { maxConnectionsPerIp }`: TCP connections of one client address on a connector (`off`; e.g. `256` for a server that faces clients directly); see [Connection limits](#connection-limits) |
| `ktor.deployment.connectionIdleTimeoutSeconds` | Ktor's key, read into `http1 { idleTimeout }` (`45`) |

The QUIC transport keys set `http3 { quic { } }` as the DSL does. Every key with its type and release is in the
[configuration reference](configuration.md#hocon-keys).

An `application.conf` (HOCON) for a TLS and HTTP/3 server on port 443 whose certificate certbot renews; every key not
set keeps the default of the table above. The `kuicksilver-ktor-server` tests load this block as it stands (with their
own paths, port and module), so its keys stay current:

```hocon
ktor {
    deployment {
        port = 443                     # TCP for HTTP/2 and HTTP/1.1 over TLS and UDP for HTTP/3, the same number
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
    http3.endpoint.maxConnectionsPerIp = 4096   # behind a NAT or kube-proxy; see deployment.md
}
```

[samples/http3-server](../../samples/http3-server/README.md) is such a server, with `kuicksilver.http2.enabled`,
`kuicksilver.http3.altSvc` and `kuicksilver.connector.proxyProtocol.trustedSources` taken from environment variables (`${?NAME}`), and a
test that starts it with its `application.conf`.

The application's main class is `io.kuicksilver.ktor.server.EngineMain` (in Gradle: `application { mainClass.set("io.kuicksilver.ktor.server.EngineMain") }`),
and `-config=<file>` picks another file, as with Ktor's own engines. The private key must be an unencrypted PKCS#8 file
(`-----BEGIN PRIVATE KEY-----`, which certbot writes); convert an older `BEGIN RSA PRIVATE KEY` or `BEGIN EC PRIVATE KEY`
file with `openssl pkcs8 -topk8 -nocrypt -in old.pem -out privkey.pem`. `TlsIdentity.fromPem` has a `password`
parameter, but encrypted keys are refused with `TlsException.Config` whatever it holds: decrypt the key before.

## Client

The client's first screen for the most common case, configuring nothing, is in the [Minimal example](#minimal-example).
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
([Why did this request not use HTTP/3?](#why-did-this-request-not-use-http3)), hence the `LogLevel.Info` logger while you
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
  inside the tunnel), see [Proxies](#proxies).
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
  permessage-deflate on every target is `PerMessageDeflate` ([WebSocket compression](#websocket-compression-experimental));
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

### HTTP/2 on the client

```kotlin
// guide:ktor:http2-client
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
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
  cancelled after its Close does (see [HTTP/3 on the client](#http3-on-the-client)). As over HTTP/1.1, one WebSocket per remote host
  is in its handshake at a time (RFC 6455 section 4.1).

### h2c on the client

```kotlin
// guide:ktor:h2c-client
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
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

### Connection pool

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

### Connection coalescing (experimental)

```kotlin
// guide:ktor:coalescing
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
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

### HTTP/3 on the client

`http3 { discovery = ... }` (`Http3Discovery`) decides when HTTP/3 is used for `https://` (never through a proxy), and
`http3 { enabled = false }` turns it off: every request goes over TCP, HTTP/2 or HTTP/1.1 (0.2's `H1Only`; together with
`H3Only` the engine's creation fails):

| Mode | Behaviour |
|---|---|
| `Auto` (default) | TCP first (HTTP/2 or HTTP/1.1); HTTP/3 once the origin announced it with `Alt-Svc` ([Discovery and Alt-Svc](#discovery-and-alt-svc)) |
| `Preferred` | HTTP/3 by prior knowledge, falling back to TCP (like `curl --http3`); `http3 { hints }` gives the same treatment to listed origins in `Auto` mode |
| `H3Only` | HTTP/3 only (like `curl --http3-only`): failures are reported, never retried over TCP; an `http://` or `ws://` request (HTTP/3 needs `https`, RFC 9114 section 3.1), and with a proxy configured every request, fails with `UnsupportedOperationException` |

HTTP/3 responses report `HttpProtocolVersion.HTTP_3_0`. One QUIC connection per origin carries all its requests; a
request the server did not process (GOAWAY above its stream, `H3_REQUEST_REJECTED`) is repeated on a new connection
without the application noticing. When HTTP/3 fails before the response headers, the request is repeated over TCP
— always if it cannot have reached the server, otherwise only for idempotent methods whose body can be sent again
(bytes, a `WriteChannelContent` writer, or no body). A streamed `ReadChannelContent` body that HTTP/3 already consumed
is never replayed, neither on the fallback nor after a 421 or a `RequestNotProcessed`: the call fails with
`H3BodyConsumed` and the application decides. The fallback uses the same `tls { }`: trust, pins and TLS 1.3 settings. When a call ends before its body was read, the rest of the stream is abandoned
with `STOP_SENDING`. A response body the connection cut short (a reset, a lost connection) never looks complete:
`bodyAsText`, `bodyAsBytes`, `readRemaining` and the other whole-body reads throw the cause, and the engine's own channel
(`rawContent`, the server's request body) throws it from `readAvailable` instead of answering -1. `bodyAsChannel()`
hands out Ktor's copy of the body, which keeps ktor-io's contract: its `readAvailable` answers -1 with the cause in
`closedCause`, so a loop over that channel checks `closedCause` after -1 (or reads the rest with `readRemaining`).

WebSockets use HTTP/1.1 `Upgrade` unless an HTTP/3 connection to the origin already allows Extended CONNECT and has
not received GOAWAY (or the mode is `H3Only`), or an HTTP/2 one does ([HTTP/2 on the client](#http2-on-the-client)); over HTTP/3 the handshake is RFC
9220, over HTTP/2 RFC 8441, and the plugin sees the usual 101. Over HTTP/1.1 at most one
WebSocket is connecting to an address and port at a time (RFC 6455 section 4.1): another one to the same address, under
any name, opens its connection once the first handshake was answered or failed; through a proxy that resolves names,
the name counts as the host. The connect timeout applies twice to such a WebSocket, in two phases: resolving the name,
waiting for a pool slot and connecting (TCP and TLS) share one, as for any request; the answer to the handshake must then
arrive within the same timeout again, counted from the moment the connection is in hand. The wait for another WebSocket
to the address is in neither: only the call (its request timeout or cancellation) bounds it.

A session's own Close goes out even when its call ends with a failure or a cancellation once that Close was queued,
over every protocol: Ktor's `webSocketSession()` ends its call that way each time the session closes (it takes the
session's cancelled outgoing channel for a failure), and the Close, and the frames queued before it, would otherwise be
lost with the call (RFC 6455 section 7.1.2: the endpoint "MUST send a Close control frame"). The session runs on until
it ends, within 5 s counted from its own Close for writing it and for the server's Close; past that the HTTP/1.1
connection is closed at once, the HTTP/2 stream reset with CANCEL and the HTTP/3 stream reset with H3_REQUEST_CANCELLED.

The transport is then closed the server's side first (RFC 6455 section 7.1.1: the client "SHOULD wait for a TCP Close
from the server"): the engine reads and drops what the server still sends, waits for its FIN (close_notify, then the FIN,
over TLS), its END_STREAM (HTTP/2) or its FIN (HTTP/3), and closes its own side after it, cleanly: close_notify and a FIN,
END_STREAM, a FIN. A server that has not closed its side 5 s after both Closes (the close wait, counted again from
there) gets the client's clean close then; over HTTP/2 and HTTP/3 the stream is reset (RST_STREAM CANCEL,
STOP_SENDING H3_REQUEST_CANCELLED) only if the server's end has not come another 5 s later. Ktor's own WebSocket writer
closes its channel right after its Close, which used to half-close the connection (or end the stream) at once; the
engine no longer lets that through. The server engine closes first: its FIN right after its close_notify over TLS (the
client's close_notify is not waited for), END_STREAM or FIN right after the session.

How long `client.close()` can wait for a WebSocket whose server stays silent: it waits for the session's end, and that is
bounded by three close waits (15 s) after the session's own Close at most: 5 s for the server's Close (then the session
is cancelled and the connection or stream ended at once: an HTTP/1.1 connection is closed cleanly when everything the
session wrote was whole and taken by the socket, and reset when something was still queued, cut inside a frame or failed,
so nothing leaves after the wait (on macOS a server that stopped reading, its receive window at 0, ignores that reset
until it sends something itself); an HTTP/2 or HTTP/3 stream is reset), 5 s for the server's close of the transport (then the client
closes its side cleanly), and over HTTP/2 and HTTP/3 5 s more for the server's END_STREAM or FIN after the client's own
(then the stream is reset). The session's end handlers are cut off two close waits after the session ended, whatever
they still wait for. The pools close after that, as for any request (at most about 3 s more). The connection, its pool slot and the engine's
`close()` wait for the session, not for the call: `client.close()` right after `close(reason)` still sends the Close
before the pools close. A call that fails or is cancelled before the session queued its Close still closes it with the
closing handshake (RFC 6455 sections 7.1.7 and 7.3): one Close, 1001 Going Away (or the application's own code when it sends
one, as from a `finally`), bounded by the same close wait; only a call that ends during the handshake ends it at once. A coroutine of
the session that fails is reported to the event listener (`webSocketFailed`).

### Discovery and Alt-Svc

In `Auto` mode the engine learns alternatives from `Alt-Svc` headers (RFC 7838) of HTTPS responses, and from ALTSVC
frames on HTTP/2 connections (section 4: "semantically equivalent to receiving an Alt-Svc header field"; one on stream
0 counts only when its Origin is the connection's own origin), and sends the next requests to the origin over HTTP/3,
with an `Alt-Used` header; SNI and certificate verification still use the origin's host. The rules:

- only responses over verified TLS count (an `http://` response can never redirect a client to an alternative), and
  nothing is learned through a proxy;
- a new `Alt-Svc` replaces every entry of the origin, and `clear` removes them, alone or anywhere in the list (section
  3: "including those specified in the same response"); this applies to every response, over HTTP/1.1, HTTP/2 and
  HTTP/3, including the ones served while a cached alternative is broken or lost the race. A 421 from the origin
  changes nothing (it is not authoritative for the origin, RFC 9110 section 15.5.20, so its `Alt-Svc` is ignored too);
  a 421 over HTTP/3 from an alternative removes that alternative and keeps the others (RFC 7838 section 6);
- `ma` defaults to 86400 seconds and counts from the response's generation (section 3.1): the response's `Age` and the
  time from sending the request to the response are subtracted, so a copy a CDN kept for a day does not get a fresh
  day; expired entries are ignored;
- the alternatives are tried in the server's order of preference: the first fresh one that is not marked broken (section
  2.4), so a broken first alternative does not hide a working second one;
- an alternative port is digits only (`h3=":+443"` is malformed);
- an alternative on an unprivileged port (1024 and up) is refused for an origin on a privileged one, as Chromium does;
- an alternative on a loopback, link-local or private address, or a `localhost` name, is refused unless the origin is
  on such an address too, and one on an unspecified, multicast or broadcast address always; an IPv4 address counts in
  every form the resolvers accept without DNS (`127.1`, `2130706433`), and a numeric host in octal or hex (`0177.0.0.1`,
  `0x7f.1`, which platforms read differently) or that is no address (`256.1.1.1`) is always refused. A DNS name is not
  resolved for this check;
- only `h3` alternatives are used.

The same checks apply to every entry a store hands back, so a store file written by an older version or edited by hand,
or an application's own `AltSvcStore`, cannot bring in what the header path refuses; `FileAltSvcStore` also checks every
field of every record again on load (origin form, protocol, host, ports, expiry, persist flag), drops what fails, and
reads at most the first 8 MiB of a file (a full store takes less).

Entries live in `http3 { altSvcStore = ... }` — `InMemoryAltSvcStore` by default (an app without one learns HTTP/3 again
after every start: the mobile [first screen](#client) keeps them in a `FileAltSvcStore`). `FileAltSvcStore(path)` keeps them
in one tab-separated text file (loaded once, rewritten atomically after every change, expired records dropped on load)
so the first request after a cold start can already use HTTP/3; implement `AltSvcStore` for any other backing store
(one engine per file: two engines sharing a file overwrite each other). A store is keyed by origin in one canonical form:
`scheme://host:port`, the host with its ASCII letters in lowercase and nothing else changed (`example.com.` is another
origin than `example.com`, RFC 6454 section 4; an internationalised name is keyed as the URL spells it, so use its
A-label), an IPv6 address in brackets in RFC 5952 text, the port always written (`https://example.com:443`,
`https://[2001:db8::1]:8443`), a `wss` URL keyed as its `https` origin. `AltSvcStore.originOf(url)` (experimental,
0.3.0) builds that key, for a store that looks an origin up or seeds one; `FileAltSvcStore` reads the origins of an
older file into it. There
is no change callback: wrap the store to see what it learns, as the engine calls `put`, `remove`, `clearNonPersistent` and
`clear` for every change. Both built-in stores keep at most 8 alternatives
per origin (the first ones of the header) and 1000 origins, dropping the least recently used; `FileAltSvcStore` skips
the rewrite when a repeated header only refreshes the expiry, and the engine writes it after releasing its lock. Entries
without `persist=1` are dropped when the network changes (RFC 7838 section 2.2): when `network { networkId }` reports a
new network, or, while `networkId` is not set (null, the default), when the networks `http3 { migration }` follows do
(the `followDefaultNetwork` factories). With `networkId`, a store also keeps the network its entries were learned on (`AltSvcStore.networkId`,
experimental; `FileAltSvcStore` writes it to its file), so the first request after a restart on another network drops
them too. A followed network is compared in memory: on Android the `Network` (a number the system gives each new
connection), on iOS and macOS the default path's interface, gateways and the interface's addresses, so a move between
two Wi-Fi networks on one interface is a change as well (a path that tells neither gateways nor addresses counts as a
change at each update; every update of the path, changed or not, flushes the HTTPS record cache). Neither survives a restart (the Android number is reused after a reboot; the Apple identity
holds local addresses and is never written), so it is never stored: at its first value after a start the engine takes
the network as changed, as it does for what it learned before that value came; requests wait for that value until
200 ms after the client was created, one deadline for all, then go on without it. Give `networkId` an identity of your
own for detection across restarts. `http3 { expert { clearAltSvcOnNetworkChange = false } }` keeps them. Without either source the engine sees no
network change.

RFC 7838 section 9.4: "In a user agent, any alternative service information MUST be removed when origin-specific data is
cleared (typically, when cookies [RFC6265] are cleared)". Call `client.clearAlternativeServices(url)` (experimental) where
the application clears an origin's cookies or other site data, or `client.clearAlternativeServices()` for all of them:
the cached alternatives (persistent ones too, and from the store file before it returns), broken marks and RTTs go;
open HTTP/3 connections stay (`closeHttp3Connections()` closes them). It returns whether everything asked for went. A
store of your own overrides `AltSvcStore.clear()`; for one that does not (written before 0.3.0) a full clear removes
the origins seen since the client started one by one, logs a warning that others it kept from earlier may remain, and
returns false, so the application can clear the store's own data.

`FileAltSvcStore(path)` takes a `kotlinx.io.files.Path`; on the JVM and Android `FileAltSvcStore(file)` (stable, 0.3.0)
takes a `java.io.File`. On Android keep the file in the app's private files directory. Do not write
`File(...).toPath()`: that is a `java.nio.file.Path`, which this API does not take, and `File.toPath()` and
`java.nio.file` only exist from API 26, while the library supports API 24. The `File` form uses no `java.nio.file`,
so it works on API 24 and 25 too (there a write replaces the file with `File.renameTo`, which is atomic on one file
system):

```kotlin
val filesDir = context.filesDir                  // android.content.Context
// guide:ktor:altsvc-store-android
HttpClient(Kuicksilver) {
    engine {
        http3 { altSvcStore = FileAltSvcStore(File(filesDir, "altsvc.tsv")) }
    }
}
```

### HTTPS records (experimental)

`network { httpsRecords = HttpsRecordSource.System }` (or `HttpsRecordSource.Exchange { query -> ... }` for your own
DNS-over-HTTPS client) makes the engine an HTTPS-record client (RFC 9460) in `Auto` mode: the origin's records say where
to connect, so the first request to an origin that publishes one with `alpn=h3` races HTTP/3 at once instead of waiting
for an `Alt-Svc` header, as browsers do. Off by default. The rules:

- for an `https://` request to a host name; never for `Preferred`, `H3Only`, `http3 { hints }`, IP addresses, requests
  through a proxy, or while `http3 { allowed }` says no;
- the name asked is the host for port 443, `_<port>._https.<host>` otherwise (section 9.1); AliasMode records are
  followed (one at random among several; at most 8 steps; a loop or a longer chain is treated as no record; an AliasMode
  "." is ignored); the ServiceMode records of the final name, by ascending priority and shuffled within a priority, are
  the endpoints (at most 32, the lowest priorities first), each at its target (the record's own name for ".") and
  `port` (the origin's when absent); after an
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
- the request waits for the records while the origin's addresses resolve and at most `network { httpsRecordWait }`
  (50 ms) longer; a lookup that answers later, fails or times out leaves the request on the origin as without records,
  and a late answer is cached for the next request (`httpsRecordWait` is 50 ms to 1 s: RFC 9460 section 5.1 asks for at
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
- answers are cached for their TTL (at most a day, expired once the monotonic or the wall clock has seen it pass, so
  neither a clock stepped back nor a device that slept keeps them longer; "no records" for the negative
  TTL of the answer's SOA record, RFC 2308 section 5, no longer than a CNAME that led there, and not at all without one; at most
  1000 names and about 1 MiB, and no answer of over 64 records), together with the other HTTPS records and the A/AAAA records the answer carried, which spare follow-up
  queries (RFC 9460 section 5; when only the A or only the AAAA records came, those are used at once and the other
  family is still looked up, joining the [Happy Eyeballs](#happy-eyeballs) race whenever it answers), and forgotten
  when the network changes (`network { networkId }`, or the networks `http3 { migration }` follows); without either the engine
  cannot see a network change and keeps no answers
  of its own (RFC 9460 section 12: a forged record must not follow the device to the next network), so every request
  asks the source (the system resolver keeps its own cache); a failed lookup is not cached, and one lookup per name runs at a time, for at
  most the connect timeout (30 s at most); closing the client cancels the lookups still running.

`HttpsRecordSource.System` asks the operating system's resolver, so lookups follow the system's DNS settings:
`res_nquery` on Linux (JVM and Kotlin/Native), `DNSServiceQueryRecord` on macOS and iOS, `DnsQuery_W` on Windows, and
`DnsResolver.rawQuery` on the default network (Private DNS included) on Android from API 29. On Android API 24 to 28 there
is no public way to ask for a record type (and a resolver of the engine's own would bypass Private DNS), so every lookup
counts as failed there and requests behave as without records. At most four system lookups run at once per process.
`HttpsRecordSource.Exchange` works everywhere. Its queries carry ID 0 (RFC 8484 section 4.1: DoH clients "SHOULD use
a DNS ID of 0 in every DNS request") and the
engine checks the question of a response, not its ID, so the exchange must tie each response to its query: DNS over
HTTPS and DNS over TLS do; an exchange over plain UDP or TCP sets a random ID of its own in the query (its first two
bytes) and accepts only a response with that ID. An answer is read in time linear in its size, at most 65535 bytes
(RFC 8484 section 6: "This media type restricts the maximum size of the DNS message to 65535 bytes"), and
a lookup's timeout stops the read: a hostile resolver cannot hold a thread with one answer.

An `http://` request (not `ws://`, not through a proxy, not to an IP address) first looks up the records of the same URL
with `https` (port 80 becomes 443), waiting for the answer as an `https` request does (while the origin's addresses
resolve and `httpsRecordWait` longer; the whole lookup with a secure source); when the origin
has an AliasMode record or a ServiceMode record the engine could use, the engine answers `307 Temporary Redirect` to the
`https` URL itself, without connecting (RFC 9460 section 9.5). Ktor's `HttpRedirect` (on by default) follows it like any
307; with `followRedirects = false` the call sees the 307, and so does a POST, PUT or other unsafe request while
`HttpRedirect`'s `checkHttpMethod` is on (its default follows GET and HEAD only): set `checkHttpMethod = false` to have
those repeated over `https` too. An AliasMode record whose target is no host name counts as "." and does not upgrade. The upgrade is no more trusted than a 307 over cleartext:
nothing is remembered for the origin beyond the records' TTL. An origin that publishes HTTPS records but serves
different content on `http://` cannot be reached over `http://` by such a client.

### Happy Eyeballs

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
  (also for the addresses of an [HTTPS record](#https-records-experimental)): an address without a usable source
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
  refusal (no broken mark) only when every address refused. The [h3/h1 race](#racing-and-fallback) runs on top: each
  side races the addresses of the request's one resolution. An `Alt-Svc` alternative's host and an HTTPS record's
  endpoint are raced the same way, and [connection migration](#connection-migration) follows the connection that won.
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

### Encrypted Client Hello (experimental)

The engine offers Encrypted Client Hello (RFC 9849) on every `https://` connection, over TCP and HTTP/3: the ClientHello on
the network names only the configuration's `public_name`, and the origin's name travels encrypted. Where the
configuration comes from, for each connection:

1. the `ech` parameter of the HTTPS record whose endpoint the connection goes to (RFC 9848), when `network { httpsRecords }`
   looks records up (`Http3Discovery.Auto`) and `tls { ech { fromHttpsRecords } }` is on (the default; it does nothing
   while `httpsRecords` is `Off`, the default);
2. else `tls { ech { configLists } }` for the request's host, given out of band (keys compared as host names: case, a trailing dot
   and IPv6 brackets do not matter, and two keys for one host fail the engine's creation);
3. else none, and the connection sends GREASE ECH (`tls { ech { grease } }`, on by default, RFC 9849 section 6.2.1), so that it
   looks like one with ECH.

```kotlin
val publishedEch = "AEj+DQBE..." // optional: the base64 of the origin's `ech` parameter, had out of band
// guide:ktor:ech-client
val client =
    HttpClient(Kuicksilver) {
        engine {
            // the records' `ech`, through your DNS-over-HTTPS exchange (see "HTTPS records")
            network { httpsRecords = HttpsRecordSource.Exchange(secure = true) { query -> dohPost(query) } }
            tls { ech { configLists = mapOf("example.com" to EchConfigList.parseBase64(publishedEch)) } }
        }
    }
```

- **Rejection.** A server that cannot decrypt the configuration (it rotated its keys) answers with its retry
  configurations after the client authenticated it for the `public_name`: the engine retries once, on a new connection
  to the addresses the request already resolved (over HTTP/3 the same address; over TCP the race of those addresses
  again), with them (RFC 9849 section 6.1.6), or without ECH when the server sent none, or none of a version this client
  supports ("securely disabled"). Retry configurations of the supported version of which none is usable fail the
  request instead: never a retry with the name in the clear. A retry that is rejected again fails the request with
  `TlsException.EchRejected` in its causes. No request is processed on a rejected connection: a 0-RTT request the server
  ignored there is sent again on the retry. Retry configurations are used for that retry only, never stored.
- **SVCB-reliant.** When every endpoint of the origin's HTTPS records has an `ech` parameter, the request never falls back
  to a connection without it: not to the origin's own address, not to the endpoint an AliasMode chain appends, not to an
  `Alt-Svc` alternative whose own records have none (RFC 9848 sections 5.1 and 6); when no endpoint can be reached the
  request fails. With ECH from the records the engine also sends no ClientHello before the records resolved (section 5.3),
  within the connect timeout: `httpsRecordWait` does not apply then.
- **0-RTT.** With `http3 { earlyData { enabled } }` the early data goes under the inner ClientHello's session. A server that rejects ECH
  ignores it (RFC 9849 section 6.1; RFC 8446 section 4.2.10), and the engine sends the request again on the retry; it is
  processed once.
- **Certificates.** On an accepted ECH the certificate is checked for the origin, as always, with its pins. On a rejection
  it is checked for the `public_name` by the base trust (`Platform`, `AnchoredCa`, a custom verifier); the origin's pins
  (`TrustConfig.Pinned`) do not apply to it, and `TrustConfig.Tofu` accepts a `public_name` only with a key stored for it
  earlier (a rejection is no first contact). Such a connection only triggers the retry, which is held to the pins. No client
  certificate is sent on a rejected connection.
- **Proxies.** Through an HTTP CONNECT or SOCKS5 proxy the TLS session inside the tunnel is the origin's, with
  `tls { ech { configLists } }` or GREASE (HTTPS records are not looked up through a proxy, RFC 9460 section 3.2); the same holds
  for the HTTP/3 connection inside a CONNECT-UDP tunnel, whose retry after a rejection goes through the same tunnel. The
  proxy learns the origin's name from the CONNECT line or the CONNECT-UDP target. The hop to an `http://` proxy is plain
  TCP; the TLS (or QUIC) hop to an `https://` or CONNECT-UDP proxy has a ClientHello of its own, which never offers the
  origin's configuration: it sends GREASE as `tls { ech { grease } }` says, and `proxies { tls { ech { configLists } } }`
  may set the proxy's own (its entry for the proxy's host is what that hop offers). A rejection on that hop fails the request as a proxy failure, never as a retry of the origin's ECH.
- **TLS 1.3 only.** ECH needs TLS 1.3 (RFC 9849 section 6.1): with a `tls` block that allows TLS 1.2, `configLists` fails
  the engine's creation and the records' `ech` is not used.
- **Unusable configurations.** A `configLists` entry with no ECHConfig this build can use, or any entry in a build without
  ECH (a system OpenSSL), fails the engine's creation with `IllegalArgumentException` (two different messages): a list
  given for a host never turns into GREASE with the host's name in the clear. The engine builds each entry's client
  configuration when it is created, for that check: a `TlsException.Config` from that build becomes the entry's
  `IllegalArgumentException`, whose message names the host. An HTTPS record's `ech` with nothing usable
  is different: that connection sends GREASE, as RFC 9849 section 6.1 allows ("If no compatible configuration is found,
  then the client SHOULD proceed as described in Section 6.2"); a record whose `mandatory` names `ech` is skipped then,
  since it must not be reached without ECH (RFC 9848 section 5).
- **What it does not hide.** The DNS queries for the origin's records and addresses (protect them with DNS over HTTPS),
  the server's address, and the traffic's sizes and timing.

### Name resolution (experimental)

The engine resolves host names with the system's resolver (`Dns.System`, the default, described under
[Happy Eyeballs](#happy-eyeballs)). `network { dns }` replaces it with a resolver of your own, as OkHttp's `Dns` does: another DNS
server (DNS over HTTPS through a client you trust), fixed addresses for some names, or a policy of your own. Whatever it
answers, the engine connects to with Happy Eyeballs over TCP (HTTP/1.1, HTTP/2) and QUIC (HTTP/3).

```kotlin
// guide:ktor:dns
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
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

### Racing and fallback

When HTTP/3 is an option (`Preferred`, an `http3 { hints }` entry, or a live Alt-Svc alternative) and no HTTP/3 connection to it is
open yet, the engine races connection setups (RFC 8305 section 5, after Chromium and curl): QUIC starts at once and
TCP + TLS starts when QUIC fails, or after a head start of 1.5 x the host's smoothed RTT (250 ms without history,
clamped to 100 ms..2 s: `RaceHeadStart.Adaptive`; `http3 { expert { raceHeadStart = RaceHeadStart.Fixed(d) } }`
overrides it) — and after 10 ms, the least RFC 8305 section 5 allows between two attempts, on a network where QUIC was
never seen working (`RaceHeadStart.NoRace` starts TCP only once QUIC failed, on any network). The TCP side is HTTP/2 when the server offers it (`raceEnded` reports `HTTP_2_0`), and an
HTTP/2 connection to the origin that is already open serves it at once. The request runs once, on the winner. A QUIC
setup that loses the race keeps going in the background and serves the next requests once it is up; a TCP connection
that loses goes back to the pool. When both setups fail, the TCP
failure is reported — the race was the one TCP attempt, there is no second one.

An alternative is marked broken only when HTTP/3 failed while HTTP/1.1 worked (a lost race, or a request that fell
back to HTTP/1.1 after the HTTP/3 connection failed as a whole: setup, QUIC transport, an HTTP/3 connection error; a
single stream reset or a malformed response falls back for that request only) — per origin and alternative, never "UDP is blocked" for everything: 5 minutes, doubling up to 2 days, and forgotten when the network changes
(`network { networkId }`, or the networks `http3 { migration }` follows). Broken alternatives are skipped (straight to TCP).
The first alternative marked broken on a network is one Warn line of the engine's logger: `HTTP/3 to <origin> failed
(<reason>); using TCP for <backoff>. See response.kuicksilverDiagnostics`; a network change arms it again. A server that refuses the QUIC setup with
`CONNECTION_REFUSED` (it is in `Drain`, stopping, or its accept queue is full: RFC 9000 section 5.2.2) has not shown the
alternative broken: that call falls back to TCP once (`fallback = Refused`), the alternative stays cached and
unmarked (RFC 7838 sections 2.2 and 3), and the next call tries HTTP/3 again. Any other close of the setup by the
server still marks it broken. Likewise a connection the server closes with H3_NO_ERROR after it sent GOAWAY (a graceful
stop whose grace period ended with requests still open: RFC 9114 section 5.2) ended in order: a request in flight on it
falls back to TCP when it may (idempotent, before its response), and the alternative is not marked broken; a close
with an error code after GOAWAY, or with H3_NO_ERROR but without a GOAWAY first, still marks it. So during a rolling restart the calls that meet a stopping instance fall back once each,
and the next calls use HTTP/3 again, instead of minutes to days of TCP for the whole origin.

### Stalled HTTP/3 connections

Some networks cut UDP flows: no answer to the first QUIC packet at all, or a handshake that completes and a flow that
stops carrying packets in both directions a moment later. On its own a QUIC connection notices only at its idle timeout
(RFC 9000 section 10.1; 30 s by default), so a request on it would wait that long before it fell back to TCP. The engine
watches the HTTP/3 connections it chose over TCP (`Auto`, `Preferred`, `http3 { hints }`; `http3 { stall { enabled } }`,
experimental, on by default) while a request runs on one: from before its wait for the handshake until its whole response arrived (the
server's FIN; from then on the exchange needs the network no more) or the call ended. The signal is the transport's,
never the response's:

- after the handshake, a connection is stalled when `stall { probeTimeouts }` probe timeouts in a row (3; RFC 9002
  section 6.2: a PTO fires only while ack-eliciting data goes unacknowledged, and doubles each time, so 3 of them take
  about 7 PTOs and grow with the RTT) went unanswered and no packet at all came back from the server for
  `stall { minSilence }` (2 s) since the first of them;
- before it (a request on a 0-RTT connection, `http3 { earlyData { } }`, on a network where QUIC worked before), when nothing at all
  came back from the server — not even an Initial — since the request started, for at least `minSilence` and two
  probe timeouts (they start from the 333 ms initial RTT and double, about 3 s: a slow path's handshake answers within
  them), instead of the connect timeout (10 s). Elsewhere the race already bounds that wait: on a network where QUIC was
  never seen working TCP starts 10 ms after QUIC ([Racing and fallback](#racing-and-fallback)), and a QUIC setup that
  loses keeps going in the background until its handshake timeout.

A slow server acknowledges the request while it thinks, and an idle long-lived response (a long poll, server-sent events
between two events) has nothing in flight: neither shows a probe timeout, so neither is a stall. Such a quiet watched
connection sends a PING now and then (RFC 9000 section 10.1.2: after half of `minSilence` without a packet, then at
twice the previous gap, up to 15 s or half the idle timeout in force, the smaller of both sides', whichever is shorter),
so that a path cut while nothing is in flight shows as well: a live server acknowledges it, a dead path turns it into
probe timeouts. Between two PINGs the watch sleeps. The PINGs also keep the connection open past the idle timeout while
a request waits for its response, as RFC 9114 section 5.1 expects of a client ("HTTP clients are expected to request
that the transport keep connections open while there are responses outstanding"). Each PING wakes the radio of a
mobile device: a client that holds long-lived responses open on a mobile network for minutes (a long poll, server-sent
events) may prefer `stall { enabled = false }` for them, or for the whole client.

On a stall the engine drains the connection: it takes no new request, the alternative is marked broken for its origin
(RFC 7838 section 2.4: 5 minutes, doubling; the backoff of a stall carries over the handshakes that work in between,
since such a network lets handshakes through, and walks one level back down for each later connection that carried a
whole exchange and that the client closed in order without it ever stalling; one that stalls after its first exchanges,
or dies by an idle timeout, never lowers it), and then, per request:

- a request that may be repeated — an idempotent method (RFC 9110 section 9.2.2: GET, HEAD, OPTIONS, PUT, DELETE,
  TRACE), a body that can be sent again (bytes, a writer, none), and no response yet — goes over TCP at once
  (`fallback = QuicStalled`, the `fallback` event with a `QuicStalledException`, one `altSvcMarkedBroken` per stalled connection);
  a request that waited for the handshake, or was handed the connection as it stalled, was never sent and goes over
  TCP whatever its method;
- any other (a POST, a streamed body) and a response body under way wait on: a short outage (a handover between radio
  networks, Wi-Fi roaming) that ends — any packet from the server — lets them finish over HTTP/3. When the path stays
  silent for `stall { abandonAfter }` (10 s) after the stall, or the QUIC idle timeout comes first, they fail with
  `QuicStalledException` (its `silence` and `probeTimeouts` say what was seen) and the connection is closed. A
  response that began is never repeated. A drained connection that came back closes once nothing runs on it any more,
  a WebSocket or WebTransport session that shared it included.

The engine does not honour an `Idempotency-Key` header (draft-ietf-httpapi-idempotency-key-header, not an RFC yet): a
POST that carries one is still not repeated; the application may send it again itself.

`stall { enabled = false }` waits for the QUIC idle timeout as before 0.3.0. `H3Only` (no TCP to go to), WebSockets and
WebTransport sessions are not watched.

### Turning HTTP/3 off remotely

`http3 { allowed = { ... } }` (stable) is a kill switch an application can flip from its remote
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
        engine { http3 { allowed = { quicAllowed.value } } }
    }
// to take HTTP/3 off at once, not only for the next requests:
client.closeHttp3Connections()
```

What it does while it returns false:

- requests go over TCP (HTTP/2 or HTTP/1.1), as with `http3 { enabled = false }`; `protocolSelected` and the response's diagnostics say
  `Http3Disabled` ([Why did this request not use HTTP/3?](#why-did-this-request-not-use-http3));
- with `discovery = H3Only` a request fails with `UnsupportedOperationException` before it opens any TCP or UDP
  connection: that mode promises never to use TCP;
- `HttpClient.webTransport` fails the same way: WebTransport has no TCP fallback;
- open HTTP/3 connections take no new requests; calls already running on them finish, and idle connections close after
  `pool { idleTimeout }`;
- `Alt-Svc` is still learned in `Auto` mode, so when the switch returns true again the next request goes to the known
  alternative without a warm-up.

`HttpClient.closeHttp3Connections()` takes HTTP/3 out of use at once, whatever the switch says: every established
pooled connection gets a GOAWAY and no further request (a request that had just been handed one, before its stream
opened, goes again on a new connection or, switched off, the next call goes over TCP), calls running on them
finish, and each closes when its last call is done; a connection still being set up serves the requests already
waiting for it and then closes; a race's own HTTP/3 setup still serves the request it was made for. A request refused
by that GOAWAY before anything of it went out is repeated on a new connection, a streamed body included (it was never
read). Every WebTransport connection gets a GOAWAY and every open session `WT_DRAIN_SESSION`: the server is asked to
wind the session down, the session's own `drainRequested` turns true so the application winds down too, and the
session stays open until either side closes it. A `webTransport` call whose CONNECT had not gone out yet fails with
`IllegalStateException` naming `closeHttp3Connections()`; one whose CONNECT completes after the call is drained as soon
as it opens. The call returns once
those frames are written, waiting at most 5 seconds for each.

The switch is not called for `http://` requests or with `http3 { enabled = false }`. A switch that throws an exception counts as true (HTTP/3
allowed), so a broken configuration cannot take down traffic; the engine logs that at `Warn`, at most once per 5
minutes. A `CancellationException` or an `Error` out of it fails the call instead.

### Connection migration

`http3 { migration = ... }` (experimental, off by default) lets the engine's pooled HTTP/3 connections follow
the device's network (RFC 9000 section 9): when the default network changes, say from Wi-Fi to the mobile network,
each connection opens a socket on the new network, validates the path to the server and moves there, so a download
and the requests in flight carry on. Without it, as in 0.2, the outcome depends on the system: the engine's socket is
bound to no network, so the system may send its datagrams over the new default network from a new address, which the
server then takes as a NAT rebinding (RFC 9000 section 9.3; that is what an Android emulator does when its default
network goes away), or keep them on an interface that is gone, and then the connection ends at its idle timeout (an
idempotent request still waiting for its response falls back to TCP). What the option adds over such a rebinding:

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
migration = Http3ConnectionMigration.followDefaultNetwork(connectivity)
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
- a migration itself neither marks the alternative broken nor forgets marks, but while `network { networkId }` is not set the
  network the factories follow (`Http3ConnectionMigration.networks`) is the engine's network: a new one gives
  alternatives marked broken on the old one a fresh chance, drops the alternatives without `persist=1` (RFC 7838 section
  2.2) and flushes the HTTPS record cache, as a `networkId` change does, within the limits of the platform's handle
  ([Discovery and Alt-Svc](#discovery-and-alt-svc)). A `networkId` that is set wins.

A WebSocket over HTTP/3 (RFC 9220) is one stream of a pooled connection, so it moves with it: the session carries on
across the switch, with no reconnect, and every message arrives once and in order, in both directions, a fragmented
message whose first half crossed the old network included, and so do pings and the closing handshake with its code
and reason (`ClientMigrationTest.webSocketSurvivesNetworkSwitch`, `.webSocketSurvivesNetworkSwitchServerCloses`: over
loopback, the old socket hears nothing once the connection moved). That needs the option and a server that allows
active migration: without the option, or towards a server that sent `disable_active_migration`, the session ends with
the old network, once the connection's idle timeout has passed: `incoming` fails and `closeReason` is 1006 (RFC 6455
section 7.1.5; `.negative_webSocketEndsWithItsNetworkWithoutMigration`,
`.negative_webSocketEndsWithItsNetworkWhenServerDisablesMigration`). A WebSocket goes over HTTP/3 only with `H3Only`
or on a connection to its origin that is open already and whose server allows Extended CONNECT ([HTTP/3 on the
client](#http3-on-the-client)); otherwise it opens over HTTP/1.1 or HTTP/2.

What does not survive a network change: HTTP/1.1 and HTTP/2 run over TCP, which cannot move, and so do WebSockets over
HTTP/1.1 and HTTP/2; a call on such a connection fails and the application repeats it. The extra connections a
server's WebTransport session limit makes (beyond the pooled one) do not follow the network either.

The Compose Multiplatform demo, [samples/compose-demo](../../samples/compose-demo/README.md) (Android and iOS, not
published), shows both sides: a download over HTTP/3 with `followDefaultNetwork` and the same download over OkHttp
(Android) or CIO and Darwin (iOS), while Wi-Fi is turned off, with the `connectionMigrated` events, an optional resume of
the TCP download with `Range`, and the limits of such a comparison on an emulator.

### Proxies

Where a request's proxy comes from:

1. `engine { proxy = ... }` (Ktor's `ProxyConfig`) when set: it applies to every request, `localhost` and loopback
   addresses included (as `curl -x` does; `java.net.Proxy.NO_PROXY` means none).
2. Otherwise `engine { proxies { resolver = ... } }` (*experimental*), asked per request and remembered for 30 seconds per
   scheme, host and port. The default is **`ProxyResolvers.System`**, the platform's settings:

| Target | `ProxyResolvers.System` | PAC / WPAD |
|---|---|---|
| JVM | `java.net.ProxySelector.getDefault()`: `https.proxyHost`/`http.proxyHost`, `socksProxyHost`, `http.nonProxyHosts`, and with `-Djava.net.useSystemProxies=true` the OS settings; its HTTP proxies (`https.proxyHost`/`https.proxyPort` included: the `https` names the URLs it serves) are always plain HTTP proxies, as on Android, since a `java.net.Proxy` has no scheme; TLS to a proxy needs `proxies { resolver = ProxyResolver { ResolvedProxy.https(..) } }` | as the JDK does |
| Android | the same: the active network's proxy, PAC through the system | yes (by the system) |
| macOS, iOS | the system proxy settings via `CFNetworkCopyProxiesForURL` (HTTP, HTTPS, SOCKS; the exceptions list; the settings' "HTTPS" proxy is the plain proxy for `https` URLs) | run by the engine on JavaScriptCore: the PAC URL or script of the settings, or WPAD when they say "auto discover" (DHCP option 252 on macOS, `http`/`https` only; `wpad.<domain>` for each DNS search domain exactly, never a parent domain, though a search domain is used as given; then `http://wpad/wpad.dat` for the resolver to complete, the only candidate on iOS); scripts fetched directly (`http`, `https`, `file`, at most 1 MiB read, kept 30 min), each run limited to 2 s; a script that fails within 5 s: the next setting, else direct, and one warning; an answer entry `HTTPS host:port` (Chrome's extension) is an `https://` proxy, port 443 by default; an answer with only proxies the engine cannot use (`SOCKS4`): the next setting, else the request fails; no WPAD script found: logged once at Info |
| Windows | the user's Internet settings via `WinHttpGetIEProxyConfigForCurrentUser` (`host:port` or `http=…;https=…;socks=…`, the bypass list with `<local>`; an entry whose value starts with `https://` is an `https://` proxy, as Chrome reads it, while `https=host:port` is the plain proxy for `https` URLs) | run by WinHTTP (`WinHttpGetProxyForUrl`, WPAD by DHCP and DNS, then the PAC URL), waited for at most 5 s; a script that fails or takes longer: the fixed proxy next to it, else direct, and one warning; no WPAD script found: the same, logged once at Info, and detection again after 5 minutes |
| Linux | `ProxyResolvers.Environment` (there is no system API; desktop settings are not read) | — |

What a PAC script sees. A PAC script is code from the network: whoever answers WPAD on the local network, or serves a
plain-`http` PAC URL, writes it, and it can send any string it is given out through
`dnsResolve("<data>.attacker.example")`. So the URL the engine passes `FindProxyForURL` is built as Chrome builds it (no
user info or fragment, the host in lower case, the default port left out; the `host` argument in lower case too), and
for secure URLs it is the origin only, as in Chrome (since 52, CVE-2016-5134), Android (CVE-2016-3763) and Firefox
(which strips the path of every URL by default). A plain `http` URL also gives its origin only, but for another reason:
the engine keeps answers per scheme, host and port, so a path could not change them (Chrome and Android pass an `http`
URL's path; Firefox strips it):

| Request | On Apple platforms and Windows the script gets | On the JVM and Android `ProxySelector.select` gets |
|---|---|---|
| `https://h/p?q` | `https://h/` | `https://h:443/` |
| `wss://h:8443/p?q` | `wss://h:8443/` (with `pacFullWebSocketUrl` and the settings' own script, inline or from an `https`/local `file` URL: `wss://h:8443/p?q`; WinHTTP: as `https://` when it refuses `wss`) | `https://h:8443/p?q` (Android's selector cuts it to `https://h:8443/` before its PAC runs; the JDK's passes the OS only scheme and host) |
| `ws://h/p?q` | `ws://h/p?q` (WinHTTP: as `http://` when it refuses `ws`) | `http://h:80/p?q` |
| `http://h/p?q` | `http://h/` | `http://h:80/` |

RFC 6455 section 4.1 asks for a WebSocket's whole URI, resource name included; for `wss` the engine departs from that
by default for this reason. `engine { proxies { pacFullWebSocketUrl = true } }` (*experimental, delicate*) gives the whole `wss` URI to the
script the system settings name, given inline (Apple) or by an `https://` or local `file:///` URL (Windows: the "Use setup
script" address; Apple: the PAC URL), and never to one WPAD found or one fetched over plain `http://`: whoever answers
on the local network writes those. On Apple platforms the PAC URL CFNetwork reports must equal the settings' string
exactly; a URL written differently (case, a trailing slash) gets the origin only. A `file:` URL with a host
(`file://srv/share/p.pac`, `file:////srv/share/p.pac`) is fetched over SMB from that host and counts as remote: origin
only. Turn it on only when that script is
yours.
On Apple platforms the engine's own runner also bounds the script: 2 s per run (creating the script's context, evaluating
the PAC utility functions and the script, and its `FindProxyForURL` call; preparing a new script's text comes before),
20 distinct lookups per run in total (as
Chrome; a name looked up by both `dnsResolve` and `dnsResolveEx` counts twice; a name with a NUL resolves to nothing),
an answer of at most 64 KiB of ASCII without a NUL, a script of at most 1 MiB; an answer entry it cannot read is skipped,
and an answer with none left counts as a failed script. JavaScriptCore's public API has no memory limit: a script that
allocates without end is stopped only by the time limit (its thread is given up, threat model 3.20.3).

`ProxyResolvers.Environment` reads the variables as curl does: `https_proxy`/`HTTPS_PROXY` for `https` and `wss`,
`http_proxy` (lower case only) for `http` and `ws`, then `all_proxy`/`ALL_PROXY`; `no_proxy`/`NO_PROXY` exempts `*`,
names with their subdomains (`example.com` covers `a.example.com`, not `badexample.com`), IP addresses and CIDR ranges;
an entry with a port (`example.com:8080`, `[2001:db8::1]:443`) exempts that port only, as Go does. On Windows
environment names are case-insensitive, so there an `HTTP_PROXY` variable is read as `http_proxy` (curl has the same
caveat).
A value is `http://host:port`, `https://host[:port]` (TLS to the proxy; port 443 by default, as curl (despite its manual's 1080), Chrome and Go), `socks5://`
(names resolved by the client), `socks5h://` (by the proxy) or a bare `host:port`; user info in it becomes the
credentials. `ProxyResolvers.None` connects directly, as 0.2 did without
`proxy`; any `ProxyResolver { url -> ... }` of your own works too. Both built-in resolvers send `localhost`,
`*.localhost` and loopback addresses directly whatever the settings say.

A proxy the engine cannot use (`socks4://`, an unknown type) fails the request with `UnsupportedOperationException`: it
is never bypassed.

How a proxy is used. An HTTP proxy gets `CONNECT` tunnels for `https` and for WebSockets, `ws://` included (RFC 6455
section 4.1, as browsers), and absolute-form requests for plain `http`; a SOCKS proxy is SOCKS5 (RFC 1928, CONNECT only;
no SOCKS4), every request tunneled, the proxy resolving the origin's name unless `socks5://` asked otherwise.
Credentials authenticate to either: SOCKS5 username/password (RFC 1929), offered and sent only when the proxy picks
that method, or `Proxy-Authorization: Basic` with the first CONNECT or absolute-form request unless the request sets
its own. A request's own `Proxy-Authorization` goes only on a hop to a proxy, never to an origin (directly or in a
tunnel, over HTTP/1.1, HTTP/2 and HTTP/3 alike). `proxies { credentials }` are for the explicit `proxy` only (off the JVM a proxy URL's user info,
`http://user:password@proxy:3128`, wins); a resolver's proxy carries its own: the user info of `https_proxy` and the
like with `ProxyResolvers.Environment`, or the `credentials` of the `ResolvedProxy` your resolver returns. Both go in
clear to an `http://` or SOCKS5 proxy (RFC 7617 section 4, RFC 1929 section 5; anyone on the path to the proxy reads
them, as with curl, Go and OkHttp) and only inside TLS to an `https://` proxy, never to the origin. `Basic` cannot carry a
user name with a colon, nor control characters (0x00-0x1F, 0x7F) in either part (RFC 7617 section 2): credentials like that
for an HTTP, `https://` or CONNECT-UDP proxy fail with `IllegalArgumentException` where the proxy is configured (the
engine's creation for its `proxy`), before anything is sent; a SOCKS5 user name may contain a colon. Through `socks5://` (names resolved here) the engine tries the origin's
addresses in turn while the proxy answers "network unreachable" or "host unreachable", within the connect timeout. A
resolver that does not answer within the engine's `connectTimeout` (not a per-request `HttpTimeout`) fails the request with
`ProxyException`. A proxy that refuses fails the request with `ProxyException` (*experimental*):
`replyCode` is the SOCKS5 reply or the CONNECT status (407: credentials wanted; not retried, so a proxy that keeps
answering 407 costs one CONNECT per request, never a loop; a plain `http` request gets the proxy's 407 as its response).

**`https://` proxies** (*experimental*, 0.3.0). `ResolvedProxy.https(host, port, credentials)`, an `https://` value in
the environment, an `https://` entry of Windows' settings, a PAC answer's `HTTPS host:port`, or, off the JVM,
`ProxyBuilder.http(Url("https://proxy:443"))` (a `java.net.Proxy` has no scheme, so on the JVM name it with a resolver;
there an HTTP `proxy` on port 443, which is what that URL becomes, fails every request with `UnsupportedOperationException`
rather than speak plain HTTP to what may be an `https://` proxy: use `ResolvedProxy.https` for TLS to it, or
`ResolvedProxy.http(host, 443)` from a resolver for a plain proxy on that port)
makes the engine speak TLS to the proxy itself, as curl's HTTPS proxy and Chrome do, before anything else: the CONNECT
or the absolute-form request, its `Proxy-Authorization` and the CONNECT's target travel inside that TLS session
([ADR-0023](../adr/0023-https-proxy.md)).

- The proxy's certificate is verified against the proxy's host as configured (a DNS name, or an IP address as an IP-ID;
  RFC 9525), which is also its SNI unless it is an IP address (RFC 6066 section 3); the name goes through the engine's
  `network { dns }`. A failed handshake (a certificate that does not verify, an alert, a proxy that closes) fails the request with
  `ProxyTlsException`, a `ProxyException` whose `cause` is the TLS layer's error; a failure of the origin's TLS inside
  the tunnel stays the origin's `TlsException`.
- Trust: `proxies { tls { } }` (the `ClientTlsConfig` of `engine { tls { } }`) configures that connection on its own. By
  default it takes the engine's `tls { trust }` without what names the origin (an `ExpectedName` gives way to its base, a `Pinned` to its base:
  the proxy has another name and another key, as curl's `--pinnedpubkey` is not applied to its proxy) and without the
  client certificate; a `proxies { tls { } }` block starts from that same trust and no identity and may set anything.
  Whatever it sets, the server name is the proxy's host and ALPN `http/1.1` alone.
- Inside the tunnel the origin's TLS runs as without a proxy (TLS in TLS): its own SNI, certificate check, pins, ALPN
  (`h2` included). Plain `http` goes in the absolute form inside TLS to the proxy, and that connection is pooled per proxy
  (an `https://` and an `http://` proxy at the same address are different routes).
- HTTP/2 to the proxy itself (CONNECT over HTTP/2, RFC 9113 section 8.5, several tunnels on one connection) is not
  offered: one TLS connection to the proxy carries one tunnel, as with curl's default and OkHttp. A new connection to the
  proxy resumes an earlier TLS session from a cache that holds proxy tickets only.

**Through an HTTP, HTTPS or SOCKS5 proxy there is no HTTP/3.** QUIC is UDP, which neither CONNECT (to an `http://` or an
`https://` proxy) nor SOCKS5 CONNECT carries (SOCKS5 UDP ASSOCIATE is not supported), as with Chrome and curl. HTTP/3 goes
through a CONNECT-UDP proxy instead: [HTTP/3 through a CONNECT-UDP proxy](#http3-through-a-connect-udp-proxy-experimental).
A proxied request uses TCP (`ProtocolReason.Proxy`: HTTP/1.1, or HTTP/2 inside a tunnel),
`Alt-Svc` is neither used nor learned and `http3 { hints }` are ignored; `H3Only` fails it with
`UnsupportedOperationException` without contacting the proxy, and `HttpClient.webTransport` refuses the URL unless
`http3 { webTransport { proxyPolicy } }` lets it bypass the proxy. To use HTTP/3 to a host, exempt it from the proxy
(`no_proxy`, the OS bypass list), or connect directly everywhere with `proxies { resolver = ProxyResolvers.None }`.

```kotlin
// guide:ktor:proxy
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val password = System.getenv("PROXY_PASSWORD") ?: ""
// one proxy for everything, with credentials for it
val viaProxy = HttpClient(Kuicksilver) {
    engine {
        proxy = ProxyBuilder.http("http://proxy.corp.test:3128")
        proxies { credentials = ProxyCredentials("user", password) } // for `proxy` only
    }
}
// a resolver of your own: its proxy carries its own credentials (ProxyResolvers.Environment takes them from https_proxy)
val perHost = HttpClient(Kuicksilver) {
    engine {
        proxies {
            resolver = ProxyResolver { url ->
                if (url.host.endsWith(".internal.test")) null // direct
                else ResolvedProxy.http("proxy.corp.test", 3128, ProxyCredentials("user", password))
            }
        }
    }
}
// an https:// proxy: TLS to the proxy itself, the CONNECT and the credentials inside it
val overTls = HttpClient(Kuicksilver) {
    engine {
        proxies {
            resolver = ProxyResolver { ResolvedProxy.https("proxy.corp.test", 443, ProxyCredentials("user", password)) }
            tls { trust = TrustConfig.Platform } // the proxy's own trust (default: the origin's, without pins)
        }
    }
}
```

### HTTP/3 through a CONNECT-UDP proxy (experimental)

`proxies { connectUdp }` sends the engine's HTTP/3 through a CONNECT-UDP proxy (RFC 9298, MASQUE): each HTTP/3 connection to an
origin it applies to runs inside a UDP tunnel through the proxy, with TLS end to end to the origin, so the proxy sees the
origin's name, port and UDP, never the requests ([HTTP/3, CONNECT-UDP](http3.md#connect-udp-experimental)). The proxy is
reached directly over HTTP/3 (its template's authority, port 443 when it names none) with the proxy's TLS settings, as
an `https://` proxy over TCP ([Proxies](#proxies)): `proxies { tls { } }`, or by default the engine's trust without an
`ExpectedName` or pins and without the client certificate (`tls { identity }` goes to the origin only); the certificate is
verified against the proxy's host, and a failed handshake with the proxy is a `ProxyTlsException`. Each tunnelled
connection has its own connection to the proxy, closed with it, a full handshake each time (no session resumption, and no
ticket of the proxy's ever shared with origins). Through several addresses of the proxy, an address whose TLS failed
makes the request's failure a `ProxyTlsException` even when a later address only timed out (the timeout is then among
its suppressed exceptions), as long as no address of the proxy completed its handshake: once one did, the CONNECT may
have gone out, and a timeout of the tunnel or of the origin's handshake is a `ConnectTimeoutException`. QUIC is TLS 1.3 only (RFC 9001 section 4.2), so a `proxies { tls { } }` limited to TLS 1.2 cannot
reach a CONNECT-UDP proxy; an ECH configuration that `proxies { tls { ech { } } }` gives the proxy is offered as given and not retried after a
rejection (RFC 9849 section 6.1.6 applies to the origin's connection). Inside the tunnel the origin's connection has the engine's `tls { }`, as a direct one. The origin's name goes to the proxy, which
resolves it: the engine does not look it up.

What it changes, for the `https` URLs its `applies` admits (all of them by default):

- They go over HTTP/3 through the tunnel only, whatever the discovery mode (H3Only, Auto, Preferred): never over HTTP/1.1
  or HTTP/2 and never directly, since both would leave the proxy out. An origin without HTTP/3, a refused tunnel
  (`Http3Exception.ConnectRejected`, its `proxy-status` in `headers`) or a failed handshake fails the request instead of
  falling back. `http3 { enabled = false }` and an `http3 { allowed }` that says no fail it with
  UnsupportedOperationException.
- `Alt-Svc` and HTTPS records are neither used nor learned for them: the tunnel goes to the URL's host and port.
- `proxy` and `proxies { resolver }` (HTTP and SOCKS5 proxies, which carry TCP) keep deciding for every other request: `http://`
  URLs and the URLs `applies` turns away. A deployment that must send everything through proxies sets both.
- WebTransport refuses such URLs (its sessions do not go through the tunnel) unless
  `http3 { webTransport { proxyPolicy = WebTransportProxyPolicy.BypassConnectUdpProxy } }` (or `BypassAll`) connects
  them directly; `BypassHttpProxy` is about HTTP and SOCKS proxies only.
- Tunnelled connections keep their session tickets apart from direct connections', one cache per proxy route, so the
  origin cannot link a proxied connection to the client's own address by the ticket it resumes.

The `ConnectUdpProxy`'s credentials go to the proxy as `proxy-authorization: Basic ...` on each tunnel's CONNECT. The connection to the proxy
must carry the inner connection's 1200-byte datagrams in its own: the engine's sockets set Don't Fragment, so DPLPMTUD
finds a path MTU above about 1250 bytes within a few round trips; over a path that does not carry that, the handshake
through the tunnel times out.

```kotlin
// guide:ktor:connect-udp-client
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val client = HttpClient(Kuicksilver) {
    engine {
        proxies { connectUdp = ConnectUdpProxy(
            UdpProxyTemplate.parse("https://masque.example/.well-known/masque/udp/{target_host}/{target_port}/"),
            ProxyCredentials("user", password),
        ) { url -> !url.host.endsWith(".internal.test") } }   // these go the usual way
    }
}
```

### WebTransport on the client (experimental)

`HttpClient.webTransport(url)` opens a WebTransport session (draft-ietf-webtrans-http3-17) to an `https` URL and
returns the `WebTransportSession` of `kuicksilver-http3` (streams, datagrams, close; see the
[HTTP/3 guide](http3.md#webtransport-experimental)). Sessions share the engine's pooled HTTP/3 connection to the URL's
host and port with each other and with requests (RFC 9114 section 3.3: one connection per address and port): a pooled
connection set up for requests alone is replaced by a WebTransport-capable one, which carries the origin's requests from
then on (the old one finishes its requests and closes). With WebTransport flow control on both sides a connection
carries up to `http3 { webTransport { maxSessionsPerConnection } }` (4) sessions, and as many as the server accepts: a session it
refuses (`H3_REQUEST_REJECTED`, its limit) opens on another connection to the same server, which the next sessions share
too and which closes with its last session; without flow control each further session gets a connection of its own.
The pooled connection stays in use while a session or a request uses it, then idles like any other. Requests and
sessions on it are not taken in turns against each other (the sessions' fair turns are among sessions): both are the
same application's traffic to one origin, requests keep their own priorities (RFC 9218) and QUIC flow control, and an
application that wants its bulk requests not to slow a session sends them at a lower urgency. A session to a server
that refuses it while none of this client's sessions is on the connection (its rate, not its session limit) fails with
`Http3Exception.RequestNotProcessed` rather than opening another connection. When it is lost,
every session on it ends with its reason. The engine's `tls { }` and `http3 { quic { } }` apply, and the per-session
receive limits of `http3 { settings { webTransport { initialMaxStreamsBidi, initialMaxStreamsUni, initialMaxData } } }`
are the client's to set (`enabled` and `maxSessions` there are derived from `http3 { webTransport { } }`), with WebTransport,
Extended CONNECT and `reset_stream_at` turned on for a WebTransport-capable connection;
`connectTimeout` bounds the setup, then the server's SETTINGS and its answer to the CONNECT get ten seconds each.
There is no fallback: a server without WebTransport fails with `Http3Exception.Settings`. Refused with
`UnsupportedOperationException`: `http3 { enabled = false }`, and a proxy that applies to the URL — WebTransport runs
over UDP, which an HTTP proxy does not carry — unless the host is exempt from the proxy or
`http3 { webTransport { proxyPolicy } }` (`WebTransportProxyPolicy.Refuse` by default) asks to connect directly. At most
`http3 { webTransport { maxSessions } }` (64) sessions are open at once on the client; one more fails at once with `IllegalStateException`, nothing waits. The
session goes straight to the URL's host and port: Alt-Svc is not consulted and the CONNECT never goes in 0-RTT; the resolved addresses are tried
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

A server that admits only clients with a certificate from its own CA sets `clientAuth = ClientAuth.Required` and a
`clientTrust` in its `tls { }` (the engine's, for every TLS connector, or one connector's own `tls { }` for that port
only):

```kotlin
val clientCaPem = File("client-ca.pem").readText()
// guide:ktor:mtls-server
val clientCa = Certificate.parsePem(clientCaPem)   // the CA that issues the client certificates
val server = embeddedServer(Kuicksilver, configure = {
    tls {
        identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
        clientAuth = ClientAuth.Required                 // no handshake without a client certificate that chains to clientCa
        clientTrust = TrustConfig.AnchoredCa(clientCa)   // or clientCaFile("/etc/kuicksilver/client-ca.pem")
    }
    tlsConnector { port = 443 }
}) {
    routing {
        get("/whoami") { call.respondText("client ${call.request.peerCertificates.first().dnsNames}") }
    }
}
server.start(wait = true)
```

The client presents its certificate with `tls { identity }`, for HTTP/3, HTTP/2 and HTTP/1.1 alike:

```kotlin
// guide:ktor:mtls-client
val identity = TlsIdentity.fromPem(clientChainPem, clientKeyPem.toCharArray())   // every target; the key array is zeroed
val client = HttpClient(Kuicksilver) {
    engine {
        tls {
            this.identity = identity                                            // presented over HTTP/3, HTTP/2 and HTTP/1.1 alike
            trust = TrustConfig.AnchoredCa(Certificate.parsePem(serverCaPem))   // or keep Platform for a public server certificate
        }
    }
}
```

- **The server.** `clientAuth` is `None` (the default), `Optional` (a certificate is asked for; a client without one
  still connects, and `peerCertificates` is empty) or `Required` (the handshake fails without one). Any value but `None`
  needs `clientTrust = TrustConfig.AnchoredCa(...)` (optionally inside `TrustConfig.Pinned`, the only trust for client
  certificates) or `clientCaFile(path)`, which reads a PEM bundle as that `AnchoredCa`; without either the start fails
  with `IllegalArgumentException` naming `tls { clientTrust }`. With `EngineMain`: `kuicksilver.tls.clientAuth` and
  `kuicksilver.tls.clientCa`. The setting applies to the TCP side and the HTTP/3
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
  `certificate_required` (116). Over TCP (`http3 { enabled = false }`) the client's side of the TLS handshake has
  completed by then, so the alert ends the connection the request is on: over HTTP/2, which the server offers by default
  since 0.3.0, the call fails with `Http2Exception.ConnectionClosed` ("the connection was lost: TLS alert received from
  the peer: certificate_required (116)") whose root cause is a `TlsException.AlertReceived`; over HTTP/1.1 (a server
  with `http2 { enabled = false }`) with an `IOException` (Ktor's `ClosedByteChannelException`) whose message is "TLS
  alert received from the peer: certificate_required (116)", with the same root cause. Over QUIC (`H3Only`) the call fails with
  `QuicException.ConnectionLost.TransportClosed`, `code` 0x174 (0x0100 + 116), with a `TlsException.AlertReceived` as
  its cause. In `Preferred` mode HTTP/3 fails that way first (the event listener's `raceEnded` or `fallback` gets that
  `TransportClosed`), the call goes on over TCP and fails there as over TCP, with no `suppressed` exceptions: the TCP
  setup did not fail. The server counts the failure by transport: over QUIC in
  `handshakesFailedTls` (`engine.http3Stats`), over TCP in its event listener's `tlsHandshakeFailed`.
- **0-RTT.** A server that asks for client certificates cannot accept 0-RTT: `http3 { earlyData { enabled = true } }`
  together with a `clientAuth` other than `None` fails the start with `IllegalArgumentException` "acceptEarlyData cannot
  be combined with client certificates" ([0-RTT](#0-rtt-opt-in-experimental)). A client with a `tls { identity }` may keep
  `http3 { earlyData { enabled } }` on; such a
  server never offers it 0-RTT, so its connections use full handshakes.
- **Rotation.** The server's own identity can be a `TlsIdentity.Reloadable` ([Certificate rotation](#certificate-rotation)).
  The client CA in `clientTrust` is read when the server starts; a `TrustConfig.reloadable(...)` CA, or `clientCaFile`
  with `reloadInterval`, rotates without a restart ([Certificate rotation](#certificate-rotation), "The client CA").

## Certificate pinning

A client that talks to its own servers can pin their keys on top of the certificate checks: `TrustConfig.Pinned` in the
engine's `tls { trust }` accepts a server only when its chain verifies against `base` (the platform's store by default)
and the public key (SPKI, SHA-256) of its leaf is one of the pins:

```kotlin
// guide:ktor:pinning
val pinned = HttpClient(Kuicksilver) {
    engine {
        tls {
            trust = TrustConfig.Pinned(
                setOf(
                    SpkiSha256.parse("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),   // the current key
                    SpkiSha256.parse("sha256/u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s="),   // the backup key
                ),
                base = TrustConfig.Platform,   // the chain is still verified; the pin comes on top
            )
        }
    }
}
```

- The pins hold for every protocol: HTTP/3 over QUIC and the TCP fallback (HTTP/2, HTTP/1.1) use the one `tls { }`, so a
  blocked UDP path never leads to a connection with weaker checks. A pin never replaces the name check.
- Pin a backup key you hold offline as well, or a key change locks the app out until it is updated.
  `scope = PinScope.AnyInValidatedChain` matches any certificate of the validated chain (an intermediate CA's key, say)
  instead of the leaf.
- A `Pinned` trust names the origin's keys, so the TLS to a proxy (`proxies { tls { } }`, [Proxies](#proxies)) starts
  from its `base` instead. The variants and their rules: [TLS: Trust](tls.md#trust).

## Priorities (experimental)

Both engines read and write RFC 9218 extensible priorities (the API is `@ExperimentalKuicksilverApi`). Over HTTP/3, and
over HTTP/2 on the server, the priority decides the order in which the responses of one connection are sent: lower
urgency first, responses of the same urgency one after another, or interleaved when incremental; within one urgency the
incremental and the non-incremental ones take turns, and a tunnel gets some bandwidth even behind more urgent responses
(RFC 9218 sections 10, 10.1): over HTTP/3 a CONNECT stream such as a WebSocket, over HTTP/2 an Extended CONNECT stream
such as a WebSocket over HTTP/2 (with RFC 8441 support). Over HTTP/1.1 a connection carries one response at a time, so there the field is
only read and sent, never used for scheduling.

On the server, `call.request.priority` is the client's current signal (urgency 3, not incremental, when it sent none; a
malformed parameter reads as its default), and `call.request.priorityUpdates` is the same as a `StateFlow` that follows
the client's PRIORITY_UPDATE frames over HTTP/3 and HTTP/2 (over HTTP/1.1 it never changes). `call.response.priority(urgency,
incremental)` sets the response's `Priority` field with only the parameters given: over HTTP/3 and HTTP/2 the engine
merges them into the client's signal (a parameter left out keeps the client's value, RFC 9218 section 8) and schedules
the response with the result, and later updates from the client no longer change it.

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
with it, a WebSocket over HTTP/3 included; over HTTP/2 the same, with an RFC 7540 weight in the request's HEADERS until
the server's SETTINGS say it ignores those (RFC 9218 section 2.1.1); over HTTP/1.1 only the `Priority` field is sent. It
replaces a `Priority` header set on the same request, so the server sees one signal.
`response.updatePriority(urgency, incremental)` sends a PRIORITY_UPDATE while the response is still coming (RFC 9218
section 7), reschedules the request's own stream, and returns true; over HTTP/2 the signals follow section 2.1.1
(PRIORITY_UPDATE unless the server left SETTINGS_NO_RFC7540_PRIORITIES at 0, an RFC 7540 PRIORITY frame unless it said
1). It returns false over HTTP/1.1, which has no such signal (also when a 421 or a failure sent the request again over
HTTP/1.1), once the call is over or the body was read to the end, and when the connection is gone. The server reschedules
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

Decompression bombs. A compressed message may inflate to at most `maxInflatedMessageSize` bytes (on Kuicksilver's
engines, to at most the smaller of that and the engine's `webSockets { maxMessageSize }`). Kuicksilver's engines
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

<a id="observability-experimental"></a>

## Observability

Both engines report what they do without a logging dependency, in their `observability { }` block: `logger` and `qlog`
are stable, the listeners (`eventListener`, `connectionListener`) experimental. The QUIC side
is the one described in [QUIC: Observability](quic.md#observability): counters, a `KuicksilverLogger`, a
`ConnectionListener` and qlog.
[`samples/kq-cli`](../../samples/kq-cli/README.md) puts the client side together in a command line, `kq get -v <url>`:
the protocol of each response and why, the QUIC connection (handshake time, RTT, ALPN, 0-RTT), the `Alt-Svc` learned
and a qlog trace per connection, built for macOS, Linux and Windows.

**Server.** In the engine's `observability { }` block, `logger` receives the HTTP/3 endpoints' diagnostics (null, the
default, sends them to the application's log, `environment.log`, where the engine's own messages go too),
`connectionListener` (*experimental*) hears every QUIC connection, `qlog` adds a trace per HTTP/3 connection, and
`eventListener` (*experimental*) takes a
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
    tlsConnector {
        tls { this.identity = identity }
        port = 443
    }
    observability {
        logger = KuicksilverLogger.stderr(LogLevel.Info)
        qlog = AsyncQlogSink(DirectoryQlogSink("/var/log/qlog"), sampleEvery = 100)
        eventListener = object : KuicksilverServerEventListener() {
            override fun requestEnded(protocol: HttpProtocolVersion, call: ApplicationCall, cause: Throwable?) {
                metrics.record(protocol, call.response.status()?.value)
            }
        }
    }
}, module = Application::module)
```

**Client.** `engine { observability { eventListener = ... } }` takes a `KuicksilverEventListener`, an abstract class with an empty method
per event in the manner of OkHttp's `EventListener`: `callStart`, `callEnd` (protocol and status) or `callFailed`;
`protocolSelected` with a `ProtocolReason` (`Configuration`, `NotSecure`, `ExistingConnection`, `Race`, `NoAlternative`,
`BrokenAlternative`, `WebSocket`, `Fallback`, `Proxy`, `Http3Disabled`, `HttpsRecord`; on the TCP path it comes once the
connection is in hand, with `HTTP_2_0` when the server picked `h2`, since 0.3.0); `raceEnded` (winner, head start, why HTTP/3 lost); `altSvcUsed`,
`httpsRecordUsed` (an endpoint of the origin's HTTPS record) and `altSvcMarkedBroken`; `fallback` from HTTP/3 to TCP,
with the HTTP/3 failure itself (not the `FallbackReason`, which is on the response, below); `retry` (a request the server
did not process after GOAWAY, HTTP_1_1_REQUIRED over HTTP/2, a stale pooled HTTP/1.1 connection, a 417); `connectionAcquired`
(reused or new) and `connectionReleased` (kept for the next request or closed); `connectionMigrated` (an HTTP/3 connection
followed the network, [Connection migration](#connection-migration)); `webSocketFailed` (a coroutine of a WebSocket
session failed; it can come after `callEnd`, since a session may outlive its call while it writes its own Close);
`dnsStart` and `dnsEnd` (since 0.3.0, as OkHttp's: one pair per name lookup, per address family for the system's resolver
and a `FamilyDns`, once for both with a plain `Dns`; the end carries the addresses the engine may connect to, or the
failure; no lookup and no event for an address literal, [Name resolution](#name-resolution-experimental)); `connectFailed`
(since 0.3.0: a connection setup that failed, a TCP connect to one address, a proxy or TLS handshake over TCP, or a QUIC
handshake, with its address; [Why did this call fail?](#why-did-this-call-fail)). `observability { logger }`
(`KuicksilverLogger.Default`, the platform's logger at warnings and up) receives the engine's and its QUIC endpoints'
diagnostics and the listener's own failures, and `observability { qlog; connectionListener }` reach the engine's QUIC
endpoints.

```kotlin
// guide:ktor:client-observability
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
HttpClient(Kuicksilver) {
    engine {
        observability {
            eventListener = object : KuicksilverEventListener() {
                override fun protocolSelected(request: HttpRequestData, protocol: HttpProtocolVersion, reason: ProtocolReason) {
                    println("${request.url}: $protocol ($reason)")
                }
            }
            qlog = AsyncQlogSink(DirectoryQlogSink("qlog"))
        }
    }
}
```

On Android, `observability { qlog = AsyncQlogSink(qlogDirectory(context)) }` writes the traces to a directory in the app's
cache directory, created owner-only (API 26 and up; [QUIC: qlog](quic.md#qlog)). It is the counterpart of
`keylogFile(context)`.

<a id="closing-the-client"></a>
**Closing the client.** `client.close()` returns at once: the calls in flight finish, then the engine closes its pools,
its UDP endpoints (every QUIC connection on them, with its CONNECTION_CLOSE) and its selector in the background. An app
that exits right after, and wants its qlog traces complete, waits for that with the usual Ktor engine idiom,
`client.engine.coroutineContext.job.join()` (0.3.0). The join first waits for every call in flight: a response body
until it is read or cancelled, a WebSocket or SSE session until it is closed. Only then are the endpoints closed, and the
join returns once every one of them finished closing, which includes `close()` on the qlog trace of every connection.
An `AsyncQlogSink` writes on its own coroutine, so `flush()` it after the join to have the files written. The join has no
bound of its own: a body nobody reads or a session nobody closes holds it for as long as it stays open, so wrap the join
in `withTimeout` where the exit must not wait for them.

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
| `Proxy` | a proxy applies to the URL | `proxy` and `proxies { resolver }` ([Proxies](#proxies)) |
| `Configuration` | `http3 { enabled = false }` | the `http3` block |
| `Http3Disabled` | `http3 { allowed }` returned false | your remote configuration ([Turning HTTP/3 off remotely](#turning-http3-off-remotely)) |
| `NoAlternative` | `Auto` and no `Alt-Svc` from the origin yet: the first call always goes over TCP | the server's `Alt-Svc`; `http3 { hints }`, `FileAltSvcStore` |
| `MisdirectedRequest` | the alternative answered 421; it was dropped and the origin answered over HTTP/1.1 | the alternative's certificate and virtual hosts |
| `BrokenAlternative` | HTTP/3 to this alternative failed recently on this network | the log line's `broken since:` names why |
| `WebSocket` | a WebSocket without an HTTP/3 connection that allows Extended CONNECT | expected for the first WebSocket |
| `HandshakeTimeout` | no QUIC answer within the handshake or connect timeout | UDP to the port: a firewall, a VPN, a cloud security group open for TCP only |
| `UdpUnreachable` | ICMP unreachable for the UDP port | not reported yet: such calls show `HandshakeTimeout` |
| `QuicUnavailable` | this host's UDP socket cannot set Don't Fragment (`QuicException.DontFragmentUnavailable`), so QUIC is not used and the call goes over TCP at once | the JVM without the `ksl` native library below JDK 19, or Kotlin/Native (iOS, macOS, Linux) when the accelerated `ksl` socket cannot open: its portable socket has no DF ([QUIC is not used without Don't Fragment](troubleshooting.md#quic-is-not-used-dontfragmentunavailable)) |
| `H3NotReady` | HTTP/1.1 was ready before HTTP/3 answered (HTTP/3 had not failed) | nothing; the QUIC setup goes on and serves later calls |
| `Refused` | the server closed the QUIC connection without a TLS alert (`CONNECTION_REFUSED`), or no common QUIC version | `CONNECTION_REFUSED`: nothing, the server is draining, stopping or full, and the next call tries HTTP/3 again (the alternative is not marked broken); otherwise the server's QUIC listener and its limits |
| `TlsFailure` | a TLS alert in the QUIC handshake, or a local certificate failure | the UDP side's certificate and its `h3` ALPN |
| `Http3Error` | the HTTP/3 connection failed as a whole (an HTTP/3 or QPACK error, a stateless reset, an idle timeout) | `h3Failure`, a qlog trace |
| `ZeroRttRejected` | the server rejected 0-RTT | nothing |
| `GoAway` | the server refused the request with GOAWAY on every attempt | the server is stopping |
| `StreamFailed` | one HTTP/3 stream failed and the idempotent request went again over HTTP/1.1 | `h3Failure` |
| `Other` | any other HTTP/3 failure | `h3Failure` |
| `QuicStalled` | the HTTP/3 connection stopped carrying packets under the request ([stall detection](#stalled-http3-connections)); the request went over TCP and the alternative is marked broken | a network that cuts UDP flows (a firewall, NAT or VPN); `http3 { stall { } }` |
| `H2Refused` | the server answered HTTP/2 with HTTP_1_1_REQUIRED (RFC 9113 section 7), on this call or lately (the route offers only `http/1.1` for 5 minutes, doubling up to 2 days), so the call went over HTTP/1.1; why HTTP/3 was not used is in the log line as `h3Fallback=` | the server's HTTP/2 support for that route ([HTTP/2 on the client](#http2-on-the-client)) |
| `ServerConnectionIdChanged` | the server switched its Source Connection ID during the QUIC handshake, which RFC 9000 sections 7.2 and 7.3 forbid: an msquic server (IIS, .NET Kestrel on Windows) given a ClientHello of 3 or more datagrams, as a resumption's is; the call went over TCP at once; after a resumed handshake the next ones use HTTP/3 without resumption (no 0-RTT) for 5 minutes, doubling up to 2 days, after a full one the alternative is marked broken | nothing on the client (msquic#4905); [msquic servers](troubleshooting.md#msquic-servers-and-a-large-clienthello) |

The engine's `observability { logger }` gets one line per call that HTTP/3 could have served but did not (a lost race, a
fallback, a broken alternative, a proxy) at `observability { protocolChoiceLogLevel }`, `Info` by default — which the
default logger, the platform's at warnings and up, leaves out: set `logger = KuicksilverLogger.platform(LogLevel.Info)`
to see them (the first alternative marked broken on a network is one Warn line all the same). Calls over HTTP/3, and
calls HTTP/3 was never a candidate for (`http://`, `http3 { enabled = false }`, `Auto` without `Alt-Svc`), are logged
at `Debug`; `null` turns
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
        observability { logger = object : KuicksilverLogger {
            override fun isEnabled(level: LogLevel) = level >= LogLevel.Info
            override fun log(level: LogLevel, message: String, cause: Throwable?) = logLine("$level $message")
        } }
        // the HTTP/3 failure itself, when it happens; why the call did not use HTTP/3 is on the response
        observability { eventListener = object : KuicksilverEventListener() {
            override fun fallback(request: HttpRequestData, cause: Throwable) = logLine("HTTP/3 failed for ${request.url.host}: $cause")
        } }
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

A call that fails has no response: its exception carries the diagnostics instead ([Why did this call
fail?](#why-did-this-call-fail)). When both the HTTP/3 and the HTTP/1.1 setups failed, the HTTP/1.1 failure is thrown
with the HTTP/3 one in `suppressed`. The diagnostics live as long as the response (they are one of its call's
attributes); the engine keeps no copy of the HTTP/3 failure, and a broken mark remembers only its `FallbackReason`. Read
them from the response: the engine puts a new object into the request's attributes when the call reaches it and fills it
as the call goes, so code that looks at the request earlier (a listener during the call, a plugin running after a
redirect copied the previous request's attributes) sees incomplete or stale ones; when an interceptor sends one request
builder through the engine twice, each engine call gets its own object.

### Which connection served this call?

Since 0.3.0 the diagnostics also name the connection (experimental): `connection` is a `QuicConnectionSnapshot` for a
call over HTTP/3 and a `TcpConnectionSnapshot` for HTTP/2 and HTTP/1.1, both with the `transport`, the `protocol`, the
`localAddress` and `remoteAddress` (the proxy's through one) and whether the call `reused` a connection that was open
before it. `transport` on the diagnostics themselves says `Quic` or `Tcp`.

- `QuicConnectionSnapshot` names the connection by its `connectionId`, the `ConnectionInfo.id` the
  `http3 { connectionListener }` hears (the connection's name for its whole life, and of its qlog trace); the active
  `path` and all `paths` with the connection IDs on each ([QUIC: Observability](quic.md#observability)); `smoothedRtt`,
  `minRtt` and `rttVariation`; and `pathChanges`, the moves to another path (migrations, NAT rebindings, the server's
  preferred address) between the moment this call took the connection and the snapshot; and the QUIC `version` the
  handshake settled, `VersionProfile.V1` or `V2` (RFC 9369), which can differ from the one the client offered first
  when both sides allow both ([QUIC: Configuration](quic.md#configuration)). It is plain data, no handle:
  neither a response nor an exception that carries the diagnostics keeps the connection in memory (for the live
  connection, join `connectionId` with what the listener hears). From the response head until the call ends, each read
  of `connection` takes a snapshot of the live connection; when the call ends — its body read or the response released,
  which is after `execute { }` returned or `bodyAsText()` read it all — one last snapshot is taken and kept, so a call
  read afterwards shows the RTT of its end and every move during its download. Calls that share a connection share its
  moves: one during two calls counts for both.
- `TcpConnectionSnapshot` has the `alpn` the server chose, whether the connection is `secure` and goes `viaProxy`.

```kotlin
// guide:ktor:client-connection
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val d =
    client.prepareGet(url).execute { response ->
        response.bodyAsChannel().discard()
        response.kuicksilverDiagnostics
    }
val c = d?.connection
if (c is QuicConnectionSnapshot) {
    println("HTTP/3 ${c.connectionId}: path #${c.path?.id?.value} ${c.localAddress}, srtt ${c.smoothedRtt}, ${c.pathChanges} moves")
} else if (c is TcpConnectionSnapshot) {
    println("${c.protocol} to ${c.remoteAddress} (${c.alpn}), reused=${c.reused}")
}
```

What it costs per call, nothing per packet: an HTTP/3 call keeps one small handle while it runs and makes one snapshot
at its end (a statistics read and two objects), plus one per read of `connection` during the call; a TCP call makes one
snapshot per connection it is sent on; a TCP setup that dials tracks its progress in one more object. The
connection IDs in `path` are linkable identifiers: show them in your own app's diagnostic screens, but do not send them
elsewhere (see `PathInfo`); the snapshots' `toString()` leaves them out, and the engine never logs them.

### Why did this call fail?

The exception of a failed call carries its diagnostics (experimental, since 0.3.0): `e.kuicksilverDiagnostics` (on the
exception or one of its causes) is the call's `ProtocolDiagnostics`, which the request's attributes held while it ran.

- `transport` is the transport the thrown failure came from: `Quic` (an HTTP/3 failure: `H3Only`, or a request HTTP/3
  had sent and could not fall back) or `Tcp` (HTTP/1.1 or HTTP/2, after a fallback or a lost race too); null only when
  the call failed before it tried either (a configuration the request cannot use).
- `h3Failure` is HTTP/3's failure when TCP came after it, whether TCP then failed or not; `fallback` classifies it.
- `connection` is the connection the failure came from, when one was up: a `TcpConnectionSnapshot` with a null
  `protocol` when its TLS handshake failed.
- `connectFailures` lists every connection setup that failed for the call, in order: each a `ConnectFailure` with the
  `transport`, the `stage` (`TcpConnect`, `ProxyHandshake`, `TlsHandshake`, `QuicHandshake`, or a wait below), the `address` tried and the
  `cause`. A TLS 1.2-only server's answer to this client's TLS 1.3 ClientHello, for example, is a `TlsHandshake` failure
  whose cause is a `TlsException.AlertReceived` with `description = "protocol_version"`. A QUIC failure says how far the
  handshake got (`quicProgress`: `NoPacketReceived` — UDP blocked or the server silent — or `HandshakeStarted`) and
  names the connection by its `connectionId` (the `ConnectionInfo.id` the `connectionListener` and qlog use). The
  connect timeout is a failure too: one per attempt it cut short, at the step it was in (`TcpConnect`, `TlsHandshake`,
  `QuicHandshake`...), with the call's `ConnectTimeoutException` as the cause, or one without an address naming what
  the time went to before any address was tried: `NameLookup`, `PoolWait` (every connection slot of the route,
  `maxConnectionsPerRoute`, in use) or `H2DialWait` (another request's HTTP/2 connect to the route). Attempts the engine cancelled because another won (the
  address race, the HTTP/3 and TCP race) are not failures. With `earlyData`, a handshake that fails after the request
  went out in 0-RTT is reported when it fails, which may be after the call ended.

```kotlin
// guide:ktor:client-failure
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
try {
    client.get(url)
} catch (e: Exception) {
    val d = e.kuicksilverDiagnostics
    val over =
        when (d?.transport) {
            Transport.Quic -> "QUIC"
            Transport.Tcp -> "TCP"
            null -> "no transport"
        }
    println("failed over $over: $e; HTTP/3 before it: ${d?.h3Failure}")
    d?.connectFailures?.forEach { f: ConnectFailure -> println("  ${f.stage} to ${f.address}: ${f.cause}") }
}
```

The event listener hears the same as it happens: `connectFailed(request, failure)` once per failed setup (also for a
call that then succeeded another way), and in `callFailed(request, cause)` the request's attributes still hold the
call's diagnostics (`request.attributes[KuicksilverDiagnosticsKey]`; the engine removes them once `callFailed` returned).
The engine attaches the diagnostics to the exception as a suppressed `FailureDiagnostics` whose message is one line —
`kuicksilver: failed over TCP; HTTP/3 failed first: Timeout (HandshakeTimeout); setups failed: QuicHandshake,
TlsHandshake` — with types and stages only, never a URL, host, address or connection ID; on the JVM and Android it has no
stack of its own, so a printed stack trace gains that one line. Ktor's request timeout (`HttpTimeout`) cancels the call
with its `HttpRequestTimeoutException`, the exception Ktor then throws, and that one carries the diagnostics. A call the
application cancels carries none; `callFailed` has the request's own diagnostics then. A connection's failure reaches
every request on the connection, and the connection listener, as one instance: the engine never puts a call's
diagnostics on that instance. A call that fails with it in the engine throws its own copy (same type, fields and cause)
carrying its diagnostics, and `callFailed` gets that copy; a call that meets it later, reading its response body, gets the instance itself, which carries
none (the body's failure comes after the call's end), as does the `ConnectionLost` that `onClosed` hears.

<a id="who-ended-the-connection"></a>
**Who ended the connection** (experimental, 0.3.0). When the TCP connection under an HTTP/1.1 or HTTP/2 call ended, a
`ConnectionEndedException` (package `io.kuicksilver.io`) among the exception's causes says who ended it, so a test
harness or an app need not match messages:

- `PeerClosed`: the peer's FIN where more was expected. Over HTTP/2 the connection's input ended; over HTTP/1.1 the
  response was cut (no response, a head without its empty line, a body short of its `Content-Length` or chunked framing),
  where the exception is the `EOFException` it always was, with `PeerClosed` as its cause.
- `PeerUnresponsive`: an HTTP/2 PING unanswered (the `pingInterval` keepalive or a pooled connection's health check),
  or the socket timeout, or a WebSocket's connect timeout, expired while the whole request was out and only the
  server's answer was awaited. While the request was still going out (a request body the application produces slowly)
  the cut is a plain `IOException`: nothing says whose side stalled.
- `LocalClose`: this client closed the connection, or read after closing it (`Socket closed`, `The connection was
  aborted`).

A reset is not typed: it stays the platform's exception (a `SocketException` on the JVM and Android, the receive error
on Kotlin/Native), as does any other failure of the socket. An HTTP/2 call usually fails with
`Http2Exception.ConnectionClosed` whose cause is one of these:
`generateSequence(e) { it.cause }.filterIsInstance<ConnectionEndedException>().firstOrNull()`. They are `IOException`s
with the messages they always had, so existing `catch` blocks and log matches still work. A QUIC connection's end is a
`QuicException.ConnectionLost` with its `initiator` instead, a TLS failure a `TlsException`, a timeout the call sees
Ktor's `ConnectTimeoutException` or `SocketTimeoutException`.

### Graceful stop

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

## 0-RTT (opt-in, experimental)

Both engines can resume HTTP/3 connections with 0-RTT ([ADR-0015](../adr/0015-0rtt-implementation.md)): a returning
client sends its first requests with its first flight, one round trip earlier. It is off by default on both sides, it
exists only over QUIC (HTTP/1.1 and HTTP/2 over TCP never send or accept early data), and the price is that an early
request can be **replayed**: an attacker who recorded the client's first flight can send it to the server again
(RFC 9846 section 8). This section is everything an application needs to decide whether to turn it on.

- **Server:** set `http3 { earlyData { enabled = true } }` in the engine configuration (`EngineMain`:
  `kuicksilver.http3.earlyData.enabled = true`). Requests the early-data policy calls replayable
  (GET, HEAD and OPTIONS by default) that arrive in 0-RTT run before the handshake completes, and
  `call.request.receivedEarly` is true for them. Every other early request waits for the handshake (the default policy,
  `Http3EarlyDataPolicy.WaitForHandshake()`): a replayed copy never completes the handshake, so it never runs.
  `http3 { earlyData { policy = Http3EarlyDataPolicy.Reject425() } }` answers those with `425 Too Early` instead,
  without running the handler, and the client repeats them after its handshake (RFC 8470 section 5.2); replayable
  requests still run early under both policies. Without `earlyData { enabled }` the server issues no session tickets for QUIC, so
  HTTP/3 clients run a full handshake every time.
- **Behind a gateway** (with or without `http3 { earlyData { enabled } }`): a CDN or reverse proxy that forwards a request it received in
  early data marks it `Early-Data: 1` (RFC 8470 section 5.1), and such a request may be a replay whatever the state of
  the connection it arrives on. Over HTTP/1.1 and HTTP/3 the server engine sets `call.request.receivedEarly` for it and
  answers `425 Too Early` to any such request the early-data policy does not declare replayable (over HTTP/1.1: anything
  but GET, HEAD and OPTIONS), without running the handler; the gateway forwards the 425 and its client retries after
  its handshake. Gate side effects on `receivedEarly`, not on the TLS state of your own connection.
- **Client:** set `http3 { earlyData { enabled = true } }`. On a new connection to a server it has a ticket for, the engine sends
  GET, HEAD and OPTIONS requests without a body in 0-RTT; other requests wait for the handshake. A `425` is retried
  once; when the server rejects 0-RTT as a whole, the early requests are repeated once on the same connection after its
  handshake (neither counts in `attempts`). 0-RTT keeps the h3/h1 race and the fallback intact:
  - A 0-RTT connection wins the race at once only on a network where QUIC was already seen working; elsewhere it must
    complete its handshake first, as in Chromium, so a network that drops UDP loses nothing over HTTP/1.1.
  - QUIC counts as working on the network, the alternative as working, and the connection's RTT is remembered only
    once the handshake completed, never on the 0-RTT start alone.
  - The connect timeout bounds the handshake of a 0-RTT connection (its handshake timer is cut to it): a GET sent early
    on a path that went dark fails then and falls back to TCP (the engine derives the QUIC `handshakeTimeout` from
    `connectTimeout` anyway).
  - A request that waits for the handshake (POST, or anything with a body) has not been sent when the handshake fails:
    it goes over TCP like any request whose HTTP/3 connection could not be set up.
- **Tickets on the client** live in memory, in the engine's QUIC endpoint, for as long as the `HttpClient` lives: each
  is used once, checked against the current `tls { trust }` before use, and dropped when the client closes. Nothing is
  persisted, so after an app restart (or a new `HttpClient`) the first connection to each server is a full handshake,
  and 0-RTT starts from the next one.
- **Client certificates:** a server that asks for them cannot accept 0-RTT, and `earlyData { enabled = true }` with a
  `tls { clientAuth }` other than `None` fails the start ([Mutual TLS](#mutual-tls-client-certificates)).

```kotlin
// guide:ktor:zero-rtt-server
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val server = embeddedServer(Kuicksilver, configure = {
    tlsConnector {
        tls { this.identity = identity }
        port = 443
    }
    http3 {
        earlyData {
            enabled = true
            policy = Http3EarlyDataPolicy.Reject425()   // or keep the default: unsafe requests wait
        }
    }
}, module = Application::module)
// guide:ktor:zero-rtt-client
val client = HttpClient(Kuicksilver) {
    engine { http3 { earlyData { enabled = true } } }
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
    tlsConnector {
        tls { this.identity = identity }
        port = 443
    }
    http3 {
        earlyData {
            enabled = true
            this.policy = policy
        }
    }
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
   every `http3 { endpoint { loops } }` loop of the process shares it. When it is full (it uses at most 1 MiB), 0-RTT is refused
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
test runs twice — `Kuicksilver-h1` (cleartext HTTP/1.1, `http3 { enabled = false }`) and `Kuicksilver-h3` (HTTPS, `H3Only`). 93 tests,
90 pass in both modes, 3 are `@Ignore`d upstream. Adapted: the `HttpTimeoutTest` success budgets are widened, room
for a fresh client's handshake on a loaded host (comments in the file). Left out:

- tests that need modules this project does not depend on: JSON content negotiation (`testJsonPostWithEmptyBody`),
  `ktor-client-auth` (three bearer-token WebSocket tests), kotlinx-serialization (`testWebSocketHeaders`, which over
  HTTP/3 would also have no `Connection`/`Upgrade`/`Sec-WebSocket-Key` to compare — RFC 9220 drops them);
- `testWebsocketWithDefaultRequest` over HTTP/3 only: `defaultRequest` sets host and port, so the URL stays `ws://`;
- `ServerSentEventsTest` and `HeadersTest`: they need serialization, logging and auth plugins (SSE is covered by the
  engine's own tests over all three protocols).

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

**Other HTTP implementations.** The engine interop bench runs both engines against Ktor's Netty and CIO engines,
OkHttp, the JDK's HttpClient and Netty's HTTP/2 and HTTP/3 codecs on the JVM; its pairs, scenarios and the peers'
deviations are in [interop.md](../spec/interop.md#engine-interop-the-ktor-engines-against-other-http-stacks-jvm-2026-11-13).

**Other WebSocket peers.** The engines check every frame against the handshake (RFC 6455 sections 5.1 and 5.2, RFC
7692 section 6.1), stricter than Ktor's own engines:

- Ktor's `WebSocketDeflateExtension` compresses each fragment of a message on its own and sets RSV1 on every fragment,
  not only the first. A peer that uses it and fragments a compressed message is closed with 1002 by Kuicksilver's
  engines; unfragmented messages, the common case, pass. When Ktor's extension runs in Kuicksilver's engines, they send
  such a message as an RFC 7692 one (RSV1 on the first frame only, the fragments one DEFLATE stream); a message in which
  Ktor's `compressCondition` left a fragment uncompressed cannot be, and fails with `ProtocolViolationException`.
- A client that does not mask its frames, or a server that masks them, is closed with 1002, as the RFC requires; Ktor's
  own frame readers accept either.
- Ktor 3.6.1's WebSocket writer on Kotlin/Native (its common `RawWebSocket`) sends every fragment of a message with the
  message's opcode instead of 0 (continuation), so a fragmented message sent from Kotlin/Native through another engine
  is refused by the peer as a new message inside an unfinished one. Kuicksilver's engines send the later fragments as
  continuations on every platform (0.3.0); with another engine on Kotlin/Native, send whole messages. Its JVM writer is
  right.
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
  `0.0.0.0` stay the wildcards, and a connector without a `host` binds `::` with `IPV6_V6ONLY` off, one dual-stack socket
  that IPv4 clients reach as IPv4-mapped addresses;
- the client's HTTP/1.1 connection (and its connection to an HTTP proxy) goes to the address in the URL; an
  IPv4-mapped literal (`[::ffff:127.0.0.1]`) is connected over IPv4, as the JVM does. A host name is resolved to all its
  addresses and connected with Happy Eyeballs ([Happy Eyeballs](#happy-eyeballs)); HTTP/3 races the same addresses over
  QUIC.
- Name lookups block a thread (`getaddrinfo`): at most 8 of each address family run at once, on their own share of
  `Dispatchers.IO`, and a name has one lookup per address family in flight however many requests wait for it, so a stalled resolver cannot take the
  threads the sockets run on (threat model 3.21). An address literal is never looked up.

HTTP/3 uses the accelerated `ksl` UDP socket, which carries the full address on every platform (the Ktor client's endpoint
is dual-stack, ADR-0006). The portable Kotlin/Native UDP socket (`IoPreference.Portable`, or a sandbox that refuses the
accelerated one) still uses `ktor-network`: it refuses to bind a specific IPv6 address (`UnsupportedOperationException`)
and to send to an IPv6 address (`IOException`), for the same reason. Tests:
`ServerH1Test.negative_ipv6ConnectorListensOnItsAddressOnly`,
`ClientH1Test.negative_h1ToIpv6LiteralReachesThatAddressOnly`, `ClientH1Test.plainHttpToIpv6Literal`,
`ClientH3Test.h1ToIpv6Loopback`, `TcpSocketsTest`, `KtorDatagramIoTest`.
