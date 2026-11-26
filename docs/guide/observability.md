<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Observability and diagnostics

**What this page is for.** Logging, event listeners, metrics and qlog of both engines, and per call: why a
request did not use HTTP/3, which connection served it, and why a call failed.

**Before you start**

- Words such as origin, alternative, route or race: the [glossary](glossary.md).
- The engines log through `observability { logger }`: the platform's logger on the client (warnings and up), Ktor's
  application log on the server.
- The imports of the code blocks: [Ktor engines: Imports](ktor.md#imports).

Both engines report what they do without a logging dependency, in their `observability { }` block: `logger` and `qlog`
are stable, the listeners (`eventListener`, `connectionListener`) experimental. The QUIC side
is the one described in [QUIC: Observability](quic.md#observability): counters, a `KuicksilverLogger`, a
`ConnectionListener` and qlog.
[`samples/kq-cli`](../../samples/kq-cli/README.md) puts the client side together in a command line, `kq get -v <url>`:
the protocol of each response and why, the QUIC connection (handshake time, RTT, ALPN, 0-RTT), the `Alt-Svc` learned
and a qlog trace per connection, built for macOS, Linux and Windows.

**Server.** A logger, a qlog sink and an event listener on the server engine:

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:server-observability
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

In the engine's `observability { }` block, `logger` receives the engine's diagnostics, its listeners and
connections on every protocol and its HTTP/3 endpoints (`ServerObservability.ApplicationLog`, the default, is the
application's log, `environment.log`; a warning about one call's answer goes there either way; on Android a logger of
your own needs `org.slf4j:slf4j-api` 2.x on the class path, since the engine hands it to Ktor as an SLF4J `Logger` built on
SLF4J 2's `LegacyAbstractLogger`: Ktor's server brings 2.x, but an app whose dependencies force SLF4J 1.7, as some older
Android libraries do, fails at the engine's start with a `NoClassDefFoundError`),
`connectionListener` (*experimental*) hears every QUIC connection, `qlog` adds a trace per HTTP/3 connection, and
`eventListener` (*experimental*) takes a
`KuicksilverServerEventListener`: `connectionOpened` and `connectionClosed` with the protocol (`HTTP/1.1` or `HTTP/2.0`
after the TLS handshake, `HTTP/3.0` once accepted) and the peer's address, `tlsHandshakeFailed`, `connectionRefused` (a
TCP client closed at accept, before TLS, with the reason: `per-IP limit` or `HTTP/2 repeat offender`; see [Connection
limits](server.md#connection-limits)), and `requestStarted` / `requestEnded`
around the application's pipeline with the `ApplicationCall` (its response status) and the pipeline's failure, if any.
On the running engine, `engine.http3Stats` (0.3.0) gives the QUIC endpoint counters (`EndpointStats`) of every HTTP/3
listener, one per connector serving HTTP/3: datagrams, drops, refusals by the admission policy, the connection limits
and the accept queue, handshakes ([Deploying: Observability](deployment.md#observability)).

**Client.** `engine { observability { eventListener = ... } }` takes a `KuicksilverEventListener`, an abstract class with an empty method
per event in the manner of OkHttp's `EventListener`: `callStart`, `callEnd` (protocol and status) or `callFailed`;
`protocolSelected` with a `ProtocolReason` (`Configuration`, `NotSecure`, `ExistingConnection`, `Race`, `NoAlternative`,
`BrokenAlternative`, `WebSocket`, `Fallback`, `Proxy`, `Http3Disabled`, `HttpsRecord`; on the TCP path it comes once the
connection is in hand, with `HTTP_2_0` when the server picked `h2`, since 0.3.0); `raceEnded` (winner, head start, why HTTP/3 lost); `altSvcUsed`,
`httpsRecordUsed` (an endpoint of the origin's HTTPS record) and `altSvcMarkedBroken`; `fallback` from HTTP/3 to TCP,
with the HTTP/3 failure itself (not the `FallbackReason`, which is on the response, below); `retry` (a request the server
did not process after GOAWAY, HTTP_1_1_REQUIRED over HTTP/2, a stale pooled HTTP/1.1 connection, a 417); `connectionAcquired`
(reused or new) and `connectionReleased` (kept for the next request or closed); `connectionMigrated` (an HTTP/3 connection
followed the network, [Connection migration](client-http3.md#connection-migration)); `webSocketFailed` (a coroutine of a WebSocket
session failed; it can come after `callEnd`, since a session may outlive its call while it writes its own Close);
`dnsStart` and `dnsEnd` (since 0.3.0, as OkHttp's: one pair per name lookup, per address family for the system's resolver
and a `FamilyDns`, once for both with a plain `Dns`; the end carries the addresses the engine may connect to, or the
failure; no lookup and no event for an address literal, [Name resolution](client.md#name-resolution-experimental)); `connectFailed`
(since 0.3.0: a connection setup that failed, a TCP connect to one address, a proxy or TLS handshake over TCP, or a QUIC
handshake, with its address; [Why did this call fail?](#why-did-this-call-fail)). `observability { logger }`
(`KuicksilverLogger.Default`, the platform's logger at warnings and up) receives the engine's and its QUIC endpoints'
diagnostics and the listener's own failures, and `observability { qlog; connectionListener }` reach the engine's QUIC
endpoints.

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:client-observability
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

Closing the client and waiting for its qlog traces to be complete: [Closing the client](client.md#closing-the-client).

Callbacks of both listeners run on the engines' coroutines and must return quickly; an exception out of one is logged and
never fails a call.

## Why did this request not use HTTP/3?

Every response of the client engine carries a `ProtocolDiagnostics` (experimental): `response.kuicksilverDiagnostics`
(the call attribute `KuicksilverDiagnosticsKey`) says which `protocol` served the call, the `reason` that
`protocolSelected` heard last, and, when the call did not go over HTTP/3, why (`fallback`, a `FallbackReason`), with
the HTTP/3 `alternative` (`host:port`) and its `alternativeSource` (`AltSvc`, `QuicHint`, `Preferred`, `H3Only`),
whether the setups `raced` and HTTP/3's `headStart`, the HTTP/3 failure itself (`h3Failure`) when there was one, and
the number of `attempts`: the first, plus one per repeat by the engine (a request the server did not process after
GOAWAY or `H3_REQUEST_REJECTED`, or that `closeHttp3Connections()` stopped before it went out; a stale pooled HTTP/1.1
connection; a 417 to `Expect: 100-continue`; a 421 from the alternative), plus one for the fallback to TCP when
HTTP/3 had tried the request. The HTTP/3 layer's own repeats of a 0-RTT request on the same connection (early data
rejected, 425 Too Early) are not counted.

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val url = "https://example.com/"
// guide:ktor:client-diagnostics
val response = client.get(url)
val d = response.kuicksilverDiagnostics
if (d == null) {
    println("not served by Kuicksilver: create the client with HttpClient(Kuicksilver)")
} else if (d.protocol != HttpProtocolVersion.HTTP_3_0) {
    println("HTTP/3 not used: ${d.fallback} (alternative ${d.alternative} via ${d.alternativeSource})")
}
```

What each `fallback` means and what to check for it is in one table, in troubleshooting: [every
`FallbackReason`](troubleshooting.md#the-ktor-client-never-uses-http3-or-stops-using-it), after a short list of what to
check first.

The engine's `observability { logger }` gets one line per call that HTTP/3 could have served but did not (a lost race, a
fallback, a broken alternative, a proxy) at `observability { protocolChoiceLogLevel }`, `Info` by default — which the
default logger, the platform's at warnings and up, leaves out: set `logger = KuicksilverLogger.platform(LogLevel.Info)`
to see them (the first alternative marked broken on a network is one Warn line all the same). Calls over HTTP/3, and
calls HTTP/3 was never a candidate for (`http://`, `http3 { enabled = false }`, `Auto` without `Alt-Svc`), are logged
at `Debug`. The first call to an origin whose response advertised no HTTP/3 (no usable `h3` in its `Alt-Svc`)
also gets one line at the protocol-choice level, once per origin for the client: `kuicksilver: https://example.com: no usable HTTP/3
alternative, using HTTP/2.0`. An alternative the client refuses (an unprivileged port for a privileged origin, say) counts
as none. A server that announces HTTP/3 only in an ALTSVC frame on its HTTP/2 connection, not in an `Alt-Svc` header
field, may still get the line on its first call: the frame can be learned after the response. `null` turns the lines off. The line is built only when the logger wants its level, and its format stays the same within 0.3.x:

```text
kuicksilver: GET https://example.com/path -> HTTP/2.0 (fallback=HandshakeTimeout, alt=example.com:443 via AltSvc, raced, headStart=10ms, h3Failure=Timeout, marked broken)
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
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
fun logLine(line: String) = println(line)   // your logging library
// guide:ktor:protocol-log
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

The first call to a new origin in `Auto` mode logs `https://example.com/ -> HTTP/2.0 (NoAlternative, fallback=NoAlternative,
h3Failure=null)`; a later one over HTTP/3 `-> HTTP/3.0 (...)` with `fallback=null`. `response.call.request.url` carries
the query: log `encodedPath` instead when queries hold tokens.

A call that fails has no response: its exception carries the diagnostics instead ([Why did this call
fail?](#why-did-this-call-fail)). When both the HTTP/3 and the TCP setups failed, the TCP failure is thrown
with the HTTP/3 one in `suppressed`. The diagnostics live as long as the response (they are one of its call's
attributes); the engine keeps no copy of the HTTP/3 failure, and a broken mark remembers only its `FallbackReason`. Read
them from the response: the engine puts a new object into the request's attributes when the call reaches it and fills it
as the call goes, so code that looks at the request earlier (a listener during the call, a plugin running after a
redirect copied the previous request's attributes) sees incomplete or stale ones; when an interceptor sends one request
builder through the engine twice, each engine call gets its own object.

## Which connection served this call?

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
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:client-connection
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

## Why did this call fail?

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
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:client-failure
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
