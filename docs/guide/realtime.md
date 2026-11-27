<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# WebSockets, server-sent events, WebTransport and priorities

**What this page is for.** WebSockets on both engines over HTTP/1.1, HTTP/2 and HTTP/3, their compression,
server-sent events, WebTransport sessions on the server and the client, and request priorities.

**Before you start**

- Words such as origin, alternative, route or race: the [glossary](glossary.md).
- The imports of the code blocks: [Ktor engines: Imports](ktor.md#imports). WebTransport below the engines: [HTTP/3:
  WebTransport](http3.md#webtransport-experimental).

## WebSockets on the server

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

The client engine applies the same rules to what servers send ([Client](client.md)).

## WebSockets over HTTP/2

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

## WebSockets over HTTP/3

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

## Server-sent events

Ktor's `SSE` plugins work on both engines over HTTP/1.1, HTTP/2 and HTTP/3: `sse("/path") {}` routes on the server,
`client.sse(url) {}` and `client.serverSentEventsSession(url)` on the client, with `SSECapability` declared by the client
engine. A client session holds its response's stream (or, over HTTP/1.1, its connection) for as long as the session is
open, pauses between events included, and gets every event in order. Ending a session the application holds, by leaving
the `sse {}` block, cancelling the session or cancelling the coroutine that collects it, abandons the stream: over HTTP/2
it is reset with RST_STREAM CANCEL (RFC 9113 section 8.1), over HTTP/3 the client sends STOP_SENDING with
H3_REQUEST_CANCELLED (RFC 9114 section 4.1.1), over HTTP/1.1 the connection is closed, and the server's `sse {}` handler
ends when its next event cannot be sent. As any call in flight, an open session keeps a closed client's cleanup waiting
until the session ends ([Closing the client](client.md#closing-the-client)).

- **Collect or cancel sessions promptly.** A session holds its call until it has read its body to the end, or was
  cancelled: not merely until the whole body arrived. A session nobody collects keeps its call, its stream slot and,
  over HTTP/2, the flow-control credit of what it has not read, up to the stream's window (`http2 { settings {
  initialStreamWindow } }`, 512 KiB, growing up to `maxStreamWindow` while read) out of the connection's, which the
  connection's other streams then do without.
- **Cancellation before the session is handed out leaks, on every Ktor engine.** `serverSentEventsSession()` (and `sse
  {}`, which calls it) runs the request in a coroutine of the client's own scope: when the coroutine that called it is
  cancelled before the response head came, the request goes on, and the session made from the response is handed to
  nobody. Nothing reads or closes it, so it holds its call, stream or connection while the server streams on, and
  `client.close()` never completes. This is Ktor's (3.6.1, CIO and OkHttp alike); the engine gets no signal that the
  session was dropped. Avoid cancelling a caller that waits for a session (a timeout around `serverSentEventsSession()`
  included); where it can happen, a client plugin that keeps each SSE response's `coroutineContext[Job]` can cancel the
  call, which ends it.

Before 0.3.0 a client session over HTTP/3 got no events, or only those that had arrived before Ktor handed it the
response, and ended without an error: the engine released the stream once Ktor completed the call, which the `SSE` plugin
does before the session reads. HTTP/1.1 was not affected, and HTTP/2, new in 0.3.0, works too.

## WebSocket compression (experimental)

`PerMessageDeflate` (`kuicksilver-ktor-network`, `@ExperimentalKuicksilverApi`) is permessage-deflate (RFC 7692) for
Ktor's `WebSockets` plugins on every target: java.util.zip on the JVM and Android, the platform's zlib on Kotlin/Native.
Install it in the client plugin, the server plugin, or both; it works on any Ktor engine, and on Kuicksilver's engines
over HTTP/1.1 and HTTP/3 (RFC 9220) alike.

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:websocket-deflate-client
val client =
    HttpClient(Kuicksilver) {
        install(WebSockets) { extensions { install(PerMessageDeflate) } }
    }
```

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:websocket-deflate-server
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

## WebTransport over HTTP/3 (experimental)

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
connection takes new sessions at (a burst of 32, then 8 a second), is refused before any route runs. The engine raises the
connection's receive window to `maxSessionsPerConnection x initialMaxData` (15 MiB with the defaults), so the server's
worst case of unread stream data is that times `http3 { endpoint { maxConnections } }`: size the three together. A draft-14 client that leaves a session without flow-control credit for ten seconds is logged once, as a warning,
through the application's log.

```kotlin
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:webtransport-server
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

## WebTransport on the client (experimental)

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
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val client = HttpClient(Kuicksilver)
val url = "https://example.com/echo"
// guide:ktor:webtransport-client
val session = client.webTransport(url, protocols = listOf("echo-v1"))
val stream = session.openBidi()
stream.output.writeFully("ping".encodeToByteArray())
stream.output.flushAndClose()
println(stream.input.readBuffer().readString())
session.close(0, "done")                           // the session's own connection closes with it
```

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
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:priority-server
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
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
// guide:ktor:priority-client
val page = client.get("$origin/index.html") { priority(urgency = 1) }
client.prepareGet("$origin/video.mp4") { priority(urgency = 5, incremental = true) }.execute { response ->
    response.updatePriority(urgency = 2, incremental = true) // now in view: more urgent
    response.bodyAsChannel().discard()
}
```

## Behaviour reference

How the client engine handles WebSocket handshakes, frames and closes, for when the sections above are not enough.

### The client's WebSocket checks

With `WebSocketExtensionsCapability` Ktor's `WebSockets` plugin offers the extensions installed with
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
application brings with its own specification defines its payload: with one agreed, text is not checked. The engine
answers every Ping itself as soon as it reads it (RFC 6455 section 5.5.2: "as soon as is practical"), with a Pong
carrying its data, between the frames the session is sending; it drops the Pong the session then writes for that
Ping, so the peer gets one. Pings are answered after this side's Close too, until the peer's: the engine keeps its
side of the transport open after its Close until the peer's Close arrives (or the close wait passes, 5 s; on the
client `webSocketCloseWaitMillis`), and closes it then, at once when the peer answers the Close promptly. This holds for a raw `webSocketRaw` session too,
which still sees the Ping in `incoming` but no longer needs to answer it: its own Pong with the Ping's data is taken
for that answer and dropped (an unsolicited Pong with other data goes out).

### Which protocol a client WebSocket takes, and how it closes

WebSockets use HTTP/1.1 `Upgrade` unless an HTTP/3 connection to the origin already allows Extended CONNECT and has
not received GOAWAY (or the mode is `H3Only`), or an HTTP/2 one does ([HTTP/2 on the client](client.md#http2-on-the-client)); over HTTP/3 the handshake is RFC
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
they still wait for. The pools close after that, as for any request (at most about 3 s more: the HTTP/1.1 and HTTP/2 connections' orderly closes, and at the same time each HTTP/3 connection's wait of up to 1 s for the server to acknowledge what it sent, then its close, repeated once a probe timeout later, at most 250 ms). The connection, its pool slot and the engine's
`close()` wait for the session, not for the call: `client.close()` right after `close(reason)` still sends the Close
before the pools close. A call that fails or is cancelled before the session queued its Close still closes it with the
closing handshake (RFC 6455 sections 7.1.7 and 7.3): one Close, 1001 Going Away (or the application's own code when it sends
one, as from a `finally`), bounded by the same close wait; only a call that ends during the handshake ends it at once. A coroutine of
the session that fails is reported to the event listener (`webSocketFailed`).

A closed client waits for no server once its Close is written. Once the engine is closed (Ktor closes it when
`client.close()` was called and the client's open work is over; a session of `webSocketSession()` still open counts as
such work), a session that wrote its own Close (RFC 6455 section 7.1.2) no longer waits for the server's Close or its
close of the transport, whether it was closing then or closes later; its transport ends cleanly (close_notify and a FIN,
END_STREAM, a FIN; section 5.5.1: the client "MAY close the connection at any time after sending and receiving a Close
message"). A session ended so before the server's Close is not a clean close (section 7.1.5: 1006), though Ktor's
`closeReason` reports the client's own code. Until the server ends its side the Close may be unread there, so the server
gets 1 s to read it and end, and over HTTP/2 and HTTP/3 a Close it never answered keeps the rest of its close wait (at
least the grace; over HTTP/2 the Close counts as written only once the stream took it), so that the end of the stream or
the connection does not discard it. A session whose Close cannot be written (a server that reads slowly or not at all)
keeps its close wait: the engine's close does not cut it short. Over HTTP/1.1 the connection closes after the grace, and
bytes the server still sends then get a reset from the closed socket (RFC 6455 sections 5.5.1 and 7.1.1 allow the
close). While the client is open the waits above apply in full. The server engine's stop likewise stops waiting for a
client's END_STREAM or FIN after a WebSocket that ended in order, so its grace period goes to the requests still
running.
