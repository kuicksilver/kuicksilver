<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# HTTP/3 with Kuicksilver

**What this page is for.** It explains the HTTP/3 layer on its own, without Ktor: QPACK, requests and responses, endpoints,
0-RTT, shutdown, priorities, Extended CONNECT, capsules and WebTransport. If you use Ktor, start with [Ktor engines](ktor.md).

**Before you start**

- Dependency: `io.kuicksilver:kuicksilver-http3:0.3.0` or newer (it brings `kuicksilver-quic` and `kuicksilver-tls`).
  Built with Kotlin 2.4.20: JVM and Android need Kotlin 2.3 or newer, Kotlin/Native 2.4.x
  ([Kotlin version](../stability.md#kotlin-version)).
- Platforms: JVM 17 or newer, Android `minSdk` 24, iOS 15, macOS 12 (macOS 11 on the JVM), Linux, Windows
  ([Platforms](../stability.md#platforms)).
- A server needs a `TlsIdentity` (certificate chain and private key); a client needs a trust configuration
  (`TrustConfig.Platform` by default). See [TLS: Configuration](tls.md#configuration).

**Minimal example.** A server that answers requests is [Serving requests](#serving-requests), a client request is
[Client requests](#client-requests), and both start from [Endpoints and connections](#endpoints-and-connections).

<a id="imports"></a>
**Imports.** The code blocks on this page start after their imports; these are the imports they use, and the test that
compiles them fails when a name moves. `InetSocketAddress` is ktor-network's, on every target. Experimental API needs
`@file:OptIn(ExperimentalKuicksilverApi::class)` or the module-wide opt-in ([stability](../stability.md#stability-levels)).

```kotlin
// guide:http3:imports
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.Capsule
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.acceptWebTransport
import io.kuicksilver.http3.capsuleConfig
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.webTransport
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.io.readString
```

Kuicksilver's HTTP/3 layer (`io.kuicksilver:kuicksilver-http3`) implements HTTP/3 (RFC 9114) with QPACK (RFC 9204),
extensible priorities (RFC 9218), Extended CONNECT (RFC 9220) and HTTP datagrams (RFC 9297) on top of
`kuicksilver-quic`. Server push is not implemented. The frame and QPACK codecs are sans-IO (ADR-0004); the connection
runtime is a set of coroutines over `QuicConnection` streams. The code blocks below compile and run as
`GuideSamplesTest` (`kuicksilver-http3/src/jvmTest`).

## QPACK

Header compression uses the static table always and the dynamic table only when both sides allow it:

- What we advertise to the peer (`Http3Settings.qpackMaxTableCapacity`, `qpackBlockedStreams`) defaults to 0/0, like
  most implementations: the peer's encoder then sends static references and literals only. `enableQpackDynamicTable()`
  advertises 4096 bytes and 16 blocked streams.
- Our own encoder uses at most `encoderMaxTableCapacity` (4096 by default) of whatever the peer advertises, and blocks
  at most min(peer's `SETTINGS_QPACK_BLOCKED_STREAMS`, 100) streams. Without a blocking budget it still inserts
  entries, but references them only once the peer has acknowledged them.
- At most 1000 sections wait for the peer's acknowledgment; above that the encoder sends static references and
  literals until the peer catches up, so a peer that never acknowledges sections cannot grow the encoder's state.
- `authorization`, `proxy-authorization`, `cookie` and `set-cookie` are never inserted into the dynamic table and are
  sent with the never-index bit (RFC 9204 section 7.1); neither are values longer than a quarter of the table.
- The 'N' bit (RFC 9204 section 4.5.4, experimental): a received section's `Http3Headers.neverIndexed` lists the field
  lines that carried it, and `headers.withNeverIndexed("x-api-key")` sends the named fields as literals with it, never
  inserted nor referenced; a received section forwarded as it is keeps the bit (section 7.1.3).
- The decoder rejects, before allocating, integers longer than 62 bits and string literals above a ceiling, and counts
  the decoded size of a field section as it goes (name + value + 32 per line, RFC 9114 section 4.2.2), stopping at
  `maxFieldSectionSize`. In a field section the ceiling is `maxFieldSectionSize` itself and a longer string makes the
  section too large (431 on the server, `FieldSectionTooLarge` on the client; the connection lives, RFC 9204 section
  7.4); on the encoder stream it is 64 KiB and a longer string closes the connection with `QPACK_ENCODER_STREAM_ERROR`.
- An encoder-stream instruction the transport delivers in pieces is reassembled in linear time: once its length is
  known the decoder only appends bytes until it is complete (at most 2 x 64 KiB + 64 bytes are held).
- A field section that references entries still in flight on the peer's encoder stream waits for them (at most
  `qpackBlockedStreams` such streams; one more closes the connection with `QPACK_DECOMPRESSION_FAILED`). If the peer
  resets a stream while it waits, the decoder sends a Stream Cancellation.

```kotlin
// guide:http3:qpack
val settings = http3Settings { enableQpackDynamicTable() }   // advertise 4096 bytes / 16 blocked streams
val client = Http3Connection.client(quicConnection, settings)
```

## Messages and errors

Requests and responses are validated as RFC 9114 sections 4.2-4.3 require. A malformed message (a field name that is
not a lowercase token, a control character other than tab in a value (CR, LF and NUL anywhere), whitespace at either end of a value, a connection-specific field such
as `transfer-encoding`, `te` other than `trailers` or `te` in a response, a missing or duplicated pseudo-header,
`:authority` and `host` that disagree or are not `host[:port]`, a classic CONNECT without a port, DATA on a response
to HEAD or with status 204 or 304) is a *stream* error: the stream is reset with `H3_MESSAGE_ERROR` and the connection
keeps serving other requests.

Failures surface as `Http3Exception`:

| Type | When |
|---|---|
| `Http3Exception.Protocol(h3Code, initiator, streamId)` | an HTTP/3 error code closed the connection (`streamId == null`) or reset a stream; unknown codes read as `H3_NO_ERROR` |
| `Http3Exception.Qpack(code)` | a QPACK error (0x200-0x202) |
| `Http3Exception.RequestNotProcessed(retrySafe)` | the server did not process the request (`GOAWAY`, `H3_REQUEST_REJECTED`); safe to retry on a new connection |
| `Http3Exception.MessageError(streamId, reason)` | the peer's message on this stream was malformed |
| `Http3Exception.FieldSectionTooLarge(streamId, limit)` | headers or trailers above `maxFieldSectionSize` once decoded, or above the peer's limit when sending (`streamId` -1: no stream was opened) |
| `Http3Exception.Settings(message)` | an operation needs a setting the peer did not send (Extended CONNECT) |
| `Http3Exception.ConnectRejected(status, headers)` | Extended CONNECT answered with a non-2xx status |

Transport failures stay `QuicException`; `Http3Exception.fromQuic(e)` reads an HTTP/3 meaning out of an application
close or a stream reset. Every exception is copyable (`CopyableThrowable`), and cancellation is never wrapped.

## Endpoints and connections

`Http3Endpoint` binds a QUIC endpoint and speaks HTTP/3 on it. Its TLS configurations must offer ALPN `h3`; a server
closes accepted connections that negotiated anything else. `SETTINGS_H3_DATAGRAM` follows the transport: it is sent as
1 only when `QuicConfig.maxDatagramFrameSize` is not 0.

```kotlin
// guide:http3:endpoints
val server = Http3Endpoint.bind(
    InetSocketAddress("0.0.0.0", 443),
    QuicEndpointConfig.Builder().apply { this.server = QuicServerConfig.Builder(serverTls /* alpn = listOf("h3") */).build() }.build(),
)
val client = Http3Endpoint.bind(InetSocketAddress("0.0.0.0", 0))
val connection = client.connect(serverAddress, clientTls /* alpn = listOf("h3") */)
```

`Http3Connection.client(quic)` and `Http3Connection.server(quic)` also wrap a `QuicConnection` you already have. Either
way the control stream, the two QPACK streams and SETTINGS go out at once, without waiting for the peer's; a reserved
setting, frame and unidirectional stream are sent too (`Http3Settings.grease`, on by default) so peers stay tolerant of
extensions. The peer's SETTINGS are in `peerSettings` once they arrive. The peer's transport parameters must let us open
those three unidirectional streams (RFC 9114 section 6.2). `server` returns at once and opens them in the background, so
an accept loop never waits on one client; `client` returns once its SETTINGS went out. A peer that does not allow them
within three seconds has its connection closed with `H3_GENERAL_PROTOCOL_ERROR` (`client` throws it).

## Client requests

```kotlin
// guide:http3:client-request
val response = connection.request(http3Request("GET", "example.com", "/"))
println(response.status)
val body = response.body            // a ByteReadChannel; reading it to the end completes response.trailers
```

A body ends only with the message: the peer's FIN after its DATA (and trailers, if any), with `content-length`
matched. Then `isClosedForRead` is true and `readAvailable` returns -1. A body cut short — a reset, a connection that
ended, a request abandoned, a frame error — fails every read with its cause (`Http3Exception`, or the
`QuicException.ConnectionLost` of the connection) and is not `isClosedForRead`, so a read loop that stops at -1 never
takes a truncated body for a complete one; `closedCause` says why. The same holds for the request body on the server.

A request body is any `ByteReadChannel`; it is copied into DATA frames as the transport accepts it, so a slow peer
slows the producer instead of filling memory. `trailers` is called after the body ends. Interim responses (1xx,
103 Early Hints included) reach `onInformational`, any number of them (RFC 9110 section 15.2); once their fields together
exceed `maxFieldSectionSize` (64 KiB) the request fails with `H3_EXCESSIVE_LOAD`. Both callbacks run on the dispatcher of the coroutine that called `request`, never on the
connection's own single-threaded dispatcher, so a slow callback delays only its own request. There is no automatic
`100-continue`. `Http3Response.cancel()` (or cancelling the calling
coroutine) resets the stream with `H3_REQUEST_CANCELLED`; the connection keeps serving other requests.

## 0-RTT (opt-in, experimental)

`Http3Endpoint.connectEarly` resumes a ticket from an earlier connection and returns before the handshake completes
(ADR-0015). A request goes out in 0-RTT only when it sets `allowEarlyData = true` **and** is a safe method (GET, HEAD,
OPTIONS) without a body. Every other request waits for the handshake. If the server answers `425 Too Early`, the client
repeats the request once after the handshake (RFC 8470 section 5.2).

On the server, bind with `quicServerConfig(tls) { earlyData = true }`. The endpoint binds its SETTINGS into its tickets,
so changed SETTINGS refuse 0-RTT (RFC 9114 section 7.2.4.2). A request that arrived in 0-RTT before the handshake
completed is handled by `Http3Settings.earlyData`:

- `Http3EarlyDataPolicy.WaitForHandshake()` (the default): requests that `replayable` admits (GET, HEAD and OPTIONS by
  default) run at once with `receivedEarly = true`. Every other request reaches `acceptRequest()` only after the
  handshake completed. A replayed flight never completes the handshake, so a replayed unsafe request never runs.
- `Http3EarlyDataPolicy.Reject425()`: non-replayable early requests are answered with `425 Too Early` and never reach
  the application.

> **Replay warning.** An early request may be a copy an attacker sent again (RFC 9846 section 8). Handlers of requests
> that run early, those with `receivedEarly = true`, must have no side effects. Narrow `replayable` if a GET handler
> of yours changes state.

## Serving requests

```kotlin
// guide:http3:serve
val connection = server.accept()
while (true) {
    val request = connection.acceptRequest()
    launch {
        val writer = request.respond(200, Http3Headers.of("content-type" to "text/plain"))
        writer.output.writeStringUtf8("hello")
        writer.finish()                  // or finish(Http3Headers.of("x-checksum" to "...")) to send trailers
    }
}
```

Malformed requests never reach `acceptRequest`: their stream is reset with `H3_MESSAGE_ERROR` (that includes a
`content-length` that is not digits or conflicts with another; identical repeats collapse to one field). A response
field the validator rejects makes `respond` throw and resets the stream with `H3_REQUEST_CANCELLED`. A response whose
`output` the application cancels (with any cause) is abandoned: the stream is reset with `H3_REQUEST_CANCELLED` (RFC
9114 section 4.1.1), never ended with a FIN. A request body the
application has not finished reading when its response is complete is dropped with `STOP_SENDING H3_NO_ERROR`; the
client's upload then ends with `QuicException.StreamError.Stopped` (code `H3_NO_ERROR`) in its body channel, and the
stream is retired as soon as the client's FIN or reset arrives, so unread uploads never exhaust the stream credit. Field
names and values are octets: a character above U+00FF is rejected rather than truncated. A response to HEAD may carry
a `content-length` without a body; the server drops whatever the application writes to a HEAD, 204 or 304 response
rather than sending DATA the client must treat as malformed. A request whose header
section is above `maxFieldSectionSize` once decoded is answered with 431 and `STOP_SENDING H3_EXCESSIVE_LOAD` by the
connection itself. The other way round, a section above the peer's `SETTINGS_MAX_FIELD_SECTION_SIZE` is never sent:
`request` fails with `FieldSectionTooLarge` before it opens a stream, `respond` and `finish(trailers)` fail before
writing; refused trailers also reset the stream with `H3_REQUEST_CANCELLED`, since the body already went out. Refused request
trailers reset the stream with `H3_REQUEST_CANCELLED`, and `request` (or, once the response began, its body and
`trailers`) fails with `FieldSectionTooLarge`. `request.remoteAddress` follows the client's path when it migrates.

Slow and oversized heads (RFC 9114 section 10.5, RFC 9000 section 21.6): a request head must be complete within
`Http3Settings.maxHeaderBlockTime` (10 s) of its stream's first byte, or the stream is reset with `H3_REQUEST_REJECTED`
before the application sees it (the client may send it again); any other field section (trailers, and on a client each
response head) must arrive within the same time of its frame header, or the request is cancelled with
`H3_REQUEST_CANCELLED` and fails with `Http3Exception.Protocol`. The time before a response starts is not limited, so
long polls are unaffected. A connection reads at most 8 × `maxFieldSectionSize` (512 KiB by default) of HEADERS frames
at once: each frame's length is reserved before its first byte is taken, and frames that do not fit wait in order with
their bytes left in the stream's flow-control window, so a peer cannot make the connection hold more by keeping heads
unfinished. Those bytes still count against the connection's flow-control window; if waiting heads fill it, the others
wait for it too, at most until `maxHeaderBlockTime` ends the waiting streams. With WebTransport on, a server's
WebTransport streams must send their signal and Session ID within the same time, or are reset with
`WT_BUFFERED_STREAM_REJECTED`. A peer's unidirectional stream must send its type within it too, or is stopped with
`H3_STREAM_CREATION_ERROR`; one stalled stream per control or QPACK stream the peer has not opened yet is spared while
its bytes so far could still be that stream's type. The Ktor server bounds `maxHeaderBlockTime` by `requestHeaderTimeoutSeconds`.

## Shutdown and GOAWAY

`connection.goAway()` shuts a connection down gracefully (RFC 9114 section 5.2). A server first announces
2^62-4 ("no promises yet"), waits about two round trips so requests already in flight arrive, then announces the first
request id it will not process; such requests are reset with `H3_REQUEST_REJECTED`. Once every request below that id
is answered — including one whose HEADERS were still arriving when GOAWAY went out — and every response has been
acknowledged by the client's QUIC stack, the connection is closed with `H3_NO_ERROR`: by the client, which closes an
idle connection after a GOAWAY once its responses are read (a Kuicksilver client always does; quic-go's server waits for
exactly that), or by the server three seconds later if the client does not. A client that never closes (some other
stacks) therefore has three seconds to read a response its QUIC stack has acknowledged; data still unread then is lost
with the connection. A response handed to QUIC is not yet received, which is why the server waits for the client
rather than closing a fixed time after the last answer. A stream gets 10 seconds after the final GOAWAY to complete its HEADERS; after that it is reset with
`H3_REQUEST_REJECTED` (it was never processed) and no longer holds the connection open. (quic-go has no such
per-stream deadline; it bounds the whole graceful shutdown with the caller's context.) A client receiving GOAWAY fails the requests it did not cover, and every
new request, with `Http3Exception.RequestNotProcessed(retrySafe = true)`: they were never processed and can be sent
again on a new connection (the Ktor engine does that by itself). Once the requests and responses it still has are done
(bodies read, tunnels ended), a client that received GOAWAY closes the connection with `H3_NO_ERROR`. A client's own
`goAway()` sends GOAWAY(0) and stops issuing requests. `goAway()` may be called from any thread; it runs on the connection's own dispatcher.

`Http3Endpoint.close()` ends every connection at once, without GOAWAY, with `H3_NO_ERROR` (a QUIC endpoint's `close()`
sends application code 0, which HTTP/3 does not define); `Http3Endpoint.shutdown(grace)` is the graceful way.

A peer that keeps sending frames nobody needs (unknown frames on the control stream or on a request stream; reserved
GREASE frames and empty DATA frames beyond the first 8 of a stream, the control stream included;
unidirectional streams that end or are reset before their type, PRIORITY_UPDATE floods) spends tokens of a glitch bucket (1000 tokens, 33 per second); an empty bucket closes the
connection with `H3_EXCESSIVE_LOAD`. `Http3Settings.glitchProtection = false` turns this off.

## qlog

A connection whose QUIC configuration has a qlog sink ([QUIC: qlog](quic.md#qlog)) gets its HTTP/3 events in the same
trace as the transport's, in the schema of that trace: qlog 0.3 with the events of draft-ietf-quic-qlog-h3-events-04
([ADR-0021](../adr/0021-qlog-http3-events.md)). Every frame sent and read is there as `http:frame_created` or
`http:frame_parsed` with its stream, its length and its contents (the fields of a HEADERS frame, the settings of a
SETTINGS frame, the identifier of a GOAWAY); unidirectional streams as `http:stream_type_set`; SETTINGS also as
`http:parameters_set` and, for a 0-RTT client, the remembered ones as `http:parameters_restored`; the QPACK dynamic
tables as `qpack:state_updated`, and a field section waiting for an insert as `qpack:stream_state_updated`. Frames the
draft has no type for (PRIORITY_UPDATE, WebTransport's stream signal) are `unknown` frames with their type number and
their own members; reserved (GREASE) frames are `reserved`.

Header and trailer values are not written: each field has its name and the value `[redacted]`, except `:method`,
`:scheme`, `:status` and `:protocol`. A sink whose `logHeaderValues` is true (`DirectoryQlogSink(dir, maxOpenTraces,
maxTotalBytes, logHeaderValues = true)`, *experimental*; `AsyncQlogSink` asks its delegate) gets every value as sent and
received, cookies and credentials included: keep such traces as secrets (threat model 3.25). A connection without a
sink formats no event; with one, events are queued (at most 4096 per connection) and written by the endpoint loop, so a
sink is still called on the loop only.

The traces were checked against the draft's definitions offline; open them in a qvis build that reads qlog 0.3.

## Priorities

Requests carry RFC 9218 priorities: `Http3Request.priority` becomes the `priority` field when it differs from the
default (`u=3`, not incremental), and `Http3Response.updatePriority(...)` sends a PRIORITY_UPDATE later. The client
schedules its own request stream with the same signal, whether it came as `Http3Request.priority` or as a `priority`
header. The server acts on the client's signal: `Http3ServerRequest.priority` follows the field and later updates, and
the response stream is scheduled with it unless the server picks its own, with `respond(status, headers, priority)` or
with a `priority` field in the response headers, which is merged into the stream's current priority (a parameter it
leaves out keeps that value, the client's or the defaults; RFC 9218 section 8, as h2o does); the server's choice then
stays. A CONNECT tunnel without a signal gets RFC 9218's defaults on both sides like any request (section 4: u=3, and
section 4.2, "The default value of the incremental parameter is false (0)"); a client that wants it to share bandwidth
with the incremental streams of its urgency signals `priority: i` (section 11: "A client that issues multiple CONNECT
requests can set the incremental parameter to true"). The
transport scheduler serves eight urgency levels in order and shares a level round-robin between incremental streams;
within a level the incremental and the non-incremental streams take turns frame by frame, and a CONNECT tunnel gets one
frame in 16 even behind more urgent streams (sections 10, 10.1); the control and QPACK streams always go first. A PRIORITY_UPDATE that arrives before its stream is remembered (up to 32
of them); one that arrives after the field replaces it.

## Extended CONNECT and datagrams

A server that accepts Extended CONNECT (RFC 9220) sets `enableConnectProtocol = true`; a client calls `connect`, which
waits for the server's SETTINGS and fails with `Http3Exception.Settings` if the server did not opt in. The result is an
`Http3Stream`: a byte stream both ways (WebSocket frames for `:protocol = websocket`, the protocol's own framing otherwise,
or capsules, see [Capsules](#capsules-experimental)) plus HTTP datagrams bound to the stream (RFC 9297). `Http3Stream.headers` holds the peer's fields: the CONNECT request's on
the server, the 2xx response's on the client (for example `sec-websocket-protocol`, RFC 9220 section 3). Each
direction ends on its own: closing `output` sends FIN and leaves `input` readable until the peer's FIN (a TCP-style
half-close, RFC 9114 section 4.4); the stream is released once both directions ended or the stream was reset. Once the
CONNECT completed only DATA travels on the stream (RFC 9114 section 4.4): `finish(trailers)` on a 2xx to CONNECT throws
`IllegalArgumentException` and sends nothing, and a CONNECT request with `trailers` is refused before it goes out.
`:protocol` must be a token (RFC 8441 section 4) and is matched in any case (`websocket`, `WebSocket`). Datagrams
follow the stream's state (RFC 9297 section 2.1): the `datagrams` flow ends when the receive side closes and later
datagrams for the stream are dropped; once our send side is closed (`output` closed, or `reset`) `trySendDatagram`
answers `Closed` and `sendDatagram` throws `IllegalStateException`.

```kotlin
// guide:http3:connect (server)
val request = connection.acceptRequest()
if (request.protocol == "echo") {
    val stream = request.acceptConnect()          // :status 200
    stream.input.copyTo(stream.output)
} else request.respond(501).finish()

// guide:http3:connect (client)
val stream = client.connect(http3Request("CONNECT", "example.com", "/chat"), protocol = "echo")
stream.trySendDatagram(byteArrayOf(1, 2, 3))      // Unsupported until both sides sent SETTINGS_H3_DATAGRAM=1
stream.datagrams.collect { println(it.size) }
```

`SETTINGS_H3_DATAGRAM` is always sent (its absence would be a fingerprint); it is 1 only when the QUIC connection has
datagrams on. A peer that announces it without QUIC datagram support keeps its connection (RFC 9297 section 2.1.1 makes
only a value other than 0 or 1 an error), but no datagram is sent to it: `trySendDatagram` answers `Unsupported`.
Datagrams for streams nobody registered are dropped silently; a datagram whose quarter stream ID cannot be parsed
closes the connection with `H3_DATAGRAM_ERROR`. Each stream keeps the newest 32 datagrams nobody has collected.

### Capsules (experimental)

Protocols such as WebTransport and CONNECT-UDP frame the stream's data as capsules (RFC 9297 section 3): a type, a
length and a value. `Http3Stream.useCapsuleProtocol(config)` turns a stream into a `CapsuleStream`; from then on the
stream's `input`, `output` and `datagrams` belong to it. Only an Extended CONNECT whose protocol has datagram semantics
speaks capsules: the Capsule Protocol "only applies to definitions of new HTTP upgrade tokens" (RFC 9297 section 3.2), so
on a `websocket` stream or a classic CONNECT `useCapsuleProtocol` throws `IllegalStateException`. `capsules` delivers the capsule types listed in
`CapsuleConfig.knownTypes` (64 KiB each at most by default) and skips every other type as its bytes arrive; `send`
writes one capsule whole, never interleaved with another; `close()` writes what is queued and then sends FIN, while
`capsules` keeps reading the peer's side.

```kotlin
// guide:http3:capsules (server)
@file:OptIn(ExperimentalKuicksilverApi::class)   // experimental API (at the top of the file)
val config = capsuleConfig { knownTypes = setOf(0x2843) }   // the capsule types the protocol defines
val tunnel = request.acceptConnect().useCapsuleProtocol(config)
tunnel.capsules.collect { tunnel.send(it) }                 // echo each capsule until the client's FIN
tunnel.close()                                              // the queued capsules, then FIN

// guide:http3:capsules (client)
val capsules = client.connect(http3Request("CONNECT", "example.com", "/chat"), protocol = "echo").useCapsuleProtocol(config)
capsules.send(Capsule(0x2843, "hello".encodeToByteArray()))
capsules.close()
val echoed = capsules.capsules.toList()                     // ends at the server's FIN
```

The stream is checked against RFC 9297 section 3.2 first: a peer message with `content-length`, `content-type` or
`transfer-encoding`, or a 204, 205 or 206 response, is malformed, so the stream is reset with `H3_MESSAGE_ERROR` and
`useCapsuleProtocol` throws `Http3Exception.MessageError`. A message that announces capsules with `Capsule-Protocol: ?1`
is checked earlier: `acceptConnect` answers such a request that breaks section 3.2 with 400 (and STOP_SENDING
`H3_MESSAGE_ERROR`) instead of 200 and throws `MessageError`, `connect` fails the same way on such a 2xx, and our own
messages are refused with `IllegalArgumentException` before they are sent, `capsule-protocol` in a response outside 2xx
included (section 3.4). The same happens later when the peer's FIN cuts a capsule in
two or a known capsule is longer than `maxCapsuleLength`: `capsules` fails with `MessageError` instead of ending, so a cut
stream is never mistaken for a clean end. A protocol whose last capsule closes the stream (WebTransport's
WT_CLOSE_SESSION) lists it in `terminalTypes`: the capsule is delivered, and anything after it is malformed the same way.
The connection lives on in every case.

Datagrams work as on a plain stream, plus DATAGRAM capsules (RFC 9297 section 3.5): those the peer sends arrive in
`datagrams` together with QUIC datagrams, and a DATAGRAM capsule longer than `maxDatagramLength` is dropped unread. When
HTTP/3 datagrams are unsupported on the connection (either side's `SETTINGS_H3_DATAGRAM` is 0), `trySendDatagram` and
`sendDatagram` send a DATAGRAM capsule instead, unless `datagramFallback = false` (until the peer's SETTINGS arrive,
datagrams count as unsupported); a datagram too large for a QUIC
DATAGRAM frame is answered `TooLarge`, not sent as a capsule. `CapsuleProtocol.isEnabled(headers)` reads the
`Capsule-Protocol` header field (section 3.4) and `CapsuleProtocol.Enabled` writes it; the stream does not require it.

Reading pauses while `receiveQueue` capsules (16) wait for the collector, which holds the peer back through flow control,
so collect `capsules` even when only datagrams matter, or list no `knownTypes`. `send`, `close()` and a falling-back
`sendDatagram` have no deadline of their own while the peer withholds flow-control credit; cancelling `close()` leaves
the writer running in the connection, so bound them with `withTimeout` and `reset` the stream when it expires. Options:
[configuration reference](configuration.md#capsuleconfig-experimental). The Capsule Protocol is only available on HTTP/3;
HTTP/1.1 and HTTP/2 upgrades are not supported.

## WebTransport (experimental)

WebTransport over HTTP/3 (draft-ietf-webtrans-http3-16) is experimental (`@ExperimentalKuicksilverApi`): sessions,
their streams and datagrams, close and drain. Both sides set `webTransport = true` in `http3Settings` (it needs
`enableConnectProtocol` and `h3Datagram`; `Http3Endpoint.bind` refuses it when QUIC datagrams are off, and
`Http3Endpoint` turns `QuicConfig.resetStreamAt` on with it). Browsers do not
speak draft-16 yet, so a server announces the SETTINGS of draft-02 (Chrome, Firefox) and draft-14 (Safari) too and
accepts both `:protocol` tokens, `webtransport-h3` and `webtransport`; a client picks the token from the server's
SETTINGS. A request with either token is `isWebTransport`; `acceptWebTransport` answers 200 once the client's SETTINGS
arrived (ten seconds at most; without them, without a WebTransport setting of the client's own, without HTTP datagrams,
or, for draft-14 and later, without `reset_stream_at` on both sides, the request is answered with 400, stopped with
`H3_MESSAGE_ERROR`, and `acceptWebTransport` throws `Http3Exception.Settings`), and a 4xx from `respond` refuses the
session. A client throws `Http3Exception.Settings` before its CONNECT when the server lacks one of them; draft-02,
which Chrome and Firefox speak, predates `reset_stream_at` and goes without it. The draft is the highest both sides
announce (a client of ours announces draft-16 and draft-02). A peer that announces a newer draft without
`reset_stream_at` but also draft-02 gets a draft-02 session when its CONNECT is a draft-02 request (`:protocol
webtransport` with `sec-webtransport-http3-draft02: 1`, which our client then sends): this is our reading of section 7.1
("the highest version supported by both endpoints" taken as the highest both can actually run), not something the
draft says. Its draft-16 or draft-14 CONNECT, and a peer that announces only the newer draft, are refused.
Interop note: Safari speaks draft-14, which needs `reset_stream_at`; WebKit bugs 303152 and 305006 suggest Safari 26.4
and later sends it, but that is not verified here ([interop](../spec/interop.md#interop-webtransport-browsers-2026-10-22-and-2026-10-23)). The client waits
ten seconds for the server's SETTINGS and ten more for the answer to its CONNECT (`WebTransportException.Timeout`). Check the `origin` field before accepting a browser's session. The client offers application
protocols in `WT-Available-Protocols` and the server picks one of `availableProtocols`; a choice the client did not
offer fails `webTransport` with `WebTransportException.Alpn` (a `WT-Protocol` that is not a valid Structured Field
String is ignored).

WebTransport flow control (draft-ietf-webtrans-http3-16 section 5) is on when both sides declare it in their SETTINGS,
which `webTransport` does by default with `webTransportInitialMaxStreamsBidi`, `webTransportInitialMaxStreamsUni` and
`webTransportInitialMaxData` (24, 24 and 3 932 160 bytes per session). Each side keeps to the other's stream and data
limits; the receiver raises its own as the peer's streams end and as their bytes are consumed (WT_MAX_STREAMS,
WT_MAX_DATA), a blocked sender says so once per limit, and a peer that breaks a limit gets its session closed with
WT_FLOW_CONTROL_ERROR (`WebTransportException.FlowControl`). Several sessions then share a connection: a server takes up
to `webTransportMaxSessions` (4) at once and refuses one more with `H3_REQUEST_REJECTED` before the application sees it
(the client gets `Http3Exception.RequestNotProcessed` and can open it on another connection), and a client puts at most
as many on one connection (`WebTransportException.ConnectionFull` beyond). A server also takes new sessions on a
connection at a bounded rate (section 5.2): a burst of 32, then 8 a second; one more is refused the same way.

Credit comes back as the application takes the bytes, for a stream that ended cleanly once all of it was handed to its
input (read or not), and for a reset or stopped stream once its final size is known; bytes of an open stream that nobody
reads give none.

How this library's sender shares a session's data credit between the session's streams follows the session's RFC 9218
priority (draft-16 section 3.4 recommends RFC 9218's scheduling for all of a session's data), the `incremental`
parameter of its CONNECT stream, read again at every grant, so a PRIORITY_UPDATE takes effect at the next one:

The mode is chosen per direction: each side shares the credit for its own sending by its own view of the CONNECT
stream's priority.

- The client's sending follows the session request's priority: `Http3Request.priority`, else a `priority` field among
  its headers, else RFC 9218's defaults (non-incremental). The server's sending follows the client's signal, the `priority` field
  of the CONNECT request and later PRIORITY_UPDATEs, unless the server overrides it with a `priority` field in its
  `acceptWebTransport` answer; that field changes only the server's sending. A priority set on the request
  (`Http3Request.priority`) always goes out as a `priority` field on a CONNECT, RFC 9218's defaults included
  (`StreamPriority(3, incremental = false)` is sent as `i=?0`), so a server with a tunnel default of its own does not
  apply it; an ordinary request at the defaults still sends no field. A `priority` field among the request's headers
  does the same.
- Non-incremental (`i=?0`, the default, as for any request without a signal, RFC 9218 section 4.2): in order. The
  streams are served in
  the order the session handed them to the application (`openUni` or `openBidi` returned; for the peer's bidirectional
  streams, `acceptBidi`): while a stream waits for credit, or writes what it was just given, no stream opened after it
  gets any. A stream that asks for more than there is gets what there is at once (one frame's worth, never a wait for
  all of it) and keeps its place for the rest; at most one chunk (16 KiB) is kept for it at a time, and a stream with
  nothing more to send keeps no place. So when the application writes the streams one after another, each written in
  full before the next, a peer that reads them one after another in that order gets their bytes in that order, and
  never waits on a stream that got no credit while credit sits in a later one. The cost: a stream that keeps writing
  holds every later stream of the session for as long as it writes, and when the peer raises the limit in small steps
  the later streams wait; mark the session incremental to share.
- Incremental (`i`, `priority: i` among the CONNECT's headers or `StreamPriority(u, incremental = true)`, or the
  server's own `priority: i` answer for its sending): shared. Each grant starts one stream further along the ring of the
  streams that wait for credit or are writing, and serves them in order from there, so of n streams that keep asking
  each leads, and gets credit, within n grants, and a busy stream never holds the others; the order between streams is
  not kept. A grant is not split evenly: the stream it starts with gets what it asks first, so a stream the peer does
  not read still gets all its bytes out and ends (its end gives the credit back).

Opens waiting for the peer's stream limit are served in the order they asked, in both modes. The order holds within a
session: the sessions of a connection still take their weighted turns (below), and one session waiting for its credit
never holds up another.

Section 5 sets no order, so a sender of another implementation may serve its streams in any order, and credit still
comes back only as the application reads: when the peer is not this library, when its session is incremental, or when
the application reads a session's streams out of the order they were opened, read them concurrently (a coroutine per accepted stream), or give the session
enough data credit for what its peer sends at once; a strictly sequential reader under a tight
`webTransportInitialMaxData` can otherwise stall the session.

Sessions
sharing a connection take turns for its stream credit and its send buffer (section 8): a weighted round robin in which
a session's weight follows its CONNECT stream's urgency (8 − urgency), so a more urgent session gets the larger share
but none waits more than a round, and a PRIORITY_UPDATE takes effect at once. Each session also holds at most its part
of the connection's send buffer (`maxSendBuffer`): a reserve stays free for a session that joins, and the rest is split
between the open sessions, so a session alone gets nearly all of it while one whose peer never reads a stream cannot
stall the others. Datagrams are outside these turns: one session's burst can push other sessions' datagrams out of the
connection's datagram queue (which drops the oldest), never stall their streams. The connection's receive window is
kept at what the open sessions may have in flight together. `Http3Endpoint` refuses settings whose sessions do not fit
the QUIC limits (`maxBidiStreams`, `maxUniStreams`, `maxConnectionWindow`). All three initial limits at 0 turn flow
control off: a connection then carries one session (section 5.1), and a second CONNECT is refused the same way.

A draft-14 client (Safari) that declares flow control only with `SETTINGS_WT_MAX_SESSIONS` above 1 starts every
limit it gives at 0 (draft-14 section 5.5): our streams and data to it wait for its WT_MAX_STREAMS and WT_MAX_DATA, and
the Ktor server logs a warning once a session waited ten seconds. Turning flow control off (the three limits at 0) is
the way out for such a peer.

WebTransport streams that arrive before their session was accepted wait, 16 per connection for up to 5 s each; the
others are rejected with `WT_BUFFERED_STREAM_REJECTED`, and still count against the session's limits once it exists.

```kotlin
// guide:http3:webtransport (server)
val request = connection.acceptRequest()
if (request.isWebTransport && request.headers["origin"] == "https://app.example") {
    val session = request.acceptWebTransport(protocol = request.availableProtocols.firstOrNull())
} else request.respond(403).finish()

// guide:http3:webtransport (client)
val request = http3Request("CONNECT", "example.com", "/wt") { headers = Http3Headers.of("origin" to "https://app.example") }
val session = client.webTransport(request, protocols = listOf("chat-v1"))
println(session.protocol)                          // "chat-v1" when the server chose it
```

A session opens and accepts streams (`openBidi`, `openUni`, `acceptBidi`, `acceptUni`) whose `input` and `output`
are plain byte channels, and sends and receives datagrams (`trySendDatagram`, `sendDatagram`, `receiveDatagram`, the
newest 32 kept), which may be lost like any QUIC datagram. Application error codes are 0..2^32-1, for streams
(`reset`, `stopSending`, reported as `WebTransportException.StreamReset` and `StreamStopped`) and for the session;
on the wire they travel mapped into the HTTP/3 code space (section 4.4). `close(code, reason)` sends
WT_CLOSE_SESSION (the reason cut to 1024 bytes of UTF-8), then FIN, and waits for the peer's FIN (stopping the peer
after five seconds without it); either side's close,
the peer's FIN or a failure completes `closed` with the code, the reason or the cause, resets the session's streams
with `WT_SESSION_GONE`, and frees the connection for a next session. `drain()` asks the peer to wind down;
`drainRequested` turns true on the peer's request, an HTTP/3 GOAWAY, or this side's own `drain()` (the side that asks
winds down too, draft-ietf-webtrans-http3 section 4.7). Writing the close waits at most five seconds
for the peer's flow-control credit; opening a stream waits for the peer's stream credit without a deadline, so bound
it with `withTimeout`. With flow control the session's own limits bound it, besides the QUIC limits (`maxBidiStreams`,
`maxUniStreams`, the stream and connection windows); without it the flow-control capsules are ignored and the QUIC
limits alone do. A stream we opened is reset with RESET_STREAM_AT, which keeps its header so the peer can still tell its
session (section 4.4); a session of draft-14 or later exists only with `reset_stream_at` on both sides, which
`Http3Endpoint` and the Ktor engines turn on with `webTransport` (a draft-02 browser without it gets a plain
RESET_STREAM, as its draft has it). A session's streams are sent at the priority of its CONNECT stream (the request's
`priority`, else its `priority` field, else urgency 3 incremental) and follow the client's PRIORITY_UPDATE for it
(section 3.4); its datagrams, like every HTTP datagram, go with the urgency of their request stream, strictly in both
directions: more urgent streams' data goes first, so a bulk download at a more urgent level holds the datagrams back
(a request is urgency 3 by default, a WebTransport session too unless its CONNECT carries a `priority`), and a datagram
goes ahead of streams of the same or a lower urgency, so a flood of datagrams can starve those streams.

```kotlin
// guide:http3:webtransport-echo (server)
val stream = session.acceptBidi()                 // the client's stream
stream.input.copyTo(stream.output)                // echo until its FIN
stream.output.flushAndClose()
session.sendDatagram(session.receiveDatagram())   // and one datagram back
println(session.closed.await().reason)            // "done" once the client closed

// guide:http3:webtransport-echo (client)
val stream = session.openBidi()
stream.output.writeFully("ping".encodeToByteArray())
stream.output.flushAndClose()
println(stream.input.readBuffer().readString())  // "ping"
session.trySendDatagram(byteArrayOf(1, 2, 3))
println(session.receiveDatagram().size)
session.close(0, "done")
```
