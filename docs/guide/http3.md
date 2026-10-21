<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# HTTP/3 with Kuicksilver

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
not a lowercase token, CR, LF or NUL anywhere, whitespace at either end of a value, a connection-specific field such
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
103 Early Hints included) reach `onInformational`; more than `maxInformationalResponses` (5) fail the request with
`H3_EXCESSIVE_LOAD`. Both callbacks run on the dispatcher of the coroutine that called `request`, never on the
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

> **Replay warning.** An early request may be a copy an attacker sent again (RFC 8446 section 8). Handlers of requests
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
field the validator rejects makes `respond` throw and resets the stream with `H3_INTERNAL_ERROR`. A request body the
application has not finished reading when its response is complete is dropped with `STOP_SENDING H3_NO_ERROR`; the
client's upload then ends with `QuicException.StreamError.Stopped` (code `H3_NO_ERROR`) in its body channel, and the
stream is retired as soon as the client's FIN or reset arrives, so unread uploads never exhaust the stream credit. Field
names and values are octets: a character above U+00FF is rejected rather than truncated. A response to HEAD may carry
a `content-length` without a body; the server drops whatever the application writes to a HEAD, 204 or 304 response
rather than sending DATA the client must treat as malformed. A request whose header
section is above `maxFieldSectionSize` once decoded is answered with 431 and `STOP_SENDING H3_EXCESSIVE_LOAD` by the
connection itself. The other way round, a section above the peer's `SETTINGS_MAX_FIELD_SECTION_SIZE` is never sent:
`request` fails with `FieldSectionTooLarge` before it opens a stream, `respond` and `finish(trailers)` fail before
writing; refused trailers also reset the stream with `H3_INTERNAL_ERROR`, since the body already went out. Refused request
trailers reset the stream with `H3_REQUEST_CANCELLED`, and `request` (or, once the response began, its body and
`trailers`) fails with `FieldSectionTooLarge`. `request.remoteAddress` follows the client's path when it migrates.

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

A peer that keeps sending frames nobody needs (unknown frames on the control stream or on a request stream — reserved GREASE types on a request stream are free —
unidirectional streams that end or are reset before their type, PRIORITY_UPDATE floods) spends tokens of a glitch bucket (1000 tokens, 33 per second); an empty bucket closes the
connection with `H3_EXCESSIVE_LOAD`. `Http3Settings.glitchProtection = false` turns this off.

## Priorities

Requests carry RFC 9218 priorities: `Http3Request.priority` becomes the `priority` field when it differs from the
default (`u=3`, not incremental), and `Http3Response.updatePriority(...)` sends a PRIORITY_UPDATE later. Only the
server acts on the client's signal: `Http3ServerRequest.priority` follows the field and later updates, and the response
stream is scheduled with it unless the server picks its own with `respond(status, headers, priority)`, which wins. The
transport scheduler serves eight urgency levels in order and shares a level round-robin between incremental streams;
the control and QPACK streams always go first. A PRIORITY_UPDATE that arrives before its stream is remembered (up to 32
of them); one that arrives after the field replaces it.

## Extended CONNECT and datagrams

A server that accepts Extended CONNECT (RFC 9220) sets `enableConnectProtocol = true`; a client calls `connect`, which
waits for the server's SETTINGS and fails with `Http3Exception.Settings` if the server did not opt in. The result is an
`Http3Stream`: a byte stream both ways (WebSocket frames for `:protocol = websocket`, the protocol's own framing otherwise:
Kuicksilver does not implement the Capsule Protocol of RFC 9297 section 3, so capsules are bytes the application writes and parses)
plus HTTP datagrams bound to the stream (RFC 9297). `Http3Stream.headers` holds the peer's fields: the CONNECT request's on
the server, the 2xx response's on the client (for example `sec-websocket-protocol`, RFC 9220 section 3). Each
direction ends on its own: closing `output` sends FIN and leaves `input` readable until the peer's FIN (a TCP-style
half-close, RFC 9114 section 4.4); the stream is released once both directions ended or the stream was reset. Datagrams
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
datagrams on. A peer that announces it without QUIC datagram support is a connection error `H3_SETTINGS_ERROR`.
Datagrams for streams nobody registered are dropped silently; a datagram whose quarter stream ID cannot be parsed
closes the connection with `H3_DATAGRAM_ERROR`. Each stream keeps the newest 32 datagrams nobody has collected.
