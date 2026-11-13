// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.engineinterop

import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationStopPreparing
import io.ktor.server.application.install
import io.ktor.server.plugins.autohead.AutoHeadResponse
import io.ktor.server.plugins.origin
import io.ktor.server.request.httpVersion
import io.ktor.server.request.receiveChannel
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSocketServerSession
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.webSocket
import io.ktor.server.websocket.webSocketRaw
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketExtensionsConfig
import io.ktor.websocket.close
import io.ktor.websocket.readText
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import java.util.concurrent.ConcurrentHashMap

/**
 * What the application saw, for the tests to wait on: every handler that a test has to observe registers under an id the
 * test chose (part of the path), so one server serves every test of a class without shared state between tests.
 */
internal class Probe {
    /** One held or endless response: [entered] when its handler started, [release] lets it finish, [aborted] when its write failed. */
    class Hold {
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val aborted = CompletableDeferred<Throwable>()
    }

    private val holds = ConcurrentHashMap<String, Hold>()
    private val closes = ConcurrentHashMap<String, CompletableDeferred<CloseReason?>>()

    /** Completed when the application is told to stop (Ktor's ApplicationStopPreparing). */
    val stopping = CompletableDeferred<Unit>()

    fun hold(id: String): Hold = holds.getOrPut(id) { Hold() }

    /** The close reason a WebSocket under [id] received from its client (null: the connection ended without a Close frame). */
    fun closeOf(id: String): CompletableDeferred<CloseReason?> = closes.getOrPut(id) { CompletableDeferred() }
}

/** What an endless response that was written to the end (the client never went away) reports as its "abort". */
internal class WrittenToTheEnd : Exception("the endless response was written to the end")

/** The bytes of /bytes/{n}: a fixed pattern, so any reordering or loss shows. */
internal fun pattern(n: Int): ByteArray = ByteArray(n) { (it % 251).toByte() }

/**
 * The routes every Ktor server of the bench serves (ours, Netty, CIO): bodies, statuses, headers, held and endless
 * responses and WebSockets. [deflate] installs the server's permessage-deflate extension (ours: PerMessageDeflate; Ktor's
 * engines: Ktor's own WebSocketDeflateExtension), so a client that offers it negotiates it.
 */
internal fun Application.interopModule(
    probe: Probe,
    deflate: (WebSocketExtensionsConfig.() -> Unit)? = null,
) {
    install(AutoHeadResponse)
    install(WebSockets) {
        maxFrameSize = 4L shl 20
        if (deflate != null) extensions { deflate() }
    }
    monitor.subscribe(ApplicationStopPreparing) { probe.stopping.complete(Unit) }
    routing {
        get("/hello") { call.respondText("hello") }
        get("/version") { call.respondText(call.request.httpVersion) }
        get("/peer") { call.respondText("${call.request.origin.remoteAddress}:${call.request.origin.remotePort}") }
        post("/echo") {
            val body = call.receiveChannel().toByteArray()
            call.response.header("x-received-length", body.size.toString())
            call.respondBytes(body, ContentType.Application.OctetStream)
        }
        get("/bytes/{n}") { call.respondBytes(pattern(call.parameters["n"]!!.toInt()), ContentType.Application.OctetStream) }
        // no Content-Length: chunked over HTTP/1.1, DATA frames over HTTP/2 and HTTP/3, written piece by piece
        get("/chunked/{n}") {
            val n = call.parameters["n"]!!.toInt()
            val all = pattern(n)
            call.respondBytesWriter(ContentType.Application.OctetStream) {
                var off = 0
                while (off < n) {
                    val len = minOf(4096, n - off)
                    writeFully(all, off, off + len)
                    flush()
                    off += len
                }
            }
        }
        get("/status/{code}") {
            val code = HttpStatusCode.fromValue(call.parameters["code"]!!.toInt())
            if (code == HttpStatusCode.NoContent ||
                code == HttpStatusCode.NotModified
            ) {
                call.respond(code)
            } else {
                call.respondText("status ${code.value}", status = code)
            }
        }
        // RFC 9110 section 13.1.2 (If-None-Match) and 15.4.5 (304 carries the ETag a 200 would have)
        get("/etag") {
            call.response.header(HttpHeaders.ETag, "\"v1\"")
            if (call.request.headers[HttpHeaders.IfNoneMatch] ==
                "\"v1\""
            ) {
                call.respond(HttpStatusCode.NotModified)
            } else {
                call.respondText("tagged")
            }
        }
        // the request's x-* fields, one per line, sorted: what reached the application after the peer's parser
        get("/headers") {
            val lines =
                call.request.headers
                    .entries()
                    .filter { it.key.lowercase().startsWith("x-") }
                    .flatMap { e -> e.value.map { "${e.key.lowercase()}: $it" } }
                    .sorted()
            call.respondText(lines.joinToString("\n"))
        }
        // n response fields x-r-000.. with values of `size` characters
        get("/many-headers") {
            val n = call.request.queryParameters["n"]!!.toInt()
            val size = call.request.queryParameters["size"]?.toInt() ?: 8
            repeat(n) { i -> call.response.header("x-r-%03d".format(i), "v".repeat(size)) }
            call.respondText("ok")
        }
        // the decoded path segment and query parameter as the application sees them (UTF-8 percent-encoding)
        get("/utf8/{seg}") { call.respondText("${call.parameters["seg"]}|${call.request.queryParameters["q"]}") }
        // the first piece, then waits for the test's release before the second
        get("/hold/{id}") {
            val h = probe.hold(call.parameters["id"]!!)
            call.respondBytesWriter(ContentType.Text.Plain) {
                writeFully("first;".encodeToByteArray())
                flush()
                h.entered.complete(Unit)
                h.release.await()
                writeFully("second".encodeToByteArray())
            }
        }
        // the first piece, then (once the test releases it) 16 KiB pieces until the write fails or 1 GiB went out: a client
        // that gave up while the response stalled is seen as a failed write
        get("/stall/{id}") {
            val h = probe.hold(call.parameters["id"]!!)
            val piece = ByteArray(16 * 1024)
            try {
                call.respondBytesWriter(ContentType.Application.OctetStream) {
                    writeFully("first;".encodeToByteArray())
                    flush()
                    h.entered.complete(Unit)
                    h.release.await()
                    repeat(65_536) {
                        writeFully(piece)
                        flush()
                    }
                }
            } catch (e: Throwable) {
                h.aborted.complete(e)
                throw e
            }
            h.aborted.complete(WrittenToTheEnd())
        }
        // writes 16 KiB pieces until the write fails (the client went away) or 1 GiB went out
        get("/endless/{id}") {
            val h = probe.hold(call.parameters["id"]!!)
            val piece = ByteArray(16 * 1024)
            try {
                call.respondBytesWriter(ContentType.Application.OctetStream) {
                    h.entered.complete(Unit)
                    repeat(65_536) {
                        writeFully(piece)
                        flush()
                    }
                }
            } catch (e: Throwable) {
                h.aborted.complete(e)
                throw e
            }
            h.aborted.complete(WrittenToTheEnd())
        }
        webSocket("/ws/echo") {
            for (frame in incoming) {
                when (frame) {
                    is Frame.Text -> {
                        send(Frame.Text(frame.fin, frame.data))
                    }

                    is Frame.Binary -> {
                        send(Frame.Binary(frame.fin, frame.data))
                    }

                    else -> {}
                }
            }
        }
        // reassembles one message (whatever its fragments) and answers its size and its frame count
        webSocket("/ws/assemble") {
            var frames = 0
            val text = StringBuilder()
            for (frame in incoming) {
                if (frame !is Frame.Text) continue
                frames++
                text.append(frame.data.decodeToString())
                if (frame.fin) break
            }
            send(Frame.Text("${text.length}:$frames:${text.take(16)}"))
        }
        // sends one message in three fragments (RFC 6455 section 5.4)
        webSocket("/ws/fragments") {
            send(Frame.Text(false, "frag".encodeToByteArray()))
            send(Frame.Text(false, "ment".encodeToByteArray()))
            send(Frame.Text(true, "ed".encodeToByteArray()))
            closeReasonOrNull()
        }
        // closes with the code and reason of the query (RFC 6455 section 7.4)
        webSocket("/ws/close") {
            val code = call.request.queryParameters["code"]!!.toShort()
            close(CloseReason(code, call.request.queryParameters["reason"].orEmpty()))
        }
        // records the close reason the client sent
        webSocket("/ws/client-close/{id}") {
            val out = probe.closeOf(call.parameters["id"]!!)
            out.complete(closeReasonOrNull())
        }
        // a raw session (no automatic Pong): pings the client and reports the Pong's payload (RFC 6455 section 5.5.3)
        webSocketRaw("/ws/ping") {
            val payload = "ping-${call.request.queryParameters["n"]}".encodeToByteArray()
            outgoing.send(Frame.Ping(payload))
            for (frame in incoming) {
                when (frame) {
                    is Frame.Pong -> {
                        outgoing.send(Frame.Text("pong:${frame.data.decodeToString()}"))
                    }

                    is Frame.Close -> {
                        outgoing.send(Frame.Close(CloseReason(CloseReason.Codes.NORMAL, "")))
                        return@webSocketRaw
                    }

                    is Frame.Text -> {
                        outgoing.send(Frame.Text("text:${frame.readText()}"))
                    }

                    else -> {}
                }
            }
        }
    }
}

private suspend fun io.ktor.utils.io.ByteReadChannel.toByteArray(): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    val buf = ByteArray(64 * 1024)
    while (true) {
        val n = readAvailable(buf, 0, buf.size)
        if (n < 0) break
        out.write(buf, 0, n)
    }
    closedCause?.let { throw it }
    return out.toByteArray()
}

/** The client's close reason, or null when the session ended without one. */
private suspend fun WebSocketServerSession.closeReasonOrNull(): CloseReason? {
    try {
        while (true) incoming.receive()
    } catch (_: ClosedReceiveChannelException) {
    }
    return (this as? io.ktor.websocket.DefaultWebSocketSession)?.closeReason?.await()
}
