// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, ExperimentalKuicksilverApi::class, ExperimentalCoroutinesApi::class)

package io.kuicksilver.http2.runtime

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameDecoder
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.H2
import io.kuicksilver.http2.frame.SettingId
import io.kuicksilver.http2.hpack.HpackEncoder
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.io.readByteArray
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Extended CONNECT over HTTP/2 (RFC 8441) in the runtime, under virtual time: the server's SETTINGS_ENABLE_CONNECT_PROTOCOL,
 * the client's `:protocol`, and the stream as a tunnel (RFC 9113 section 8.5): DATA both ways, END_STREAM for an orderly
 * end, no content-length and no trailers.
 */
class H2ExtendedConnectTest {
    private class Wire {
        val toServer = ByteChannel()
        val toClient = ByteChannel()

        fun close() {
            toServer.close()
            toClient.close()
        }
    }

    private fun TestScope.clock(): () -> Long = { testScheduler.currentTime * 1_000_000 }

    private suspend fun TestScope.pair(enableConnectProtocol: Boolean = true): Pair<H2ClientConnection, H2ServerConnection> {
        val w = Wire()
        val server =
            H2ServerConnection.start(
                w.toServer,
                w.toClient,
                Http2Settings(),
                backgroundScope,
                { w.close() },
                clock(),
                enableConnectProtocol = enableConnectProtocol,
            )
        val client =
            H2ClientConnection.start(w.toClient, w.toServer, Http2Settings(), backgroundScope, kotlin.time.Duration.INFINITE, {
                w.close()
            }, clock = clock())
        return client to server
    }

    private fun H2ClientConnection.webSocket(fields: List<Pair<String, String>> = listOf("sec-websocket-version" to "13")): H2ClientStream {
        assertTrue(tryReserve())
        return open("CONNECT", "https", "example.com", "/chat", fields, endStream = false, protocol = "websocket")
    }

    private fun CoroutineScope.serve(
        server: H2ServerConnection,
        handler: suspend (H2ServerStream) -> Unit,
    ) = launch {
        for (r in server.requests) {
            launch {
                try {
                    handler(r)
                } finally {
                    r.release()
                }
            }
        }
    }

    private suspend fun ByteReadChannel.readAll(): ByteArray = readBuffer().readByteArray()

    /**
     * RFC 8441 section 3: the client may use `:protocol` once the server's SETTINGS enabled it, and only then; the client
     * waits for those SETTINGS before it decides ([H2ClientConnection.awaitServerSettings]).
     */
    @Test fun serverSettingIsSeenByTheClient() =
        runTest {
            for (enabled in listOf(true, false)) {
                val (client, _) = pair(enableConnectProtocol = enabled)
                client.awaitServerSettings()
                assertEquals(enabled, client.serverAllowsExtendedConnect)
            }
        }

    /**
     * RFC 8441 sections 4, 5 and RFC 9113 section 8.5: CONNECT with `:protocol`, `:scheme`, `:path` and `:authority`;
     * after the 2xx every DATA frame is tunnel data, and END_STREAM on each side is the orderly close (no reset follows).
     */
    @Test fun tunnelCarriesDataBothWaysAndEndsInOrder() =
        runTest {
            val (client, server) = pair()
            val seen = CompletableDeferred<H2ServerStream>()
            val serverDone = CompletableDeferred<String>()
            backgroundScope.serve(server) { r ->
                seen.complete(r)
                r.respond(200, listOf("sec-websocket-protocol" to "chat"))
                serverDone.complete(r.body.readAll().decodeToString())
                r.sendBody(ByteReadChannel("pong".encodeToByteArray()))
            }
            client.awaitServerSettings()
            val s = client.webSocket()
            val head = s.response()
            assertEquals(200, head.status)
            assertEquals(listOf("sec-websocket-protocol" to "chat"), head.fields)
            val r = seen.await()
            assertEquals("CONNECT", r.method)
            assertEquals("websocket", r.protocol)
            assertEquals("https", r.scheme)
            assertEquals("/chat", r.path)
            assertEquals("example.com", r.authority)
            assertEquals(listOf("sec-websocket-version" to "13"), r.fields)
            s.sendBody(ByteReadChannel("ping".encodeToByteArray()), stallMillis = null) { error("no stall") }
            assertEquals("ping", serverDone.await())
            assertEquals("pong", s.body.readAll().decodeToString())
            assertTrue(s.awaitServerEnd(), "the server's END_STREAM, not a reset")
            runCurrent()
            assertFalse(r.failed, "a tunnel closed in order both ways is not reset")
            s.release()
        }

    /** An ordinary request is not a tunnel: `protocol` is null on the server, and a GET cannot carry one (RFC 8441 section 4). */
    @Test fun negative_protocolOnlyWithConnect() =
        runTest {
            val (client, server) = pair()
            val seen = CompletableDeferred<H2ServerStream>()
            backgroundScope.serve(server) { r ->
                seen.complete(r)
                r.respond(204, endStream = true)
            }
            client.awaitServerSettings()
            assertTrue(client.tryReserve())
            assertFailsWith<IllegalArgumentException> {
                client.open("GET", "https", "example.com", "/", emptyList(), endStream = true, protocol = "websocket")
            }
            val get = client.open("GET", "https", "example.com", "/", emptyList(), endStream = true)
            assertEquals(204, get.response().status)
            assertNull(seen.await().protocol)
            get.release()
        }

    /** Without the server's setting the client refuses `:protocol` locally (RFC 8441 section 3), never sends it malformed. */
    @Test fun negative_noProtocolWithoutTheServersSetting() =
        runTest {
            val (client, _) = pair(enableConnectProtocol = false)
            client.awaitServerSettings()
            assertFalse(client.serverAllowsExtendedConnect)
            assertTrue(client.tryReserve())
            assertFailsWith<IllegalArgumentException> {
                client.open("CONNECT", "https", "example.com", "/chat", emptyList(), endStream = false, protocol = "websocket")
            }
        }

    /**
     * RFC 9110 section 9.3.6: "A client MUST ignore any Content-Length or Transfer-Encoding header fields received in a
     * successful response to CONNECT": the tunnel's bytes are not response content, so a `content-length: 0` does not
     * make them malformed (RFC 9113 section 8.1.1 does not apply).
     */
    @Test fun contentLengthOfASuccessfulConnectResponseIsIgnored() =
        runTest {
            val (srv, client) = raw()
            val s = client.webSocket()
            runCurrent()
            srv.read()
            srv.write(srv.headers(s.id, listOf(":status" to "200", "content-length" to "0"), endStream = false))
            srv.write(FrameEncoder.data(s.id, "abc".encodeToByteArray(), 0, 3, true))
            assertEquals(200, s.response().status)
            assertEquals("abc", s.body.readAll().decodeToString())
            s.release()
        }

    /**
     * RFC 9113 section 8.5: on a connected stream, "Frame types other than DATA or stream management frames ... MUST NOT
     * be sent on a connected stream and MUST be treated as a stream error (Section 5.4.2) if received": a HEADERS after the
     * 2xx (trailers) resets the stream with PROTOCOL_ERROR and fails the tunnel; the connection stays.
     */
    @Test fun negative_headersOnAConnectedStreamAreAStreamError() =
        runTest {
            val (srv, client) = raw()
            val s = client.webSocket()
            runCurrent()
            srv.read()
            srv.write(srv.headers(s.id, listOf(":status" to "200"), endStream = false))
            assertEquals(200, s.response().status)
            srv.write(srv.headers(s.id, listOf("x-trailer" to "1"), endStream = true))
            val e = assertFailsWith<Http2Exception> { s.body.readAll() }
            assertIs<Http2Exception.MalformedMessage>(e)
            runCurrent()
            val rst = srv.read().filterIsInstance<Frame.RstStream>().single { it.streamId == s.id }
            assertEquals(Http2ErrorCode.PROTOCOL_ERROR.code, rst.errorCode)
            assertTrue(client.isUsable)
            s.release()
        }

    /** A non-2xx answer to the CONNECT is an ordinary response (RFC 9110 section 9.3.6): its content-length holds. */
    @Test fun refusedConnectIsAnOrdinaryResponse() =
        runTest {
            val (srv, client) = raw()
            val s = client.webSocket()
            runCurrent()
            srv.read()
            srv.write(srv.headers(s.id, listOf(":status" to "404", "content-length" to "2"), endStream = false))
            srv.write(FrameEncoder.data(s.id, "no".encodeToByteArray(), 0, 2, true))
            assertEquals(404, s.response().status)
            assertEquals("no", s.body.readAll().decodeToString())
            s.release()
        }

    /**
     * The server side of RFC 9113 section 8.5: a CONNECT stream carries no trailers. Once the tunnel is answered with a
     * 2xx, [H2ServerStream.trailers] refuses (IllegalStateException) instead of sending a HEADERS the client must treat as
     * a stream error; a client's own HEADERS after its request is a stream error PROTOCOL_ERROR, and its content-length
     * (a CONNECT request has no content, RFC 9110 section 9.3.6) is not held against the tunnel's bytes.
     */
    @Test fun negative_noTrailersOnAConnectStream() =
        runTest {
            val (client, server) = pair()
            val refused = CompletableDeferred<Throwable?>()
            val read = CompletableDeferred<String>()
            backgroundScope.serve(server) { r ->
                r.respond(200)
                read.complete(r.body.readAll().decodeToString())
                refused.complete(runCatching { r.trailers(listOf("x" to "y")) }.exceptionOrNull())
                r.sendBody(ByteReadChannel.Empty)
            }
            client.awaitServerSettings()
            val s = client.webSocket(listOf("sec-websocket-version" to "13", "content-length" to "1"))
            assertEquals(200, s.response().status)
            s.sendBody(ByteReadChannel("more than one byte".encodeToByteArray()), stallMillis = null) { error("no stall") }
            assertEquals("more than one byte", read.await())
            assertIs<IllegalStateException>(refused.await())
            assertEquals(0, s.body.readAll().size)
            s.release()
        }

    /**
     * RFC 9110 section 9.3.6: "A server MUST NOT send any Transfer-Encoding or Content-Length header fields in a 2xx
     * (Successful) response to CONNECT": such a head is never sent, the stream is reset with INTERNAL_ERROR and the
     * handler gets IllegalArgumentException, as for any field section the server must not generate.
     */
    @Test fun negative_contentLengthInASuccessfulConnectResponseIsNeverSent() =
        runTest {
            val (client, server) = pair()
            val refused = CompletableDeferred<Throwable?>()
            backgroundScope.serve(server) { r ->
                refused.complete(runCatching { r.respond(200, listOf("content-length" to "0")) }.exceptionOrNull())
            }
            client.awaitServerSettings()
            val s = client.webSocket()
            val e = assertFailsWith<Http2Exception.StreamReset> { s.response() }
            assertEquals(Http2ErrorCode.INTERNAL_ERROR, e.code)
            assertIs<IllegalArgumentException>(refused.await())
            s.release()
        }

    // ---- a raw server that sent SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 ----

    private class RawServer(
        val w: Wire,
    ) {
        val hpack = HpackEncoder()
        private val dec = FrameDecoder(H2.MAX_MAX_FRAME_SIZE)
        private var prefaceLeft = H2.PREFACE.size
        private val buf = ByteArray(65_536)

        suspend fun write(vararg frames: ByteArray) {
            for (f in frames) w.toClient.writeFully(f)
            w.toClient.flush()
        }

        suspend fun read(): List<Frame> {
            val out = mutableListOf<Frame>()
            while (w.toServer.hasBufferedBytes()) {
                val n = w.toServer.readAvailable(buf, 0, buf.size)
                var p = 0
                if (prefaceLeft > 0) {
                    val k = minOf(prefaceLeft, n)
                    prefaceLeft -= k
                    p = k
                }
                while (p < n) {
                    p += dec.feed(buf, p, n - p)
                    while (true) out += dec.next() ?: break
                }
            }
            return out
        }

        fun headers(
            id: Int,
            fields: List<Pair<String, String>>,
            endStream: Boolean,
        ): ByteArray = FrameEncoder.headers(id, hpack.encode(fields), endStream, true, -1)
    }

    private suspend fun TestScope.raw(): Pair<RawServer, H2ClientConnection> {
        val w = Wire()
        val r = RawServer(w)
        val client =
            backgroundScope.async {
                H2ClientConnection.start(w.toClient, w.toServer, Http2Settings(), backgroundScope, kotlin.time.Duration.INFINITE, {
                    w.close()
                }, clock = clock())
            }
        runCurrent()
        r.write(FrameEncoder.settings(intArrayOf(SettingId.ENABLE_CONNECT_PROTOCOL), longArrayOf(1L)))
        val c = client.await()
        c.awaitServerSettings()
        return r to c
    }
}

/** Bytes readable without suspending. */
@OptIn(io.ktor.utils.io.InternalAPI::class)
private fun ByteReadChannel.hasBufferedBytes(): Boolean = !readBuffer.exhausted()
