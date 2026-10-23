// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** What reads and writes of a request see when the connection ends under them. */
class ConnectionEndTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Holds the server's datagrams, then delivers them back to back: the client processes them all before it reads. */
    private class Held(
        val q: QuicPair,
    ) {
        val datagrams = ArrayList<Triple<InetSocketAddress, InetSocketAddress, ByteArray>>()

        fun hold() {
            q.net.drop = { from, to, bytes -> from == q.server.localAddress && datagrams.add(Triple(from, to, bytes)) }
        }

        fun release() {
            q.net.drop = null
            for ((from, to, bytes) in datagrams) q.net.deliver(from, to, bytes)
        }
    }

    /** A raw server that answered [GET] with HEADERS and DATA "hello" and FIN, then closed: the client's response. */
    private suspend fun respondThenClose(
        q: QuicPair,
        client: suspend (Http3Connection) -> Unit,
    ) {
        val (c, s) = q.connect()
        val conn = Http3Connection.client(c)
        val raw = RawPeer(s)
        raw.openControl()
        conn.peerSettings.filterNotNull().first()
        kotlinx.coroutines.coroutineScope {
            val done = async { client(conn) }
            val st = s.acceptBidi()
            st.input.readAllBytes()
            val held = Held(q)
            held.hold()
            st.output.writeFully(raw.headers(st.id, listOf(":status" to "200")) + raw.data("hello".encodeToByteArray()))
            st.output.flushAndClose()
            s.close(Http3ErrorCode.NO_ERROR, "")
            held.release()
            done.await()
        }
    }

    /**
     * The response arrives with the close, so `request` returns after the connection's coroutines were cancelled: the body's
     * pump, launched then, never ran. Its body still ends (whole or with the connection's error), it never waits forever.
     */
    @Test fun responseAfterTheConnectionEndedNeverHangs() =
        h3Test {
            QuicPair.open().useScoped { q ->
                respondThenClose(q) { client ->
                    val r = runCatching { client.request(get()) }
                    val body = runCatching { withTimeout(5.seconds) { r.getOrThrow().body.readAllBytes() } }
                    val e = body.exceptionOrNull()
                    assertTrue(e !is TimeoutCancellationException, "the body read hung: request $r")
                    if (e != null) assertTrue(e is Http3Exception, "the body ends with the connection's error: $e")
                }
            }
        }

    /** The client already has the headers; the body and its FIN come with the close, and are read whole. */
    @Test fun bodyThenFinThenCloseReadsWhole() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c)
                val raw = RawPeer(s)
                raw.openControl()
                client.peerSettings.filterNotNull().first()
                val response = async { client.request(get()) }
                val st = s.acceptBidi()
                st.input.readAllBytes()
                st.output.writeFully(raw.headers(st.id, listOf(":status" to "200")))
                st.output.flush()
                val r = withTimeout(5.seconds) { response.await() }
                val held = Held(q)
                held.hold()
                st.output.writeFully(raw.data("hello".encodeToByteArray()))
                st.output.flushAndClose()
                s.close(Http3ErrorCode.NO_ERROR, "")
                held.release()
                withTimeout(5.seconds) { client.closed.await() }
                val body = runCatching { withTimeout(5.seconds) { r.body.readAllBytes() } }
                assertEquals("hello", body.getOrNull()?.decodeToString(), "body read: $body")
            }
        }

    /** Headers, body and FIN all come with the close: the request is answered and its body read whole. */
    @Test fun wholeResponseThenCloseIsAnswered() =
        h3Test {
            QuicPair.open().useScoped { q ->
                respondThenClose(q) { client ->
                    val r = runCatching { client.request(get()) }
                    val body = runCatching { withTimeout(5.seconds) { r.getOrThrow().body.readAllBytes() } }
                    assertEquals("hello", body.getOrNull()?.decodeToString(), "request: $r, body read: $body")
                }
            }
        }

    /** A response nobody reads does not keep the lost connection's readers alive: they are cut after the drain grace. */
    @Test fun unreadBodyIsCutAfterTheGrace() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c)
                val raw = RawPeer(s)
                raw.openControl()
                client.peerSettings.filterNotNull().first()
                val response = async { client.request(get()) }
                val st = s.acceptBidi()
                st.input.readAllBytes()
                st.output.writeFully(raw.headers(st.id, listOf(":status" to "200")))
                st.output.flush()
                val r = withTimeout(5.seconds) { response.await() } as ResponseImpl
                // more than the body channel holds before its writer waits: the pump waits on a reader that never comes
                val chunk = ByteArray(16 * 1024)
                repeat(256) { st.output.writeFully(raw.data(chunk)) }
                st.output.flush()
                withTimeout(5.seconds) {
                    // beyond the stream window: the pump read into the body channel and now waits for room
                    while (c.stats.bytesReceived < 1_200_000) kotlinx.coroutines.delay(10)
                }
                s.close(Http3ErrorCode.NO_ERROR, "")
                withTimeout(5.seconds) { client.closed.await() }
                withTimeout(H3Session.DRAIN_GRACE + 2.seconds) { r.pump.join() }
                assertFailsWith<Http3Exception> { withTimeout(5.seconds) { r.body.readAllBytes() } }
            }
        }

    /** On a server: a request's body and FIN come with the client's close, and the handler reads the body whole. */
    @Test fun requestBodyThenFinThenCloseReadsWhole() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, GET))
                st.output.flush()
                val req = withTimeout(5.seconds) { server.acceptRequest() }
                val held = ArrayList<Triple<InetSocketAddress, InetSocketAddress, ByteArray>>()
                q.net.drop = { from, to, bytes -> from != q.server.localAddress && held.add(Triple(from, to, bytes)) }
                st.output.writeFully(raw.data("hello".encodeToByteArray()))
                st.output.flushAndClose()
                c.close(Http3ErrorCode.NO_ERROR, "")
                q.net.drop = null
                for ((from, to, bytes) in held) q.net.deliver(from, to, bytes)
                withTimeout(5.seconds) { server.closed.await() }
                val body = runCatching { withTimeout(5.seconds) { req.body.readAllBytes() } }
                assertEquals("hello", body.getOrNull()?.decodeToString(), "body read: $body")
            }
        }

    /**
     * The client's connection ends while the server's handler has a response open: the writer's pump, cancelled with the
     * connection, ends its channel, so the handler's writes fail instead of waiting forever for a pump that is gone.
     */
    @Test fun responseWriteAfterTheConnectionEndedFails() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val response = async { runCatching { p.client.request(get()) } }
                val req = withTimeout(5.seconds) { p.server.acceptRequest() }
                val w = req.respond(200)
                p.client.close()
                withTimeout(5.seconds) { p.server.closed.await() }
                val chunk = ByteArray(64 * 1024)
                assertFailsWith<Throwable> {
                    withTimeout(5.seconds) {
                        repeat(256) {
                            // 16 MiB: far more than the channel buffers
                            w.output.writeFully(chunk)
                            w.output.flush()
                        }
                    }
                }.let { e -> assertTrue(e !is TimeoutCancellationException, "the handler's write hung") }
                response.join()
            }
        }

    /** Likewise for a request body: the connection ends while the application still writes it, and its writes fail. */
    @Test fun requestBodyWriteAfterTheConnectionEndedFails() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val body = ByteChannel()
                val response = async { runCatching { p.client.request(http3Request("POST", "server.test", "/") { this.body = body }) } }
                withTimeout(5.seconds) { p.server.acceptRequest() }
                p.server.close()
                withTimeout(5.seconds) { p.client.closed.await() }
                val chunk = ByteArray(64 * 1024)
                assertFailsWith<Throwable> {
                    withTimeout(5.seconds) {
                        repeat(256) {
                            body.writeFully(chunk)
                            body.flush()
                        }
                    }
                }.let { e -> assertTrue(e !is TimeoutCancellationException, "the application's body write hung") }
                response.join()
            }
        }
}
