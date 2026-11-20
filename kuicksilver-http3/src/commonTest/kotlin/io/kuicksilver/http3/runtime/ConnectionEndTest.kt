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
import io.kuicksilver.http3.acceptWebTransport
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.useScoped
import io.kuicksilver.http3.webTransport
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.awaitReceivedAllForTest
import io.kuicksilver.quic.receivedAll
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.seconds

/** What reads and writes of a request see when the connection ends under them. */
class ConnectionEndTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * Waits until the session's coroutines are cancelled (the connection's end reached them). A wait that must succeed:
     * its bound only turns a hang into a failure that says what it waited for, well inside the test's own.
     */
    private suspend fun awaitCoroutinesCancelled(s: H3Session) {
        withTimeoutOrNull(20.seconds) { while (!s.job.isCancelled) kotlinx.coroutines.yield() }
            ?: fail("the session's coroutines were not cancelled once the connection ended")
    }

    /** What of the server's requests [s] still keeps: requests, datagram channels, WebTransport sessions; null when nothing. */
    private suspend fun registered(s: H3Session): String? =
        withContext(s.dispatcher) {
            buildList {
                if (s.activeServerRequests.isNotEmpty()) add("requests ${s.activeServerRequests.keys}")
                if (s.datagrams.registeredCount > 0) add("${s.datagrams.registeredCount} datagram channel(s)")
                if (s.wtSessions.isNotEmpty()) add("WebTransport sessions ${s.wtSessions.keys}")
            }.joinToString().ifEmpty { null }
        }

    /** Waits until [s] keeps nothing of its requests ([registered]); a wait that must succeed, as [awaitCoroutinesCancelled]. */
    private suspend fun awaitNothingRegistered(s: H3Session) {
        withTimeoutOrNull(20.seconds) { while (registered(s) != null) kotlinx.coroutines.yield() }
            ?: fail("the server still keeps ${registered(s)} after the connection ended")
    }

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
     * The response arrives with the close, so `request` may return after the connection's coroutines were cancelled. Its
     * body still ends (whole or with the connection's error), it never waits forever.
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

    /**
     * The whole response (HEADERS, DATA, FIN) arrived before the server's CONNECTION_CLOSE, but the body's reader runs only
     * after the drain grace measured from the connection's end has passed: the scheduler paused it (a loaded Android 7
     * emulator, a slow Windows VM, macOS under memory pressure). The stream had every byte (RFC 9000 section 3.2, "Data
     * Recvd"), so the body is read whole; the grace cut it with H3_NO_ERROR from the peer.
     */
    @Test fun wholeResponseReaderRunLateReadsWhole() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c)
                val session = client.session
                val reader = CompletableDeferred<Unit>()
                session.beforeDrainerForTest = { reader.await() } // the scheduler pauses the body's reader
                session.drainTimer = {} // and the grace is over as soon as it starts
                val raw = RawPeer(s)
                raw.openControl()
                client.peerSettings.filterNotNull().first()
                val response = async { client.request(get()) }
                val st = s.acceptBidi()
                st.input.readAllBytes()
                st.output.writeFully(raw.headers(st.id, listOf(":status" to "200")) + raw.data("hello".encodeToByteArray()))
                st.output.flushAndClose() // one STREAM frame: the client has the FIN once it has the headers
                val r = withTimeout(5.seconds) { response.await() }
                s.close(Http3ErrorCode.NO_ERROR, "")
                withTimeout(5.seconds) { client.closed.await() }
                withTimeout(5.seconds) {
                    session.scope.coroutineContext.job
                        .join()
                }
                // the reader's drainer saw the end first (notified before this coroutine), so its grace has run out here
                withContext(session.dispatcher) {}
                reader.complete(Unit)
                val body = runCatching { withTimeout(5.seconds) { r.body.readAllBytes() } }
                assertEquals("hello", body.getOrNull()?.decodeToString(), "body read: $body")
            }
        }

    /**
     * The server's mirror: a request body larger than its channel holds came whole (FIN included) before the client's
     * close, and the handler reads it only after the drain grace. The body pump waits for the handler, not for the network,
     * and the body is read whole.
     */
    @Test fun wholeRequestBodyReadAfterTheGraceReadsWhole() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val session = server.session
                session.drainTimer = {} // the grace is over as soon as it starts
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, POST))
                st.output.flush()
                val req = withTimeout(5.seconds) { server.acceptRequest() } as ServerRequestImpl
                // more than the body channel takes before its writer waits: the pump waits for the handler to read
                val chunk = ByteArray(16 * 1024) { (it * 7).toByte() }
                val chunks = 80
                repeat(chunks) { st.output.writeFully(raw.data(chunk)) }
                st.output.flushAndClose()
                withTimeout(5.seconds) { req.stream.awaitReceivedAllForTest() } // the FIN is in
                c.close(Http3ErrorCode.NO_ERROR, "")
                withTimeout(5.seconds) { server.closed.await() }
                // the session's end and its (zero) grace ran before these
                repeat(2) { withContext(session.dispatcher) {} }
                val body = runCatching { withTimeout(5.seconds) { req.body.readAllBytes() } }
                assertEquals(chunks * chunk.size, body.getOrNull()?.size, "body read: $body")
            }
        }

    /**
     * A whole request body larger than its channel holds, which the handler never reads, does not keep the server's session
     * once the connection is gone: its reader hands the rest over without waiting for the handler and ends, so the session
     * ends too (no grace involved: it never runs out here). The bytes then live only in the body the handler holds.
     */
    @Test fun unreadWholeRequestBodyLetsTheSessionEnd() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val session = server.session
                session.drainTimer = { awaitCancellation() } // the grace never runs out: only the reader's own end counts
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, POST))
                st.output.flush()
                val req = withTimeout(5.seconds) { server.acceptRequest() } as ServerRequestImpl
                val chunk = ByteArray(16 * 1024) { (it * 7).toByte() }
                val chunks = 80 // more than the body channel takes before its writer waits for the handler
                repeat(chunks) { st.output.writeFully(raw.data(chunk)) }
                st.output.flushAndClose()
                withTimeout(5.seconds) { req.stream.awaitReceivedAllForTest() }
                c.close(Http3ErrorCode.NO_ERROR, "")
                withTimeout(5.seconds) { server.closed.await() }
                withTimeout(5.seconds) {
                    session.scope.coroutineContext.job
                        .join()
                }
                val body = withTimeout(5.seconds) { req.body.readAllBytes() }
                assertEquals(chunks * chunk.size, body.size)
            }
        }

    /** Passes everything to [d], but holds [close] until [gate] opens: the HTTP/3 close is then ahead of the transport's. */
    private class GatedClose(
        val d: QuicConnection,
    ) : QuicConnection by d {
        val gate = CompletableDeferred<Unit>()

        override suspend fun close(
            code: Long,
            reason: String,
        ) {
            gate.await()
            d.close(code, reason)
        }
    }

    /**
     * A local close is decided before the transport settled which streams came whole: the session's `closed` completes
     * at once, while the last DATA and FIN of an unread request body still sit in the network, and they arrive before the
     * transport acts on the close. The stream then came whole, so the body's pump must not go on waiting for a handler that
     * never reads: it hands the rest over once the transport is gone, and the session ends.
     */
    @Test fun unreadBodyWholeOnlyAfterALocalCloseLetsTheSessionEnd() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val gated = GatedClose(s)
                val server = Http3Connection.server(gated)
                val session = server.session
                session.drainTimer = { awaitCancellation() } // the grace never runs out: only the reader's own end counts
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, POST))
                st.output.flush()
                val req = withTimeout(5.seconds) { server.acceptRequest() } as ServerRequestImpl
                val chunk = ByteArray(16 * 1024) { (it * 7).toByte() }
                val chunks = 80 // more than the body channel takes before its writer waits for the handler
                // the bytes the server's endpoint took from its socket, counted as it takes them
                val toServer = MutableStateFlow(0L)
                q.net.taken = { _, to, bytes -> if (to == q.server.localAddress) toServer.update { it + bytes.size } }
                repeat(chunks - 1) { st.output.writeFully(raw.data(chunk)) }
                st.output.flush()
                withTimeout(5.seconds) { toServer.first { it >= (chunks - 1).toLong() * chunk.size } }
                // the last chunk and the FIN stay in the network until the session decided on its close
                val held = ArrayList<Triple<InetSocketAddress, InetSocketAddress, ByteArray>>()
                val heldOne = CompletableDeferred<Unit>()
                q.net.drop = { from, to, bytes ->
                    from != q.server.localAddress && held.add(Triple(from, to, bytes)).also { heldOne.complete(Unit) }
                }
                st.output.writeFully(raw.data(chunk))
                st.output.flushAndClose()
                withTimeout(5.seconds) { heldOne.await() }
                val closing = async { session.close(Http3ErrorCode.NO_ERROR, "") }
                withTimeout(5.seconds) { server.closed.await() }
                repeat(2) { withContext(session.dispatcher) {} } // the pump saw the HTTP/3 close, the stream not yet whole
                assertTrue(!req.stream.receivedAll, "the FIN is still in the network")
                q.net.drop = null
                for ((from, to, bytes) in held) q.net.deliver(from, to, bytes)
                withTimeout(5.seconds) { req.stream.awaitReceivedAllForTest() }
                gated.gate.complete(Unit)
                withTimeout(5.seconds) { closing.await() }
                withTimeout(5.seconds) {
                    session.scope.coroutineContext.job
                        .join()
                }
                val body = withTimeout(5.seconds) { req.body.readAllBytes() }
                assertEquals(chunks * chunk.size, body.size)
            }
        }

    /** The client's mirror: a whole response body nobody reads lets its reader end once the connection is gone. */
    @Test fun unreadWholeResponseBodyLetsItsReaderEnd() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c)
                client.session.drainTimer = { awaitCancellation() }
                val raw = RawPeer(s)
                raw.openControl()
                client.peerSettings.filterNotNull().first()
                val response = async { client.request(get()) }
                val st = s.acceptBidi()
                st.input.readAllBytes()
                st.output.writeFully(raw.headers(st.id, listOf(":status" to "200")))
                st.output.flush()
                val r = withTimeout(5.seconds) { response.await() } as ResponseImpl
                val chunk = ByteArray(16 * 1024) { (it * 7).toByte() }
                val chunks = 80
                repeat(chunks) { st.output.writeFully(raw.data(chunk)) }
                st.output.flushAndClose()
                withTimeout(5.seconds) { r.stream.awaitReceivedAllForTest() }
                s.close(Http3ErrorCode.NO_ERROR, "")
                withTimeout(5.seconds) { client.closed.await() }
                withTimeout(5.seconds) { r.pump.join() }
                withTimeout(5.seconds) {
                    client.session.scope.coroutineContext.job
                        .join()
                }
                val body = withTimeout(5.seconds) { r.body.readAllBytes() }
                assertEquals(chunks * chunk.size, body.size)
            }
        }

    /**
     * A reader started after the connection ended still runs: a response whose headers were read after the session
     * processed the close launched its body's pump into a cancelled scope, and the body ended with H3_NO_ERROR, unread.
     */
    @Test fun drainerLaunchedAfterTheEndRuns() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c)
                RawPeer(s).openControl()
                client.peerSettings.filterNotNull().first()
                s.close(Http3ErrorCode.NO_ERROR, "")
                withTimeout(5.seconds) { client.closed.await() }
                val session = client.session
                val sessionJob = session.scope.coroutineContext.job
                withTimeout(5.seconds) { sessionJob.join() } // the session's own coroutines are gone
                val ran = CompletableDeferred<Unit>()
                val job = withContext(session.dispatcher) { session.launchDrainer { ran.complete(Unit) } }
                withTimeout(5.seconds) { job.join() }
                assertTrue(ran.isCompleted, "the drainer ran: $job")
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
                // the bytes the client's endpoint took from its socket, counted as it takes them
                val toClient = MutableStateFlow(0L)
                q.net.taken = { _, to, bytes -> if (to == q.client.localAddress) toClient.update { it + bytes.size } }
                // more than the body channel holds before its writer waits: the pump waits on a reader that never comes
                val chunk = ByteArray(16 * 1024)
                repeat(256) { st.output.writeFully(raw.data(chunk)) }
                st.output.flush()
                // beyond the stream window: the server could send that much only after the client gave credit for what its
                // pump read into the body channel, which now waits for room
                withTimeout(5.seconds) { toClient.first { it >= 1_200_000 } }
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
                assertFailsWith<Throwable>("the handler's response writes (16 MiB, no reader) succeeded") {
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

    /**
     * The connection ends while the server's handler has a response open and its writer's pump waits for content: the
     * pump is cancelled with the session's coroutines, the handler's answer then fails, and the request still ends with
     * nothing of it registered. A pump cancelled so used to end without ending the request, which stayed in the session's
     * map for good: EarlyDataTest.earlyRequestEndsWhenTheConnectionIsLostBeforeTheAnswer failed so on a Windows VM, where
     * the client's close reached the server between the handler's respond and its write.
     */
    @Test fun responseOpenWhenTheConnectionEndsLeavesNoRequest() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val response = async { runCatching { p.client.request(get()) } }
                val req = withTimeout(5.seconds) { p.server.acceptRequest() }
                val w = req.respond(200)
                val s = p.server.session
                p.client.close()
                withTimeout(5.seconds) { p.server.closed.await() }
                // the order behind the bug: the session's coroutines, the waiting pump among them, are cancelled before the write
                awaitCoroutinesCancelled(s)
                val answer =
                    runCatching {
                        w.output.writeFully("GET ok".encodeToByteArray())
                        w.finish()
                    }
                assertTrue(answer.isFailure, "the answer on a lost connection failed: $answer")
                awaitNothingRegistered(s)
                response.join()
            }
        }

    /**
     * The handler resets its request once the connection ended, before it answered: the request ends with the reset. Its
     * end was launched into the session's scope, gone with the connection, so it never ran and the request stayed
     * registered.
     */
    @Test fun requestResetAfterTheConnectionEndedLeavesNoRequest() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val response = async { runCatching { p.client.request(get()) } }
                val req = withTimeout(5.seconds) { p.server.acceptRequest() }
                val s = p.server.session
                p.client.close()
                withTimeout(5.seconds) { p.server.closed.await() }
                awaitCoroutinesCancelled(s)
                runCatching { req.reset(Http3ErrorCode.REQUEST_CANCELLED) }
                awaitNothingRegistered(s)
                response.join()
            }
        }

    /**
     * The same for an extended CONNECT whose tunnel the server already ended its way (FIN sent): the connection ends while
     * the client's direction is open, then the handler resets the tunnel. The exchange ends with the reset, its datagram
     * channel included; that end was launched into the session's scope, gone with the connection.
     */
    @Test fun tunnelResetAfterTheConnectionEndedLeavesNothing() =
        h3Test {
            H3Pair.open(serverSettings = http3Settings { enableConnectProtocol = true }).useScoped { p ->
                val tunnel = async { runCatching { p.client.connect(connectReq(), "echo") } }
                val st = withTimeout(5.seconds) { p.server.acceptRequest() }.acceptConnect()
                st.output.flushAndClose()
                val s = p.server.session
                assertTrue(withContext(s.dispatcher) { s.datagrams.registeredCount } > 0, "the tunnel has a datagram channel")
                p.client.close()
                withTimeout(5.seconds) { p.server.closed.await() }
                awaitCoroutinesCancelled(s)
                runCatching { st.reset(Http3ErrorCode.REQUEST_CANCELLED) }
                awaitNothingRegistered(s)
                tunnel.join()
            }
        }

    /**
     * The client's side of a tunnel: its datagram channel goes when the tunnel's receive side ended, in a coroutine of the
     * session's scope, which the connection's end cancelled before it ran. Once the connection ended and the session's
     * coroutines are gone, the client keeps no datagram channel (an application reading datagrams is not left waiting on one
     * nothing will ever close).
     */
    @Test fun clientTunnelDatagramChannelEndsWithTheConnection() =
        h3Test {
            H3Pair.open(serverSettings = http3Settings { enableConnectProtocol = true }).useScoped { p ->
                val tunnel = async { p.client.connect(connectReq(), "echo") }
                withTimeout(5.seconds) { p.server.acceptRequest() }.acceptConnect()
                withTimeout(5.seconds) { tunnel.await() }
                val c = p.client.session
                assertTrue(withContext(c.dispatcher) { c.datagrams.registeredCount } > 0, "the client's tunnel has a datagram channel")
                p.server.close()
                withTimeout(5.seconds) { p.client.closed.await() }
                awaitCoroutinesCancelled(c)
                withTimeoutOrNull(20.seconds) {
                    while (withContext(c.dispatcher) { c.datagrams.registeredCount } > 0) kotlinx.coroutines.yield()
                }
                    ?: fail("the client still keeps ${withContext(c.dispatcher) { c.datagrams.registeredCount }} datagram channel(s)")
            }
        }

    /**
     * The handler never answers (it failed before respond, or its engine cancelled it): once the connection ended and the
     * session's coroutines are gone, the request ends anyway, and an answer tried after that fails with the connection's
     * error, not with a request that is merely finished. Nothing ended such a request before: it stayed registered.
     */
    @Test fun requestNeverAnsweredEndsWithTheConnection() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val response = async { runCatching { p.client.request(get()) } }
                val req = withTimeout(5.seconds) { p.server.acceptRequest() }
                val s = p.server.session
                p.client.close()
                withTimeout(5.seconds) { p.server.closed.await() }
                awaitCoroutinesCancelled(s)
                awaitNothingRegistered(s)
                val late = assertFailsWith<Throwable> { req.respond(200) }
                assertTrue(late is Http3Exception, "an answer after the connection ended fails with the connection's error: $late")
                response.join()
            }
        }

    /** A WebTransport session the server accepted ends with the connection: no session, request or datagram channel is kept. */
    @Test fun webTransportSessionLeavesNothingWhenTheConnectionEnds() =
        h3Test {
            val wt =
                http3Settings {
                    enableConnectProtocol = true
                    webTransport = true
                }
            H3Pair.open(clientSettings = wt, serverSettings = wt).useScoped { p ->
                val server = async { p.server.acceptRequest().acceptWebTransport() }
                p.client.webTransport(http3Request("CONNECT", "server.test", "/wt"))
                withTimeout(5.seconds) { server.await() }
                val s = p.server.session
                assertTrue(registered(s) != null, "the session is registered while the connection lives")
                p.client.close()
                withTimeout(5.seconds) { p.server.closed.await() }
                awaitCoroutinesCancelled(s)
                awaitNothingRegistered(s)
            }
        }

    /**
     * A handler cancelled inside finish, while the writer's pump still hands its content over, on a live connection: the
     * response is abandoned, reset with H3_REQUEST_CANCELLED (RFC 9114 section 4.1.1), and the request ends. The pump saw
     * that finish would end the stream and left it to finish, which its cancelled caller never did: no FIN, no reset, the
     * client's body read waited for good and the request stayed registered (counted against the GOAWAY idle close).
     */
    @Test fun finishCancelledWhileThePumpHandsOverAbandonsTheResponse() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val s = p.server.session
                val atEnd = CompletableDeferred<Unit>()
                val release = CompletableDeferred<Unit>()
                s.atResponseContentEndForTest = {
                    atEnd.complete(Unit)
                    release.await()
                }
                val response = async { p.client.request(get()) }
                val req = withTimeout(5.seconds) { p.server.acceptRequest() }
                val handler =
                    launch {
                        val w = req.respond(200)
                        w.output.writeFully("partial".encodeToByteArray())
                        w.finish()
                    }
                withTimeoutOrNull(20.seconds) { atEnd.await() } ?: fail("the pump did not reach the end of the content")
                // the client has the response's head before the abandon: after a reset, STREAM data not yet received is never sent
                // again (RFC 9000 sections 13.3 and 19.4): a lost HEADERS frame fails the request, as it may (API 24 in CI)
                val r = withTimeout(5.seconds) { response.await() }
                handler.cancel()
                handler.join()
                release.complete(Unit)
                val body = withTimeoutOrNull(20.seconds) { runCatching { r.body.readAllBytes() } }
                assertTrue(body != null, "the client's body read never ended: neither FIN nor reset was sent")
                assertTrue(body.isFailure, "the abandoned response reads as failed, not complete: $body")
                awaitNothingRegistered(s)
                assertFalse(p.server.closed.isCompleted, "the connection lives on")
            }
        }

    /**
     * A handler cancelled inside finish as the FIN is handed over (the stream's flushAndClose suspends), with the request
     * body still unread: the response is abandoned and never counted as complete. The finally around the FIN marked it
     * complete first, so respondedInFull was set and the client stopped with H3_NO_ERROR before the abandon's reset.
     */
    @Test fun finishCancelledAtTheFinIsNotCountedComplete() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val s = p.server.session
                val atFin = CompletableDeferred<Unit>()
                s.beforeResponseFinForTest = {
                    atFin.complete(Unit)
                    awaitCancellation()
                }
                val body = ByteChannel() // left open: the request's body is never read to its end
                val response = async { p.client.request(http3Request("POST", "server.test", "/") { this.body = body }) }
                val req = withTimeout(5.seconds) { p.server.acceptRequest() } as ServerRequestImpl
                val handler =
                    launch {
                        val w = req.respond(200)
                        w.output.writeFully("partial".encodeToByteArray())
                        w.finish()
                    }
                withTimeoutOrNull(20.seconds) { atFin.await() } ?: fail("finish did not reach the FIN")
                val r = withTimeout(5.seconds) { response.await() } // its head first, as above
                handler.cancel()
                handler.join()
                assertFalse(req.respondedInFull, "a response whose finish was cancelled before its FIN is not complete")
                val read = withTimeoutOrNull(20.seconds) { runCatching { r.body.readAllBytes() } }
                assertTrue(read != null && read.isFailure, "the abandoned response reads as failed: $read")
                awaitNothingRegistered(s)
                body.close()
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
                assertBodyWritesFail(body)
                response.join()
            }
        }

    /**
     * The connection ends between the request's HEADERS and the start of its sender: the stream's flush fails with the
     * close, so the request fails before a sender exists. The application writing the body is released all the same. Only
     * the sender (or its cancellation) ended the body, so its writes waited forever: requestBodyWriteAfterTheConnectionEndedFails
     * failed so on a macOS runner, where the server's close won the race with the flush of the request's HEADERS.
     */
    @Test fun requestBodyWriteFailsWhenTheConnectionEndsBeforeTheSenderStarts() =
        h3Test {
            H3Pair.open().useScoped { p ->
                // the order behind the bug, forced: the connection is gone before the HEADERS are flushed
                p.client.session.afterRequestHeadersForTest = {
                    p.server.close()
                    withTimeout(5.seconds) { p.client.closed.await() }
                }
                val body = ByteChannel()
                val response = async { runCatching { p.client.request(http3Request("POST", "server.test", "/") { this.body = body }) } }
                val result = withTimeout(5.seconds) { response.await() }
                assertTrue(result.isFailure, "a request whose connection ended before its body was sent failed: $result")
                assertBodyWritesFail(body)
            }
        }

    /** Writes [body] far beyond what its channel buffers: they must fail, neither succeed (no reader) nor hang. */
    private suspend fun assertBodyWritesFail(body: ByteChannel) {
        val chunk = ByteArray(64 * 1024)
        assertFailsWith<Throwable>("the application's body writes (16 MiB, no reader) succeeded") {
            withTimeout(5.seconds) {
                repeat(256) {
                    // 16 MiB: far more than the channel buffers
                    body.writeFully(chunk)
                    body.flush()
                }
            }
        }.let { e -> assertTrue(e !is TimeoutCancellationException, "the application's body write hung (the body was never cancelled)") }
    }
}
