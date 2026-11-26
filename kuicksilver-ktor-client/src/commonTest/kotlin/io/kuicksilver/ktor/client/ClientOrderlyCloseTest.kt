// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.prepareGet
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.runtime.Http2Exception
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.IO
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * How the client ends its TLS connections. RFC 9846 section 6.1: "Each party MUST send a 'close_notify' alert before
 * closing its write side of the connection, unless it has already sent some error alert". RFC 9113 section 5.4.1: "An
 * endpoint that encounters a connection error SHOULD first send a GOAWAY frame", and a client that closes an HTTP/2
 * connection sends GOAWAY first (section 6.8). The server is ours over TLS: its input ends cleanly only after the client's
 * close_notify, and fails as a truncation without one.
 */
class ClientOrderlyCloseTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun engine(c: io.ktor.client.HttpClient) = c.engine as KuicksilverEngine

    /** Reads [this] to its end: true when it ended with close_notify, false on a truncation or another failure. */
    private suspend fun ByteReadChannel.endsCleanly(): Boolean =
        runCatching {
            val b = ByteArray(4096)
            while (readAvailable(b, 0, b.size) >= 0) continue
            closedCause == null
        }.getOrDefault(false)

    @Test fun connectionCloseResponseEndsWithCloseNotify() =
        clientTest {
            val clean = CompletableDeferred<Boolean>()
            tlsH1WithSilentUdp(silentUdp = false, handler = { _, input, output ->
                readRequest(input)
                output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                output.flush()
                clean.complete(input.endsCleanly())
            }) { port ->
                testClient().use { c -> assertEquals("ok", c.get("https://127.0.0.1:$port/").bodyAsText()) }
                assertTrue(withTimeout(10.seconds) { clean.await() }, "the server saw the client's close_notify")
            }
        }

    @Test fun idleConnectionClosedWithTheEngineEndsWithCloseNotify() =
        clientTest {
            val clean = CompletableDeferred<Boolean>()
            tlsH1WithSilentUdp(silentUdp = false, handler = { _, input, output ->
                readRequest(input)
                output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                output.flush()
                clean.complete(input.endsCleanly())
            }) { port ->
                testClient().use { c -> assertEquals("ok", c.get("https://127.0.0.1:$port/").bodyAsText()) }
                assertTrue(withTimeout(10.seconds) { clean.await() }, "the server saw the client's close_notify")
            }
        }

    /**
     * RFC 9846 section 6.1: an exchange that fails after the whole request went out leaves the client's write side whole,
     * so the connection ends with close_notify (a TLS 1.3 client has no error alert to send): a malformed response head.
     */
    @Test fun malformedResponseHeadEndsWithCloseNotify() =
        clientTest {
            val clean = CompletableDeferred<Boolean>()
            tlsH1WithSilentUdp(silentUdp = false, handler = { _, input, output ->
                readRequest(input)
                output.writeStringUtf8("not a status line\r\n\r\n")
                output.flush()
                clean.complete(input.endsCleanly())
            }) { port ->
                testClient().use { c -> assertTrue(runCatching { c.get("https://127.0.0.1:$port/") }.isFailure) }
                assertTrue(withTimeout(10.seconds) { clean.await() }, "the server saw the client's close_notify")
            }
        }

    /**
     * RFC 9846 section 6.1 on first contact (TLS without ALPN, so the OPTIONS probe goes first): the connection a server
     * closes after its HTTP/1.0 answer to the probe, and the new one on which the request then fails before anything of
     * it is sent (a body of unknown length over the bound), both end with close_notify. Before, both were closed abruptly.
     */
    @Test fun firstContactEndsWithCloseNotify() =
        clientTest {
            val clean = List(2) { CompletableDeferred<Boolean>() }
            tlsWithSilentUdp(emptyList(), silentUdp = false, handler = { index, _, input, output ->
                if (index == 0) {
                    readRequest(input)
                    output.writeStringUtf8("HTTP/1.0 204 No Content\r\n\r\n")
                    output.flush()
                }
                clean.getOrNull(index)?.complete(input.endsCleanly())
            }) { port ->
                testClient().use { c ->
                    val big =
                        object : io.ktor.http.content.OutgoingContent.WriteChannelContent() {
                            override suspend fun writeTo(channel: ByteWriteChannel) {
                                channel.writeFully(ByteArray(io.kuicksilver.ktor.client.h1.FIRST_CONTACT_BODY_LIMIT + 1))
                            }
                        }
                    assertFailsWith<IllegalStateException> { c.post("https://127.0.0.1:$port/") { setBody(big) } }
                }
                for (i in clean.indices) {
                    assertTrue(
                        withTimeout(10.seconds) { clean[i].await() },
                        "connection $i saw the client's close_notify",
                    )
                }
            }
        }

    /** The same for a response that does not come within the socket timeout. */
    @Test fun responseTimeoutEndsWithCloseNotify() =
        clientTest {
            val clean = CompletableDeferred<Boolean>()
            tlsH1WithSilentUdp(silentUdp = false, handler = { _, input, _ ->
                readRequest(input)
                clean.complete(input.endsCleanly())
            }) { port ->
                testClient(block = { install(HttpTimeout) { socketTimeoutMillis = 300 } }).use { c ->
                    assertTrue(runCatching { c.get("https://127.0.0.1:$port/") }.isFailure)
                }
                assertTrue(withTimeout(10.seconds) { clean.await() }, "the server saw the client's close_notify")
            }
        }

    /**
     * The socket timeout fires on time against a hung server that never answers our close_notify: the orderly close runs
     * behind the call (its reader is cut at once), not in front of its SocketTimeoutException. Counted from the moment the
     * server read the request (the socket timeout's own start, near enough), the timeout of 300 ms surfaces within 10 s;
     * the orderly close, whose bound (1 s otherwise) is stretched to 30 s here, would hold it 30 s more in front of it.
     */
    @Test fun negative_socketTimeoutFiresOnTimeAgainstAHungServer() =
        clientTest {
            val clean = CompletableDeferred<Boolean>()
            val release = CompletableDeferred<Unit>()
            val requestRead = CompletableDeferred<kotlin.time.TimeSource.Monotonic.ValueTimeMark>()
            tlsH1WithSilentUdp(silentUdp = false, handler = { _, input, _ ->
                readRequest(input)
                requestRead.complete(
                    kotlin.time.TimeSource.Monotonic
                        .markNow(),
                )
                clean.complete(input.endsCleanly())
                release.await() // never answers the client's close_notify, holds the connection
            }) { port ->
                testClient(block = { install(HttpTimeout) { socketTimeoutMillis = 300 } }).use { c ->
                    engine(c).h1.orderlyCloseTimeoutForTest = 30.seconds
                    val e = runCatching { c.get("https://127.0.0.1:$port/") }.exceptionOrNull()
                    val took = requestRead.await().elapsedNow()
                    assertTrue(e is io.ktor.client.network.sockets.SocketTimeoutException, "failed with $e")
                    assertTrue(took < 10.seconds, "the timeout of 300 ms surfaced $took after the server read the request")
                    assertTrue(withTimeout(10.seconds) { clean.await() }, "the server saw the client's close_notify")
                }
                release.complete(Unit)
            }
        }

    /**
     * The class of curl #23551 (a shutdown that waits on a silent peer with no timer armed): a server that keeps reading but
     * never answers the client's close_notify, and never closes, holds the client's connection for the orderly close's bound
     * (1 s) at most: the FIN follows the close_notify within it, armed when the close starts and not by anything the peer does
     * (here the close a `Connection: close` response starts, with the engine still open).
     * The server's TLS session reads a copy of the socket's input, so the FIN is seen under it.
     */
    @Test fun negative_aServerThatNeverAnswersCloseNotifyHoldsTheConnectionForTheBoundOnly() =
        clientTest {
            val selector =
                io.ktor.network.selector
                    .SelectorManager(kotlinx.coroutines.Dispatchers.IO)
            val listener =
                io.kuicksilver.ktor.network
                    .bindTcp(selector, "127.0.0.1", 0)
            val closeNotify = CompletableDeferred<kotlin.time.TimeSource.Monotonic.ValueTimeMark>()
            val fin = CompletableDeferred<kotlin.time.TimeSource.Monotonic.ValueTimeMark>()
            val hold = CompletableDeferred<Unit>()
            try {
                kotlinx.coroutines.coroutineScope {
                    val server =
                        launch {
                            val socket = listener.accept()
                            try {
                                val socketIn = socket.openReadChannel()
                                val socketOut = socket.openWriteChannel(autoFlush = true)
                                val fed =
                                    io.ktor.utils.io
                                        .ByteChannel()
                                launch {
                                    val buf = ByteArray(16_384)
                                    while (true) {
                                        val n = runCatching { socketIn.readAvailable(buf, 0, buf.size) }.getOrDefault(-1)
                                        if (n < 0) break
                                        runCatching {
                                            fed.writeFully(buf, 0, n)
                                            fed.flush()
                                        }
                                    }
                                    fin.complete(
                                        kotlin.time.TimeSource.Monotonic
                                            .markNow(),
                                    )
                                    fed.flushAndClose()
                                }
                                val session =
                                    io.kuicksilver.tls.TlsConnection.server(
                                        fed,
                                        socketOut,
                                        io.kuicksilver.tls.tlsConfig(io.kuicksilver.tls.TlsRole.Server) {
                                            identity = ClientFixtures.identity()
                                            alpn = listOf("http/1.1")
                                        },
                                        coroutineContext,
                                    )
                                readRequest(session.input)
                                session.output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                                session.output.flush()
                                if (session.input.endsCleanly()) {
                                    closeNotify.complete(
                                        kotlin.time.TimeSource.Monotonic
                                            .markNow(),
                                    )
                                }
                                hold.await() // never answers the close_notify, never closes
                            } finally {
                                socket.close() // once the test is over (the leak sentinel counts an accepted socket left open)
                            }
                        }
                    val port = (listener.localAddress as io.ktor.network.sockets.InetSocketAddress).port
                    // the engine stays open: its close (which cuts every orderly close after 2 s) is not what ends this one
                    testClient().use { c ->
                        assertEquals("ok", c.get("https://127.0.0.1:$port/").bodyAsText())
                        val notified = withTimeout(10.seconds) { closeNotify.await() }
                        val finAt = withTimeout(10.seconds) { fin.await() }
                        val held = finAt - notified
                        assertTrue(held < 5.seconds, "the client's FIN came $held after its close_notify to a server that never answered")
                    }
                    hold.complete(Unit)
                    server.cancel()
                }
            } finally {
                listener.close()
                selector.close()
            }
        }

    /**
     * The server sends [head] and then a body of [size] bytes, then its close_notify (its write side ends), and keeps the
     * connection until the client's close is over and the client's end was read (the fixture closes the raw socket as the
     * handler returns, which would cut the server's own drain short); [call] makes the request and leaves the response. The client's orderly close (its
     * bound stretched to 30 s) must end well within it either way. With [cut] false, what is left of the body is within
     * the session's drop bound (TlsConnection.INPUT_DROP_LIMIT): the server must see close_notify, and its writes must all
     * go through, as the client read and dropped them until the server's close_notify rather than closing under them
     * (which resets the connection). With [cut], what is left is far beyond the bound and every buffer on the way: the
     * client stops reading once it dropped its bound and closes under the rest, so the server's writes fail instead of
     * running to the end (a response nobody reads is not downloaded for the length of the close's wait).
     *
     * With [leftAfter] the server sends only that much of the body, then waits until [call] returned (the application
     * left the response) before it sends the rest: the rest arrives only after the response was left. Without that order,
     * a response that fits every buffer on the way (192 KiB; the body's channel alone holds 1 MiB) could arrive whole
     * while the application, descheduled under load, still held it. The body then ended by its length, and the
     * connection was rightly kept for reuse instead of closed: the test no longer tested an abandoned response. It
     * waited for a close that came only at the idle timeout (5 minutes; an Android device run under load timed out at
     * 60 s). The connection must be released as not kept, so a run that falls back into reuse fails on that, not on time.
     */
    private suspend fun assertOrderlyCloseOfUnreadBody(
        head: String,
        size: Int,
        cut: Boolean,
        leftAfter: Int? = null,
        call: suspend (io.ktor.client.HttpClient, String) -> Unit,
    ) {
        val chunkSize = 16 * 1024
        require(leftAfter == null || (leftAfter % chunkSize == 0 && leftAfter in chunkSize until size)) {
            "leftAfter ($leftAfter) must be a whole number of ${chunkSize shr 10} KiB chunks inside the body ($size bytes)"
        }
        val left = CompletableDeferred<Unit>()
        val released = CompletableDeferred<Boolean>()
        val events =
            object : KuicksilverEventListener() {
                override fun connectionReleased(
                    request: io.ktor.client.request.HttpRequestData,
                    protocol: HttpProtocolVersion,
                    kept: Boolean,
                ) {
                    released.complete(kept)
                }
            }
        val clean = CompletableDeferred<Boolean>()
        val took = CompletableDeferred<kotlin.time.Duration>()
        val sent = CompletableDeferred<Boolean>()
        tlsH1WithSilentUdp(silentUdp = false, handler = { _, input, output ->
            readRequest(input)
            launch { clean.complete(input.endsCleanly()) }
            sent.complete(
                runCatching {
                    output.writeStringUtf8(head)
                    val chunk = ByteArray(chunkSize)
                    repeat(size / chunk.size) { i ->
                        if (leftAfter != null && i * chunk.size == leftAfter) {
                            output.flush()
                            left.await()
                        }
                        output.writeFully(chunk)
                    }
                    output.flushAndClose() // then the server's close_notify
                }.isSuccess,
            )
            // the reading of the client's end too: with a short rest the client's close can be over (its wait ended by the
            // server's close_notify, already read) before this side read the client's close_notify, and the handler's end
            // would cancel that read
            withTimeoutOrNull(60.seconds) {
                took.await()
                clean.await()
            }
        }) { port ->
            testClient(engine = { eventListener = events }).use { c ->
                engine(c).h1.orderlyCloseTimeoutForTest = 30.seconds
                engine(c).h1.orderlyCloseTookForTest = { took.complete(it) }
                try {
                    call(c, "https://127.0.0.1:$port/")
                } finally {
                    left.complete(Unit) // also after a call that failed: the server does not wait for ever
                }
                assertFalse(
                    withTimeout(10.seconds) { released.await() },
                    "the connection was kept for reuse: the response arrived whole before the application left it",
                )
                val t = withTimeout(60.seconds) { took.await() }
                assertTrue(t < 10.seconds, "the orderly close took $t behind a response nobody reads")
                if (cut) {
                    assertFalse(
                        withTimeout(20.seconds) { sent.await() },
                        "the server wrote all of the ${size shr 20} MiB nobody reads: the client downloaded it while it closed",
                    )
                } else {
                    assertTrue(withTimeout(10.seconds) { clean.await() }, "the server saw the client's close_notify")
                    assertTrue(withTimeout(10.seconds) { sent.await() }, "the server's writes went through, not cut by a reset")
                }
            }
        }
    }

    /**
     * A response of [size] bytes the application leaves after its first 64 KiB, which is all the server sends before the
     * application left it (once `execute` returned: the response was cleaned up, its body cancelled).
     */
    private suspend fun abandonAfter64KiB(
        size: Int,
        cut: Boolean,
    ) = assertOrderlyCloseOfUnreadBody(
        "HTTP/1.1 200 OK\r\nContent-Length: $size\r\n\r\n",
        size,
        cut,
        leftAfter = 64 * 1024,
    ) { c, url ->
        c.prepareGet(url).execute { r ->
            val ch = r.bodyAsChannel()
            val buf = ByteArray(16 * 1024)
            var read = 0
            while (read < 64 * 1024) read += ch.readAvailable(buf, 0, buf.size).also { check(it >= 0) }
        } // the rest is abandoned
    }

    /** A response refused after its head (an invalid Content-Length, RFC 9112 section 6.3 item 5) with [size] bytes after it. */
    private suspend fun refuse(
        size: Int,
        cut: Boolean,
    ) = assertOrderlyCloseOfUnreadBody("HTTP/1.1 200 OK\r\nContent-Length: 1, 2\r\n\r\n", size, cut) { c, url ->
        assertTrue(runCatching { c.get(url) }.isFailure, "the invalid Content-Length was refused")
    }

    /**
     * A response the application leaves halfway ends the connection in order without waiting behind the rest of the body.
     * The abandoned body's channel cancels the connection's input; the TLS session then reads on and drops what still
     * comes (128 KiB here, within its drop bound) until the server's close_notify. Before, it stopped reading there: the
     * close did not wait for the server's close_notify and closed under the rest of the body, so the kernel reset the
     * connection (the server's writes failed, and the reset could erase the client's close_notify before the server read
     * it).
     */
    @Test fun negative_anAbandonedResponseDoesNotHoldTheOrderlyClose() = clientTest { abandonAfter64KiB(192 * 1024, cut = false) }

    /**
     * An abandoned response whose rest is far beyond the session's drop bound (64 MiB, as an abandoned download or a
     * request timeout mid-body leaves it) is cut: the session drops its bound and stops reading, and the connection closes
     * under the rest, so the server's writes fail. Before, the session read and dropped all of it for as long as the
     * close's wait lasted (1 s; 30 s here), so the server wrote the whole response (engine interop's
     * requestTimeoutMidBody against Netty: 1 GiB within the second).
     */
    @Test fun negative_anAbandonedLargeResponseIsCutPastTheDropBound() = clientTest { abandonAfter64KiB(64 shl 20, cut = true) }

    /**
     * A response the client refuses after its head while the server goes on sending (128 KiB after it, within the drop
     * bound): the exchange failed after the whole request went out, so the connection ends in order (RFC 9846 section
     * 6.1), and nothing reads what still comes. The client reads and drops it, so the server's writes go through and its
     * close_notify ends the wait. Before, the session waited for room in a channel nobody read, the server's writes waited
     * behind it, and every such close ran to its bound (1 s, stretched to 30 s here).
     */
    @Test fun negative_aRefusedResponseDoesNotHoldTheOrderlyClose() = clientTest { refuse(128 * 1024, cut = false) }

    /**
     * A refused response with 64 MiB after its head, far beyond the drop bound, neither holds the close to its bound nor
     * is read to its end: the session drops its bound and the connection closes under the rest.
     */
    @Test fun negative_aRefusedLargeResponseIsCutPastTheDropBound() = clientTest { refuse(64 shl 20, cut = true) }

    /**
     * What a hand-written HTTP/2 server saw of the client's end: the GOAWAY codes and last-stream-ids, in order, and whether
     * TLS ended cleanly (recorded after every GOAWAY: what came before the end). The lists are written by the server's
     * handler only; tests read them after [clean] completed, which the handler does after its last write.
     */
    private class H2End {
        val goAways = ArrayList<Long>()
        val goAwayLastIds = ArrayList<Long>()
        val clean = CompletableDeferred<Boolean>()

        /** Exactly one GOAWAY, with [code] and last-stream-id 0 (the server opens no streams), and then a clean TLS end. */
        suspend fun assertOneGoAwayThenCleanEnd(code: Http2ErrorCode) {
            assertTrue(withTimeout(10.seconds) { clean.await() }, "the server saw the client's close_notify")
            assertEquals(listOf(code.code), goAways, "one GOAWAY ($code) before the end")
            assertEquals(listOf(0L), goAwayLastIds, "its last-stream-id")
        }
    }

    private fun frame(
        type: Int,
        flags: Int,
        stream: Int,
        payload: ByteArray = ByteArray(0),
    ): ByteArray =
        byteArrayOf(
            (payload.size shr 16).toByte(),
            (payload.size shr 8).toByte(),
            payload.size.toByte(),
            type.toByte(),
            flags.toByte(),
            (stream ushr 24).toByte(),
            (stream shr 16).toByte(),
            (stream shr 8).toByte(),
            stream.toByte(),
        ) + payload

    /**
     * Answers every request with 200 and END_STREAM; with [violate] it answers with DATA on stream 0 instead, a connection
     * error of type PROTOCOL_ERROR (RFC 9113 section 6.1). Records every GOAWAY until the input ends.
     */
    private suspend fun h2Server(
        input: ByteReadChannel,
        output: ByteWriteChannel,
        end: H2End,
        violate: Boolean,
    ) {
        try {
            input.readByteArray(24)
            output.writeFully(frame(4, 0, 0))
            output.flush()
            while (true) {
                val head = input.readByteArray(9)
                val len = ((head[0].toInt() and 0xff) shl 16) or ((head[1].toInt() and 0xff) shl 8) or (head[2].toInt() and 0xff)
                val type = head[3].toInt() and 0xff
                val flags = head[4].toInt() and 0xff
                val stream =
                    ((head[5].toInt() and 0x7f) shl 24) or ((head[6].toInt() and 0xff) shl 16) or
                        ((head[7].toInt() and 0xff) shl 8) or (head[8].toInt() and 0xff)
                val payload = input.readByteArray(len)
                when {
                    type == 4 && flags and 1 == 0 -> {
                        output.writeFully(frame(4, 1, 0))
                    }

                    type == 1 && violate -> {
                        output.writeFully(frame(0, 0, 0, "x".encodeToByteArray()))
                    }

                    type == 1 -> {
                        output.writeFully(frame(1, 0x5, stream, byteArrayOf(0x88.toByte())))
                    }

                    type == 7 -> {
                        end.goAwayLastIds +=
                            ((payload[0].toLong() and 0x7f) shl 24) or ((payload[1].toLong() and 0xff) shl 16) or
                            ((payload[2].toLong() and 0xff) shl 8) or (payload[3].toLong() and 0xff)
                        end.goAways +=
                            ((payload[4].toLong() and 0xff) shl 24) or ((payload[5].toLong() and 0xff) shl 16) or
                            ((payload[6].toLong() and 0xff) shl 8) or (payload[7].toLong() and 0xff)
                    }
                }
                output.flush()
            }
        } catch (_: Throwable) {
            // the input ended: how is what endsCleanly says
        }
        end.clean.complete(input.closedCause == null && input.isClosedForRead)
    }

    /** RFC 9113 section 6.8: an engine that closes its idle HTTP/2 connection sends GOAWAY (NO_ERROR), then close_notify. */
    @Test fun h2ConnectionClosedWithTheEngineSendsGoAwayAndCloseNotify() =
        clientTest {
            val end = H2End()
            tlsWithSilentUdp(listOf("h2"), silentUdp = false, handler = { _, _, input, output ->
                h2Server(input, output, end, violate = false)
            }) { port ->
                testClient().use { c -> assertEquals(HttpProtocolVersion.HTTP_2_0, c.get("https://127.0.0.1:$port/").version) }
                assertTrue(withTimeout(10.seconds) { end.clean.await() }, "the server saw the client's close_notify")
                assertEquals(listOf(0L), end.goAways, "one GOAWAY (NO_ERROR)")
            }
        }

    /**
     * RFC 9113 section 6.8, RFC 9846 section 6.1: the pool's own close of a live connection, here idle past `idleTimeout`,
     * sends GOAWAY (NO_ERROR) and then close_notify, while the engine is still open (the engine's close is the test above).
     */
    @Test fun h2ConnectionEvictedIdleSendsGoAwayAndCloseNotify() =
        clientTest {
            val end = H2End()
            tlsWithSilentUdp(listOf("h2"), silentUdp = false, handler = { _, _, input, output ->
                h2Server(input, output, end, violate = false)
            }) { port ->
                // 1 ms (the least the pool takes): the engine's reaper evicts the connection soon after the response
                testClient(engine = { idleTimeout = 1.milliseconds }).use { c ->
                    assertEquals(HttpProtocolVersion.HTTP_2_0, c.get("https://127.0.0.1:$port/").version)
                    end.assertOneGoAwayThenCleanEnd(Http2ErrorCode.NO_ERROR)
                }
            }
        }

    /**
     * A failure of ours between the start of an HTTP/2 connection and its hand-out (afterH2StartForTest throws): the call
     * fails with it, and the connection, its transport sound, ends in order: GOAWAY (INTERNAL_ERROR, RFC 9113 section
     * 5.4.1), then close_notify (RFC 9846 section 6.1); none of its coroutines stays behind.
     */
    @Test fun negative_failureAfterH2StartEndsTheConnectionInOrder() =
        clientTest {
            val end = H2End()
            tlsWithSilentUdp(listOf("h2"), silentUdp = false, handler = { _, _, input, output ->
                h2Server(input, output, end, violate = false)
            }) { port ->
                testClient().use { c ->
                    val pool = engine(c).h1
                    val failure = IllegalStateException("a failure after the HTTP/2 start")
                    pool.afterH2StartForTest = { _, _ -> throw failure }
                    val e = runCatching { c.get("https://127.0.0.1:$port/") }.exceptionOrNull()
                    assertTrue(generateSequence(e) { it.cause }.any { it === failure }, "the call failed with $e")
                    end.assertOneGoAwayThenCleanEnd(Http2ErrorCode.INTERNAL_ERROR)
                    assertEquals(0, pool.h2.connectionCount)
                    withTimeout(5.seconds) { pool.h2JobsForTest.toList().forEach { it.join() } }
                    assertEquals(emptyList(), pool.h2JobsForTest.toList())
                }
            }
        }

    /**
     * A server that stops answering PINGs (this one never does) has not lost the transport: the connection that fails its
     * health PING ends in order, GOAWAY (INTERNAL_ERROR, RFC 9113 sections 5.4.1 and 6.8) then close_notify (RFC 9846
     * section 6.1), and the request goes over a new connection.
     */
    @Test fun negative_h2PeerThatMissesAHealthPingGetsGoAwayAndCloseNotify() =
        clientTest {
            val first = H2End()
            tlsWithSilentUdp(listOf("h2"), silentUdp = false, handler = { index, _, input, output ->
                // only the first connection, the one that misses the PING, is inspected; the second just serves
                h2Server(input, output, if (index == 0) first else H2End(), violate = false)
            }) { port ->
                // the health PING waits half the connect timeout (1.5 s; this server never answers, so always that long),
                // and the new connection the remaining ~1.5 s of the same budget, as in ClientH2Test's health tests
                testClient(engine = { connectTimeout = 3.seconds }).use { c ->
                    engine(c).h1.h2HealthAfterIdleMillis = 0 // every reuse is checked
                    assertEquals(HttpProtocolVersion.HTTP_2_0, c.get("https://127.0.0.1:$port/").version)
                    assertEquals(HttpProtocolVersion.HTTP_2_0, c.get("https://127.0.0.1:$port/").version)
                    first.assertOneGoAwayThenCleanEnd(Http2ErrorCode.INTERNAL_ERROR)
                }
            }
        }

    /**
     * An HTTP/2 connection the client ends after a connection error (DATA on stream 0, RFC 9113 section 6.1) while the
     * server goes on sending more than every buffer on the way holds: the client's orderly close (GOAWAY, then
     * close_notify, its bound stretched to 30 s) reads and drops what still comes, up to the session's drop bound, and then
     * closes under the rest (64 MiB, far beyond it), so the server's writes fail rather than run to the end. Before, the
     * read loop had stopped with the closed connection, nothing read the session's input, and the close waited for the
     * server's close_notify behind it until the bound.
     */
    @Test fun negative_anH2CloseDoesNotWaitBehindDataNobodyReads() =
        clientTest {
            val took = CompletableDeferred<kotlin.time.Duration>()
            val sent = CompletableDeferred<Boolean>()
            tlsWithSilentUdp(listOf("h2"), silentUdp = false, handler = { _, _, input, output ->
                sent.complete(
                    runCatching {
                        input.readByteArray(24)
                        output.writeFully(frame(4, 0, 0))
                        output.flush()
                        while (true) {
                            val head = input.readByteArray(9)
                            val len =
                                ((head[0].toInt() and 0xff) shl 16) or ((head[1].toInt() and 0xff) shl 8) or
                                    (head[2].toInt() and 0xff)
                            input.readByteArray(len)
                            if (head[3].toInt() == 1) break // the request's HEADERS
                        }
                        output.writeFully(frame(0, 0, 0, "x".encodeToByteArray())) // a connection error: the client closes
                        val data = frame(0, 0, 1, ByteArray(16 * 1024))
                        repeat(4096) { output.writeFully(data) } // 64 MiB the client will not read
                        output.flushAndClose() // then the server's close_notify
                    }.isSuccess,
                )
                withTimeoutOrNull(60.seconds) { took.await() }
            }) { port ->
                testClient().use { c ->
                    engine(c).h1.orderlyCloseTimeoutForTest = 30.seconds
                    engine(c).h1.orderlyCloseTookForTest = { took.complete(it) }
                    assertTrue(runCatching { c.get("https://127.0.0.1:$port/") }.isFailure, "the connection error failed the call")
                    val t = withTimeout(60.seconds) { took.await() }
                    assertTrue(t < 10.seconds, "the HTTP/2 orderly close took $t behind DATA nobody reads")
                    assertFalse(
                        withTimeout(20.seconds) { sent.await() },
                        "the server wrote all of the 64 MiB nobody reads: the client downloaded it while it closed",
                    )
                }
            }
        }

    /** RFC 9113 section 5.4.1: a connection error found by the client is sent as GOAWAY before the connection closes. */
    @Test fun negative_h2ConnectionErrorReachesTheServerAsGoAway() =
        clientTest {
            val end = H2End()
            tlsWithSilentUdp(listOf("h2"), silentUdp = false, handler = { _, _, input, output ->
                h2Server(input, output, end, violate = true)
            }) { port ->
                testClient().use { c ->
                    // the call fails with the connection error before the engine closes (whose GOAWAY would be NO_ERROR)
                    val e = runCatching { c.get("https://127.0.0.1:$port/") }.exceptionOrNull()
                    val closed = generateSequence(e) { it.cause }.filterIsInstance<Http2Exception.ConnectionClosed>().firstOrNull()
                    assertEquals(Http2ErrorCode.PROTOCOL_ERROR, closed?.code, "the call failed with $e")
                    withTimeout(10.seconds) { end.clean.await() }
                }
                assertEquals(listOf(1L), end.goAways, "one GOAWAY (PROTOCOL_ERROR) reached the server")
            }
        }
}
