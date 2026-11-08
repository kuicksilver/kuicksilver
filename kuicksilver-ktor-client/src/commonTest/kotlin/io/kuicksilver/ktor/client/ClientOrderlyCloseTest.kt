// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
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
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
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
     * behind the call (its reader is cut at once), not in front of its SocketTimeoutException.
     */
    @Test fun negative_socketTimeoutFiresOnTimeAgainstAHungServer() =
        clientTest {
            val clean = CompletableDeferred<Boolean>()
            val release = CompletableDeferred<Unit>()
            tlsH1WithSilentUdp(silentUdp = false, handler = { _, input, _ ->
                readRequest(input)
                clean.complete(input.endsCleanly())
                release.await() // never answers the client's close_notify, holds the connection
            }) { port ->
                testClient(block = { install(HttpTimeout) { socketTimeoutMillis = 300 } }).use { c ->
                    val start =
                        kotlin.time.TimeSource.Monotonic
                            .markNow()
                    val e = runCatching { c.get("https://127.0.0.1:$port/") }.exceptionOrNull()
                    val took = start.elapsedNow()
                    assertTrue(e is io.ktor.client.network.sockets.SocketTimeoutException, "failed with $e")
                    assertTrue(took < 800.milliseconds, "the timeout of 300 ms surfaced after $took")
                    assertTrue(withTimeout(10.seconds) { clean.await() }, "the server saw the client's close_notify")
                }
                release.complete(Unit)
            }
        }

    /** What a hand-written HTTP/2 server saw of the client's end: the GOAWAY codes and whether TLS ended cleanly. */
    private class H2End {
        val goAways = ArrayList<Long>()
        val clean = CompletableDeferred<Boolean>()
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
