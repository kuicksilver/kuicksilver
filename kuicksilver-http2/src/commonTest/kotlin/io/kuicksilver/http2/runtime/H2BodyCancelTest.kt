// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalAPI::class, ExperimentalCoroutinesApi::class)

package io.kuicksilver.http2.runtime

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameDecoder
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.H2
import io.kuicksilver.http2.hpack.HpackEncoder
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.io.Buffer
import kotlinx.io.IOException
import kotlinx.io.RawSink
import kotlinx.io.readByteArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration

/**
 * Cancelling a body ([H2BodyChannel.cancel]) while its reader is at work. The reader owns the body's buffer; a cancel
 * comes from any thread (Ktor's `execute {}` ending the call, the call job's completion handler, both at once) while the
 * reader (Ktor's copier into the application's channel) is in the middle of a read. A cancel that emptied that buffer
 * pulled the bytes from under the read: `Buffer.clear()` ran against a buffer read on another thread and threw an
 * EOFException out of `cancel`, before the stream was reset, so the stream stayed open (ClientH2Test, found by the leak
 * sentinel). The cancel now leaves the buffer to its reader and only marks the body failed; it still resets the stream
 * with CANCEL (RFC 9113 section 8.1), once, however many cancels race.
 */
class H2BodyCancelTest {
    private class Wire {
        val toServer = ByteChannel()
        val toClient = ByteChannel()

        fun close() {
            toServer.close()
            toClient.close()
        }
    }

    private fun TestScope.clock(): () -> Long = { testScheduler.currentTime * 1_000_000 }

    private suspend fun TestScope.pair(): Pair<H2ClientConnection, H2ServerConnection> {
        val w = Wire()
        val server = H2ServerConnection.start(w.toServer, w.toClient, Http2Settings.Default, backgroundScope, { w.close() }, clock())
        val client =
            H2ClientConnection.start(
                w.toClient,
                w.toServer,
                Http2Settings.Default,
                backgroundScope,
                Duration.INFINITE,
                { w.close() },
                clock = clock(),
            )
        return client to server
    }

    /** A server that answers 200 with [part] and then holds the stream open; completes with the code it was reset with. */
    private fun TestScope.serveAndHold(
        server: H2ServerConnection,
        part: ByteArray,
    ): CompletableDeferred<Http2ErrorCode> {
        val reset = CompletableDeferred<Http2ErrorCode>()
        backgroundScope.async {
            val r = server.requests.receive()
            try {
                r.respond(200)
                r.sendBody(ByteReadChannel(part), end = false)
                val e = assertFailsWith<Http2Exception.StreamReset> { r.body.readAvailable(ByteArray(1)) }
                reset.complete(e.code)
            } finally {
                r.release()
            }
        }
        return reset
    }

    private fun H2ClientConnection.post(): H2ClientStream {
        assertTrue(tryReserve())
        return open("POST", "https", "example.com", "/", emptyList(), endStream = false)
    }

    /** A sink that runs [during] in the middle of the write it is given, then takes the bytes it was promised. */
    private class InterruptedSink(
        private val during: () -> Unit,
    ) : RawSink {
        val got = Buffer()

        override fun write(
            source: Buffer,
            byteCount: Long,
        ) {
            during()
            got.write(source.readByteArray(byteCount.toInt()))
        }

        override fun flush() {}

        override fun close() {}
    }

    /**
     * The reproducer: the cancel lands while the reader is inside a read of the body's buffer (here forced: the read's sink
     * runs it). Before, the cancel emptied that buffer and the read failed with an EOFException; the reader's bytes stay
     * its own now, and the body is failed for every later read.
     */
    @Test fun cancelDuringAReadLeavesTheReadersBytes() =
        runTest {
            val (client, server) = pair()
            val part = ByteArray(4096) { it.toByte() }
            val reset = serveAndHold(server, part)
            val s = client.post()
            s.response()
            val body = s.body
            assertTrue(body.awaitContent(part.size))
            val cause = IOException("the application left")
            val src = body.readBuffer
            val sink = InterruptedSink { body.cancel(cause) }
            src.readTo(sink, part.size.toLong())
            assertContentEquals(part, sink.got.readByteArray())
            assertSame(cause, body.closedCause)
            assertSame(cause, assertFailsWith<IOException> { body.readBuffer })
            assertSame(cause, assertFailsWith<IOException> { body.awaitContent(1) })
            assertFalse(body.isClosedForRead) // failed, never at its end
            assertEquals(Http2ErrorCode.CANCEL, reset.await()) // RFC 9113 section 8.1
            s.release()
        }

    /** A reader waiting for content when the body is cancelled fails at once with the cancel's cause, not the stream's. */
    @Test fun cancelWakesAWaitingReaderWithItsCause() =
        runTest {
            val (client, server) = pair()
            val reset = serveAndHold(server, ByteArray(0))
            val s = client.post()
            s.response()
            val body = s.body
            val read = backgroundScope.async(start = CoroutineStart.UNDISPATCHED) { runCatching { body.awaitContent(1) } }
            runCurrent()
            assertFalse(read.isCompleted, "the reader waits for content")
            val cause = IOException("the application left")
            body.cancel(cause)
            assertSame(cause, read.await().exceptionOrNull())
            assertEquals(Http2ErrorCode.CANCEL, reset.await())
            s.release()
        }

    /** Cancel is idempotent: the first cause stays, a later cancel neither throws nor resets again. */
    @Test fun cancelTwiceKeepsTheFirstCause() =
        runTest {
            val (client, server) = pair()
            val part = ByteArray(100) { 7 }
            val reset = serveAndHold(server, part)
            val s = client.post()
            s.response()
            val body = s.body
            assertTrue(body.awaitContent(part.size))
            val first = IOException("first")
            body.cancel(first)
            body.cancel(IOException("second"))
            body.cancel(null)
            assertSame(first, body.closedCause)
            assertSame(first, assertFailsWith<IOException> { body.awaitContent(1) })
            assertEquals(Http2ErrorCode.CANCEL, reset.await())
            s.release()
            body.cancel(IOException("after release")) // nothing left to do, nothing thrown
            assertSame(first, body.closedCause)
        }

    /** A cancel without a cause still fails the body (an IOException of its own) and resets the stream. */
    @Test fun cancelWithoutACauseFailsTheBody() =
        runTest {
            val (client, server) = pair()
            val reset = serveAndHold(server, ByteArray(10))
            val s = client.post()
            s.response()
            s.body.cancel(null)
            assertFailsWith<IOException> { s.body.readAvailable(ByteArray(1)) }
            assertEquals(Http2ErrorCode.CANCEL, reset.await())
            s.release()
        }

    /** A body read to its end is complete: a cancel then changes nothing (no cause, no reset of a finished stream). */
    @Test fun cancelAfterTheEndChangesNothing() =
        runTest {
            val (client, server) = pair()
            val done = CompletableDeferred<Unit>()
            backgroundScope.async {
                val r = server.requests.receive()
                try {
                    r.respond(200)
                    r.sendBody(ByteReadChannel(ByteArray(5) { 1 }), end = true)
                    done.complete(Unit)
                } finally {
                    r.release()
                }
            }
            assertTrue(client.tryReserve())
            val s = client.open("GET", "https", "example.com", "/", emptyList(), endStream = true)
            s.response()
            val body = s.body
            val all = ByteArray(5)
            var n = 0
            while (n < 5) n += body.readAvailable(all, n, 5 - n)
            assertFalse(body.awaitContent(1))
            assertTrue(body.isClosedForRead)
            body.cancel(IOException("too late"))
            assertEquals(null, body.closedCause)
            assertTrue(body.isClosedForRead)
            done.await()
            s.release()
        }

    /** A server that writes frames by hand; [read] decodes what the client wrote after its preface. */
    private class RawServer(
        val w: Wire,
    ) {
        private val hpack = HpackEncoder()
        private val dec = FrameDecoder(H2.MAX_MAX_FRAME_SIZE)
        private var prefaceLeft = H2.PREFACE.size
        private val buf = ByteArray(65_536)

        suspend fun write(vararg frames: ByteArray) {
            for (f in frames) w.toClient.writeFully(f)
            w.toClient.flush()
        }

        /** Frames the client wrote so far (without waiting for more). */
        suspend fun read(): List<Frame> {
            val out = mutableListOf<Frame>()
            while (!w.toServer.readBuffer.exhausted()) {
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

        /** A 200 without its end, and [part] of its content. */
        fun answer(
            id: Int,
            part: ByteArray,
        ): Array<ByteArray> =
            arrayOf(
                FrameEncoder.headers(id, hpack.encode(listOf(":status" to "200")), false, true, -1),
                FrameEncoder.data(id, part, 0, part.size, false),
            )
    }

    /** A client of a [RawServer] that sent its SETTINGS, with one GET open and its response head read. */
    private suspend fun TestScope.rawExchange(): Triple<RawServer, H2ClientConnection, H2ClientStream> {
        val w = Wire()
        val srv = RawServer(w)
        val client =
            H2ClientConnection.start(w.toClient, w.toServer, Http2Settings.Default, backgroundScope, Duration.INFINITE, {
                w.close()
            }, clock = clock())
        srv.write(FrameEncoder.settings(IntArray(0), LongArray(0)))
        client.rt.prefaceReceived.await()
        assertTrue(client.tryReserve())
        val s = client.open("GET", "https", "example.com", "/", emptyList(), endStream = true)
        runCurrent()
        srv.read()
        srv.write(*srv.answer(s.id, ByteArray(3) { 1 }))
        s.response()
        runCurrent()
        return Triple(srv, client, s)
    }

    private fun List<Frame>.resets(id: Int): List<Long> =
        filterIsInstance<Frame.RstStream>().filter { it.streamId == id }.map { it.errorCode }

    /**
     * The server's RST_STREAM arrives first, then the application cancels the body before it read anything. Either cause
     * may stand (the reader never saw the reset, so the cancel's may win), every read fails with it, and the client sends
     * no RST_STREAM of its own: none in answer to the peer's (RFC 9113 section 5.4.2), none at the release.
     */
    @Test fun aCancelAfterThePeersResetSendsNoRstStream() =
        runTest {
            val (srv, _, s) = rawExchange()
            srv.write(FrameEncoder.rstStream(s.id, Http2ErrorCode.INTERNAL_ERROR.code))
            runCurrent()
            assertFalse(s.awaitServerEnd(), "the client took the reset")
            val body = s.body
            val cause = IOException("the application left")
            body.cancel(cause)
            val seen = assertFailsWith<Throwable> { body.awaitContent(1) }
            assertSame(body.closedCause, seen)
            if (seen !== cause) assertEquals(Http2ErrorCode.INTERNAL_ERROR, assertIs<Http2Exception.StreamReset>(seen).code)
            runCurrent()
            assertEquals(emptyList(), srv.read().resets(s.id), "no RST_STREAM after the peer's")
            s.release()
            runCurrent()
            assertEquals(emptyList(), srv.read().resets(s.id), "none at the release either")
        }

    /**
     * The reverse order: the cancel resets the stream with CANCEL, then the server's own RST_STREAM (sent before ours
     * arrived) comes in. The cancel's cause stays, and nothing more goes out: one RST_STREAM in all.
     */
    @Test fun thePeersResetAfterACancelChangesNothing() =
        runTest {
            val (srv, _, s) = rawExchange()
            val body = s.body
            val cause = IOException("the application left")
            body.cancel(cause)
            runCurrent()
            assertEquals(listOf(Http2ErrorCode.CANCEL.code), srv.read().resets(s.id), "RFC 9113 section 8.1")
            srv.write(FrameEncoder.rstStream(s.id, Http2ErrorCode.INTERNAL_ERROR.code))
            runCurrent()
            assertSame(cause, body.closedCause)
            assertSame(cause, assertFailsWith<IOException> { body.awaitContent(1) })
            assertEquals(emptyList(), srv.read().resets(s.id), "no answer to the peer's RST_STREAM")
            s.release()
            runCurrent()
            assertEquals(emptyList(), srv.read().resets(s.id), "none at the release")
        }
}
