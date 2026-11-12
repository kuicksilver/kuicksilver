// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.writeFully
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.RawWebSocket
import io.ktor.websocket.close
import io.kuicksilver.ktor.network.WsTestFrames.Wire
import io.kuicksilver.ktor.network.WsTestFrames.bytes
import io.kuicksilver.ktor.network.WsTestFrames.close
import io.kuicksilver.ktor.network.WsTestFrames.frame
import io.kuicksilver.ktor.network.WsTestFrames.frames
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The engines' check of the frames they send (RFC 6455 sections 5.1, 5.3, 5.4 and 7.4): every client frame masked with a
 * fresh key from OpenSSL's CSPRNG, no server frame masked, the non-first fragments of a message sent as continuations,
 * and no Close frame with a code an endpoint must not send.
 */
class WebSocketOutputGuardTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** What [write] wrote through the guard, as frames on the wire. */
    private suspend fun CoroutineScope.sent(
        masking: Boolean,
        checkText: Boolean = true,
        inflateSent: Boolean = false,
        write: suspend (io.ktor.utils.io.ByteWriteChannel) -> Unit,
    ): List<Wire> {
        val wire = ByteChannel()
        val guarded = guardWebSocketOutput(wire, masking, checkText, inflateSent)
        launch {
            write(guarded)
            guarded.flushAndClose()
        }
        return frames(wire as ByteReadChannel)
    }

    /** RFC 6455 section 5.3: the client masks every frame, each with its own key; Ktor's own key (or none) is replaced. */
    @Test fun negative_clientFramesGetFreshMaskingKeys() =
        runTest {
            val ktorKey = bytes(1, 2, 3, 4)
            val out =
                sent(masking = true) { w ->
                    repeat(64) { w.writeFully(frame(0x82, bytes(it, 0x55), ktorKey)) }
                    w.writeFully(frame(0x81, "unmasked by Ktor".encodeToByteArray()))
                    w.flush()
                }
            assertEquals(65, out.size)
            assertTrue(out.all { it.mask != null }, "every frame masked")
            assertEquals(65, out.map { it.mask!!.toList() }.toSet().size, "a new key for every frame")
            assertTrue(out.none { it.mask!!.contentEquals(ktorKey) }, "never Ktor's key")
            out.take(64).forEachIndexed { i, f -> assertContentEquals(bytes(i, 0x55), f.payload) }
            assertEquals("unmasked by Ktor", out.last().payload.decodeToString())
        }

    /** RFC 6455 section 5.1: a server never masks, whatever Ktor's `masking` says. */
    @Test fun negative_serverFramesAreNeverMasked() =
        runTest {
            val out = sent(masking = false) { w -> w.writeFully(frame(0x81, "hi".encodeToByteArray(), bytes(9, 8, 7, 6))) }
            assertNull(out.single().mask)
            assertEquals("hi", out.single().payload.decodeToString())
        }

    /**
     * RFC 6455 section 5.4: the frames after the first of a fragmented message have opcode 0. Ktor's common (Kotlin/Native)
     * writer gives every fragment the message's opcode; a Ping between fragments keeps its own.
     */
    @Test fun negative_laterFragmentsAreSentAsContinuations() =
        runTest {
            val out =
                sent(masking = true) { w ->
                    w.writeFully(frame(0x01, bytes(0x61)))
                    w.writeFully(frame(0x89, bytes(1)))
                    w.writeFully(frame(0x01, bytes(0x62)))
                    w.writeFully(frame(0x81, bytes(0x63)))
                    w.writeFully(frame(0x82, bytes(0x64)))
                }
            assertEquals(listOf(0x01, 0x89, 0x00, 0x80, 0x82), out.map { it.b0 })
        }

    /** The same through Ktor's own raw session, whatever its platform's writer does with fragments and masking. */
    @Test fun ktorRawSessionThroughTheGuard() =
        runTest {
            val wire = ByteChannel()
            val job = Job()
            val ws =
                RawWebSocket(
                    ByteChannel(),
                    guardWebSocketOutput(wire, masking = true),
                    masking = false,
                    coroutineContext =
                        coroutineContext + job,
                )
            ws.outgoing.send(Frame.Text(false, "ab".encodeToByteArray()))
            ws.outgoing.send(Frame.Text(true, "cd".encodeToByteArray()))
            ws.close(CloseReason(CloseReason.Codes.NORMAL, "done"))
            val out = frames(wire)
            job.cancel()
            assertEquals(listOf(0x01, 0x80, 0x88), out.map { it.b0 })
            assertTrue(out.all { it.mask != null })
            assertEquals("abcd", (out[0].payload + out[1].payload).decodeToString())
            assertEquals(1000, out[2].closeCode)
        }

    /**
     * RFC 6455 section 7.4.1: 1005, 1006 and 1015 MUST NOT be set as a status code in a Close frame; nor is a code of no
     * use (0-999, section 7.4.2) or one the peer would refuse. Such a Close goes out without a body ("no status code").
     */
    @Test fun negative_closeWithAForbiddenCodeGoesOutWithoutABody() =
        runTest {
            for (code in listOf(1005, 1006, 1015, 999, 1004, 5000)) {
                val out = sent(masking = false) { w -> w.writeFully(close(code, "x".encodeToByteArray())) }
                assertTrue(out.single().payload.isEmpty(), "code $code")
            }
            val ok = sent(masking = true) { w -> w.writeFully(close(4000, "app".encodeToByteArray(), bytes(5, 5, 5, 5))) }
            assertEquals(4000, ok.single().closeCode)
            assertEquals("app", ok.single().closeReason.decodeToString())
            assertNotNull(ok.single().mask)
        }

    /** RFC 6455 section 5.5.1: a reason is UTF-8; a Close whose reason is not keeps its code and loses the reason. */
    @Test fun negative_closeReasonNotUtf8IsDropped() =
        runTest {
            val out = sent(masking = false) { w -> w.writeFully(close(1000, bytes(0xC0, 0xAF))) }
            assertEquals(1000, out.single().closeCode)
            assertTrue(out.single().closeReason.isEmpty())
        }

    /**
     * RFC 6455 section 5.6: a text message MUST be UTF-8 as a whole. One that is not (here split across fragments) is not
     * sent whole: the write fails and the connection is cancelled; a valid text and a binary with the same bytes pass.
     */
    @Test fun negative_textThatIsNotUtf8IsNotSent() =
        runTest {
            val wire = ByteChannel()
            val guarded = guardWebSocketOutput(wire, masking = true)
            guarded.writeFully(frame(0x01, bytes(0x61, 0xE2)) + frame(0x80, bytes(0x41)))
            val e = assertFails { guarded.flush() }
            assertTrue(e is io.ktor.websocket.ProtocolViolationException, e.toString())
            assertNotNull(wire.closedCause, "the connection is cancelled")
            guarded.flushAndClose() // what Ktor's writer does after a failure: nothing more

            val ok = sent(masking = true) { w -> w.writeFully(frame(0x81, "€".encodeToByteArray()) + frame(0x82, bytes(0xC0, 0xAF))) }
            assertEquals(listOf(0x81, 0x82), ok.map { it.b0 })
        }

    /** A frame written in pieces across flushes (Ktor's JVM writer flushes when its buffer is full) is handed on whole. */
    @Test fun frameSplitAcrossFlushes() =
        runTest {
            val bytes = frame(0x82, ByteArray(70_000) { it.toByte() })
            val out =
                sent(masking = true) { w ->
                    var at = 0
                    for (piece in listOf(1, 1, 3, 5, 1000, 69_000, bytes.size)) {
                        val end = minOf(piece + at, bytes.size)
                        w.writeFully(bytes, at, end)
                        w.flush()
                        at = end
                    }
                }
            assertContentEquals(ByteArray(70_000) { it.toByte() }, out.single().payload)
        }

    /**
     * An application's own extension (no RSV bit, `checkText` false from the handshake) may carry any payload in a text
     * frame: the guard does not check it, as the input guard does not.
     */
    @Test fun textOfAnApplicationExtensionIsNotChecked() =
        runTest {
            val out = sent(masking = true, checkText = false) { w -> w.writeFully(frame(0x81, bytes(0xC0, 0xAF))) }
            assertContentEquals(bytes(0xC0, 0xAF), out.single().payload)
        }

    /**
     * RFC 7692 section 6 with an extension that does not check what it compresses (Ktor's `WebSocketDeflateExtension`,
     * which sets RSV1 on every frame it compresses): each compressed frame is inflated on the side, the window kept
     * across messages, and a message that is not UTF-8 is not sent whole.
     */
    @Test fun negative_compressedTextOfAnotherExtensionIsChecked() =
        runTest {
            // a stored block, then the 0x00 a sync flush leaves once its 0x00 0x00 0xff 0xff is removed (RFC 7692 section 7.2.1)
            val stored = { data: ByteArray -> bytes(0x00, data.size, 0, data.size.inv() and 0xff, 0xff) + data + bytes(0x00) }
            val ok =
                sent(masking = true, inflateSent = true) { w ->
                    w.writeFully(frame(0xC1, stored("caf".encodeToByteArray())))
                    w.writeFully(frame(0xC1, stored(bytes(0xC3, 0xA9))))
                }
            assertEquals(2, ok.size, "valid compressed text passes")
            val wire = ByteChannel()
            val guarded = guardWebSocketOutput(wire, masking = true, inflateSent = true)
            guarded.writeFully(frame(0xC1, stored(bytes(0xC0, 0xAF))))
            assertFails { guarded.flush() }
            assertNotNull(wire.closedCause)
            guarded.flushAndClose()
        }

    /** Frames written one byte per flush (headers, keys and payloads split anywhere) come out as written whole. */
    @Test fun outputWrittenByteByByte() =
        runTest {
            val input =
                frame(0x01, bytes(0x61, 0xE2), bytes(1, 2, 3, 4)) + frame(0x89, bytes(9)) + frame(0x81, bytes(0x82, 0xAC)) +
                    frame(0x82, ByteArray(300) { it.toByte() }) + close(1000, "ok".encodeToByteArray())
            val out =
                sent(masking = true) { w ->
                    for (b in input) {
                        w.writeFully(byteArrayOf(b))
                        w.flush()
                    }
                }
            assertEquals(listOf(0x01, 0x89, 0x80, 0x82, 0x88), out.map { it.b0 })
            assertEquals("a\u20ac", (out[0].payload + out[2].payload).decodeToString())
            assertContentEquals(ByteArray(300) { it.toByte() }, out[3].payload)
            assertEquals(1000, out[4].closeCode)
        }
}
