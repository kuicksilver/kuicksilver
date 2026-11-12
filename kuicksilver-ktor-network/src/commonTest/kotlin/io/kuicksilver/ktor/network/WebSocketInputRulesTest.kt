// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.util.AttributeKey
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.writeByte
import io.ktor.utils.io.writeFully
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketExtension
import io.ktor.websocket.WebSocketExtensionFactory
import io.ktor.websocket.WebSocketExtensionHeader
import io.kuicksilver.ktor.network.WsTestFrames.Wire
import io.kuicksilver.ktor.network.WsTestFrames.bytes
import io.kuicksilver.ktor.network.WsTestFrames.close
import io.kuicksilver.ktor.network.WsTestFrames.frame
import io.kuicksilver.ktor.network.WsTestFrames.frames
import io.kuicksilver.ktor.network.WsTestFrames.header
import io.kuicksilver.ktor.network.websocket.WebSocketInflate
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The frame guard's checks of what a peer sends beyond the first two bytes: the size limit (RFC 6455 section 10.4), UTF-8
 * in text messages and Close reasons (sections 5.6 and 8.1), the Close frame's body (sections 5.5.1 and 7.4), control
 * frames and the order of fragments (sections 5.4 and 5.5), and RSV1 with permessage-deflate beside another extension
 * (RFC 7692 section 6.1). A violation ends the guarded stream with a Close frame carrying the code, in place of the frame.
 */
class WebSocketInputRulesTest {
    private val mask = bytes(0x37, 0xfa, 0x21, 0x3d)

    private fun guarded(
        input: ByteArray,
        peerMasks: Boolean = false,
        maxMessageSize: Long = 1024,
        allowedRsv: Int = 0,
        perMessageDeflate: Boolean = false,
        inflate: WebSocketInflate? = null,
        block: (List<Wire>) -> Unit,
    ) = runTest {
        val raw = ByteChannel()
        launch {
            raw.writeFully(input)
            raw.flushAndClose()
        }
        val out =
            guardWebSocketInput(
                raw,
                allowedRsv,
                untilClose = false,
                peerMasks = peerMasks,
                context = coroutineContext,
                inflate = inflate,
                perMessageDeflate = perMessageDeflate,
                maxMessageSize = maxMessageSize,
            )
        block(frames(out))
    }

    private fun List<Wire>.data() = filter { it.opcode < 8 }.fold(ByteArray(0)) { a, f -> a + f.payload }

    // ---------------------------------------------------------------- RFC 6455 section 10.4: the size limit

    /**
     * A 14-byte header claiming 2 GiB (masked, as a client sends it) is refused from its header with 1009: nothing of it
     * reaches the session, whose JVM reader would allocate the claimed length at once.
     */
    @Test fun negative_frameOverTheLimitClosesWith1009FromItsHeader() =
        guarded(header(0x82, 0x7FFFFFF0L, mask), peerMasks = true, maxMessageSize = 16L shl 20) { out ->
            assertEquals(1, out.size, "only the Close")
            assertEquals(0x88, out[0].b0)
            assertEquals(1009, out[0].closeCode)
        }

    /** The limit holds for the reassembled message too: the fragment that passes it is refused, those before pass. */
    @Test fun negative_fragmentedMessageOverTheLimitClosesWith1009() =
        guarded(frame(0x02, ByteArray(600)) + frame(0x80, ByteArray(600)), maxMessageSize = 1000) { out ->
            assertEquals(listOf(0x02, 0x88), out.map { it.b0 })
            assertEquals(1009, out[1].closeCode)
        }

    @Test fun messageAtTheLimitPasses() =
        guarded(frame(0x02, ByteArray(500)) + frame(0x80, ByteArray(500)) + frame(0x82, ByteArray(1000)), maxMessageSize = 1000) { out ->
            assertEquals(listOf(0x02, 0x80, 0x82), out.map { it.b0 })
        }

    /** A compressed message is held to the smaller of the extension's limit and this one, counted inflated. */
    @Test fun negative_compressedMessageOverTheLimitClosesWith1009() {
        // a final stored deflate block of 600 zero bytes
        val stored = bytes(0x01, 600 and 0xff, 600 shr 8, (600 and 0xff).inv() and 0xff, (600 shr 8).inv() and 0xff) + ByteArray(600)
        guarded(
            frame(0xC2, stored),
            maxMessageSize = 100,
            allowedRsv = WS_RSV1,
            perMessageDeflate = true,
            inflate = WebSocketInflate(noContextTakeover = false, maxMessageSize = 16L shl 20),
        ) { out ->
            assertEquals(0x88, out.last().b0)
            assertEquals(1009, out.last().closeCode)
        }
    }

    // ---------------------------------------------------------------- RFC 6455 sections 5.6 and 8.1: UTF-8

    @Test fun negative_invalidUtf8TextClosesWith1007() =
        guarded(frame(0x81, bytes(0xC0, 0xAF))) { out ->
            assertEquals(listOf(0x88), out.map { it.b0 }, "nothing of the text is handed on")
            assertEquals(1007, out[0].closeCode)
        }

    /** Each fragment is fine on its own; the message as a whole is not (an E2 lead byte followed by 'A'). */
    @Test fun negative_invalidUtf8AcrossFragmentsClosesWith1007() =
        guarded(frame(0x01, bytes(0xE2)) + frame(0x80, bytes(0x41))) { out ->
            assertEquals(0x88, out.last().b0)
            assertEquals(1007, out.last().closeCode)
            assertTrue(out.none { it.fin && it.opcode < 8 }, "the message is never completed")
        }

    @Test fun negative_textEndingInsideACharacterClosesWith1007() =
        guarded(frame(0x81, bytes(0x61, 0xE2, 0x82))) { out ->
            assertEquals(1007, out.last().closeCode)
            assertTrue(out.none { it.fin && it.opcode < 8 })
        }

    @Test fun negative_overlongSurrogateAndOutOfRangeSequencesClose1007() {
        for (bad in listOf(bytes(0xE0, 0x80, 0x80), bytes(0xED, 0xA0, 0x80), bytes(0xF4, 0x90, 0x80, 0x80), bytes(0xF5), bytes(0x80))) {
            guarded(frame(0x81, bad)) { out -> assertEquals(1007, out.last().closeCode, bad.toList().toString()) }
        }
    }

    /** "€" split across a masked fragment boundary and a Ping between the fragments: valid, handed on whole. */
    @Test fun validUtf8SplitAcrossMaskedFragmentsPasses() =
        guarded(
            frame(0x01, bytes(0x61, 0xE2), mask) + frame(0x89, bytes(1), mask) + frame(0x80, bytes(0x82, 0xAC), mask),
            peerMasks = true,
        ) { out ->
            assertEquals("a€", out.data().decodeToString())
            assertTrue(out.last().fin)
            assertEquals(1, out.count { it.opcode == 9 })
        }

    @Test fun binaryIsNotCheckedForUtf8() =
        guarded(frame(0x82, bytes(0xC0, 0xAF))) { out -> assertContentEquals(bytes(0xC0, 0xAF), out.single().payload) }

    /** A compressed text message is checked after it is inflated. */
    @Test fun negative_invalidUtf8InACompressedTextClosesWith1007() {
        val stored = bytes(0x01, 2, 0, 0xfd, 0xff, 0xC0, 0xAF) // a final stored block with C0 AF
        guarded(
            frame(0xC1, stored),
            allowedRsv = WS_RSV1,
            perMessageDeflate = true,
            inflate = WebSocketInflate(noContextTakeover = false, maxMessageSize = 1024),
        ) { out ->
            assertEquals(listOf(0x88), out.map { it.b0 })
            assertEquals(1007, out[0].closeCode)
        }
    }

    // ---------------------------------------------------------------- RFC 6455 sections 5.5.1 and 7.4: Close frames

    @Test fun negative_closeWithAReservedOrUnusedCodeClosesWith1002() {
        for (code in listOf(0, 999, 1004, 1005, 1006, 1015, 1016, 2999, 5000, 65535)) {
            guarded(close(code)) { out ->
                assertEquals(1, out.size)
                assertEquals(1002, out[0].closeCode, "code $code")
            }
        }
    }

    @Test fun closeWithAValidCodePasses() {
        for (code in listOf(1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 3000, 3999, 4000, 4999)) {
            guarded(close(code, "bye".encodeToByteArray(), mask), peerMasks = true) { out ->
                assertEquals(code, out.single().closeCode)
                assertEquals("bye", out.single().closeReason.decodeToString())
            }
        }
        guarded(frame(0x88, ByteArray(0))) { out -> assertTrue(out.single().payload.isEmpty(), "an empty Close passes") }
    }

    @Test fun negative_closeWithAOneByteBodyClosesWith1002() =
        guarded(frame(0x88, bytes(0x03))) { out -> assertEquals(1002, out.single().closeCode) }

    /**
     * A reason that is not UTF-8 fails the connection with 1007. Before, 123 invalid bytes (369 bytes as U+FFFD) failed
     * Ktor's `CloseReason` check inside its session, which then ended with 1006 and sent no Close at all.
     */
    @Test fun negative_closeReasonNotUtf8ClosesWith1007() {
        guarded(close(1000, bytes(0xC0, 0xAF), mask), peerMasks = true) { out -> assertEquals(1007, out.single().closeCode) }
        guarded(close(1000, ByteArray(123) { 0xFF.toByte() })) { out -> assertEquals(1007, out.single().closeCode) }
    }

    // ---------------------------------------------------------------- RFC 6455 sections 5.4 and 5.5: control frames, order

    @Test fun negative_fragmentedControlFrameClosesWith1002() =
        guarded(frame(0x09, bytes(1))) { out -> assertEquals(1002, out.single().closeCode) }

    @Test fun negative_controlFrameOver125BytesClosesWith1002() =
        guarded(frame(0x89, ByteArray(126))) { out -> assertEquals(1002, out.single().closeCode) }

    @Test fun negative_continuationOutsideAMessageClosesWith1002() =
        guarded(frame(0x80, bytes(0x61))) { out -> assertEquals(1002, out.single().closeCode) }

    @Test fun negative_newMessageInsideAFragmentedOneClosesWith1002() =
        guarded(frame(0x01, bytes(0x61)) + frame(0x82, bytes(1))) { out ->
            assertEquals(0x88, out.last().b0)
            assertEquals(1002, out.last().closeCode)
        }

    // ---------------------------------------------------------------- RFC 6455 section 5.2: minimal length encoding

    /** "the minimal number of bytes MUST be used to encode the length" (section 5.2; section 10.7 lets the receiver fail). */
    @Test fun negative_nonMinimalLengthClosesWith1002() {
        val sixteenBitFor5 = bytes(0x82, 126, 0, 5) + ByteArray(5)
        val sixtyFourBitFor65535 = bytes(0x82, 127, 0, 0, 0, 0, 0, 0, 0xff, 0xff)
        for (bad in listOf(sixteenBitFor5, sixtyFourBitFor65535)) {
            guarded(bad, maxMessageSize = 1L shl 20) { out -> assertEquals(1002, out.single().closeCode) }
        }
        guarded(header(0x82, 126) + ByteArray(126) + header(0x82, 65536) + ByteArray(65536), maxMessageSize = 1L shl 20) { out ->
            assertEquals(listOf(126, 65536), out.map { it.payload.size }, "minimal encodings pass")
        }
    }

    // ---------------------------------------------------------------- compressed frames: the compressed bound from the header

    /**
     * A compressed frame whose header claims more than the message's compressed bound (8 times the limit plus 64 KiB) is
     * refused with 1009 from its header: nothing of it is read (here nothing of it is even sent).
     */
    @Test fun negative_compressedFrameOverTheCompressedBoundClosesWith1009FromItsHeader() =
        guarded(
            header(0xC2, 8 * 100 + 65536 + 1L),
            maxMessageSize = 1L shl 20,
            allowedRsv = WS_RSV1,
            perMessageDeflate = true,
            inflate = WebSocketInflate(noContextTakeover = false, maxMessageSize = 100),
        ) { out ->
            assertEquals(1009, out.single().closeCode)
        }

    // ---------------------------------------------------------------- input in any pieces; text re-framing

    /** The same frames fed one byte at a time (split headers, masks and payloads) come out as fed whole. */
    @Test fun inputFedByteByByte() =
        runTest {
            val input =
                frame(0x01, "a\u20ac".encodeToByteArray().copyOf(3), mask) + frame(0x89, bytes(7), mask) +
                    frame(0x80, "a\u20ac".encodeToByteArray().copyOfRange(3, 4), mask) + frame(0x82, ByteArray(300) { it.toByte() }, mask) +
                    close(1000, "ok".encodeToByteArray(), mask)
            val raw = ByteChannel()
            launch {
                for (b in input) {
                    raw.writeByte(b)
                    raw.flush()
                    yield()
                }
                raw.flushAndClose()
            }
            val out = frames(guardWebSocketInput(raw, 0, untilClose = false, peerMasks = true, context = coroutineContext))
            assertEquals("a\u20ac", out.filter { it.opcode <= 1 }.fold(ByteArray(0)) { a, f -> a + f.payload }.decodeToString())
            assertContentEquals(ByteArray(300) { it.toByte() }, out.single { it.opcode == 2 }.payload)
            assertEquals(1, out.count { it.opcode == 9 })
            assertEquals(1000, out.last().closeCode)
        }

    /**
     * A checked text frame is handed on in frames of at most 64 KiB, the first with its opcode and the rest continuations;
     * a character split where the guard's 16 KiB reads split the payload passes.
     */
    @Test fun checkedTextIsReframedInPiecesOf64KiB() {
        val text = ByteArray(2 * 65536 + 100) { 'x'.code.toByte() }
        "\u20ac".encodeToByteArray().copyInto(text, 16 * 1024 - 1) // the read boundary falls inside it
        guarded(frame(0x81, text, mask), peerMasks = true, maxMessageSize = 1L shl 20) { out ->
            assertEquals(listOf(65536, 65536, 100), out.map { it.payload.size })
            assertEquals(listOf(0x01, 0x00, 0x80), out.map { it.b0 })
            assertContentEquals(text, out.fold(ByteArray(0)) { a, f -> a + f.payload })
        }
    }

    // ---------------------------------------------------------------- RFC 7692 section 6.1 beside another extension

    /**
     * With permessage-deflate and another extension (here one with RSV2) negotiated, RSV1 is still refused on a
     * continuation and a control frame; the other extension's bit is allowed, the third bit is not.
     */
    @Test fun negative_rsv1PlacementIsCheckedBesideAnotherExtension() {
        val rsv =
            negotiatedWebSocketRsv(listOf("permessage-deflate", "x-rsv2"), listOf("permessage-deflate", "x-rsv2"), listOf(Rsv2Extension()))
        assertEquals(WS_RSV1 or WS_RSV2, rsv, "permessage-deflate's RSV1 and the factory's RSV2")
        for (bad in listOf(frame(0x01, bytes(0x61)) + frame(0xC0, bytes(0x62)), frame(0xC9, ByteArray(0)), frame(0x92, ByteArray(0)))) {
            guarded(bad, allowedRsv = rsv, perMessageDeflate = true) { out -> assertEquals(1002, out.last().closeCode) }
        }
        guarded(frame(0xA2, bytes(1)), allowedRsv = rsv, perMessageDeflate = true) { out -> assertEquals(0xA2, out.single().b0) }
    }

    /** An extension both sides agreed on that no installed extension implements may use any bit, as before. */
    @Test fun unknownExtensionAllowsEveryBit() =
        assertEquals(
            WS_RSV_ALL,
            negotiatedWebSocketRsv(listOf("x-own"), listOf("x-own"), emptyList()),
        )

    private class Rsv2Extension : WebSocketExtension<Unit> {
        override val factory: WebSocketExtensionFactory<Unit, Rsv2Extension> = Factory
        override val protocols: List<WebSocketExtensionHeader> = listOf(WebSocketExtensionHeader("x-rsv2", emptyList()))

        override fun clientNegotiation(negotiatedProtocols: List<WebSocketExtensionHeader>): Boolean = true

        override fun serverNegotiation(requestedProtocols: List<WebSocketExtensionHeader>): List<WebSocketExtensionHeader> = protocols

        override fun processOutgoingFrame(frame: Frame): Frame = frame

        override fun processIncomingFrame(frame: Frame): Frame = frame

        object Factory : WebSocketExtensionFactory<Unit, Rsv2Extension> {
            override val key = AttributeKey<Rsv2Extension>("x-rsv2")
            override val rsv1 = false
            override val rsv2 = true
            override val rsv3 = false

            override fun install(config: Unit.() -> Unit) = Rsv2Extension()
        }
    }
}
