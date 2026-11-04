// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network.websocket

import io.ktor.websocket.Frame
import io.ktor.websocket.FrameTooBigException
import io.ktor.websocket.FrameType
import io.ktor.websocket.ProtocolViolationException
import io.ktor.websocket.WebSocketExtensionHeader
import io.ktor.websocket.parseWebSocketExtensions
import io.ktor.websocket.readText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** permessage-deflate (RFC 7692 sections 5-8): the extension, its codec and its negotiation, on every target. */
class PerMessageDeflateTest {
    private fun bytes(vararg b: Int) = ByteArray(b.size) { b[it].toByte() }

    private fun client(config: PerMessageDeflate.Config.() -> Unit = {}): PerMessageDeflate =
        PerMessageDeflate.install(config).also { assertTrue(it.clientNegotiation(parseWebSocketExtensions("permessage-deflate"))) }

    private fun server(config: PerMessageDeflate.Config.() -> Unit = {}): PerMessageDeflate =
        PerMessageDeflate.install(config).also {
            assertEquals(1, it.serverNegotiation(parseWebSocketExtensions("permessage-deflate")).size)
        }

    private fun compressed(data: ByteArray) = Frame.Text(true, data, true, false, false)

    // ---- RFC 7692 section 7.2.3: the examples, decompressed (compression output depends on the zlib in use)

    @Test fun rfc7692Section72Examples() {
        val hello = bytes(0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00) // 7.2.3.1
        val shared = bytes(0xf2, 0x00, 0x11, 0x00, 0x00) // 7.2.3.2: the second "Hello" refers back into the first
        val stored = bytes(0x00, 0x05, 0x00, 0xfa, 0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00) // 7.2.3.3
        val bfinal = bytes(0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00) // 7.2.3.4
        val twoBlocks = bytes(0xf2, 0x48, 0x05, 0x00, 0x00, 0x00, 0xff, 0xff, 0xca, 0xc9, 0xc9, 0x07, 0x00) // 7.2.3.5
        val ext = client()
        for ((i, payload) in listOf(hello, shared, stored, bfinal, twoBlocks, hello, shared).withIndex()) {
            val frame = ext.processIncomingFrame(compressed(payload))
            assertEquals("Hello", (frame as Frame.Text).readText(), "example $i")
            assertFalse(frame.rsv1, "the decompressed frame carries no RSV1")
        }
    }

    /** RFC 7692 section 7.2.3.1, fragmented: RSV1 on the first frame, the message is the concatenated payloads. */
    @Test fun fragmentedCompressedMessageFromTheRfc() {
        val inflater = MessageInflater(noContextTakeover = false, maxMessageSize = 1024)
        val out = ByteArray(64)
        inflater.input(bytes(0xf2, 0x48, 0xcd), 0, 3)
        var n = inflater.read(out, 0, out.size)
        inflater.input(bytes(0xc9, 0xc9, 0x07, 0x00), 0, 4)
        n += inflater.read(out, n, out.size - n)
        inflater.endOfMessage()
        n += inflater.read(out, n, out.size - n)
        inflater.messageDone()
        assertEquals("Hello", out.decodeToString(0, n))
    }

    @Test fun uncompressedFramePassesThrough() {
        val frame = Frame.Text("plain")
        assertSame(frame, client().processIncomingFrame(frame))
    }

    // ---- RFC 7692 section 7.2.1: compression

    @Test fun emptyMessageIsSingleZeroByte() {
        val ext = client()
        for (round in 1..3) { // a fresh stream, then after messages (with context takeover)
            val frame = ext.processOutgoingFrame(Frame.Text(""))
            assertContentEquals(bytes(0x00), frame.data, "round $round")
            assertTrue(frame.rsv1)
            ext.processOutgoingFrame(Frame.Text("between"))
        }
        assertEquals("", (server().processIncomingFrame(compressed(bytes(0x00))) as Frame.Text).readText())
    }

    @Test fun trailerStrippedAndRestored() {
        val c = client()
        val s = server()
        val text = "Hello, Hello, Hello"
        val frame = c.processOutgoingFrame(Frame.Text(text))
        assertTrue(frame.rsv1)
        val tail = frame.data.copyOfRange(frame.data.size - 4, frame.data.size)
        assertFalse(tail.contentEquals(bytes(0x00, 0x00, 0xff, 0xff)), "0x00 0x00 0xff 0xff is removed from the tail")
        assertEquals(text, (s.processIncomingFrame(frame) as Frame.Text).readText())
    }

    @Test fun contextTakeoverRoundTripAcrossMessages() {
        val c = client()
        val s = server()
        val message = "kuicksilver permessage-deflate ".repeat(50)
        val sizes = ArrayList<Int>()
        repeat(4) {
            val frame = c.processOutgoingFrame(Frame.Binary(true, message.encodeToByteArray()))
            sizes += frame.data.size
            assertEquals(message, (s.processIncomingFrame(frame) as Frame.Binary).data.decodeToString())
        }
        assertTrue(sizes[1] < sizes[0], "the second message refers back into the first: $sizes")
    }

    @Test fun noContextTakeoverResetsDictionary() {
        val c = client { clientNoContextTakeover = true }
        val first = c.processOutgoingFrame(Frame.Text("Hello")).data
        val second = c.processOutgoingFrame(Frame.Text("Hello")).data
        assertContentEquals(first, second, "every message starts from an empty window")
        val takeover = client()
        takeover.processOutgoingFrame(Frame.Text("Hello"))
        assertNotEquals(first.toList(), takeover.processOutgoingFrame(Frame.Text("Hello")).data.toList())
    }

    @Test fun fragmentedSendSetsRsv1OnFirstFrameOnly() {
        val c = client()
        val s = server()
        val parts = listOf("Hel", "", "lo, ", "fragments")
        val frames = parts.mapIndexed { i, p -> c.processOutgoingFrame(Frame.Text(i == parts.lastIndex, p.encodeToByteArray())) }
        assertEquals(listOf(true, false, false, false), frames.map { it.rsv1 })
        assertEquals(listOf(false, false, false, true), frames.map { it.fin })
        val message = frames.fold(ByteArray(0)) { acc, f -> acc + f.data }
        assertEquals(parts.joinToString(""), (s.processIncomingFrame(compressed(message)) as Frame.Text).readText())
        // the next message starts a new one
        assertTrue(c.processOutgoingFrame(Frame.Text("next")).rsv1)
    }

    @Test fun controlFramesNeverCompressed() {
        val c = client()
        val ping = Frame.Ping(bytes(1, 2, 3))
        assertSame(ping, c.processOutgoingFrame(ping))
        val close = Frame.Close()
        assertSame(close, c.processOutgoingFrame(close))
    }

    @Test fun messagesBelowMinSizeAreSentUncompressed() {
        val c = client { minSizeToCompress = 16 }
        val small = c.processOutgoingFrame(Frame.Text("short"))
        assertFalse(small.rsv1)
        assertEquals("short", (small as Frame.Text).readText())
        assertTrue(c.processOutgoingFrame(Frame.Text("long enough to be compressed")).rsv1)
        // a fragmented message's size is not known at its first frame: it is compressed
        val first = c.processOutgoingFrame(Frame.Text(false, "ab".encodeToByteArray()))
        val last = c.processOutgoingFrame(Frame.Text(true, "c".encodeToByteArray()))
        assertTrue(first.rsv1)
        assertFalse(last.rsv1)
        assertEquals("abc", (server().processIncomingFrame(compressed(first.data + last.data)) as Frame.Text).readText())
    }

    // ---- limits and corrupt input

    @Test fun negative_inflateBombStopsAtLimit() {
        val deflater = MessageDeflater(level = 9, windowBits = 15, noContextTakeover = false)
        val bomb = deflater.compress(ByteArray(10 * 1024 * 1024), fin = true)
        deflater.close()
        assertTrue(bomb.size < 32 * 1024, "10 MiB of zeros compress to ${bomb.size} bytes")

        val limit = 1024L * 1024
        val inflater = MessageInflater(noContextTakeover = false, maxMessageSize = limit)
        val chunk = ByteArray(INFLATE_CHUNK)
        var produced = 0L
        val e =
            assertFailsWith<MessageTooBigException> {
                inflater.input(bomb, 0, bomb.size)
                while (true) {
                    val n = inflater.read(chunk, 0, chunk.size)
                    if (n == 0) break
                    produced += n
                }
                inflater.endOfMessage()
                while (inflater.read(chunk, 0, chunk.size) > 0) continue
            }
        assertTrue(produced <= limit + INFLATE_CHUNK, "produced $produced before stopping")
        assertTrue(e.size > limit)
        inflater.close()

        val ext = client { maxInflatedMessageSize = limit }
        assertFailsWith<FrameTooBigException> { ext.processIncomingFrame(compressed(bomb)) }
    }

    @Test fun messageAtTheLimitPasses() {
        val c = client()
        val s = server { maxInflatedMessageSize = 1000 }
        val frame = c.processOutgoingFrame(Frame.Binary(true, ByteArray(1000) { it.toByte() }))
        assertEquals(1000, s.processIncomingFrame(frame).data.size)
        val over = c.processOutgoingFrame(Frame.Binary(true, ByteArray(1001)))
        assertFailsWith<FrameTooBigException> { s.processIncomingFrame(over) }
    }

    @Test fun negative_corruptDeflateStreamFails() {
        // BTYPE 11 (reserved) is invalid DEFLATE
        assertFailsWith<ProtocolViolationException> { client().processIncomingFrame(compressed(bytes(0xff, 0xff, 0xff))) }
        // a stored block whose NLEN is not the complement of LEN
        assertFailsWith<ProtocolViolationException> {
            client().processIncomingFrame(compressed(bytes(0x00, 0x05, 0x00, 0x00, 0x00, 0x48)))
        }
    }

    @Test fun negative_dataAfterFinalBlockFails() {
        // 7.2.3.4 (BFINAL) followed by more data in the same message
        val payload = bytes(0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00, 0xf2, 0x48)
        assertFailsWith<ProtocolViolationException> { client().processIncomingFrame(compressed(payload)) }
    }

    @Test fun configValidated() {
        assertFailsWith<IllegalArgumentException> { PerMessageDeflate.install { compressionLevel = 10 } }
        assertFailsWith<IllegalArgumentException> { PerMessageDeflate.install { compressionLevel = -1 } }
        assertFailsWith<IllegalArgumentException> { PerMessageDeflate.install { maxInflatedMessageSize = 0 } }
        assertFailsWith<IllegalArgumentException> { PerMessageDeflate.install { minSizeToCompress = -1 } }
        assertTrue(PerMessageDeflate.rsv1)
        assertFalse(PerMessageDeflate.rsv2)
        assertFalse(PerMessageDeflate.rsv3)
        assertEquals(16L * 1024 * 1024, PerMessageDeflate.Config().maxInflatedMessageSize)
    }

    // ---- RFC 7692 sections 5 and 7.1: negotiation, the client side

    @Test fun clientOffer() {
        assertEquals(listOf("permessage-deflate"), PerMessageDeflate.install {}.protocols.map { it.toString().trim() })
        val both =
            PerMessageDeflate.install {
                clientNoContextTakeover = true
                serverNoContextTakeover = true
            }
        assertEquals("permessage-deflate", both.protocols.single().name)
        assertEquals(listOf("client_no_context_takeover", "server_no_context_takeover"), both.protocols.single().parameters)
    }

    @Test fun clientAcceptsValidResponses() {
        for (response in listOf(
            "permessage-deflate",
            "permessage-deflate; server_no_context_takeover",
            "permessage-deflate; client_no_context_takeover",
            "permessage-deflate; server_max_window_bits=8",
            "permessage-deflate; server_max_window_bits=15",
            "permessage-deflate; server_max_window_bits=\"10\"",
            "PerMessage-Deflate; Server_No_Context_Takeover",
        )) {
            assertTrue(PerMessageDeflate.install {}.clientNegotiation(parseWebSocketExtensions(response)), response)
        }
        assertFalse(PerMessageDeflate.install {}.clientNegotiation(emptyList()), "not accepted: not used")
        assertFalse(PerMessageDeflate.install {}.clientNegotiation(parseWebSocketExtensions("x-other")))
    }

    /** RFC 7692 section 7.1.1.2: client_no_context_takeover in the response binds the client's compressor. */
    @Test fun clientNoContextTakeoverFromServerIsHonoured() {
        val c = PerMessageDeflate.install {}
        assertTrue(c.clientNegotiation(parseWebSocketExtensions("permessage-deflate; client_no_context_takeover")))
        assertContentEquals(c.processOutgoingFrame(Frame.Text("Hello")).data, c.processOutgoingFrame(Frame.Text("Hello")).data)
    }

    /** RFC 7692 section 7.1.2.2: a client that did not offer client_max_window_bits fails on a response that has it. */
    @Test fun negative_unrequestedClientMaxWindowBitsRejected() {
        for (response in listOf("permessage-deflate; client_max_window_bits=10", "permessage-deflate; client_max_window_bits")) {
            assertFailsWith<ProtocolViolationException>(response) {
                PerMessageDeflate.install {}.clientNegotiation(parseWebSocketExtensions(response))
            }
        }
    }

    /** RFC 7692 section 5: a response with an unknown, repeated or invalid parameter fails the connection. */
    @Test fun negative_invalidResponseParametersFail() {
        for (response in listOf(
            "permessage-deflate; x_unknown",
            "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
            "permessage-deflate; server_no_context_takeover=1",
            "permessage-deflate; client_no_context_takeover=x",
            "permessage-deflate; server_max_window_bits",
            "permessage-deflate; server_max_window_bits=7",
            "permessage-deflate; server_max_window_bits=16",
            "permessage-deflate; server_max_window_bits=010",
            "permessage-deflate; server_max_window_bits=+9",
            "permessage-deflate; server_max_window_bits=10; server_max_window_bits=10",
            "permessage-deflate, permessage-deflate", // two PMCEs on RSV1
        )) {
            assertFailsWith<ProtocolViolationException>(response) {
                PerMessageDeflate.install {}.clientNegotiation(parseWebSocketExtensions(response))
            }
        }
    }

    /** RFC 7692 section 7.1.1.1: a server that accepts an offer with server_no_context_takeover includes it. */
    @Test fun negative_requestedServerNoContextTakeoverMissingFails() {
        val c = PerMessageDeflate.install { serverNoContextTakeover = true }
        assertFailsWith<ProtocolViolationException> { c.clientNegotiation(parseWebSocketExtensions("permessage-deflate")) }
    }

    // ---- the server side

    private fun serverAnswer(
        offer: String,
        config: PerMessageDeflate.Config.() -> Unit = {},
    ): List<WebSocketExtensionHeader> = PerMessageDeflate.install(config).serverNegotiation(parseWebSocketExtensions(offer))

    private fun List<WebSocketExtensionHeader>.text() = joinToString(", ") { (listOf(it.name) + it.parameters).joinToString("; ") }

    @Test fun serverAcceptsTheFirstValidOffer() {
        assertEquals("permessage-deflate", serverAnswer("permessage-deflate").text())
        assertEquals(
            "permessage-deflate; server_no_context_takeover",
            serverAnswer("permessage-deflate; server_no_context_takeover").text(),
            "a server that accepts server_no_context_takeover includes it",
        )
        assertEquals(
            "permessage-deflate; client_no_context_takeover",
            serverAnswer("permessage-deflate; client_no_context_takeover").text(),
        )
        assertEquals(
            "permessage-deflate",
            serverAnswer("permessage-deflate; client_max_window_bits").text(),
            "client_max_window_bits is a hint the server need not answer",
        )
        assertEquals("permessage-deflate", serverAnswer("permessage-deflate; client_max_window_bits=9").text())
        assertEquals(
            "permessage-deflate",
            serverAnswer("permessage-deflate; x_unknown, permessage-deflate").text(),
            "an offer with an unknown parameter is declined, the next one accepted",
        )
        assertEquals("permessage-deflate; server_max_window_bits=15", serverAnswer("permessage-deflate; server_max_window_bits=15").text())
        assertEquals(
            "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
            serverAnswer("permessage-deflate") {
                serverNoContextTakeover = true
                clientNoContextTakeover = true
            }.text(),
            "the server may ask for no context takeover on its own",
        )
    }

    /** RFC 7692 section 5.1: the server declines an offer it cannot accept, and accepts nothing when none is left. */
    @Test fun negative_serverDeclinesInvalidOffers() {
        for (offer in listOf(
            "permessage-deflate; x_unknown",
            "permessage-deflate; server_no_context_takeover=1",
            "permessage-deflate; client_no_context_takeover; client_no_context_takeover",
            "permessage-deflate; server_max_window_bits",
            "permessage-deflate; server_max_window_bits=16",
            "permessage-deflate; server_max_window_bits=7",
            "permessage-deflate; client_max_window_bits=16",
            "permessage-deflate; client_max_window_bits=08",
            "permessage-deflate; server_max_window_bits=8", // zlib's raw deflate has no 256-byte window
            "x-other",
        )) {
            assertEquals(emptyList(), serverAnswer(offer).map { it.name }, offer)
        }
    }

    /** A smaller window than the deflater can honour is declined; one it can is answered with the same value. */
    @Test fun serverMaxWindowBitsHonouredOrDeclined() {
        for (bits in 9..14) {
            val answer = serverAnswer("permessage-deflate; server_max_window_bits=$bits, permessage-deflate")
            if (bits >= DEFLATE_MIN_WINDOW_BITS) {
                assertEquals("permessage-deflate; server_max_window_bits=$bits", answer.text())
            } else {
                assertEquals("permessage-deflate", answer.text(), "declined, the fallback offer accepted")
            }
        }
    }

    @Test fun serverCompressesWithinTheNegotiatedWindow() {
        if (DEFLATE_MIN_WINDOW_BITS > 9) return // the JVM's Deflater has a 32 KiB window only: such offers are declined
        val s = PerMessageDeflate.install {}
        assertEquals(1, s.serverNegotiation(parseWebSocketExtensions("permessage-deflate; server_max_window_bits=9")).size)
        val c = client()
        // the repeat is 1000 bytes back: beyond a 512-byte window, so it may not be referred to
        val block = ByteArray(1000) { (it * 7919 % 251).toByte() }
        val frame = s.processOutgoingFrame(Frame.Binary(true, block + block))
        assertContentEquals(block + block, c.processIncomingFrame(frame).data)
        val inflater = RawInflater(windowBits = 9)
        try {
            inflater.setInput(frame.data + bytes(0x00, 0x00, 0xff, 0xff), 0, frame.data.size + 4)
            val out = ByteArray(4096)
            var n = 0
            while (true) {
                val r = inflater.inflate(out, n, out.size - n)
                if (r == 0) break
                n += r
            }
            assertEquals(2000, n, "a 512-byte window inflates it")
        } finally {
            inflater.close()
        }
    }

    @Test fun serverNegotiationState() {
        val s = server { serverNoContextTakeover = true }
        // server_no_context_takeover the server asked for on its own binds its compressor
        assertContentEquals(s.processOutgoingFrame(Frame.Text("Hello")).data, s.processOutgoingFrame(Frame.Text("Hello")).data)
        assertEquals(FrameType.TEXT, s.processIncomingFrame(compressed(bytes(0x00))).frameType)
    }

    @Test fun disposedExtensionRefusesFurtherWork() {
        val c = client()
        c.processOutgoingFrame(Frame.Text("before"))
        c.dispose()
        c.dispose()
        assertFailsWith<IllegalStateException> { c.processOutgoingFrame(Frame.Text("after")) }
        val plain = Frame.Text("plain")
        assertSame(plain, c.processIncomingFrame(plain), "an uncompressed frame needs no codec")
    }

    // ---- review: malformed message ends, the window after a final block, the compressed size

    /** An RSV1 message with no payload is not DEFLATE data (the empty message is 0x00, section 7.2.3.6). */
    @Test fun negative_emptyCompressedPayloadFails() {
        val ext = client()
        assertFailsWith<ProtocolViolationException> { ext.processIncomingFrame(compressed(ByteArray(0))) }
        val inflater = MessageInflater(noContextTakeover = false, maxMessageSize = 1024)
        assertFailsWith<DeflateDataException> { inflater.endOfMessage() }
    }

    /**
     * A message that ends inside a DEFLATE block (cut short) does not end at a block boundary once the empty block is
     * appended: Kotlin/Native's zlib reports it (data_type) and it fails; the JDK's Inflater cannot tell (as OkHttp's).
     */
    @Test fun negative_truncatedMessageFailsWhereZlibTellsTheBoundary() {
        val full = client { compressionLevel = 0 }.processOutgoingFrame(Frame.Binary(true, ByteArray(300) { it.toByte() })).data
        val cut = full.copyOf(full.size - 100) // inside the stored block
        val result = runCatching { server().processIncomingFrame(compressed(cut)) }
        if (RawInflater().let { r -> r.atBlockBoundary.also { r.close() } } != null) {
            assertTrue(result.exceptionOrNull() is ProtocolViolationException, "Native: $result")
        }
    }

    /**
     * RFC 7692 section 7.2.2: without no_context_takeover the next message is decompressed with the window of the last
     * one, also when that one ended its DEFLATE stream with a final block (section 7.2.3.4).
     */
    @Test fun windowCarriesOverAFinalBlock() {
        val ext = client()
        val bfinal = bytes(0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00)
        assertEquals("Hello", (ext.processIncomingFrame(compressed(bfinal)) as Frame.Text).readText())
        // 7.2.3.2's second message: a back reference of 5 bytes, 5 back, into the first one's window
        assertEquals("Hello", (ext.processIncomingFrame(compressed(bytes(0xf2, 0x00, 0x11, 0x00, 0x00))) as Frame.Text).readText())
    }

    /** Compressed data that produces nothing (empty blocks) cannot stream on without bound: it counts toward a limit. */
    @Test fun negative_endlessEmptyBlocksStopAtTheCompressedLimit() {
        val limit = 1000L
        val inflater = MessageInflater(noContextTakeover = false, maxMessageSize = limit)
        val emptyBlock = bytes(0x00, 0x00, 0x00, 0xff, 0xff)
        val out = ByteArray(64)
        assertFailsWith<MessageTooBigException> {
            repeat(100_000) {
                // 500 KB of empty blocks: past 8 times the limit plus 64 KiB
                inflater.input(emptyBlock, 0, emptyBlock.size)
                while (inflater.read(out, 0, out.size) > 0) continue
            }
        }
        inflater.close()
    }
}
