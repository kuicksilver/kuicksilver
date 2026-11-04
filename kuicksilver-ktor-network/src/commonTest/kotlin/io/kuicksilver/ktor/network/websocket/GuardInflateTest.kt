// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network.websocket

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeFully
import io.kuicksilver.ktor.network.WS_RSV1
import io.kuicksilver.ktor.network.guardWebSocketInput
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.io.EOFException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The engines' frame guard with permessage-deflate negotiated (RFC 7692 section 7.2.2): it decompresses each compressed
 * message as it arrives, hands it on as plain frames of at most 64 KiB, and fails a message over the limit with a Close
 * frame with 1009 (RFC 6455 section 7.4.1), malformed data with 1002.
 */
class GuardInflateTest {
    private fun bytes(vararg b: Int) = ByteArray(b.size) { b[it].toByte() }

    private class Out(
        val b0: Int,
        val payload: ByteArray,
    ) {
        val fin get() = b0 and 0x80 != 0
        val rsv get() = b0 and 0x70
        val opcode get() = b0 and 0x0f
        val closeCode get() = ((payload[0].toInt() and 0xff) shl 8) or (payload[1].toInt() and 0xff)
    }

    /** The frames the guard hands on (unmasked, as it writes them), until its output ends. */
    private suspend fun frames(channel: ByteReadChannel): List<Out> {
        val out = ArrayList<Out>()
        while (true) {
            val b0 =
                try {
                    channel.readByte().toInt() and 0xff
                } catch (_: EOFException) {
                    return out
                }
            val b1 = channel.readByte().toInt() and 0xff
            var length = (b1 and 0x7f).toLong()
            if (length == 126L) {
                length = channel.readByteArray(2).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xff) }
            } else if (length == 127L) {
                length = channel.readByteArray(8).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xff) }
            }
            val mask = if (b1 and 0x80 != 0) channel.readByteArray(4) else null
            val payload = channel.readByteArray(length.toInt())
            if (mask != null) for (i in payload.indices) payload[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
            out += Out(b0, payload)
        }
    }

    private fun header(
        b0: Int,
        length: Int,
        mask: ByteArray? = null,
    ): ByteArray {
        val m = if (mask != null) 0x80 else 0
        val h =
            when {
                length < 126 -> bytes(b0, m or length)
                length < 65536 -> bytes(b0, m or 126, length shr 8, length and 0xff)
                else -> bytes(b0, m or 127, 0, 0, 0, 0, length ushr 24, (length shr 16) and 0xff, (length shr 8) and 0xff, length and 0xff)
            }
        return if (mask != null) h + mask else h
    }

    private fun frame(
        b0: Int,
        payload: ByteArray,
        mask: ByteArray? = null,
    ): ByteArray {
        val p = payload.copyOf()
        if (mask != null) for (i in p.indices) p[i] = (p[i].toInt() xor mask[i % 4].toInt()).toByte()
        return header(b0, p.size, mask) + p
    }

    private fun guarded(
        input: ByteArray,
        inflate: WebSocketInflate = WebSocketInflate(noContextTakeover = false, maxMessageSize = 16L * 1024 * 1024),
        peerMasks: Boolean = false,
        block: suspend (List<Out>) -> Unit,
    ) = runTest {
        val raw = ByteChannel()
        launch {
            raw.writeFully(input)
            raw.flushAndClose()
        }
        val out =
            guardWebSocketInput(raw, WS_RSV1, untilClose = false, peerMasks = peerMasks, context = coroutineContext, inflate = inflate)
        block(frames(out))
    }

    private fun List<Out>.text() = filter { it.opcode <= 2 }.fold(ByteArray(0)) { a, f -> a + f.payload }.decodeToString()

    private val hello = bytes(0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00)

    @Test fun compressedMessageIsInflatedAndRsv1Cleared() =
        guarded(frame(0xC1, hello) + frame(0x82, bytes(1, 2, 3))) { out ->
            assertEquals(2, out.size)
            assertEquals(0x81, out[0].b0, "a final text frame without RSV1")
            assertEquals("Hello", out[0].payload.decodeToString())
            assertEquals(0x82, out[1].b0, "an uncompressed message passes as it was")
            assertEquals(listOf<Byte>(1, 2, 3), out[1].payload.toList())
        }

    /** RFC 7692 section 7.2.3.1, fragmented, with a Ping between the fragments; the client's frames are masked. */
    @Test fun fragmentedCompressedMessageWithInterleavedControlFrame() {
        val mask = bytes(0x37, 0xfa, 0x21, 0x3d)
        val input =
            frame(0x41, bytes(0xf2, 0x48, 0xcd), mask) + frame(0x89, bytes(0x70), mask) + frame(0x80, bytes(0xc9, 0xc9, 0x07, 0x00), mask)
        guarded(input, peerMasks = true) { out ->
            assertTrue(out.all { it.rsv == 0 }, "no RSV bit on what is handed on")
            val data = out.filter { it.opcode != 0x9 }
            assertEquals(0x1, data.first().opcode)
            assertTrue(data.drop(1).all { it.opcode == 0 }, "continuations after the first frame")
            assertTrue(data.last().fin && data.dropLast(1).none { it.fin })
            assertEquals("Hello", out.text())
            assertEquals(1, out.count { it.opcode == 0x9 && it.payload.contentEquals(bytes(0x70)) }, "the Ping passes, unmasked")
        }
    }

    /** RFC 7692 section 7.2.3.2: the second message refers back into the first. */
    @Test fun contextTakeoverAcrossMessages() =
        guarded(frame(0xC1, hello) + frame(0xC1, bytes(0xf2, 0x00, 0x11, 0x00, 0x00))) { out ->
            assertEquals(listOf("Hello", "Hello"), out.map { it.payload.decodeToString() })
        }

    @Test fun noContextTakeoverStartsEachMessageEmpty() =
        guarded(
            frame(0xC1, hello) + frame(0xC1, bytes(0xf2, 0x00, 0x11, 0x00, 0x00)),
            WebSocketInflate(noContextTakeover = true, maxMessageSize = 1024),
        ) { out ->
            assertEquals("Hello", out[0].payload.decodeToString())
            assertEquals(0x88, out[1].b0, "a back reference into an emptied window is malformed")
            assertEquals(1002, out[1].closeCode)
            assertEquals(2, out.size)
        }

    @Test fun largeMessageIsHandedOnInPiecesOf64KiB() {
        val message = ByteArray(300_000) { (it % 251).toByte() }
        val deflater = MessageDeflater(6, 15, noContextTakeover = false)
        val compressed = deflater.compress(message, fin = true)
        deflater.close()
        guarded(frame(0xC2, compressed)) { out ->
            assertTrue(out.all { it.payload.size <= INFLATE_CHUNK }, out.map { it.payload.size }.toString())
            assertEquals(0x2, out.first().opcode)
            assertTrue(out.last().fin)
            assertEquals(message.toList(), out.fold(ByteArray(0)) { a, f -> a + f.payload }.toList())
        }
    }

    @Test fun negative_inflateBombClosesWith1009() {
        val deflater = MessageDeflater(9, 15, noContextTakeover = false)
        val bomb = deflater.compress(ByteArray(10 * 1024 * 1024), fin = true)
        deflater.close()
        val limit = 1024L * 1024
        guarded(frame(0xC2, bomb) + frame(0x81, "never".encodeToByteArray()), WebSocketInflate(false, limit)) { out ->
            val close = out.last()
            assertEquals(0x88, close.b0)
            assertEquals(1009, close.closeCode)
            val delivered = out.dropLast(1).sumOf { it.payload.size.toLong() }
            assertTrue(delivered <= limit + INFLATE_CHUNK, "handed on $delivered bytes before the Close")
            assertTrue(out.dropLast(1).none { it.fin }, "the message is never completed")
        }
    }

    @Test fun negative_corruptDeflateStreamClosesWith1002() =
        guarded(frame(0xC1, bytes(0xff, 0xff, 0xff)) + frame(0x81, "never".encodeToByteArray())) { out ->
            assertEquals(1, out.size)
            assertEquals(1002, out.single().closeCode)
        }

    @Test fun negative_continuationWithoutMessageClosesWith1002() =
        guarded(frame(0x80, bytes(0x61))) { out ->
            assertEquals(1002, out.single().closeCode)
        }

    @Test fun negative_newMessageInsideAFragmentedOneClosesWith1002() =
        guarded(frame(0x41, bytes(0xf2, 0x48)) + frame(0xC1, hello)) { out ->
            assertEquals(1002, out.last().closeCode)
        }
}
