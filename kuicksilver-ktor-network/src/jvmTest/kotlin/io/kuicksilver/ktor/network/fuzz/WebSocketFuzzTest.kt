// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeFully
import io.kuicksilver.ktor.network.WS_RSV1
import io.kuicksilver.ktor.network.guardWebSocketInput
import io.kuicksilver.ktor.network.websocket.DeflateDataException
import io.kuicksilver.ktor.network.websocket.INFLATE_CHUNK
import io.kuicksilver.ktor.network.websocket.MessageDeflater
import io.kuicksilver.ktor.network.websocket.MessageInflater
import io.kuicksilver.ktor.network.websocket.MessageTooBigException
import io.kuicksilver.ktor.network.websocket.WebSocketInflate
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.io.EOFException
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The limits the first input byte picks from: small enough that a fuzzer reaches them, one the default's size. */
private val LIMITS = longArrayOf(1, 1_000, 70_000, 16L * 1024 * 1024)

/**
 * Splits [data] from [from] into messages: each is a length byte `n` and then that many bytes, the length byte times 64
 * when its top bit is set (so messages of up to 8 KiB come from short inputs); the last takes what is left.
 */
private fun messages(
    data: ByteArray,
    from: Int,
): List<ByteArray> {
    val out = ArrayList<ByteArray>()
    var p = from
    while (p < data.size) {
        val b = data[p++].toInt() and 0xff
        val n = minOf(if (b and 0x80 != 0) (b and 0x7f) * 64 else b, data.size - p)
        out += data.copyOfRange(p, p + n)
        p += n
    }
    return out
}

/**
 * Fuzz target `inflate`: input = [mode byte][messages]. The mode's low bit picks context takeover, bits 1-2 the limit
 * ([LIMITS]), bit 3 the direction:
 * - clear: each message is the compressed payload of a permessage-deflate message (RFC 7692 section 7.2.2), fed to one
 *   [MessageInflater] in pieces of 1 + (mode >> 4) * 97 bytes. Only [DeflateDataException] and [MessageTooBigException] may
 *   escape, and the latter only once more than the limit came out; no message hands on more than the limit plus one
 *   64 KiB piece, and nothing is asked of it after an error (a session ends there).
 * - set: each message is plain data, compressed by a [MessageDeflater] (section 7.2.1, fragmented at the piece size)
 *   and inflated again: the round trip gives back every message unchanged, the empty one included, across messages with
 *   and without context takeover.
 */
class InflateFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun inflate(data: ByteArray) {
        if (data.isEmpty()) return
        val mode = data[0].toInt() and 0xff
        val noContextTakeover = mode and 1 != 0
        val limit = LIMITS[(mode shr 1) and 3]
        val piece = 1 + (mode shr 4) * 97
        if (mode and 8 != 0) return roundTrip(messages(data, 1), noContextTakeover, piece)
        val inflater = MessageInflater(noContextTakeover, limit)
        val chunk = ByteArray(INFLATE_CHUNK)
        try {
            for (message in messages(data, 1)) {
                var produced = 0L

                fun drain() {
                    while (true) {
                        val n =
                            try {
                                inflater.read(chunk, 0, chunk.size)
                            } catch (e: MessageTooBigException) {
                                assertTrue(e.size > limit && e.size <= limit + INFLATE_CHUNK, "${e.size} for a limit of $limit")
                                throw e
                            }
                        if (n == 0) return
                        produced += n
                        assertTrue(produced <= limit, "$produced bytes handed on, limit $limit")
                    }
                }
                var p = 0
                while (p < message.size) {
                    val n = minOf(piece, message.size - p)
                    inflater.input(message, p, n)
                    drain()
                    p += n
                }
                inflater.endOfMessage()
                drain()
                inflater.messageDone()
            }
        } catch (_: DeflateDataException) {
        } catch (_: MessageTooBigException) {
        } finally {
            inflater.close()
        }
    }

    private fun roundTrip(
        plain: List<ByteArray>,
        noContextTakeover: Boolean,
        piece: Int,
    ) {
        val deflater = MessageDeflater(level = 6, windowBits = 15, noContextTakeover = noContextTakeover)
        val inflater = MessageInflater(noContextTakeover, Long.MAX_VALUE)
        val chunk = ByteArray(INFLATE_CHUNK)
        try {
            for (message in plain) {
                val fragments =
                    (0 until maxOf(1, (message.size + piece - 1) / piece)).map { i ->
                        val end = minOf(message.size, (i + 1) * piece)
                        deflater.compress(message.copyOfRange(minOf(i * piece, end), end), fin = end == message.size)
                    }
                val out = java.io.ByteArrayOutputStream()
                for (f in fragments) {
                    inflater.input(f, 0, f.size)
                    while (true) {
                        val n = inflater.read(chunk, 0, chunk.size)
                        if (n == 0) break
                        out.write(chunk, 0, n)
                    }
                }
                inflater.endOfMessage()
                while (true) {
                    val n = inflater.read(chunk, 0, chunk.size)
                    if (n == 0) break
                    out.write(chunk, 0, n)
                }
                inflater.messageDone()
                assertContentEquals(message, out.toByteArray())
            }
        } finally {
            deflater.close()
            inflater.close()
        }
    }
}

/**
 * Fuzz target `wsGuard`: input = [mode byte][WebSocket frames]. The engines' frame guard with permessage-deflate
 * negotiated (RFC 7692 section 7.2.2) reads the frames as a client's (masked, mode bit 4) or a server's; the low bits
 * pick context takeover and the limit as in [InflateFuzzTest]. Every frame it hands on carries no RSV bit (RSV1 messages
 * are decompressed, other bits fail the connection); a message it hands on is no larger than the input (passed through)
 * or the limit plus one 64 KiB piece (decompressed); with masked input its own Close frames (unmasked, 1002 or 1009) are
 * the last thing it writes; and it ends.
 */
class WsGuardFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun wsGuard(data: ByteArray) {
        if (data.isEmpty()) return
        val mode = data[0].toInt() and 0xff
        val limit = LIMITS[(mode shr 1) and 3]
        val peerMasks = mode and 16 != 0
        runBlocking(Dispatchers.Unconfined) {
            val input = ByteChannel()
            val job = Job()
            val out =
                guardWebSocketInput(
                    input,
                    WS_RSV1,
                    untilClose = false,
                    peerMasks = peerMasks,
                    context = coroutineContext + job,
                    inflate = WebSocketInflate(noContextTakeover = mode and 1 != 0, maxMessageSize = limit),
                )
            launch {
                input.writeFully(data, 1, data.size) // start and end index
                input.flushAndClose()
            }
            var message = 0L
            var closed = false
            while (true) {
                val b0 =
                    try {
                        out.readByte().toInt() and 0xff
                    } catch (_: EOFException) {
                        break
                    }
                assertTrue(!closed, "nothing after the guard's own Close frame")
                assertEquals(0, b0 and 0x70, "no RSV bit on a frame handed on")
                val b1 = out.readByte().toInt() and 0xff
                var length = (b1 and 0x7f).toLong()
                if (length == 126L) {
                    length = out.readByteArray(2).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xff) }
                } else if (length == 127L) {
                    length = out.readByteArray(8).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xff) }
                }
                if (b1 and 0x80 != 0) out.readByteArray(4)
                // a passed-through header may claim more than the input has: the output then ends inside the payload
                val payload =
                    try {
                        out.readByteArray(minOf(length, Int.MAX_VALUE.toLong()).toInt())
                    } catch (_: EOFException) {
                        break
                    }
                val opcode = b0 and 0x0f
                if (opcode >= 8) {
                    if (opcode == 8 && peerMasks && b1 and 0x80 == 0) closed = true // the guard's own: a client's is masked
                    continue
                }
                message += payload.size
                assertTrue(message <= maxOf(data.size.toLong(), limit + INFLATE_CHUNK), "a message of $message, limit $limit")
                if (b0 and 0x80 != 0) message = 0
            }
            job.cancel()
            assertTrue(out.isClosedForRead)
        }
    }
}
