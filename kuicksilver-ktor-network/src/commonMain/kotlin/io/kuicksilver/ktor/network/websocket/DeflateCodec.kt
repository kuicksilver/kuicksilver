// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network.websocket

import kotlinx.io.Buffer
import kotlinx.io.IOException
import kotlinx.io.readByteArray

/** The LZ77 window an inflater keeps across a final block: 32 KiB, the most RFC 7692 allows (section 7.2.2). */
private const val WINDOW = 32 * 1024

/** The output of an inflater is produced, counted and handed on in pieces of this size, never more at once. */
internal const val INFLATE_CHUNK: Int = 64 * 1024

/** The empty stored block a sync flush ends with, which RFC 7692 section 7.2.1 removes and section 7.2.2 appends again. */
private val TAIL = byteArrayOf(0x00, 0x00, 0xff.toByte(), 0xff.toByte())

/**
 * A message too big to process (RFC 6455 section 7.4.1: 1009): it inflates to more than [limit] bytes ([size] so far),
 * or, with [compressedBytes], its compressed data passed [limit] bytes.
 */
internal class MessageTooBigException(
    val size: Long,
    val limit: Long,
    val compressedBytes: Boolean = false,
) : IOException(
        if (compressedBytes) {
            "a compressed message has more than $limit bytes of compressed data"
        } else {
            "a compressed message inflates to more than $limit bytes"
        },
    )

/**
 * Decompresses the messages of one direction (RFC 7692 section 7.2.2): the payloads of a message's frames go to [input]
 * as they arrive, [endOfMessage] appends 0x00 0x00 0xff 0xff, and [read] hands the output on in pieces; [messageDone]
 * ends the message. A message that would inflate to more than [maxMessageSize] bytes fails [read] with
 * [MessageTooBigException] once at most one piece past the limit was produced: nothing is sized by what the data claims.
 * With [noContextTakeover] each message starts with an empty window. Without it, the next message is decompressed with
 * the window of the last one (section 7.2.2, MUST), also after a message that ended its DEFLATE stream with a final block
 * (section 7.2.3.4): the stream is restarted and primed with the window: the last 32 KiB of output is kept for that on
 * every platform (the JDK's Inflater cannot hand the window over, and zlib's inflateGetDictionary is newer than the
 * zlib 1.2.7 of the glibc 2.17 Linux floor).
 *
 * A message is malformed (DeflateDataException) when it has no compressed data at all (the empty message is 0x00,
 * section 7.2.3.6), when data follows a final block other than the 0x00 that pads it (section 7.2.3.4), and, where the
 * platform's zlib tells (Kotlin/Native; the JDK's Inflater does not, nor does OkHttp's MessageInflater), when it does not
 * end at a DEFLATE block boundary once 0x00 0x00 0xff 0xff is appended (a message cut short). A message whose compressed
 * data passes 8 times [maxMessageSize] plus 64 KiB fails as too big as well: data that inflates to nothing (empty blocks)
 * cannot stream on without bound, and no sender needs more (a sync-flushed one-byte fragment takes about 6 bytes).
 * The zlib state is made on the first compressed message only.
 */
internal class MessageInflater(
    private val noContextTakeover: Boolean,
    private val maxMessageSize: Long,
) {
    private var raw: RawInflater? = null
    private var produced = 0L
    private var tail = false
    private var streamEnded = false

    // the input last given to the inflater, to look at what it left after a final block
    private var lastInput: ByteArray = TAIL
    private var lastEnd = 0

    // bytes of the message after the final block of its stream
    private var afterEnd = 0

    // the message's compressed bytes, and the most it may have
    private var compressed = 0L
    private val maxCompressed =
        if (maxMessageSize >
            (Long.MAX_VALUE - (64 shl 10)) / 8
        ) {
            Long.MAX_VALUE
        } else {
            maxMessageSize * 8 + (64 shl 10)
        }

    // the last 32 KiB of output (a ring), to keep the window across a final block; with context takeover only
    private var history: ByteArray? = null
    private var historyEnd = 0
    private var historyFull = false

    private fun raw(): RawInflater = raw ?: RawInflater().also { raw = it }

    /**
     * The next [length] bytes of the message's compressed data; [read] must have drained the previous input (returned 0).
     * After the final block of a stream only the 0x00 that pads it to a whole empty block may follow (section 7.2.3.4):
     * anything more fails with [DeflateDataException].
     */
    fun input(
        bytes: ByteArray,
        offset: Int,
        length: Int,
    ) {
        if (length == 0) return
        compressed += length
        if (compressed > maxCompressed) throw MessageTooBigException(compressed, maxCompressed, compressedBytes = true)
        if (streamEnded) return trailing(bytes, offset, length)
        check(raw?.needsInput != false) { "the previous input was not read to its end" }
        raw().setInput(bytes, offset, length)
        lastInput = bytes
        lastEnd = offset + length
    }

    /** The message's data is complete: the removed empty block is appended (RFC 7692 section 7.2.2). */
    fun endOfMessage() {
        tail = true
        if (compressed == 0L) throw DeflateDataException("a compressed message without compressed data")
        if (!streamEnded) {
            check(raw?.needsInput != false) { "the previous input was not read to its end" }
            raw().setInput(TAIL, 0, TAIL.size)
            lastInput = TAIL
            lastEnd = TAIL.size
        }
    }

    /** Decompressed bytes of the message into [output]; 0 when the input so far is used up. */
    fun read(
        output: ByteArray,
        offset: Int,
        length: Int,
    ): Int {
        val r = raw ?: return 0
        if (streamEnded || length == 0) return 0
        val n = r.inflate(output, offset, length)
        if (r.finished) {
            streamEnded = true
            // what follows the final block: the rest of the appended empty block, or in the data the 0x00 before it
            if (!tail) trailing(lastInput, lastEnd - r.remaining, r.remaining)
        } else if (n == 0 && !r.needsInput) {
            throw DeflateDataException("DEFLATE data the inflater cannot make progress on")
        } else if (n == 0 && tail && r.atBlockBoundary == false) {
            throw DeflateDataException("a compressed message that does not end at a DEFLATE block boundary")
        }
        // the window survives a final block: the last 32 KiB of output is kept for it on every platform (zlib's
        // inflateGetDictionary would hand it over on Native, but it needs zlib 1.2.7.1, above the manylinux2014 floor)
        if (n > 0 && !noContextTakeover) remember(output, offset, n)
        produced += n
        if (produced > maxMessageSize) throw MessageTooBigException(produced, maxMessageSize)
        return n
    }

    private fun trailing(
        bytes: ByteArray,
        offset: Int,
        length: Int,
    ) {
        afterEnd += length
        if (afterEnd > 1 || (length > 0 && bytes[offset] != 0.toByte())) {
            throw DeflateDataException("data after the final DEFLATE block of a message")
        }
    }

    private fun remember(
        bytes: ByteArray,
        offset: Int,
        length: Int,
    ) {
        val h = history ?: ByteArray(WINDOW).also { history = it }
        var from = offset
        var left = length
        if (left >= WINDOW) {
            from += left - WINDOW
            left = WINDOW
        }
        while (left > 0) {
            val n = minOf(left, WINDOW - historyEnd)
            bytes.copyInto(h, historyEnd, from, from + n)
            historyEnd += n
            if (historyEnd == WINDOW) {
                historyEnd = 0
                historyFull = true
            }
            from += n
            left -= n
        }
    }

    /** Ends the message; the next one refers back into it unless context takeover is off (section 7.2.2). */
    fun messageDone() {
        val r = raw
        if (r != null && noContextTakeover) {
            r.reset()
        } else if (r != null && streamEnded) {
            // a final block ended the stream: a new one, primed with the window the next message may refer back into
            r.reset()
            val h = history
            if (h != null) {
                if (historyFull) {
                    val window = h.copyOfRange(historyEnd, WINDOW) + h.copyOfRange(0, historyEnd)
                    r.setDictionary(window, 0, window.size)
                } else {
                    r.setDictionary(h, 0, historyEnd)
                }
            }
        }
        finishMessage()
    }

    private fun finishMessage() {
        compressed = 0
        produced = 0
        tail = false
        streamEnded = false
        afterEnd = 0
        lastInput = TAIL
        lastEnd = 0
    }

    /** Frees the zlib state. */
    fun close() {
        raw?.close()
        raw = null
    }
}

/**
 * Compresses the messages of one direction (RFC 7692 section 7.2.1): each fragment's data is compressed and flushed
 * (a sync flush, so a fragment never waits for the next); the final fragment of a message ends without the
 * 0x00 0x00 0xff 0xff of its flush, and is a single 0x00 when the flush had nothing to write (section 7.2.3.6).
 * With [noContextTakeover] each message starts with an empty window. The zlib state is made on the first message.
 */
internal class MessageDeflater(
    private val level: Int,
    private val windowBits: Int,
    private val noContextTakeover: Boolean,
) {
    private var raw: RawDeflater? = null
    private var chunk: ByteArray? = null

    /** The compressed form of [data], the next fragment of a message, the last one when [fin]. */
    fun compress(
        data: ByteArray,
        fin: Boolean,
    ): ByteArray {
        val d = raw ?: RawDeflater(level, windowBits).also { raw = it }
        val buf = chunk ?: ByteArray(16 * 1024).also { chunk = it }
        val out = Buffer()
        d.setInput(data, 0, data.size)
        while (true) {
            val n = d.deflate(buf, 0, buf.size, syncFlush = true)
            out.write(buf, 0, n)
            if (n < buf.size) break
        }
        check(d.needsInput) { "the deflater kept input after a sync flush" }
        var bytes = out.readByteArray()
        if (fin) {
            bytes =
                if (bytes.size >= TAIL.size && bytes.endsWith(TAIL)) {
                    bytes.copyOf(bytes.size - TAIL.size)
                } else {
                    // the flush wrote nothing (no new input since the last one): an empty stored block, 0x00 0x00 0x00 0xff
                    // 0xff on a byte boundary, minus its last four bytes
                    bytes + 0x00
                }
            if (noContextTakeover) d.reset()
        }
        return bytes
    }

    /** Frees the zlib state. */
    fun close() {
        raw?.close()
        raw = null
        chunk = null
    }

    private fun ByteArray.endsWith(suffix: ByteArray): Boolean {
        val start = size - suffix.size
        for (i in suffix.indices) if (this[start + i] != suffix[i]) return false
        return true
    }
}
