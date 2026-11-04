// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network.websocket

import kotlinx.io.Buffer
import kotlinx.io.IOException
import kotlinx.io.readByteArray

/** The output of an inflater is produced, counted and handed on in pieces of this size, never more at once. */
internal const val INFLATE_CHUNK: Int = 64 * 1024

/** The empty stored block a sync flush ends with, which RFC 7692 section 7.2.1 removes and section 7.2.2 appends again. */
private val TAIL = byteArrayOf(0x00, 0x00, 0xff.toByte(), 0xff.toByte())

/** A message that decompresses to more than the limit (RFC 6455 section 7.4.1: 1009, message too big); [size] so far. */
internal class MessageTooBigException(
    val size: Long,
    limit: Long,
) : IOException("a compressed message inflates to more than $limit bytes")

/**
 * Decompresses the messages of one direction (RFC 7692 section 7.2.2): the payloads of a message's frames go to [input]
 * as they arrive, [endOfMessage] appends 0x00 0x00 0xff 0xff, and [read] hands the output on in pieces; [messageDone]
 * ends the message. A message that would inflate to more than [maxMessageSize] bytes fails [read] with
 * [MessageTooBigException] once at most one piece past the limit was produced: nothing is sized by what the data claims.
 * With [noContextTakeover] each message starts with an empty window; so does the one after a message that ended its
 * DEFLATE stream with a final block (section 7.2.3.4). The zlib state is made on the first compressed message only.
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
        if (streamEnded) return trailing(bytes, offset, length)
        check(raw?.needsInput != false) { "the previous input was not read to its end" }
        raw().setInput(bytes, offset, length)
        lastInput = bytes
        lastEnd = offset + length
    }

    /** The message's data is complete: the removed empty block is appended (RFC 7692 section 7.2.2). */
    fun endOfMessage() {
        tail = true
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
        }
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

    /** Ends the message; the next one may refer back into it unless context takeover is off or its stream ended. */
    fun messageDone() {
        if (noContextTakeover || streamEnded) raw?.reset()
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
