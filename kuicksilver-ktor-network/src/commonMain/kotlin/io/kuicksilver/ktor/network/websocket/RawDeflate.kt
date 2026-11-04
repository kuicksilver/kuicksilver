// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network.websocket

import kotlinx.io.IOException

/*
 * Raw DEFLATE (RFC 1951, no zlib or gzip wrapper) for permessage-deflate (RFC 7692 section 7): java.util.zip on the JVM and
 * Android, the platform's zlib (platform.zlib) on Kotlin/Native. Both are the same zlib underneath, used the same way:
 * streaming input, output into a caller's buffer, a sync flush that ends each compressed piece on a byte boundary.
 */

/** Malformed DEFLATE data (zlib's Z_DATA_ERROR, the JVM's DataFormatException). */
internal class DeflateDataException(
    message: String,
) : IOException(message)

/**
 * The smallest LZ77 window, in bits, the deflater of this target can compress within (the server_max_window_bits it can
 * honour, RFC 7692 section 7.1.2.1): 15 on the JVM, whose `Deflater` has no window setting; 9 on Kotlin/Native, since
 * zlib refuses a raw deflate stream with an 8-bit window (deflateInit2 returns Z_STREAM_ERROR).
 */
internal expect val DEFLATE_MIN_WINDOW_BITS: Int

/**
 * A raw DEFLATE decompressor with a window of [windowBits] (8..15; the JVM always uses 15, which reads any smaller window).
 * The input given to [setInput] must stay unchanged until [needsInput] is true. Not thread-safe; [close] frees it.
 */
internal expect class RawInflater(
    windowBits: Int = 15,
) {
    /** Takes [length] bytes of [input] from [offset] as the next input. */
    fun setInput(
        input: ByteArray,
        offset: Int,
        length: Int,
    )

    /**
     * Decompresses into [output] at [offset], at most [length] bytes; returns how many it wrote, 0 when it needs input
     * or the stream ended. Throws [DeflateDataException] on malformed data.
     */
    fun inflate(
        output: ByteArray,
        offset: Int,
        length: Int,
    ): Int

    /** The end of a final block (BFINAL) was reached; the input after it is left in [remaining]. */
    val finished: Boolean

    /** All input was consumed. */
    val needsInput: Boolean

    /** Input bytes not consumed yet. */
    val remaining: Int

    /** Starts a new stream with an empty window. */
    fun reset()

    /** Frees the decompressor; it is not used again. */
    fun close()
}

/**
 * A raw DEFLATE compressor at [level] (0..9) with a window of [windowBits] (15 on the JVM, [DEFLATE_MIN_WINDOW_BITS]..15
 * on Kotlin/Native). The input given to [setInput] must stay unchanged until [needsInput] is true. Not thread-safe;
 * [close] frees it.
 */
internal expect class RawDeflater(
    level: Int,
    windowBits: Int,
) {
    /** Takes [length] bytes of [input] from [offset] as the next input. */
    fun setInput(
        input: ByteArray,
        offset: Int,
        length: Int,
    )

    /**
     * Compresses into [output] at [offset], at most [length] bytes; returns how many it wrote. With [syncFlush] all
     * input is compressed and ended with an empty stored block (zlib's Z_SYNC_FLUSH): while the return value is [length]
     * the caller calls again with the same flag for the rest. Without, it writes what is ready.
     */
    fun deflate(
        output: ByteArray,
        offset: Int,
        length: Int,
        syncFlush: Boolean,
    ): Int

    /** All input was consumed. */
    val needsInput: Boolean

    /** Starts a new stream with an empty window. */
    fun reset()

    /** Frees the compressor; it is not used again. */
    fun close()
}
