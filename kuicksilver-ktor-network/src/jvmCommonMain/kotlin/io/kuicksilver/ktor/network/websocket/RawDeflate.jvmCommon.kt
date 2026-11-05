// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network.websocket

import java.util.zip.DataFormatException
import java.util.zip.Deflater
import java.util.zip.Inflater

/** java.util.zip.Deflater has no window setting: it always compresses with 15 bits (32 KiB). */
internal actual val DEFLATE_MIN_WINDOW_BITS: Int = 15

internal actual class RawInflater actual constructor(
    windowBits: Int,
) {
    // nowrap: raw DEFLATE; java.util.zip always inflates with a 32 KiB window, which reads any smaller one
    private val inflater = Inflater(true)

    init {
        require(windowBits in 8..15) { "windowBits $windowBits is not in 8..15" }
    }

    actual fun setInput(
        input: ByteArray,
        offset: Int,
        length: Int,
    ) {
        inflater.setInput(input, offset, length)
    }

    actual fun inflate(
        output: ByteArray,
        offset: Int,
        length: Int,
    ): Int {
        try {
            val n = inflater.inflate(output, offset, length)
            if (n == 0 && inflater.needsDictionary()) throw DeflateDataException("raw DEFLATE data asks for a preset dictionary")
            return n
        } catch (e: DataFormatException) {
            throw DeflateDataException(e.message ?: "invalid DEFLATE data")
        }
    }

    actual val finished: Boolean get() = inflater.finished()

    actual val needsInput: Boolean get() = inflater.needsInput()

    actual val remaining: Int get() = inflater.remaining

    // java.util.zip.Inflater does not expose zlib's data_type
    actual val atBlockBoundary: Boolean? get() = null

    actual fun setDictionary(
        bytes: ByteArray,
        offset: Int,
        length: Int,
    ) {
        inflater.setDictionary(bytes, offset, length)
    }

    actual fun reset() {
        inflater.reset()
    }

    actual fun close() {
        inflater.end()
    }
}

internal actual class RawDeflater actual constructor(
    level: Int,
    windowBits: Int,
) {
    init {
        require(level in 0..9) { "level $level is not in 0..9" }
        require(windowBits == 15) { "java.util.zip compresses with a 15-bit window only, not $windowBits" }
    }

    private val deflater = Deflater(level, true)

    actual fun setInput(
        input: ByteArray,
        offset: Int,
        length: Int,
    ) {
        deflater.setInput(input, offset, length)
    }

    actual fun deflate(
        output: ByteArray,
        offset: Int,
        length: Int,
        syncFlush: Boolean,
    ): Int = deflater.deflate(output, offset, length, if (syncFlush) Deflater.SYNC_FLUSH else Deflater.NO_FLUSH)

    actual val needsInput: Boolean get() = deflater.needsInput()

    actual fun reset() {
        deflater.reset()
    }

    actual fun close() {
        deflater.end()
    }
}
