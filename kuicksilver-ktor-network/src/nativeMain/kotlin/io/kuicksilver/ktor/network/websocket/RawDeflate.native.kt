// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class, ExperimentalNativeApi::class, ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.network.websocket

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.free
import kotlinx.cinterop.nativeHeap
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.toKString
import kotlinx.cinterop.usePinned
import platform.posix.memset
import platform.zlib.Z_BUF_ERROR
import platform.zlib.Z_DATA_ERROR
import platform.zlib.Z_DEFAULT_STRATEGY
import platform.zlib.Z_DEFLATED
import platform.zlib.Z_MEM_ERROR
import platform.zlib.Z_NEED_DICT
import platform.zlib.Z_NO_FLUSH
import platform.zlib.Z_OK
import platform.zlib.Z_STREAM_END
import platform.zlib.Z_SYNC_FLUSH
import platform.zlib.deflate
import platform.zlib.deflateEnd
import platform.zlib.deflateInit2
import platform.zlib.deflateReset
import platform.zlib.inflate
import platform.zlib.inflateEnd
import platform.zlib.inflateInit2
import platform.zlib.inflateReset
import platform.zlib.inflateSetDictionary
import platform.zlib.z_stream
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.createCleaner

/** zlib refuses a raw deflate stream with an 8-bit window (deflateInit2: `windowBits == 8 && wrap != 1`). */
internal actual val DEFLATE_MIN_WINDOW_BITS: Int = 9

/** memLevel 8 (zlib's default): with a 15-bit window, 256 KiB for a deflater; an inflater takes its window, 32 KiB. */
private const val MEM_LEVEL = 8

/**
 * A z_stream in the native heap, freed once: by [free] or, for one never closed, by the cleaner of its owner. It holds
 * nothing of the owner, so the cleaner does not keep the owner alive.
 */
private class ZStream(
    private val deflate: Boolean,
) {
    val strm: z_stream = nativeHeap.alloc<z_stream>().also { memset(it.ptr, 0, sizeOf<z_stream>().convert()) }
    private val freed = AtomicBoolean(false)

    fun free() {
        if (!freed.compareAndSet(expectedValue = false, newValue = true)) return
        if (deflate) deflateEnd(strm.ptr) else inflateEnd(strm.ptr)
        nativeHeap.free(strm)
    }
}

/** The input of a z_stream, held in Kotlin and pinned only while zlib runs (zlib keeps no pointer to it between calls). */
private class PendingInput {
    var bytes: ByteArray? = null
    var offset = 0
    var length = 0

    fun set(
        input: ByteArray,
        offset: Int,
        length: Int,
    ) {
        require(offset >= 0 && length >= 0 && offset + length <= input.size) { "offset $offset, length $length, size ${input.size}" }
        bytes = input
        this.offset = offset
        this.length = length
    }

    fun clear() {
        bytes = null
        offset = 0
        length = 0
    }
}

/**
 * Runs [call] on [z] with [input] as its input and [length] bytes of [output] from [offset] as its output; returns zlib's
 * result code and moves [input] past what zlib consumed. The second value is the number of bytes written.
 */
private inline fun ZStream.run(
    input: PendingInput,
    output: ByteArray,
    offset: Int,
    length: Int,
    call: () -> Int,
): Pair<Int, Int> {
    require(offset >= 0 && length > 0 && offset + length <= output.size) { "offset $offset, length $length, size ${output.size}" }
    val inBytes = input.bytes
    val inLength = input.length
    var rc = 0
    var consumed = 0
    var produced = 0
    output.usePinned { out ->
        strm.next_out = out.addressOf(offset).reinterpret()
        strm.avail_out = length.convert()
        if (inBytes != null && inLength > 0) {
            inBytes.usePinned { pin ->
                strm.next_in = pin.addressOf(input.offset).reinterpret()
                strm.avail_in = inLength.convert()
                rc = call()
                consumed = inLength - strm.avail_in.toInt()
            }
        } else {
            strm.next_in = null
            strm.avail_in = 0u
            rc = call()
        }
        produced = length - strm.avail_out.toInt()
        strm.next_in = null
        strm.avail_in = 0u
        strm.next_out = null
        strm.avail_out = 0u
    }
    input.offset += consumed
    input.length -= consumed
    if (input.length == 0) input.clear()
    return rc to produced
}

private fun ZStream.message(rc: Int): String = strm.msg?.toKString() ?: "zlib error $rc"

internal actual class RawInflater actual constructor(
    windowBits: Int,
) {
    private val z = ZStream(deflate = false)

    @Suppress("unused") // frees the z_stream of an inflater that was never closed
    private val cleaner = createCleaner(z) { it.free() }

    private val input = PendingInput()
    private var ended = false

    init {
        require(windowBits in 8..15) { "windowBits $windowBits is not in 8..15" }
        val rc = inflateInit2(z.strm.ptr, -windowBits) // negative: raw DEFLATE, no zlib header
        if (rc != Z_OK) {
            z.free()
            if (rc == Z_MEM_ERROR) throw OutOfMemoryError("inflateInit2: out of memory")
            error("inflateInit2 failed: $rc")
        }
    }

    actual fun setInput(
        input: ByteArray,
        offset: Int,
        length: Int,
    ) {
        this.input.set(input, offset, length)
    }

    actual fun inflate(
        output: ByteArray,
        offset: Int,
        length: Int,
    ): Int {
        if (length == 0 || ended) return 0
        val (rc, produced) = z.run(input, output, offset, length) { inflate(z.strm.ptr, Z_NO_FLUSH) }
        when (rc) {
            Z_OK, Z_BUF_ERROR -> {}

            Z_STREAM_END -> {
                ended = true
            }

            Z_DATA_ERROR -> {
                throw DeflateDataException(z.message(rc))
            }

            Z_NEED_DICT -> {
                throw DeflateDataException("raw DEFLATE data asks for a preset dictionary")
            }

            Z_MEM_ERROR -> {
                throw OutOfMemoryError("inflate: out of memory")
            }

            else -> {
                error("inflate failed: ${z.message(rc)}")
            }
        }
        return produced
    }

    actual val finished: Boolean get() = ended

    actual val needsInput: Boolean get() = input.length == 0

    actual val remaining: Int get() = input.length

    // zlib sets data_type after every inflate(): + 128 when it waits for the next block's header (inflate.c)
    actual val atBlockBoundary: Boolean? get() = z.strm.data_type and 128 != 0

    actual fun setDictionary(
        bytes: ByteArray,
        offset: Int,
        length: Int,
    ) {
        if (length == 0) return
        val rc = bytes.usePinned { inflateSetDictionary(z.strm.ptr, it.addressOf(offset).reinterpret(), length.convert()) }
        check(rc == Z_OK) { "inflateSetDictionary failed: $rc" }
    }

    actual fun reset() {
        check(inflateReset(z.strm.ptr) == Z_OK) { "inflateReset failed" }
        input.clear()
        ended = false
    }

    actual fun close() {
        input.clear()
        z.free()
    }
}

internal actual class RawDeflater actual constructor(
    level: Int,
    windowBits: Int,
) {
    private val z = ZStream(deflate = true)

    @Suppress("unused") // frees the z_stream of a deflater that was never closed
    private val cleaner = createCleaner(z) { it.free() }

    private val input = PendingInput()

    init {
        require(level in 0..9) { "level $level is not in 0..9" }
        require(windowBits in DEFLATE_MIN_WINDOW_BITS..15) { "windowBits $windowBits is not in $DEFLATE_MIN_WINDOW_BITS..15" }
        val rc = deflateInit2(z.strm.ptr, level, Z_DEFLATED, -windowBits, MEM_LEVEL, Z_DEFAULT_STRATEGY)
        if (rc != Z_OK) {
            z.free()
            if (rc == Z_MEM_ERROR) throw OutOfMemoryError("deflateInit2: out of memory")
            error("deflateInit2 failed: $rc")
        }
    }

    actual fun setInput(
        input: ByteArray,
        offset: Int,
        length: Int,
    ) {
        this.input.set(input, offset, length)
    }

    actual fun deflate(
        output: ByteArray,
        offset: Int,
        length: Int,
        syncFlush: Boolean,
    ): Int {
        if (length == 0) return 0
        val flush = if (syncFlush) Z_SYNC_FLUSH else Z_NO_FLUSH
        val (rc, produced) = z.run(input, output, offset, length) { deflate(z.strm.ptr, flush) }
        // Z_BUF_ERROR: no progress was possible (no input and nothing left to flush), not an error
        check(rc == Z_OK || rc == Z_BUF_ERROR) { "deflate failed: ${z.message(rc)}" }
        return produced
    }

    actual val needsInput: Boolean get() = input.length == 0

    actual fun reset() {
        check(deflateReset(z.strm.ptr) == Z_OK) { "deflateReset failed" }
        input.clear()
    }

    actual fun close() {
        input.clear()
        z.free()
    }
}
