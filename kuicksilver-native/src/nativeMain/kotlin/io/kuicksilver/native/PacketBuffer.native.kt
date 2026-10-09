// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.native

import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.get
import kotlinx.cinterop.nativeHeap
import kotlinx.cinterop.plus
import kotlinx.cinterop.set
import kotlinx.cinterop.usePinned
import platform.posix.memcpy

public actual class PacketBuffer private constructor(
    private var ptr: CPointer<UByteVar>?,
    public actual val capacity: Int,
) : AutoCloseable {
    internal fun address(): CPointer<UByteVar> = ptr ?: throw IllegalStateException("PacketBuffer is closed")

    private fun check(
        offset: Int,
        length: Int,
        what: String,
    ) = checkRange(capacity, offset, length, what)

    public actual operator fun get(index: Int): Byte {
        check(index, 1, "get")
        return address()[index].toByte()
    }

    public actual operator fun set(
        index: Int,
        value: Byte,
    ) {
        check(index, 1, "set")
        address()[index] = value.toUByte()
    }

    public actual fun copyFrom(
        src: ByteArray,
        srcOffset: Int,
        dstOffset: Int,
        length: Int,
    ) {
        check(dstOffset, length, "copyFrom")
        checkRange(src.size, srcOffset, length, "copyFrom source")
        if (length == 0) return
        src.usePinned { memcpy(address() + dstOffset, it.addressOf(srcOffset), length.toULong()) }
    }

    public actual fun copyTo(
        dst: ByteArray,
        srcOffset: Int,
        dstOffset: Int,
        length: Int,
    ) {
        check(srcOffset, length, "copyTo")
        checkRange(dst.size, dstOffset, length, "copyTo destination")
        if (length == 0) return
        dst.usePinned { memcpy(it.addressOf(dstOffset), address() + srcOffset, length.toULong()) }
    }

    actual override fun close() {
        ptr?.let { nativeHeap.free(it.rawValue) }
        ptr = null
    }

    public actual companion object {
        public actual fun allocate(capacity: Int): PacketBuffer =
            PacketBuffer(
                nativeHeap.allocArray<UByteVar>(
                    if (capacity >
                        0
                    ) {
                        capacity
                    } else {
                        1
                    },
                ),
                capacity,
            )
    }
}
