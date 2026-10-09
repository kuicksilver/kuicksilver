// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.native

import java.nio.ByteBuffer

public actual class PacketBuffer private constructor(
    private var buffer: ByteBuffer?,
) : AutoCloseable {
    public actual val capacity: Int = buffer!!.capacity()

    /** Cursor for bulk copies; a PacketBuffer is used by one thread at a time, so one view serves every copy without allocating. */
    private val view: ByteBuffer = buffer!!.duplicate()

    internal fun direct(): ByteBuffer = buffer ?: throw IllegalStateException("PacketBuffer is closed")

    /** A fresh view over the same direct memory (position 0, limit = capacity) for NIO calls; the view shares the bytes, not the lifetime. */
    public fun asByteBuffer(): ByteBuffer = direct().duplicate().also { it.clear() }

    public actual operator fun get(index: Int): Byte = direct().get(index)

    public actual operator fun set(
        index: Int,
        value: Byte,
    ) {
        direct().put(index, value)
    }

    public actual fun copyFrom(
        src: ByteArray,
        srcOffset: Int,
        dstOffset: Int,
        length: Int,
    ) {
        checkRange(capacity, dstOffset, length, "copyFrom")
        checkRange(src.size, srcOffset, length, "copyFrom source")
        direct()
        val d = view
        d.clear()
        d.position(dstOffset)
        d.put(src, srcOffset, length)
    }

    public actual fun copyTo(
        dst: ByteArray,
        srcOffset: Int,
        dstOffset: Int,
        length: Int,
    ) {
        checkRange(capacity, srcOffset, length, "copyTo")
        checkRange(dst.size, dstOffset, length, "copyTo destination")
        direct()
        val d = view
        d.clear()
        d.position(srcOffset)
        d.get(dst, dstOffset, length)
    }

    actual override fun close() {
        buffer = null
    }

    public actual companion object {
        public actual fun allocate(capacity: Int): PacketBuffer = PacketBuffer(ByteBuffer.allocateDirect(capacity))
    }
}
