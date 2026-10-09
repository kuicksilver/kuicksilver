// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.native

/**
 * Off-heap packet memory handed to `ksl` by address: a direct `ByteBuffer` on the JVM, native heap on Kotlin/Native.
 * Not thread-safe; one owner at a time. [close] releases the memory; use after close throws [IllegalStateException].
 */
public expect class PacketBuffer : AutoCloseable {
    /** Size in bytes, fixed by [allocate]; valid indices are `0 until capacity`. */
    public val capacity: Int

    /** The byte at [index]; throws [IndexOutOfBoundsException] outside `0 until capacity`. */
    public operator fun get(index: Int): Byte

    /** Writes [value] at [index]; throws [IndexOutOfBoundsException] outside `0 until capacity`. */
    public operator fun set(
        index: Int,
        value: Byte,
    )

    /**
     * Copies `src[srcOffset, +length)` into this buffer at [dstOffset]. Both ranges are checked before any byte moves:
     * [IndexOutOfBoundsException] when either lies outside its array.
     */
    public fun copyFrom(
        src: ByteArray,
        srcOffset: Int,
        dstOffset: Int,
        length: Int,
    )

    /**
     * Copies `this[srcOffset, +length)` into [dst] at [dstOffset]. Both ranges are checked before any byte moves:
     * [IndexOutOfBoundsException] when either lies outside its array.
     */
    public fun copyTo(
        dst: ByteArray,
        srcOffset: Int,
        dstOffset: Int,
        length: Int,
    )

    override fun close()

    /** Factory for buffers; extensions such as [of] hang off it. */
    public companion object {
        /**
         * A new buffer of [capacity] bytes owned by the caller, who must [close] it: on Kotlin/Native the memory is not
         * garbage collected. The contents are unspecified (zeroed on the JVM, not on Native), so write before reading.
         */
        public fun allocate(capacity: Int): PacketBuffer
    }
}

/** Throws [IndexOutOfBoundsException] unless `[offset, offset + length)` lies within `[0, size)`; overflow-safe. Every binding that hands a Kotlin array to native code checks with it first, so native code never copies past the array. */
internal fun checkRange(
    size: Int,
    offset: Int,
    length: Int,
    what: String,
) {
    if (offset < 0 || length < 0 || offset > size - length) throw IndexOutOfBoundsException("$what: $offset+$length outside 0..$size")
}

/** Convenience: a buffer holding a copy of [bytes]. */
public fun PacketBuffer.Companion.of(bytes: ByteArray): PacketBuffer = allocate(bytes.size).also { it.copyFrom(bytes, 0, 0, bytes.size) }

/** Convenience: the first [length] bytes as a new array. */
public fun PacketBuffer.toByteArray(length: Int = capacity): ByteArray = ByteArray(length).also { copyTo(it, 0, 0, length) }
