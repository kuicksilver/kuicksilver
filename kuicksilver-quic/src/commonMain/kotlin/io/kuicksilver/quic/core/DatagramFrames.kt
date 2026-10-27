// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.DatagramPacketWriter
import io.kuicksilver.quic.recovery.SentFrames
import io.kuicksilver.quic.wire.FrameEncoder
import io.kuicksilver.quic.wire.WireWriter

/** Received DATAGRAM payloads waiting for the application: a ring of [capacity] pooled buffers; a full ring drops the oldest (bounded memory, threat-model 3.2). */
internal class DatagramQueue(
    private val capacity: Int,
) {
    private val slots = arrayOfNulls<ByteArray>(capacity)
    private val lengths = IntArray(capacity)
    private var head = 0
    var size: Int = 0
        private set

    /** Copies the payload in; true when the oldest datagram was dropped to make room. */
    fun push(
        data: PacketBuffer,
        off: Int,
        len: Int,
    ): Boolean {
        var dropped = false
        if (size == capacity) {
            head = (head + 1) % capacity
            size--
            dropped = true
        }
        val i = (head + size) % capacity
        val slot = slots[i]?.takeIf { it.size >= len } ?: ByteArray(maxOf(len, 1500)).also { slots[i] = it }
        data.copyTo(slot, off, 0, len)
        lengths[i] = len
        size++
        return dropped
    }

    /** Copies the oldest datagram into [into] at [offset]; -1 when empty. */
    fun poll(
        into: ByteArray,
        offset: Int,
    ): Int {
        if (size == 0) return -1
        val len = lengths[head]
        slots[head]!!.copyInto(into, offset, 0, len)
        head = (head + 1) % capacity
        size--
        return len
    }
}

/** The [DatagramPacketWriter] of one packet under construction. */
@OptIn(ExperimentalKuicksilverApi::class)
internal class DatagramWriter : DatagramPacketWriter {
    private var w: WireWriter? = null
    private var frames: SentFrames? = null
    private var maxPayloadValue = 0
    var wrote: Boolean = false
        private set

    fun bind(
        w: WireWriter,
        frames: SentFrames,
        maxPayload: Int,
    ) {
        this.w = w
        this.frames = frames
        this.maxPayloadValue = maxPayload
        wrote =
            false
    }

    fun unbind() {
        w = null
        frames = null
    }

    override val maxPayload: Int get() = maxPayloadValue
    override val remaining: Int get() {
        val w =
            w ?: return 0
        return minOf(maxPayloadValue, largestDatagramPayload(w.remaining))
    }

    override fun write(
        data: ByteArray,
        offset: Int,
        length: Int,
        id: Long,
    ): Boolean {
        val w = w ?: return false
        val f = frames ?: return false
        if (length < 0 || length > remaining) return false
        FrameEncoder.datagram(w, data, offset, length)
        f.addDatagram(id)
        wrote = true
        return true
    }
}

/**
 * The largest payload whose DATAGRAM frame (type 0x31, a Length varint, the payload) fits in [room] bytes, 0 when none does:
 * the frame cannot be split across packets (RFC 9221 section 5). The best of a 1-byte Length (up to 63), a 2-byte one (up to
 * 16 383) and a 4-byte one; sizing the Length from the room rather than from the payload left a 66-byte room offering 64
 * bytes, a 67-byte frame. Two-argument maxOf calls only: the four-argument one is vararg and allocates an IntArray per
 * packet on the send path.
 */
internal fun largestDatagramPayload(room: Int): Int = maxOf(maxOf(0, minOf(63, room - 2)), maxOf(minOf(16_383, room - 3), room - 5))
