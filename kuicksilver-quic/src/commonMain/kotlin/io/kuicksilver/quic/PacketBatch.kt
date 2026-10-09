// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.native.PacketBuffer

/**
 * A fixed set of datagram slots the core fills on [ConnectionCore.poll] and the I/O layer sends or receives (ADR-0006).
 *
 * @property capacity Number of slots; one `poll` produces at most this many datagrams.
 * @property segmentSize Bytes per slot: the largest datagram a slot holds (1500 by default; larger for a core configured beyond it).
 */
public class PacketBatch(
    public val capacity: Int,
    public val segmentSize: Int = 1500,
) : AutoCloseable {
    private val buffers = Array(capacity) { PacketBuffer.allocate(segmentSize) }
    private val lengths = IntArray(capacity)
    private val addresses = arrayOfNulls<InetSocketAddress>(capacity)
    private val ecns = Array(capacity) { Ecn.NotEct }
    private val paths = IntArray(capacity)

    /** Number of filled slots. */
    public var count: Int = 0

    /** The buffer of slot [i]; its first [length] bytes are the datagram. */
    public fun buffer(i: Int): PacketBuffer = buffers[i]

    /** Datagram length in bytes of slot [i]. */
    public fun length(i: Int): Int = lengths[i]

    /** Sets the datagram length of slot [i] to [n] bytes and grows [count] to cover the slot. */
    public fun setLength(
        i: Int,
        n: Int,
    ) {
        lengths[i] = n
        if (i >= count) count = i + 1
    }

    /**
     * The peer address of slot [i]: the destination of an outgoing datagram, the source of a received one; null for a slot never filled.
     */
    public fun address(i: Int): InetSocketAddress? = addresses[i]

    /** Sets the peer address of slot [i]. */
    public fun setAddress(
        i: Int,
        a: InetSocketAddress,
    ) {
        addresses[i] = a
    }

    /** ECN codepoint of slot [i]: the mark to send with, or the mark the datagram arrived with (RFC 9000 section 13.4). */
    public fun ecn(i: Int): Ecn = ecns[i]

    /** Sets the ECN codepoint of slot [i]. */
    public fun setEcn(
        i: Int,
        e: Ecn,
    ) {
        ecns[i] = e
    }

    /** The local socket (path) a datagram goes out on; [PathId.Initial] for the one socket of a single-path endpoint. */
    public fun path(i: Int): PathId = PathId(paths[i])

    /** Sets the local socket (path) slot [i] goes out on. */
    public fun setPath(
        i: Int,
        p: PathId,
    ) {
        paths[i] = p.value
    }

    /** Marks every slot free ([count] = 0) for the next poll or receive; the buffers stay allocated until [close]. */
    public fun clear() {
        count = 0
    }

    override fun close() {
        buffers.forEach { it.close() }
    }
}
