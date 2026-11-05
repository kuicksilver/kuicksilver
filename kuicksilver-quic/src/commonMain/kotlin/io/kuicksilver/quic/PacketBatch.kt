// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer

/**
 * A fixed set of datagram slots the core fills on [ConnectionCore.poll] and the I/O layer sends or receives (ADR-0006).
 *
 * @property capacity Number of slots; one `poll` produces at most this many datagrams.
 * @property segmentSize Bytes per slot: the largest datagram a slot holds (1500 by default; larger for a core configured beyond it).
 */
public class PacketBatch internal constructor(
    public val capacity: Int,
    public val segmentSize: Int,
    allocate: (Int) -> PacketBuffer,
) : AutoCloseable {
    /** A batch of [capacity] slots of [segmentSize] bytes each. */
    public constructor(capacity: Int, segmentSize: Int = 1500) : this(capacity, segmentSize, PacketBuffer::allocate)

    // native memory on Kotlin/Native: an allocation that fails part-way frees the slots made before it
    private val buffers: Array<PacketBuffer> =
        arrayOfNulls<PacketBuffer>(capacity).let { made ->
            try {
                for (i in 0 until capacity) made[i] = allocate(segmentSize)
            } catch (e: Throwable) {
                val r = Releaser(e) // what a release throws is suppressed into e
                for (b in made) if (b != null) r.release { b.close() }
                throw e
            }
            @Suppress("UNCHECKED_CAST")
            made as Array<PacketBuffer>
        }
    private val lengths = IntArray(capacity)
    private val addresses = arrayOfNulls<InetSocketAddress>(capacity)
    private val locals = arrayOfNulls<InetSocketAddress>(capacity)
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

    /** Sets the peer address of slot [i]; clears its [localAddress], so a producer that does not know it never leaves a stale one. */
    public fun setAddress(
        i: Int,
        a: InetSocketAddress,
    ) {
        addresses[i] = a
        locals[i] = null
    }

    /**
     * Our address of slot [i] (RFC 9000 section 9: a path is the 4-tuple). For a received datagram, the address it was sent to, which
     * a socket bound to a wildcard address learns from IP_PKTINFO / IPV6_PKTINFO (the accelerated socket; null when the socket cannot
     * tell, as the portable ones). For an outgoing one, the source it must leave from, null for the socket's own choice. Set it after
     * [setAddress], which clears it.
     */
    @ExperimentalKuicksilverApi
    public fun localAddress(i: Int): InetSocketAddress? = locals[i]

    /** Sets our address of slot [i] ([localAddress]); null lets the socket choose. */
    @ExperimentalKuicksilverApi
    public fun setLocalAddress(
        i: Int,
        a: InetSocketAddress?,
    ) {
        locals[i] = a
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
        val r = Releaser() // every slot even when one before it fails to close
        for (b in buffers) r.release { b.close() }
        r.finish()
    }
}
