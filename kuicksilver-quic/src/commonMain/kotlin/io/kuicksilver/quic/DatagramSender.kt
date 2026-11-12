// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/**
 * The core's hook for RFC 9221 DATAGRAM frames: while a 1-RTT packet is assembled and the congestion window
 * is open, [onTransmit] is called with a writer for the room left in that packet. Datagrams are ack-eliciting, counted
 * by congestion control and never retransmitted; [onAcked] / [onLost] report what happened to each id handed to
 * [DatagramPacketWriter.write]. The coroutine API of `QuicConnection` builds its queues on this.
 */
@ExperimentalKuicksilverApi
@SubclassOptInRequired(ExperimentalKuicksilverApi::class)
public interface DatagramSender {
    /** Called on every 1-RTT packet with room; write zero or more datagrams that fit [DatagramPacketWriter.remaining]. */
    public fun onTransmit(packet: DatagramPacketWriter)

    /** False when nothing waits: the core then builds no packet for datagrams alone (a sender that always answers true makes the core assemble, and discard, an empty packet per poll). */
    public fun hasPending(): Boolean = true

    /**
     * The RFC 9218 urgency (0..7) of the datagram the sender would write next, or -1 (the default) for none: the core then
     * writes stream data of strictly more urgent streams (a lower urgency, and the critical streams) before calling
     * [onTransmit] in a packet, so such a datagram never preempts them, while stream data of the same or a lower urgency
     * still waits behind it. With -1 datagrams go first, ahead of every stream (RFC 9221 leaves the order to the sender).
     */
    public fun nextUrgency(): Int = -1

    /** The packet carrying datagram [id] was acknowledged, so the peer received it (RFC 9221 section 5.2); called on the endpoint loop. */
    public fun onAcked(id: Long) {}

    /**
     * The packet carrying datagram [id] was declared lost; the datagram is not sent again, the sender decides what to do (RFC 9221 section
     * 5.2).
     */
    public fun onLost(id: Long) {}
}

/** Room for DATAGRAM frames in the packet being built. */
@ExperimentalKuicksilverApi
public interface DatagramPacketWriter {
    /**
     * Payload bytes that still fit (frame header already accounted for); never above `ConnectionCore.maxDatagramPayload`. 0 also when
     * no frame fits at all: an empty datagram still needs 2 bytes, and [write] then returns false.
     */
    public val remaining: Int

    /** The largest payload any frame of this packet could carry (`ConnectionCore.maxDatagramPayload`); a queued datagram above it can never be sent. */
    public val maxPayload: Int

    /** Writes one DATAGRAM frame; false when [length] exceeds [remaining] or the frame does not fit (an empty one still takes 2 bytes). [id] comes back in `onAcked` / `onLost` (-1: no callback). */
    public fun write(
        data: ByteArray,
        offset: Int,
        length: Int,
        id: Long = -1,
    ): Boolean
}
