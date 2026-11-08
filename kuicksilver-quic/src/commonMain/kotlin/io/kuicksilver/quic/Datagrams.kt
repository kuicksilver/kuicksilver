// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

/** What happens when the send queue of [QuicConnection.sendDatagram] is full (docs/guide/quic.md, "Datagrams (RFC 9221)"). */
public sealed interface DatagramPolicy {
    /** Drop the oldest queued datagram to make room; never refuses, never waits. */
    public object DropOldest : DatagramPolicy {
        /** For logs. */
        override fun toString(): String = "DropOldest"
    }

    /** Refuse: `trySendDatagram` answers [DatagramSendResult.QueueFull], `sendDatagram` waits for room. */
    public object Reject : DatagramPolicy {
        /** For logs. */
        override fun toString(): String = "Reject"
    }

    /** Replace a queued datagram sent under the same [key][DatagramPolicy.LatestWins.key] (a sensor reading, a cursor position); otherwise behaves like [DropOldest]. */
    public class LatestWins(
        /** Datagrams sent under an equal key replace each other in the queue. */
        public val key: Any,
    ) : DatagramPolicy {
        /** For logs. */
        override fun toString(): String = "LatestWins($key)"
    }
}

/** The answer of [QuicConnection.trySendDatagram]. */
public sealed interface DatagramSendResult {
    /**
     * The datagram is queued for the loop; whether it arrives stays unknown, since datagrams are never retransmitted (RFC 9221 section 5).
     */
    public object Sent : DatagramSendResult {
        /** For logs. */
        override fun toString(): String = "Sent"
    }

    /** The send queue is full under [DatagramPolicy.Reject]; worth retrying once the loop has sent some of it. */
    public object QueueFull : DatagramSendResult {
        /** For logs. */
        override fun toString(): String = "QueueFull"
    }

    /** The connection is closed or closing: nothing will ever be sent again, unlike [QueueFull], which is worth retrying. */
    public object Closed : DatagramSendResult {
        /** For logs. */
        override fun toString(): String = "Closed"
    }

    /**
     * The payload exceeds what the peer's limit and the path allow at the call ([QuicConnection.maxDatagramSize]). [max][DatagramSendResult.TooLarge.max] is the
     * largest payload that fits, 0 also when none fits; a TooLarge for an empty payload means not even an empty datagram fits
     * (e.g. a peer `max_datagram_frame_size` of 1). Machine-readable: `peerSupportsDatagrams && maxDatagramSize.value == 0`.
     */
    public class TooLarge(
        /** The largest payload that fits at the call, in bytes. */
        public val max: Int,
    ) : DatagramSendResult {
        /** Equal when the limits are. */
        override fun equals(other: Any?): Boolean = other is TooLarge && other.max == max

        /** Consistent with [equals]. */
        override fun hashCode(): Int = max

        /** For logs. */
        override fun toString(): String = "TooLarge(max=$max)"
    }

    /** Datagrams cannot be sent on this connection, for [reason][DatagramSendResult.Unsupported.reason]; nothing will change that for its lifetime. */
    public class Unsupported(
        /** Why datagrams cannot be used. */
        public val reason: DatagramUnsupportedReason,
    ) : DatagramSendResult {
        /** Equal when the reasons are. */
        override fun equals(other: Any?): Boolean = other is Unsupported && other.reason == reason

        /** Consistent with [equals]. */
        override fun hashCode(): Int = reason.hashCode()

        /** For logs. */
        override fun toString(): String = "Unsupported($reason)"
    }
}

/** Why datagrams cannot be sent on this connection. */
public enum class DatagramUnsupportedReason {
    /**
     * The peer did not advertise `max_datagram_frame_size`, or advertised 0 (RFC 9221 section 3). Any value above 0, however
     * small, is support: a datagram it does not fit is [DatagramSendResult.TooLarge].
     */
    PeerDoesNotSupport,

    /** Our own `QuicConfig.maxDatagramFrameSize` is 0. */
    Disabled,
}

/**
 * One received DATAGRAM payload (RFC 9221).
 *
 * @property data The payload, a copy the application owns.
 */
public class Datagram(
    public val data: ByteArray,
)
