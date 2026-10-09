// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

/** What happens when the send queue of [QuicConnection.sendDatagram] is full (docs/guide/quic.md, "Datagrams (RFC 9221)"). */
public sealed interface DatagramPolicy {
    /** Drop the oldest queued datagram to make room; never refuses, never waits. */
    public object DropOldest : DatagramPolicy {
        override fun toString(): String = "DropOldest"
    }

    /** Refuse: `trySendDatagram` answers [DatagramSendResult.QueueFull], `sendDatagram` waits for room. */
    public object Reject : DatagramPolicy {
        override fun toString(): String = "Reject"
    }

    /** Replace a queued datagram sent under the same [key] (a sensor reading, a cursor position); otherwise behaves like [DropOldest]. */
    public class LatestWins(
        public val key: Any,
    ) : DatagramPolicy {
        override fun toString(): String = "LatestWins($key)"
    }
}

/** The answer of [QuicConnection.trySendDatagram]. */
public sealed interface DatagramSendResult {
    /**
     * The datagram is queued for the loop; whether it arrives stays unknown, since datagrams are never retransmitted (RFC 9221 section 5).
     */
    public object Sent : DatagramSendResult {
        override fun toString(): String = "Sent"
    }

    /** The send queue is full under [DatagramPolicy.Reject]; worth retrying once the loop has sent some of it. */
    public object QueueFull : DatagramSendResult {
        override fun toString(): String = "QueueFull"
    }

    /** The connection is closed or closing: nothing will ever be sent again, unlike [QueueFull], which is worth retrying. */
    public object Closed : DatagramSendResult {
        override fun toString(): String = "Closed"
    }

    /** The payload exceeds [QuicConnection.maxDatagramSize], which was [max] bytes at the call. */
    public class TooLarge(
        public val max: Int,
    ) : DatagramSendResult {
        override fun equals(other: Any?): Boolean = other is TooLarge && other.max == max

        override fun hashCode(): Int = max

        override fun toString(): String = "TooLarge(max=$max)"
    }

    /** Datagrams cannot be sent on this connection, for [reason]; nothing will change that for its lifetime. */
    public class Unsupported(
        public val reason: DatagramUnsupportedReason,
    ) : DatagramSendResult {
        override fun equals(other: Any?): Boolean = other is Unsupported && other.reason == reason

        override fun hashCode(): Int = reason.hashCode()

        override fun toString(): String = "Unsupported($reason)"
    }
}

/** Why datagrams cannot be sent on this connection. */
public enum class DatagramUnsupportedReason {
    /** The peer did not advertise `max_datagram_frame_size` (RFC 9221 section 3). */
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
