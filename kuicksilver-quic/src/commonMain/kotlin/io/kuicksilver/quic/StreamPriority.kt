// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.InternalKuicksilverApi

/**
 * Send priority of a stream (RFC 9218 semantics at the transport): lower [urgency] first; [incremental] streams share their level
 * round-robin.
 *
 * @property urgency 0 (most urgent) to 7; 3 by default, as in RFC 9218 section 4.1. IllegalArgumentException outside that range.
 * @property incremental True lets streams of the same urgency take turns; false sends them one after another in id order.
 */
public class StreamPriority(
    public val urgency: Int = 3,
    public val incremental: Boolean = false,
) {
    init {
        require(urgency in 0..7) { "urgency must be 0..7" }
    }

    override fun equals(other: Any?): Boolean = other is StreamPriority && other.urgency == urgency && other.incremental == incremental

    override fun hashCode(): Int = urgency * 2 + if (incremental) 1 else 0

    override fun toString(): String = "StreamPriority(urgency=$urgency, incremental=$incremental)"

    /** Holds [Default]. */
    public companion object { /** Urgency 3, not incremental. */
        public val Default: StreamPriority = StreamPriority()

        /**
         * Reads as urgency 0, not incremental, but the transport sends a stream opened with this very instance before every
         * other stream, whatever their urgency (the HTTP/3 control and QPACK streams: a peer's u=0 must not delay them).
         */
        @InternalKuicksilverApi
        public val Critical: StreamPriority = StreamPriority(0)
    }
}
