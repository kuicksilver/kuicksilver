// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import kotlin.jvm.JvmInline
import kotlin.time.Duration
import kotlin.time.Duration.Companion.nanoseconds

/**
 * A point on a monotonic clock, in nanoseconds (ADR-0004). The core never reads a clock: every call takes the current
 * mark as a parameter, so tests and the simulator drive virtual time.
 *
 * @property nanos Nanoseconds since an arbitrary origin of the caller's monotonic clock; only differences mean anything.
 */
@JvmInline
public value class TimeMark(
    public val nanos: Long,
) : Comparable<TimeMark> {
    /** Saturates at [NEVER]: a deadline past the end of time stays "never" instead of wrapping into the past. */
    public operator fun plus(d: Duration): TimeMark {
        if (nanos == Long.MAX_VALUE ||
            d == Duration.INFINITE
        ) {
            return NEVER
        }
        val n = d.inWholeNanoseconds
        val r =
            nanos + n
        return if (n > 0 && r < nanos) {
            NEVER
        } else if (n < 0 && r > nanos) {
            TimeMark(Long.MIN_VALUE)
        } else {
            TimeMark(r)
        }
    }

    /** The time from [other] to this mark; negative when [other] is later. */
    public operator fun minus(other: TimeMark): Duration = (nanos - other.nanos).nanoseconds

    /** The mark [d] earlier; saturates at the ends of the range instead of wrapping. */
    public operator fun minus(d: Duration): TimeMark {
        val n = d.inWholeNanoseconds
        val r =
            nanos - n
        return if (n > 0 && r > nanos) {
            TimeMark(Long.MIN_VALUE)
        } else if (n < 0 && r < nanos) {
            NEVER
        } else {
            TimeMark(r)
        }
    }

    override fun compareTo(other: TimeMark): Int = nanos.compareTo(other.nanos)

    override fun toString(): String = if (this == NEVER) "TimeMark(never)" else "TimeMark(${nanos}ns)"

    /** Holds [NEVER]. */
    public companion object {
        /** No deadline: compares after every real instant. Hot paths use it instead of a nullable (boxed) TimeMark. */
        public val NEVER: TimeMark = TimeMark(Long.MAX_VALUE)
    }
}
