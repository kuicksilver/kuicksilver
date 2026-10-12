// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

/**
 * A windowed maximum over a virtual clock (round trips, ProbeBW cycles): the best, second-best and third-best samples of the
 * last [window] ticks, so the maximum expires gracefully instead of dropping to zero (Kathleen Nichols' algorithm, as in
 * Linux `lib/win_minmax.c`; draft-ietf-ccwg-bbr section 5.5.3). A sample more than [window] ticks older than the newest one is gone.
 * Three slots, no allocation after construction.
 */
internal class WindowedMaxFilter(
    var window: Long,
) {
    private val time = LongArray(3)
    private val value = LongArray(3)

    /** The maximum of the window, 0 when empty. */
    val best: Long get() = value[0]

    fun reset(
        t: Long,
        v: Long,
    ) {
        for (i in 0..2) {
            time[i] = t
            value[i] = v
        }
    }

    /** Adds [v] measured at tick [t] (ticks never go backwards) and returns the new maximum. */
    fun update(
        v: Long,
        t: Long,
    ): Long {
        if (v >= value[0] || t - time[2] > window) {
            reset(t, v)
            return v
        } // a new maximum, or nothing in the window survives
        if (v >= value[1]) {
            set(2, t, v)
            set(1, t, v)
        } else if (v >= value[2]) {
            set(2, t, v)
        }
        val dt = t - time[0]
        if (dt > window) {
            shift(t, v)
            if (t - time[0] > window) shift(t, v)
        } // the best expired: the second takes over
        else if (time[1] == time[0] && dt > window / 4) {
            set(2, t, v)
            set(1, t, v)
        } // a quarter window passed without a second choice: take one
        else if (time[2] == time[1] && dt > window / 2) {
            set(2, t, v)
        } // half a window passed without a third choice
        return value[0]
    }

    private fun shift(
        t: Long,
        v: Long,
    ) {
        set(0, time[1], value[1])
        set(1, time[2], value[2])
        set(2, t, v)
    }

    private fun set(
        i: Int,
        t: Long,
        v: Long,
    ) {
        time[i] = t
        value[i] = v
    }
}
