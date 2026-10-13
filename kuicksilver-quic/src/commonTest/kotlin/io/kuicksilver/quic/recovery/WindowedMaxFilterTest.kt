// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import kotlin.test.Test
import kotlin.test.assertEquals

/** The windowed max of draft-ietf-ccwg-bbr section 5.5.3 (Linux win_minmax): the best of the window, expiring gracefully. */
class WindowedMaxFilterTest {
    @Test fun keepsTheMaximumWithinTheWindow() {
        val f = WindowedMaxFilter(10)
        assertEquals(5, f.update(5, 0))
        assertEquals(9, f.update(9, 1))
        assertEquals(9, f.update(3, 2))
        assertEquals(9, f.update(4, 11))
    }

    @Test fun anExpiredMaximumHandsOverToTheNextBest() {
        val f = WindowedMaxFilter(10)
        f.update(9, 0)
        f.update(7, 4) // a quarter window later: the second choice
        f.update(6, 8) // half a window later: the third
        assertEquals(7, f.update(1, 11)) // 9 is 11 ticks old
        assertEquals(6, f.update(1, 15)) // 7 is too
        assertEquals(1, f.update(1, 30)) // nothing survives a whole window
    }

    @Test fun aTwoCycleWindowForgetsTheCycleBeforeLast() {
        val f = WindowedMaxFilter(1) // BBR.max_bw: the current and the previous ProbeBW cycle
        f.update(100, 0)
        assertEquals(100, f.update(60, 1))
        assertEquals(60, f.update(50, 2))
        assertEquals(50, f.update(40, 3))
    }

    @Test fun aNewMaximumReplacesEverything() {
        val f = WindowedMaxFilter(10)
        f.update(5, 0)
        f.update(4, 1)
        assertEquals(8, f.update(8, 2))
        assertEquals(8, f.best)
    }
}
