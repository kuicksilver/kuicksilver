// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TestTimeSource

/** The repeat-offender table of the HTTP/2 flood defences (threat model 3.23), on virtual time. */
class RepeatOffendersTest {
    private val a = InetSocketAddress("192.0.2.1", 40_000)
    private val b = InetSocketAddress("192.0.2.2", 40_000)

    @Test fun negative_threeStrikesWithinAMinuteRefuseForThirtySeconds() {
        val t = TestTimeSource()
        val o = RepeatOffenders(timeSource = t)
        assertFalse(o.strike(a))
        t += 20.seconds
        assertFalse(o.strike(a))
        assertFalse(o.refuses(a), "two strikes are not a penalty")
        t += 20.seconds
        assertTrue(o.strike(a), "the third within a minute starts the penalty")
        assertTrue(o.refuses(InetSocketAddress("192.0.2.1", 40_001)), "the address, whatever its port")
        assertFalse(o.refuses(b), "another address is not affected")
        t += 29.seconds
        assertTrue(o.refuses(a))
        t += 1.seconds
        assertFalse(o.refuses(a), "the penalty ends after 30 s")
        assertEquals(0, o.tracked, "an address with nothing left to remember is forgotten")
    }

    @Test fun strikesOlderThanTheWindowDoNotCount() {
        val t = TestTimeSource()
        val o = RepeatOffenders(timeSource = t)
        repeat(10) {
            o.strike(a)
            o.strike(a)
            t += 61.seconds
        }
        assertFalse(o.refuses(a), "two strikes a minute never add up")
    }

    @Test fun ipv6CountsByItsSlash64() {
        val o = RepeatOffenders()
        o.strike(InetSocketAddress("2001:db8:1:2::1", 1))
        o.strike(InetSocketAddress("2001:db8:1:2::2", 1))
        o.strike(InetSocketAddress("2001:db8:1:2:ffff::3", 1))
        assertTrue(o.refuses(InetSocketAddress("2001:db8:1:2::99", 1)), "the same /64")
        assertFalse(o.refuses(InetSocketAddress("2001:db8:1:3::1", 1)), "another /64")
    }

    @Test fun negative_trackedAddressesAreBounded() {
        val o = RepeatOffenders(maxTracked = 100)
        for (i in 0 until 1_000) o.strike(InetSocketAddress("10.0.${i / 256}.${i % 256}", 1))
        assertEquals(100, o.tracked)
    }
}
