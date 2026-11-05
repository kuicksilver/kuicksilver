// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TestTimeSource

/** The repeat-offender table of the HTTP/2 flood defences (threat model 3.23, opt-in), on virtual time. */
class RepeatOffendersTest {
    private val a = InetSocketAddress("192.0.2.1", 40_000)
    private val b = InetSocketAddress("192.0.2.2", 40_000)

    private fun offenders(
        t: TestTimeSource = TestTimeSource(),
        maxTracked: Int = 4_096,
    ) = RepeatOffenders(penalty = 30.seconds, maxTracked = maxTracked, timeSource = t)

    @Test fun negative_threeStrikesWithinAMinuteRefuseForThePenalty() =
        runBlocking<Unit> {
            val t = TestTimeSource()
            val o = offenders(t)
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
            assertEquals(0, o.tracked(), "an address with nothing left to remember is forgotten")
        }

    @Test fun strikesOlderThanTheWindowDoNotCount() =
        runBlocking<Unit> {
            val t = TestTimeSource()
            val o = offenders(t)
            repeat(10) {
                o.strike(a)
                o.strike(a)
                t += 61.seconds
            }
            assertFalse(o.refuses(a), "two strikes a minute never add up")
        }

    /**
     * A dual-stack listener reports IPv4 peers as IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`, RFC 4291 section 2.5.5.2;
     * Kotlin/Native's accept does): each is its IPv4 address, never one shared IPv6 prefix of zeros.
     */
    @Test fun negative_ipv4MappedPeersCountAsTheirIpv4Address() =
        runBlocking<Unit> {
            fun mapped(last: Int) =
                ByteArray(16).also {
                    it[10] = -1
                    it[11] = -1
                    it[12] = 192.toByte()
                    it[14] = 2
                    it[15] = last.toByte()
                }
            assertEquals(RepeatOffenders.keyOf(byteArrayOf(192.toByte(), 0, 2, 1)), RepeatOffenders.keyOf(mapped(1)))
            assertNotEquals(RepeatOffenders.keyOf(mapped(1)), RepeatOffenders.keyOf(mapped(2)))
            assertEquals("192.0.2.1", RepeatOffenders.describe(mapped(1)))
            val o = offenders()
            repeat(3) { o.strike(InetSocketAddress("::ffff:192.0.2.1", 1)) }
            assertTrue(o.refuses(InetSocketAddress("192.0.2.1", 2)))
            assertFalse(o.refuses(InetSocketAddress("::ffff:192.0.2.2", 1)), "another IPv4 client is not refused")
        }

    /** An IPv6 client counts by its /56: end sites get a /56 or a /48 (RFC 6177), so a /64 would be one subnet away. */
    @Test fun ipv6CountsByItsSlash56() =
        runBlocking<Unit> {
            val o = offenders()
            o.strike(InetSocketAddress("2001:db8:1:200::1", 1))
            o.strike(InetSocketAddress("2001:db8:1:2ff::2", 1))
            o.strike(InetSocketAddress("2001:db8:1:240:ffff::3", 1))
            assertTrue(o.refuses(InetSocketAddress("2001:db8:1:2aa::99", 1)), "the same /56")
            assertFalse(o.refuses(InetSocketAddress("2001:db8:1:300::1", 1)), "another /56")
            assertEquals("2001:db8:1:200::/56", RepeatOffenders.describe(parseIpLiteral("2001:db8:1:2ff::2")!!))
        }

    @Test fun negative_trackedAddressesAreBounded() =
        runBlocking<Unit> {
            val o = offenders(maxTracked = 100)
            for (i in 0 until 1_000) o.strike(InetSocketAddress("10.0.${i / 256}.${i % 256}", 1))
            assertEquals(100, o.tracked())
        }

    /** Addresses that merely struck once make room first: a penalty is not cut short by a stream of new addresses. */
    @Test fun negative_penalisedAddressesOutliveEviction() =
        runBlocking<Unit> {
            val t = TestTimeSource()
            val o = offenders(t, maxTracked = 10)
            repeat(3) { o.strike(a) }
            for (i in 0 until 1_000) o.strike(InetSocketAddress("10.0.${i / 256}.${i % 256}", 1))
            assertTrue(o.refuses(a), "still serving its penalty")
            assertEquals(10, o.tracked())
        }

    @Test fun ipLiteralsParseWithoutALookup() =
        runBlocking<Unit> {
            assertContentEquals(byteArrayOf(192.toByte(), 0, 2, 1), parseIpLiteral("192.0.2.1"))
            assertContentEquals(ByteArray(15) + byteArrayOf(1), parseIpLiteral("::1"))
            assertContentEquals(
                ByteArray(10) + byteArrayOf(-1, -1, 192.toByte(), 0, 2, 7),
                parseIpLiteral("::ffff:192.0.2.7"),
            )
            assertContentEquals(
                byteArrayOf(0x20, 0x01, 0x0d, 0xb8.toByte()) + ByteArray(11) + byteArrayOf(5),
                parseIpLiteral("[2001:db8::5%en0]"),
            )
            assertContentEquals(ByteArray(12) + byteArrayOf(1, 2, 3, 4), parseIpLiteral("0:0:0:0:0:0:1.2.3.4"))
            for (bad in listOf(
                "server.test",
                "1.2.3",
                "1.2.3.256",
                "1::2::3",
                "",
                "12345::",
                "1:2:3:4:5:6:7:8:9",
                // a sign is no hex digit
                "+1::",
                "-1::",
                "::+f",
                "1:2:3:4:5:6:7:-8",
                // a dotted quad only as the last 32 bits
                "1.2.3.4::",
                "::1.2.3.4:5",
                "1.2.3.4:1::",
                "1:1.2.3.4::5",
            )) {
                assertNull(parseIpLiteral(bad), bad)
            }
        }
}
